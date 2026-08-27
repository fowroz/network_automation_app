"""
========================================================================
 Network Automation Web Console - Flask Backend  (AI + multi-device edition)
========================================================================

WHAT THIS IS
------------
A tiny, single-purpose Flask app that serves a browser UI
(templates/index.html) for running network automation checks
(ping, TCP port check, and optional SSH command execution) against
ONE OR MANY devices at once, with:

    - live streaming output + a structured JSON report at the end
    - a built-in library of common Cisco/Juniper/Arista/Aruba commands
      for one-click / autocomplete insertion
    - optional AI assistance (command suggestions + run analysis) via
      OpenRouter, NVIDIA NIM, or a local Ollama install -- all called
      with the Python standard library only (no extra pip installs
      required for the AI features)

Missing required Python packages (Flask, paramiko) are installed
automatically on first run -- you don't need to run `pip install`
yourself beforehand.

HOW TO RUN
----------
    1. python app.py
       (missing packages like Flask/paramiko are auto-installed the
        first time you run this script)
    2. Open http://localhost:5000 in your browser

FOLDER LAYOUT REQUIRED
-----------------------
    network_automation_app/
        app.py                <- this file
        templates/
            index.html        <- the UI

No Docker, no virtualenv, no Node.js required.

AI FEATURES ARE FULLY OPTIONAL
-------------------------------
If you leave the AI provider set to "None" in the UI, none of this
code path is used and the app behaves exactly like the non-AI version.
API keys you type into the browser are sent directly from your browser
to this local Flask server for a single request, forwarded straight to
the provider you chose, and are NEVER written to disk or logged by
this server.
========================================================================
"""

import functools
import importlib
import io
import ipaddress
import json
import os
import queue
import re
import socket
import subprocess
import sys
import platform
import threading
import time
import uuid
import paramiko
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from typing import Optional


# --------------------------------------------------------------------------
# STEP 0: Auto-install missing dependencies before we try to import them.
#
# This lets a brand new user just run `python app.py` without first having
# to remember to run `pip install flask paramiko`. If a package is already
# present, this is a no-op (fast import check only -- no network calls).
# The AI integrations below deliberately use only `urllib` (stdlib) so no
# extra packages are ever required for them.
# --------------------------------------------------------------------------
def ensure_package(import_name: str, pip_name: Optional[str] = None):
    """
    Try to import `import_name`. If it's missing, attempt to install it
    with pip (using the same Python interpreter that's running this
    script) and import it again. Returns the imported module, or None
    if it could not be imported/installed.
    """
    pip_name = pip_name or import_name
    try:
        return importlib.import_module(import_name)
    except ImportError:
        print(f"[SETUP] Required package '{import_name}' not found. "
              f"Installing '{pip_name}' automatically...")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet", pip_name]
            )
        except Exception as exc:
            print(f"[SETUP] ERROR: Automatic install of '{pip_name}' failed: {exc}")
            return None
        try:
            module = importlib.import_module(import_name)
            print(f"[SETUP] Successfully installed and imported '{import_name}'.")
            return module
        except ImportError as exc:
            print(f"[SETUP] ERROR: '{import_name}' still not importable after install: {exc}")
            return None


# Flask is required -- if it can't be installed, we can't run at all.
_flask_module = ensure_package("flask")
if _flask_module is None:
    print("\nFATAL: Flask is required and could not be installed automatically.")
    print("Please run:  pip install flask")
    print("...then try running this script again.\n")
    sys.exit(1)

from flask import Flask, Response, jsonify, render_template, request, send_file, stream_with_context

paramiko.Transport._preferred_kex = (
    'diffie-hellman-group14-sha1',
    'diffie-hellman-group-exchange-sha1',
    'diffie-hellman-group1-sha1',
)

# paramiko is optional -- only needed for real SSH command execution.
# We attempt an automatic install; if that fails (e.g. no internet access,
# no compiler for a dependency, restricted environment), the app still
# runs fine and simply skips the SSH step with a clear warning message.
_paramiko_module = ensure_package("paramiko")
PARAMIKO_AVAILABLE = _paramiko_module is not None
paramiko = _paramiko_module  # convenience alias used below

# netmiko is also optional and NOT currently used by the core execution
# engine below (which is hand-built on top of paramiko and already handles
# multi-vendor prompt detection, config mode, jump hosts, and SSH-key auth
# on its own). It's auto-installed here anyway so it's available in the
# environment for anyone extending this app, and so /health accurately
# reports whether it's present.
_netmiko_module = ensure_package("netmiko")
NETMIKO_AVAILABLE = _netmiko_module is not None
netmiko = _netmiko_module  # convenience alias, currently unused by app logic

# Jinja2 powers the "Generate dynamic configurations" feature (VLAN
# creation, bulk interface configuration, and fully custom templates).
# Optional -- if it can't be installed, the rest of the app still runs
# fine and the template-rendering endpoints just return a clear error.
_jinja2_module = ensure_package("jinja2")
JINJA2_AVAILABLE = _jinja2_module is not None

# PyYAML is required by the vendored inventory_collector package (Audit
# profiles are YAML files) -- auto-installed like everything else above.
_yaml_module = ensure_package("yaml", pip_name="PyYAML")
YAML_AVAILABLE = _yaml_module is not None
_openpyxl_module = ensure_package("openpyxl")
OPENPYXL_AVAILABLE = _openpyxl_module is not None

# TextFSM/ntc-templates power `parser: textfsm` / table-mode profiles
# specifically -- they are NOT imported (let alone auto-installed) here
# at startup. They're comparatively heavy (ntc-templates bundles
# hundreds of vendor template files) and only a table-mode/TextFSM
# profile (e.g. interface_inventory) ever needs them, so eagerly loading
# them for every single app startup -- even for users who never touch
# that one profile -- was pure wasted latency/memory. The actual import
# is now deferred to inventory_collector.textfsm_support, triggered only
# the first time such a profile is actually executed (see that module's
# docstring). AUDIT_TEXTFSM_AVAILABLE below is a fast presence CHECK
# (no import) purely for the UI/health-check "is this available" badge.

import storage  # local module, see storage.py -- SQLite persistence + optional encryption
import logging_setup  # local module -- professional app + audit logging (logs/app.log, logs/audit.log)
import health_checks  # local module -- before/after automated health check parsing + comparison
import alerts  # local module -- email/Slack alert delivery
import templates_engine  # local module -- Jinja2 dynamic configuration generation
import secure_credentials  # local module -- ephemeral (RAM-only, wiped-on-completion) credential mode
import redaction  # local module -- shared secret-pattern/key redaction (see storage.py, templates_engine.py)

# audit_bridge (Phase 1 of the integration strategy) imports the vendored
# inventory_collector package -- only attempted once YAML is available,
# since inventory_collector.profile imports yaml at module load time.
AUDIT_AVAILABLE = False
audit_bridge = None
if YAML_AVAILABLE:
    try:
        import audit_bridge  # local module -- see audit_bridge.py
        AUDIT_AVAILABLE = True
    except Exception as _audit_import_exc:  # pragma: no cover - defensive
        print(f"[SETUP] WARNING: Audit feature unavailable (import failed): {_audit_import_exc}")
else:
    print("[SETUP] WARNING: PyYAML unavailable; Audit tab (inventory_collector) disabled.")

# Fast presence-only check (no import, no auto-install) -- the real
# lazy import happens on first actual use inside
# inventory_collector.textfsm_support, the first time a TextFSM/table
# mode profile is executed. This is purely for the UI badge / /health.
if AUDIT_AVAILABLE:
    from inventory_collector.textfsm_support import is_textfsm_installed
    AUDIT_TEXTFSM_AVAILABLE = is_textfsm_installed()
else:
    AUDIT_TEXTFSM_AVAILABLE = False

storage.init_db()
ENCRYPTION_AVAILABLE = storage.init_encryption(ensure_package)

# Automated database pruning & compaction: reclaim disk space freed by
# already-pruned history/rollback rows (see storage.py's
# "Automated database pruning & compaction" section) once per app
# startup. Cheap (incremental, not a full VACUUM) and non-fatal on
# failure -- printed via the plain print() below since logging_setup
# hasn't been configured yet at this point in module load order.
_vacuum_result = storage.compact_database()
if _vacuum_result["error"]:
    print(f"[STORAGE] Database compaction skipped (non-fatal): {_vacuum_result['error']}")
elif _vacuum_result["freed_pages"] > 0:
    print(f"[STORAGE] Reclaimed {_vacuum_result['freed_bytes'] / 1024:.1f} KB "
          f"({_vacuum_result['freed_pages']} page(s)) of disk space from previously deleted records.")

# Force all print() calls to flush immediately. Without this, output from
# the background scheduler thread (which prints status on every scheduled
# run) can sit in Python's stdout buffer and not appear in your terminal
# for a long time, making it look like the scheduler isn't doing anything.
print = functools.partial(print, flush=True)

# Professional logging: everything that used to only go to print()/console
# also now goes to a rotating logs/app.log file, and every state-changing
# action (config commands, backups, rollbacks, schedule runs, alerts) is
# additionally recorded as a one-line JSON audit record in logs/audit.log.
# See logging_setup.py for details. `log` below is used throughout this
# file; `log_audit()` is called at the specific points that change device
# state or fire an automated job.
log = logging_setup.setup_logging()
log_audit = logging_setup.log_audit

app = Flask(__name__)

# --------------------------------------------------------------------------
# Basic safety limits -- keep the tool well-behaved instead of open-ended.
# --------------------------------------------------------------------------
MAX_DEVICES = 200
MAX_COMMANDS = 60
MAX_COMMAND_LENGTH = 500
CONNECT_TIMEOUT_MIN = 1
CONNECT_TIMEOUT_MAX = 60
MAX_WORKERS_LIMIT = 50
MIN_SCHEDULE_INTERVAL_MINUTES = 5
MAX_SCHEDULE_INTERVAL_MINUTES = 60 * 24 * 7  # 1 week
SCHEDULER_POLL_SECONDS = 20

# --------------------------------------------------------------------------
# Worker pool isolation (background scheduled jobs vs. interactive use)
# --------------------------------------------------------------------------
# Automation runs and Audit runs each already get their OWN fresh
# ThreadPoolExecutor per invocation (see _run_parallel() / audit_bridge's
# run_device_mode()/run_table_mode()) -- they never literally share one
# pool object. The real resource-contention risk is different: an
# intensive SCHEDULED job (e.g. a 50-device audit with TextFSM table
# parsing, fired unattended in the background) can spin up just as many
# concurrent SSH/CPU-bound worker threads as an interactive user's
# manual run happening at the exact same time (e.g. clicking "Rollback"
# on the Run tab), competing for the same OS thread/CPU/network
# resources and making the interactive action feel sluggish or delayed
# for no reason the user did anything wrong.
#
# Two independent guards address this:
#   1. SCHEDULED_MAX_WORKERS_LIMIT hard-caps the worker count for ANY
#      schedule-triggered run (automation or audit) to a much smaller
#      number than what an interactive run is allowed (MAX_WORKERS_LIMIT
#      above) -- applied in _fire_automation_schedule()/
#      _fire_audit_schedule() regardless of what a schedule's saved
#      config happens to request, so a schedule can never accidentally
#      (or via a stale saved config) claim the full interactive pool size.
#   2. _scheduled_job_slot is a semaphore that only allows
#      MAX_CONCURRENT_SCHEDULED_JOBS scheduled jobs (across BOTH job
#      types) to actually be executing at once -- see _scheduler_loop().
#      This is 1 by default: scheduled jobs already fire one-at-a-time
#      within a single scheduler-loop tick (a simple for-loop), but that
#      was an accidental side effect of the loop's structure, not an
#      enforced guarantee -- making it an explicit semaphore documents
#      the constraint and keeps it true even if the loop is ever changed
#      to fire schedules concurrently in the future.
# Interactive (manual) runs are NEVER subject to either limit -- they
# always get the full MAX_WORKERS_LIMIT and never wait on this semaphore.
SCHEDULED_MAX_WORKERS_LIMIT = 10
MAX_CONCURRENT_SCHEDULED_JOBS = 1
_scheduled_job_slot = threading.Semaphore(MAX_CONCURRENT_SCHEDULED_JOBS)

# --------------------------------------------------------------------------
# Configuration backups
# --------------------------------------------------------------------------
# Default location for device config backups if the user doesn't type a
# custom path. Always resolved relative to this script's own folder so it
# works the same regardless of the current working directory the app was
# launched from.
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BACKUP_DIR = os.path.join(APP_DIR, "backups")
MAX_BACKUP_PATH_LENGTH = 500

# AI request limits
AI_MAX_CONTEXT_CHARS = 8000       # truncate run logs before sending to an LLM
AI_MAX_DESCRIPTION_CHARS = 800
AI_REQUEST_TIMEOUT = 45           # seconds
ALLOWED_AI_PROVIDERS = {"openrouter", "nim", "ollama"}
ALLOWED_AI_MODES = {"suggest_commands", "analyze_output"}

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


# ==========================================================================
# Vendor command library (static, non-AI "autocomplete" data)
# ==========================================================================
COMMAND_LIBRARY = {
    "cisco_ios": {
        "label": "Cisco IOS / IOS-XE (Router & Switch)",
        "categories": {
            "Show / Verification": [
                "show version", "show running-config", "show startup-config",
                "show inventory", "show processes cpu", "show processes memory",
                "show memory statistics", "show clock", "show environment",
                "show environment all", "show boot", "show file systems",
                "show license", "show license all", "show module", "show diag",
                "show platform", "show redundancy", "show flash",
                "show switch", "show ntp status", "show ntp associations",
                "show power inline", "show bootvar",
            ],
            "Interfaces": [
                "show ip interface brief", "show interfaces", "show interfaces status",
                "show interfaces description", "show interfaces counters errors",
                "show interfaces counters", "show interfaces summary", "show interfaces trunk",
                "show interfaces switchport", "show ip interface", "show ipv6 interface brief",
                "show cdp neighbors detail", "show cdp neighbors", "show lldp neighbors detail",
                "show lldp neighbors", "show controllers", "show interfaces transceiver",
                "show interfaces status err-disabled", "show interfaces stats",
                "show lacp neighbor", "show pagp neighbor", "clear counters",
            ],
            "Routing": [
                "show ip route", "show ip route summary", "show ip protocols",
                "show ip ospf neighbor", "show ip ospf database", "show ip ospf interface",
                "show ip bgp summary", "show ip bgp", "show ip bgp neighbors",
                "show ip eigrp neighbors", "show ip arp", "show ip arp inspection",
                "show ipv6 route", "show ipv6 protocols", "traceroute", "ping",
                "show ip nat translations", "show ip nat statistics",
                "show standby brief", "show vrrp brief", "show ip cef",
                "show ip eigrp topology", "show ip route ospf", "show ip route bgp",
                "show ip mroute",
            ],
            "VLAN / Switching": [
                "show vlan brief", "show vlan", "show spanning-tree", "show spanning-tree summary",
                "show spanning-tree detail", "show mac address-table", "show mac address-table dynamic",
                "show etherchannel summary", "show etherchannel detail",
                "show interfaces trunk", "show port-security", "show port-security address",
                "show vtp status", "show errdisable recovery", "show spanning-tree blockedports",
            ],
            "Security / ACLs": [
                "show ip access-lists", "show access-lists", "show crypto isakmp sa",
                "show crypto ipsec sa", "show crypto session", "show aaa sessions",
                "show users", "show privilege", "show ip ssh", "show line",
                "show dot1x all", "show authentication sessions",
                "show ip dhcp snooping binding", "show ip source binding",
                "show crypto ikev2 sa", "show radius statistics",
            ],
            "Diagnostics / Troubleshooting": [
                "show logging", "show logging | include", "show tech-support",
                "show tech-support | redirect", "show debugging", "show processes cpu sorted",
                "show interfaces | include error", "show ip interface brief | exclude unassigned",
                "traceroute", "ping repeat 100", "debug ip packet",
                "undebug all", "show processes cpu history", "show logging | count",
                "test cable-diagnostics tdr interface ",
            ],
        },
        "config_categories": {
            "Enter / Exit / Save": [
                "configure terminal", "end", "exit", "write memory",
                "copy running-config startup-config", "copy running-config tftp",
                "show running-config", "reload",
            ],
            "Interface Config": [
                "interface GigabitEthernet0/1", "interface range GigabitEthernet0/1-24",
                "description ", "ip address ", "no ip address",
                "switchport mode access", "switchport mode trunk",
                "switchport access vlan ", "switchport trunk allowed vlan ",
                "switchport trunk native vlan ", "speed auto", "duplex auto",
                "no shutdown", "shutdown", "spanning-tree portfast",
                "channel-group 1 mode active", "mtu 9000",
                "ipv6 address dhcp", "ipv6 address autoconfig",
                "power inline auto", "power inline never",
                "storm-control broadcast level 10.0", "spanning-tree bpduguard enable",
            ],
            "VLAN Config": [
                "vlan ", "name ", "vlan database", "interface vlan ",
                "ip address dhcp",
            ],
            "Routing Config": [
                "router ospf 1", "router bgp 65000", "router eigrp 100",
                "network 0.0.0.0 0.0.0.0 area 0", "ip route 0.0.0.0 0.0.0.0 ",
                "neighbor  remote-as ", "default-information originate",
                "passive-interface default",
                "ipv6 unicast-routing", "standby 1 ip ", "standby 1 priority 110",
            ],
            "Security / AAA / ACL": [
                "ip access-list extended ", "ip access-list standard ",
                "permit ip any any", "deny ip any any", "access-list 100 permit ip any any",
                "line vty 0 4", "login local", "transport input ssh",
                "username  privilege 15 secret ", "enable secret ",
                "aaa new-model", "ip ssh version 2", "crypto key generate rsa modulus 2048",
                "service password-encryption",
            ],
            "System / Hostname": [
                "hostname ", "banner motd #", "ntp server ", "logging host ",
                "snmp-server community  RO", "clock timezone  0",
                "no ip domain-lookup", "ip domain-name ",
            ],
            "Services / Management": [
                "ip dhcp pool ", "ip domain name ", "ip name-server ",
            ],
        },
    },
    "cisco_nxos": {
        "label": "Cisco Nexus (NX-OS)",

        "categories": {
            "Show / Verification": [
                "show version", "show running-config", "show startup-config",
                "show inventory", "show environment", "show module", "show hardware",
                "show install active", "show boot", "show license", "show system resources",
            ],
            "Interfaces": [
                "show interface brief", "show interface status", "show interface counters error",
                "show interface counters", "show interface transceiver",
                "show cdp neighbors detail", "show lldp neighbors", "show lldp neighbors detail",
                "show interface switchport",
            ],
            "Routing": [
                "show ip route", "show ip route summary", "show ip ospf neighbors",
                "show ip ospf database", "show ip bgp summary", "show ip bgp neighbors",
                "show ip arp", "show ip interface brief",
            ],
            "VLAN / Switching": [
                "show vlan brief", "show vlan", "show spanning-tree summary",
                "show spanning-tree detail", "show mac address-table", "show vpc",
                "show vpc brief", "show port-channel summary", "show port-channel detail",
            ],
            "Diagnostics / Troubleshooting": [
                "show logging last 50", "show logging logfile", "show tech-support brief",
                "show interface transceiver details", "show accounting log", "show cores",
            ],
        },
        "config_categories": {
            "Enter / Exit / Save": [
                "configure terminal", "end", "exit", "copy running-config startup-config",
                "show running-config", "reload",
            ],
            "Interface Config": [
                "interface Ethernet1/1", "description ", "no shutdown", "shutdown",
                "switchport mode access", "switchport mode trunk",
                "switchport access vlan ", "switchport trunk allowed vlan ",
                "mtu 9216", "speed 10000",
            ],
            "VLAN Config": [
                "vlan ", "name ", "interface vlan ", "vn-segment ",
            ],
            "Routing Config": [
                "router ospf 1", "router bgp 65000", "ip route 0.0.0.0/0 ",
                "feature ospf", "feature bgp", "feature interface-vlan",
            ],
            "VPC / Port-Channel": [
                "vpc domain 1", "peer-keepalive destination ", "vpc peer-link",
                "interface port-channel 1", "vpc ", "channel-group 1 mode active",
            ],
            "System / Hostname": [
                "hostname ", "feature lldp", "feature lacp", "ntp server ",
                "snmp-server community  ro",
            ],
        },
    },
    "juniper_junos": {
        "label": "Juniper Junos",
        "categories": {
            "Show / Verification": [
                "show version", "show configuration", "show chassis hardware",
                "show chassis routing-engine", "show system uptime", "show system users",
                "show system storage", "show chassis environment", "show system processes",
                "show version detail", "show system license",
            ],
            "Interfaces": [
                "show interfaces terse", "show interfaces diagnostics optics",
                "show interfaces descriptions", "show interfaces extensive",
                "show lldp neighbors", "show lldp neighbors detail",
                "show ethernet-switching interfaces",
            ],
            "Routing": [
                "show route", "show route summary", "show route protocol ospf",
                "show route protocol bgp", "show bgp summary", "show bgp neighbor",
                "show ospf neighbor", "show ospf database", "show arp", "show route forwarding-table",
            ],
            "VLAN / Switching": [
                "show vlans", "show spanning-tree bridge", "show ethernet-switching table",
                "show ethernet-switching interfaces",
            ],
            "Diagnostics / Troubleshooting": [
                "show log messages", "show system alarms", "show chassis alarms",
                "monitor interface traffic", "show system core-dumps", "show pfe statistics traffic",
            ],
        },
        "config_categories": {
            "Enter / Exit / Save (Junos)": [
                "configure", "commit", "commit check", "commit confirmed 5",
                "rollback 0", "exit configuration-mode", "exit", "show | compare",
            ],
            "Interface Config": [
                "set interfaces ge-0/0/0 description ", "set interfaces ge-0/0/0 unit 0 family inet address ",
                "delete interfaces ge-0/0/0", "set interfaces ge-0/0/0 disable",
                "delete interfaces ge-0/0/0 disable", "set interfaces ge-0/0/0 mtu 9000",
            ],
            "VLAN Config": [
                "set vlans VLAN10 vlan-id 10", "set interfaces ge-0/0/0 unit 0 family ethernet-switching vlan members VLAN10",
                "set vlans VLAN10 l3-interface irb.10",
            ],
            "Routing Config": [
                "set protocols ospf area 0.0.0.0 interface ge-0/0/0",
                "set protocols bgp group EXTERNAL neighbor ",
                "set routing-options static route 0.0.0.0/0 next-hop ",
            ],
            "System / Hostname": [
                "set system host-name ", "set system ntp server ",
                "set system syslog host  any any", "set system login user  class super-user",
                "set system root-authentication plain-text-password",
            ],
        },
    },
    "arista_eos": {
        "label": "Arista EOS",
        "categories": {
            "Show / Verification": [
                "show version", "show running-config", "show inventory",
                "show environment all", "show environment power", "show environment cooling",
                "show boot", "show system environment temperature",
            ],
            "Interfaces": [
                "show interfaces status", "show interfaces description",
                "show interfaces counters errors", "show interfaces counters",
                "show lldp neighbors", "show lldp neighbors detail",
                "show interfaces transceiver",
            ],
            "Routing": [
                "show ip route", "show ip route summary", "show ip bgp summary",
                "show ip ospf neighbor", "show ip ospf database", "show ip arp",
            ],
            "VLAN / Switching": [
                "show vlan", "show spanning-tree", "show spanning-tree detail",
                "show mac address-table", "show port-channel summary", "show port-channel detail",
            ],
            "Diagnostics / Troubleshooting": [
                "show logging", "show tech-support", "show agent logs crash",
                "show platform fap all",
            ],
        },
        "config_categories": {
            "Enter / Exit / Save": [
                "configure terminal", "end", "exit", "write memory", "copy running-config startup-config",
                "show running-config",
            ],
            "Interface Config": [
                "interface Ethernet1", "description ", "no shutdown", "shutdown",
                "switchport mode access", "switchport mode trunk",
                "switchport access vlan ", "switchport trunk allowed vlan ", "mtu 9214",
            ],
            "VLAN Config": [
                "vlan ", "name ", "interface vlan ",
            ],
            "Routing Config": [
                "router ospf 1", "router bgp 65000", "ip route 0.0.0.0/0 ",
                "network  area 0.0.0.0",
            ],
            "System / Hostname": [
                "hostname ", "ntp server ", "snmp-server community  ro",
            ],
        },
    },
    "aruba_hp": {
        "label": "Aruba / HP (ArubaOS-CX & ProCurve)",
        "categories": {
            "Show / Verification": [
                "show version", "show running-config", "show system",
                "show inventory", "show environment", "show system resource-utilization",
            ],
            "Interfaces": [
                "show interface brief", "show lldp neighbor-info", "show interface",
                "show interface transceiver", "show lldp neighbor-info detail",
            ],
            "Routing": [
                "show ip route", "show ip ospf neighbor", "show arp", "show ip bgp summary",
            ],
            "VLAN / Switching": [
                "show vlan", "show spanning-tree", "show mac-address-table",
                "show lacp interfaces",
            ],
            "Diagnostics / Troubleshooting": [
                "show logging", "show tech", "show core-dump",
            ],
        },
        "config_categories": {
            "Enter / Exit / Save": [
                "configure terminal", "end", "exit", "write memory",
                "copy running-config startup-config", "show running-config",
            ],
            "Interface Config": [
                "interface 1/1/1", "description ", "no shutdown", "shutdown",
                "vlan access ", "vlan trunk allowed ", "vlan trunk native ",
            ],
            "VLAN Config": [
                "vlan ", "name ", "interface vlan ",
            ],
            "Routing Config": [
                "router ospf 1", "ip route 0.0.0.0/0 ",
            ],
            "System / Hostname": [
                "hostname ", "ntp server ",
            ],
        },
    },
    "generic_linux": {
        "label": "Generic Linux Host",
        "categories": {
            "System": [
                "uname -a", "uptime", "df -h", "free -m", "top -bn1 | head -20",
                "lscpu", "lsblk", "cat /etc/os-release", "hostnamectl",
                "systemctl list-units --failed", "ps aux --sort=-%cpu | head -20",
                "vmstat 1 5", "iostat -x 1 5", "who", "last -n 20",
            ],
            "Network": [
                "ip addr show", "ip route show", "ss -tuln", "ss -tunap",
                "ping -c 4 8.8.8.8", "traceroute 8.8.8.8", "cat /etc/resolv.conf",
                "ip link show", "ip neigh show", "netstat -rn", "curl -sI https://example.com",
                "ethtool eth0", "cat /proc/net/dev",
            ],
            "Diagnostics / Troubleshooting": [
                "journalctl -xe --no-pager | tail -50", "dmesg | tail -50",
                "systemctl status", "systemctl status sshd", "tail -f /var/log/syslog",
                "cat /var/log/auth.log | tail -50", "iptables -L -n -v",
            ],
        },
        "config_categories": {
            "Network Config (NetworkManager/ip)": [
                "sudo ip addr add 192.168.1.1/24 dev eth0", "sudo ip link set eth0 up",
                "sudo ip route add default via 192.168.1.254",
                "sudo nmcli con mod eth0 ipv4.addresses 192.168.1.1/24",
                "sudo nmcli con up eth0",
            ],
            "Firewall Config": [
                "sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
                "sudo ufw allow 22/tcp", "sudo ufw enable", "sudo firewall-cmd --add-service=ssh --permanent",
            ],
            "System / Hostname": [
                "sudo hostnamectl set-hostname ", "sudo systemctl restart networking",
                "sudo systemctl enable sshd",
            ],
        },
    },
}


# ==========================================================================
# Validation helpers
# ==========================================================================
def is_valid_host(host: str) -> bool:
    """Accept either a valid IPv4/IPv6 address or a valid hostname."""
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return bool(HOSTNAME_RE.match(host))


def resolve_backup_dir(raw_path: str):
    """
    Validates and resolves a user-supplied backup folder path. Accepts any
    absolute path (e.g. "C:\\NetworkBackups" on Windows, "/mnt/backups" on
    Linux/Mac) or a relative path (resolved under this app's own folder).
    Creates the directory (including parents) if it doesn't exist yet.
    Returns (absolute_path, None) on success or (None, "error message").

    This intentionally does NOT restrict paths to "inside the app folder"
    -- the whole point of the feature is letting you pick your own backup
    location (a mounted drive, a synced folder, etc.) -- but it does
    reject empty/whitespace-only input and surfaces permission errors
    clearly instead of failing silently mid-run.
    """
    raw_path = (raw_path or "").strip()
    if not raw_path:
        raw_path = DEFAULT_BACKUP_DIR
    if len(raw_path) > MAX_BACKUP_PATH_LENGTH:
        return None, f"Backup path is too long (max {MAX_BACKUP_PATH_LENGTH} characters)."

    # Expand "~" and environment variables so paths like "~/backups" or
    # "$HOME/backups" work the same as they would in a shell.
    expanded = os.path.expanduser(os.path.expandvars(raw_path))
    abs_path = expanded if os.path.isabs(expanded) else os.path.join(APP_DIR, expanded)
    abs_path = os.path.normpath(abs_path)

    try:
        os.makedirs(abs_path, exist_ok=True)
    except Exception as exc:
        return None, f"Could not create/access backup folder '{abs_path}': {exc}"

    if not os.access(abs_path, os.W_OK):
        return None, f"Backup folder '{abs_path}' is not writable by this app."

    return abs_path, None


def sanitize_backup_filename(text: str) -> str:
    """Turns a hostname/port label into a filesystem-safe filename component."""
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", text.strip())
    return safe.strip("_") or "device"


def write_backup_file(backup_dir: str, host: str, port: int, vendor: str, config_text: str) -> str:
    """
    Writes one device's config backup to `backup_dir`, named
    "<host>_<port>_<YYYYmmdd-HHMMSS>.cfg". Returns the absolute file path.
    Raises on any filesystem error (permissions, disk full, etc.) so the
    caller can surface a clear message instead of silently losing a backup.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"{sanitize_backup_filename(host)}_{port}_{timestamp}.cfg"
    file_path = os.path.join(backup_dir, filename)
    header = (
        f"! Backup of {host}:{port} (platform: {vendor})\n"
        f"! Taken at {datetime.now(timezone.utc).isoformat(timespec='seconds')} UTC "
        f"by Network Automation Console\n"
        f"!{'=' * 70}\n\n"
    )
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(header)
        f.write(config_text)
        if not config_text.endswith("\n"):
            f.write("\n")
    return file_path


def validate_device(raw, index: int):
    """
    Validate a single device entry. Returns (clean_dict, None) or (None, error).

    Devices may optionally carry their own `username`/`password` that
    override the shared credentials for that device only -- useful when
    a device list (typed, pasted, or uploaded from CSV/TXT) mixes devices
    that need different logins. Per-device credentials are never required;
    when absent the shared username/password/key from the rest of the
    payload is used instead (see run_device_checks()).
    """
    if not isinstance(raw, dict):
        return None, f"Device #{index}: malformed entry."

    host = (raw.get("host") or "").strip()
    if not host:
        return None, f"Device #{index}: host/IP address is required."
    if not is_valid_host(host):
        return None, f"Device #{index}: '{host}' is not a valid hostname or IP address."

    port_raw = raw.get("port", 22)
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        return None, f"Device #{index} ({host}): port must be a whole number."
    if not (1 <= port <= 65535):
        return None, f"Device #{index} ({host}): port must be between 1 and 65535."

    device_username = (raw.get("username") or "").strip()
    device_password = raw.get("password") or ""
    if len(device_username) > 200:
        return None, f"Device #{index} ({host}): username is too long."
    if len(device_password) > 500:
        return None, f"Device #{index} ({host}): password is too long."

    clean = {"host": host, "port": port}
    if device_username:
        clean["username"] = device_username
    if device_password:
        clean["password"] = device_password
    return clean, None


def validate_payload(data: dict, allow_config_mode: bool = True):
    """
    Validate the full incoming request body (shared settings + device list).
    Returns (cleaned_dict, None) on success, or (None, "error message").

    `allow_config_mode=False` is used when validating a SCHEDULED run:
    scheduled jobs are hard-restricted to read-only checks (ping/port/show
    commands) so unattended automation can never push configuration
    changes to real devices without a human explicitly clicking "Run Now"
    and passing through the normal confirmation flow.
    """
    if not isinstance(data, dict):
        return None, "Malformed request body."

    devices_raw = data.get("devices")
    if not isinstance(devices_raw, list) or len(devices_raw) == 0:
        return None, "At least one device is required."
    if len(devices_raw) > MAX_DEVICES:
        return None, f"Too many devices in one run. Max allowed is {MAX_DEVICES}."

    devices = []
    seen = set()
    for i, raw in enumerate(devices_raw, start=1):
        clean, error = validate_device(raw, i)
        if error:
            return None, error
        key = (clean["host"], clean["port"])
        if key in seen:
            continue  # silently drop exact duplicates
        seen.add(key)
        devices.append(clean)

    if not devices:
        return None, "No valid devices were found after removing duplicates."

    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    private_key_text = (data.get("private_key_text") or "").strip() or None
    private_key_passphrase = data.get("private_key_passphrase") or ""

    jump_host_raw = (data.get("jump_host") or "").strip()
    jump_host = None
    jump_port = 22
    jump_username = ""
    jump_password = ""
    jump_private_key_text = None
    jump_private_key_passphrase = ""
    if jump_host_raw:
        if not is_valid_host(jump_host_raw):
            return None, f"Jump host '{jump_host_raw}' is not a valid hostname or IP address."
        jump_host = jump_host_raw
        jump_port_raw = data.get("jump_port", 22)
        try:
            jump_port = int(jump_port_raw)
        except (TypeError, ValueError):
            return None, "Jump host port must be a whole number."
        if not (1 <= jump_port <= 65535):
            return None, "Jump host port must be between 1 and 65535."
        jump_username = (data.get("jump_username") or "").strip()
        jump_password = data.get("jump_password") or ""
        jump_private_key_text = (data.get("jump_private_key_text") or "").strip() or None
        jump_private_key_passphrase = data.get("jump_private_key_passphrase") or ""
        if not jump_username:
            return None, "A username is required for the jump host."
        if not jump_password and not jump_private_key_text:
            return None, "A password or private key is required for the jump host."

    timeout_raw = data.get("timeout", 10)
    try:
        timeout = float(timeout_raw)
    except (TypeError, ValueError):
        return None, "Timeout must be a number."
    if not (CONNECT_TIMEOUT_MIN <= timeout <= CONNECT_TIMEOUT_MAX):
        return None, f"Timeout must be between {CONNECT_TIMEOUT_MIN} and {CONNECT_TIMEOUT_MAX} seconds."

    commands_raw = data.get("commands") or ""
    commands = [c.strip() for c in commands_raw.splitlines() if c.strip()]
    if len(commands) > MAX_COMMANDS:
        return None, f"Too many commands. Max allowed is {MAX_COMMANDS}."
    for c in commands:
        if len(c) > MAX_COMMAND_LENGTH:
            return None, f"A command exceeds the max length of {MAX_COMMAND_LENGTH} characters."

    run_ssh = bool(data.get("run_ssh"))
    # Every device without its OWN username needs the shared credentials;
    # a device that supplies its own username/password is exempt (it's
    # fully self-contained), which is what makes mixed-credential CSV
    # uploads work without also requiring a pointless shared login.
    devices_missing_own_creds = [d for d in devices if not d.get("username")]
    if run_ssh and devices_missing_own_creds and not username:
        return None, (
            "Username is required to run SSH commands (or give each device its own "
            "username/password, e.g. via CSV upload)."
        )
    if run_ssh and devices_missing_own_creds and not password and not private_key_text:
        return None, (
            "Provide a password or an SSH private key to run SSH commands (or give each "
            "device its own username/password, e.g. via CSV upload)."
        )

    vendor = (data.get("vendor") or "generic_linux").strip()
    if vendor not in COMMAND_LIBRARY:
        vendor = "generic_linux"

    config_mode = bool(data.get("config_mode"))
    save_config = bool(data.get("save_config"))
    confirm_config = bool(data.get("confirm_config"))

    if config_mode and not allow_config_mode:
        return None, (
            "Configuration-mode commands cannot run on a schedule. Scheduled jobs are "
            "restricted to read-only checks for safety -- use 'Run Now' for config changes."
        )
    if config_mode and not run_ssh:
        return None, "Config mode requires 'execute commands over SSH' to be enabled."
    if config_mode and not commands:
        return None, "Config mode is enabled but no commands were provided."
    if config_mode and not confirm_config:
        return None, (
            "You must explicitly confirm that you want to apply configuration "
            "changes to real devices before a config-mode run can start."
        )
    if save_config and not config_mode:
        return None, "The 'save configuration' option requires config mode to be enabled."

    show_diff = bool(data.get("show_diff"))
    dry_run = bool(data.get("dry_run"))
    if (show_diff or dry_run) and not config_mode:
        return None, "The config diff / dry-run options require config mode to be enabled."

    backup_configs = bool(data.get("backup_configs"))
    backup_dir = None
    if backup_configs:
        if not run_ssh:
            return None, "Config backup requires 'execute commands over SSH' to be enabled."
        if devices_missing_own_creds and not username:
            return None, (
                "Username is required to back up device configurations (or give each "
                "device its own username/password)."
            )
        if devices_missing_own_creds and not password and not private_key_text:
            return None, (
                "Provide a password or an SSH private key to back up device configurations."
            )
        backup_dir, backup_error = resolve_backup_dir(data.get("backup_path"))
        if backup_error:
            return None, backup_error

    # Automated health check (before/after) -- only meaningful alongside
    # a config-mode change; a plain read-only run has nothing to compare
    # "before" vs "after" of.
    health_check = bool(data.get("health_check"))
    if health_check and not config_mode:
        return None, "Health checks (before/after) require config mode to be enabled."

    # Rollback safety net -- snapshots the FULL running-config immediately
    # before a config-mode change (independent of show_diff, which is
    # opt-in and only stores a computed diff, not the raw before-text).
    # Always allowed whenever config_mode is on; not itself a separate
    # user toggle -- see run_ssh_commands()'s rollback_snapshot_result arg.
    rollback_safety = bool(config_mode)

    parallel = bool(data.get("parallel"))
    max_workers_raw = data.get("max_workers", 5)
    try:
        max_workers = int(max_workers_raw)
    except (TypeError, ValueError):
        return None, "Max concurrent workers must be a whole number."
    if not (1 <= max_workers <= MAX_WORKERS_LIMIT):
        return None, f"Max concurrent workers must be between 1 and {MAX_WORKERS_LIMIT}."

    # Ephemeral execution (session-bound, RAM-only credentials) -- see
    # secure_credentials.py. Opt-in only, and deliberately UNAVAILABLE
    # when this run will be saved as a schedule (allow_config_mode=False
    # is also True in that codepath, but ephemeral mode is refused
    # independently of config_mode so the intent is explicit): a
    # schedule's whole purpose is running again later, which requires a
    # retrievable (encrypted-at-rest) credential -- "ephemeral" and
    # "recurring" are mutually exclusive by definition.
    ephemeral = bool(data.get("ephemeral"))

    return {
        "devices": devices,
        "username": username,
        "password": password,
        "private_key_text": private_key_text,
        "private_key_passphrase": private_key_passphrase,
        "jump_host": jump_host,
        "jump_port": jump_port,
        "jump_username": jump_username,
        "jump_password": jump_password,
        "jump_private_key_text": jump_private_key_text,
        "jump_private_key_passphrase": jump_private_key_passphrase,
        "timeout": timeout,
        "commands": commands,
        "run_ssh": run_ssh,
        "vendor": vendor,
        "config_mode": config_mode,
        "save_config": save_config,
        "show_diff": show_diff,
        "dry_run": dry_run,
        "backup_configs": backup_configs,
        "backup_dir": backup_dir,
        "health_check": health_check,
        "rollback_safety": rollback_safety,
        "parallel": parallel,
        "max_workers": max_workers,
        "ephemeral": ephemeral,
    }, None


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ==========================================================================
# Low-level check helpers (used per device)
# ==========================================================================
def ping_host(host: str, timeout: float):
    """Run a single ICMP ping using the OS's native ping utility."""
    system = platform.system().lower()
    count_flag = "-n" if system == "windows" else "-c"
    timeout_flag = "-w" if system == "windows" else "-W"
    timeout_value = str(int(timeout * 1000)) if system == "windows" else str(int(timeout))

    cmd = ["ping", count_flag, "1", timeout_flag, timeout_value, host]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        success = result.returncode == 0
        output = (result.stdout or "") + (result.stderr or "")
        return success, output.strip()
    except FileNotFoundError:
        return False, "The 'ping' utility was not found on this system."
    except subprocess.TimeoutExpired:
        return False, "Ping timed out."
    except Exception as exc:  # pragma: no cover - defensive
        return False, f"Unexpected error while pinging: {exc}"


def check_tcp_port(host: str, port: int, timeout: float):
    """Attempt a raw TCP connection to see if the target port is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"TCP port {port} is OPEN on {host}."
    except socket.timeout:
        return False, f"Connection to {host}:{port} timed out."
    except (ConnectionRefusedError, OSError) as exc:
        return False, f"Could not connect to {host}:{port} -> {exc}"


# ==========================================================================
# Auth failure lockout tracking
# ==========================================================================
# Guards against an accidental typo or bad credential set hammering a real
# device (or its AAA server) with repeated failed logins during a run,
# which on many platforms triggers a temporary account lockout policy.
# Tracked per (host, port) in memory only -- resets when the app restarts.
AUTH_FAILURE_THRESHOLD = 3          # consecutive failures before we back off
AUTH_FAILURE_COOLDOWN_SECONDS = 120  # how long we refuse to retry after that

_auth_failure_lock = threading.Lock()
_auth_failure_state = {}  # (host, port) -> {"count": int, "locked_until": float or None}


def _auth_failure_key(host, port):
    return f"{host}:{port}"


def is_auth_locked_out(host, port):
    """Returns (locked: bool, seconds_remaining: float) for this device."""
    key = _auth_failure_key(host, port)
    with _auth_failure_lock:
        state = _auth_failure_state.get(key)
        if not state or not state.get("locked_until"):
            return False, 0
        remaining = state["locked_until"] - time.time()
        if remaining <= 0:
            # Cooldown expired -- clear it so the next attempt gets a fresh count.
            _auth_failure_state.pop(key, None)
            return False, 0
        return True, remaining


def record_auth_failure(host, port):
    key = _auth_failure_key(host, port)
    with _auth_failure_lock:
        state = _auth_failure_state.setdefault(key, {"count": 0, "locked_until": None})
        state["count"] += 1
        if state["count"] >= AUTH_FAILURE_THRESHOLD:
            state["locked_until"] = time.time() + AUTH_FAILURE_COOLDOWN_SECONDS


def record_auth_success(host, port):
    _auth_failure_state.pop(_auth_failure_key(host, port), None)


# Many real network devices (Cisco IOS/NX-OS, Juniper, Arista, Aruba, etc.)
# only permit ONE active "exec" style SSH session per connection, or don't
# support paramiko's exec_command() being called repeatedly on the same
# connection at all. Since exec_command() opens a brand-new channel for
# every call, the FIRST command tends to work fine and every command after
# it fails or returns empty output -- exactly the symptom of running one
# command per exec channel against strict/older device SSH stacks.
#
# The fix (same approach used by tools like Netmiko) is to open a single
# persistent interactive shell channel with invoke_shell() and send every
# command into that one channel, reading output until the device goes
# idle (i.e. the prompt reappears) between commands.
SHELL_READ_CHUNK = 4096
SHELL_IDLE_GAP = 0.5          # seconds of silence once a prompt is visible -- safe to stop fast
SHELL_QUIET_IDLE_GAP = 2.5    # seconds of silence to tolerate BEFORE a prompt is visible yet --
                               # real devices commonly go quiet for well over 0.5s mid-output
                               # (e.g. Cisco's "Building configuration..." pause on
                               # 'show running-config', or a big config being assembled/paged
                               # before it starts streaming) and 0.5s alone was cutting output
                               # off after just the banner line, corrupting config backups.
SHELL_MAX_WAIT_MULTIPLIER = 3  # multiply the user's timeout for slow commands

# Matches the tail of an interactive CLI prompt (Cisco/Juniper/Arista/Aruba/
# Linux all end an exec/config prompt in one of these characters, optionally
# followed by trailing whitespace where the cursor sits waiting for input).
# Used to tell the difference between "device is mid-output, still typing"
# and "device is done and back at a prompt" -- much more reliable than a
# fixed silence timer alone, since real devices can legitimately pause for
# a couple of seconds in the middle of producing a large response.
_PROMPT_TAIL_RE = re.compile(r"[#>%\$]\s*$")


def _looks_like_prompt_tail(decoded_text: str) -> bool:
    """
    Heuristic: does the last line currently in the buffer look like a
    finished device prompt (short, no leading whitespace, ends in a
    typical prompt character)? If so it's safe to stop reading soon after
    the data goes quiet. If not (e.g. the last line is part of a config
    dump, or the device is still assembling output), we should keep
    waiting longer before deciding the command is actually finished.
    """
    if not decoded_text:
        return False
    normalized = decoded_text.replace("\r\n", "\n").replace("\r", "\n")
    last_line = normalized.split("\n")[-1]
    stripped = last_line.strip()
    if not stripped or len(stripped) > 80 or stripped[0].isspace():
        return False
    return bool(_PROMPT_TAIL_RE.search(stripped))

# Sent once per session (if the vendor is recognized) to stop the device
# from pausing output with a "--More--" style pager, which would otherwise
# look like the connection hung on longer command output.
DISABLE_PAGING_COMMANDS = {
    "cisco_ios": "terminal length 0",
    "cisco_nxos": "terminal length 0",
    "arista_eos": "terminal length 0",
    "aruba_hp": "terminal length 0",
    "juniper_junos": "set cli screen-length 0",
    # generic_linux and unknown vendors: no paging command needed/sent.
}

# ==========================================================================
# Config-mode support
# ==========================================================================
# Commands used to ENTER global configuration mode, per vendor. Once inside
# config mode, sub-modes (interface, router ospf, line vty, etc.) are just
# more commands typed by the user (e.g. "interface GigabitEthernet0/1"),
# and returning to a parent mode is normally "exit"; returning all the way
# to exec mode is normally "end" -- both of which the user can simply
# include in their command list, since we run everything through one
# persistent interactive shell that tracks real device prompts.
ENTER_CONFIG_COMMANDS = {
    "cisco_ios": "configure terminal",
    "cisco_nxos": "configure terminal",
    "arista_eos": "configure terminal",
    "aruba_hp": "configure terminal",
    "juniper_junos": "configure",
}

# Commands used to persist the configuration to non-volatile memory, i.e.
# "save the config" -- ONLY sent if the user explicitly checks the "save
# configuration after applying" option, never automatically.
SAVE_CONFIG_COMMANDS = {
    "cisco_ios": "write memory",
    "cisco_nxos": "copy running-config startup-config",
    "arista_eos": "write memory",
    "aruba_hp": "write memory",
    "juniper_junos": "commit",
}

# Command used to fetch the full running configuration, for the optional
# before/after config diff feature (works on any vendor -- shows exactly
# what changed as a result of the commands that were applied).
SHOW_CONFIG_COMMANDS = {
    "cisco_ios": "show running-config",
    "cisco_nxos": "show running-config",
    "arista_eos": "show running-config",
    "aruba_hp": "show running-config",
    "juniper_junos": "show configuration",
}

# Junos supports a TRUE dry-run: "commit check" validates the candidate
# config without activating it, and "rollback 0" discards the uncommitted
# candidate entirely. No other vendor in this app has an equivalent --
# Cisco/Arista/Aruba apply each config-mode command immediately as you
# type it, so there's no vendor-agnostic way to "preview" first. For
# those platforms we instead offer the before/after diff (see above),
# which does NOT prevent the change but shows exactly what was applied.
JUNOS_DRY_RUN_CHECK_COMMAND = "commit check"
JUNOS_DRY_RUN_DISCARD_COMMAND = "rollback 0"

# Command used to leave config mode entirely and return to exec mode.
EXIT_CONFIG_COMMANDS = {
    "cisco_ios": "end",
    "cisco_nxos": "end",
    "arista_eos": "end",
    "aruba_hp": "end",
    "juniper_junos": "exit",
}

# Rough patterns that indicate a command failed on common network OSes,
# used only to mark a command as failed/succeeded in the structured report
# (SSH itself succeeded -- this is about the *command's own* response).
COMMAND_ERROR_PATTERNS = re.compile(
    r"(% ?Invalid input|% ?Incomplete command|% ?Ambiguous command|"
    r"invalid command|unknown command|syntax error|command not found|"
    r"error:|% ?Unrecognized command)",
    re.IGNORECASE,
)

# Strips ANSI/VT100 escape sequences (color codes, cursor movement, terminal
# mode toggles like bracketed-paste-mode) that some shells/devices emit and
# which would otherwise show up as garbled characters in the captured output.
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[=>]")


def _strip_ansi(text: str) -> str:
    return ANSI_ESCAPE_RE.sub("", text)


def _read_until_idle(shell, timeout, idle_gap=SHELL_IDLE_GAP, quiet_idle_gap=None):
    """
    Reads from an interactive shell channel until the device has gone
    quiet AND the buffer ends with what looks like a finished prompt, or
    the overall `timeout` is reached. Returns the decoded text read so
    far either way, so a slow/hanging command still surfaces whatever
    partial output the device sent instead of losing it.

    Uses a PROMPT-AWARE variable idle gap rather than a single fixed
    silence timer:
      - Once the buffer's last line already looks like a real device
        prompt (e.g. "router1#"), only `idle_gap` (short, ~0.5s) of
        additional silence is required before stopping -- the command is
        almost certainly done.
      - Until then, silence is tolerated for up to `quiet_idle_gap`
        before giving up -- because real devices commonly pause
        mid-response for longer than half a second (classic example:
        Cisco IOS prints "Building configuration..." for
        'show running-config' and then goes quiet for a second or more
        while it assembles the actual config before streaming the rest).
        A fixed 0.5s cutoff was mistaking that pause for "command
        finished", truncating output right after the banner line -- this
        was most visible as corrupted/near-empty configuration backup
        files, but it could truncate ANY command with a similar pause.
        When not given explicitly, `quiet_idle_gap` scales with the
        caller's overall `timeout` (capped at 20s) so a longer configured
        timeout also buys more patience for a slow-to-assemble response
        like a very large running-config, instead of one fixed value
        that could still be too short on a slow device.
    """
    if quiet_idle_gap is None:
        quiet_idle_gap = min(max(SHELL_QUIET_IDLE_GAP, timeout * 0.3), 20)
    buf = b""
    start = time.time()
    last_data_time = time.time()
    while True:
        now = time.time()
        if now - start > timeout:
            break
        if shell.recv_ready():
            try:
                chunk = shell.recv(SHELL_READ_CHUNK)
            except Exception:
                break
            if chunk:
                buf += chunk
                last_data_time = time.time()
            else:
                break  # channel closed
        else:
            if buf:
                decoded_so_far = _strip_ansi(buf.decode(errors="replace"))
                gap = idle_gap if _looks_like_prompt_tail(decoded_so_far) else quiet_idle_gap
                if (now - last_data_time) > gap:
                    break
            time.sleep(0.05)
    return buf.decode(errors="replace")


def _send_and_capture(shell, cmd, max_wait, command_log, tag_auto=False):
    """
    Sends one command into an already-open interactive shell, reads the
    response, cleans it up (strips echo/prompt/ANSI), appends a structured
    record to `command_log`, and yields human-readable lines for the live
    stream. Shared by both plain "show" style execution and config-mode
    execution so both paths get identical parsing/error-detection.
    `tag_auto=True` marks commands the app itself injected (entering/
    exiting config mode, saving config) so the UI can visually distinguish
    them from commands the user actually typed.
    """
    yield f"\n$ {cmd}\n"
    out_text = ""
    err_text = ""
    success = True
    cmd_started_at = _now_iso()
    cmd_start_perf = time.time()
    try:
        shell.send(cmd + "\n")
        raw = _strip_ansi(_read_until_idle(shell, max_wait))
        lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        while lines and lines[0].strip() == "":
            lines.pop(0)
        while lines and lines[-1].strip() == "":
            lines.pop()
        if lines and cmd.strip() and lines[0].strip().startswith(cmd.strip()):
            lines = lines[1:]
        if lines and lines[-1].strip() and len(lines[-1].strip()) < 40 and not lines[-1].strip()[0].isspace():
            if re.search(r"[#>$%]\s*$", lines[-1].strip()):
                lines = lines[:-1]
        out_text = "\n".join(lines).strip("\n")

        for line in out_text.splitlines():
            yield line + "\n"

        if not raw.strip():
            success = False
            err_text = "No response received from the device for this command (it may not be supported, or the session may have dropped)."
            yield f"[ERROR] {err_text}\n"
        elif COMMAND_ERROR_PATTERNS.search(out_text):
            success = False
            err_text = "Device reported a command error (see output above)."
            yield f"[ERROR] {err_text}\n"

    except (socket.timeout, TimeoutError):
        success = False
        err_text = f"Timed out waiting for a response after {max_wait:.0f}s."
        yield f"[ERROR] {err_text}\n"
    except Exception as cmd_exc:
        success = False
        err_text = str(cmd_exc)
        yield f"[ERROR] Failed to run '{cmd}': {cmd_exc}\n"

    duration_seconds = round(time.time() - cmd_start_perf, 3)
    command_log.append({
        "command": cmd,
        "output": out_text,
        "error": err_text,
        "success": success,
        "auto": tag_auto,
        "started_at": cmd_started_at,
        "duration_seconds": duration_seconds,
        "output_lines": len(out_text.splitlines()) if out_text else 0,
        "output_chars": len(out_text),
    })
    if duration_seconds >= 1.0:
        yield f"[INFO] (completed in {duration_seconds:.2f}s)\n"
    return success


def _compute_config_diff(before_text, after_text):
    """
    Produces a compact unified-diff-style list of added/removed lines
    between two full config dumps. Returns a list of {"type": "+"|"-", "line": ...}
    dicts (empty list if there was no textual difference) -- kept simple
    (line-based, not a true sequence diff) since network configs are
    naturally line-oriented and this is easy to read at a glance.
    """
    import difflib
    before_lines = before_text.splitlines()
    after_lines = after_text.splitlines()
    diff = []
    for line in difflib.unified_diff(before_lines, after_lines, lineterm=""):
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        if line.startswith("+"):
            diff.append({"type": "+", "line": line[1:]})
        elif line.startswith("-"):
            diff.append({"type": "-", "line": line[1:]})
    return diff


def _build_ssh_client(host, port, username, password, private_key_text, private_key_passphrase, timeout, jump_client=None):
    """
    Creates and connects a paramiko SSHClient, either directly or (if
    `jump_client` is provided) tunneled through an already-connected jump
    host client via a paramiko 'direct-tcpip' channel -- i.e. a standard
    SSH bastion/proxy-jump setup. Supports both password and private-key
    authentication; if both are supplied, the key is tried first and the
    password is used as a fallback (matches typical SSH client behavior).
    Raises the same paramiko exceptions connect() would raise; the caller
    is responsible for catching them.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    sock = None
    if jump_client is not None:
        jump_transport = jump_client.get_transport()
        sock = jump_transport.open_channel(
            "direct-tcpip", (host, port), ("127.0.0.1", 0), timeout=timeout,
        )

    pkey = None
    if private_key_text:
        pkey = _load_private_key(private_key_text, private_key_passphrase)

    connect_kwargs = dict(
        hostname=host, port=port, username=username,
        timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
    )
    if sock is not None:
        connect_kwargs["sock"] = sock

    if pkey is not None:
        connect_kwargs["pkey"] = pkey
        if password:
            # Some devices want a password too even with key-based auth
            # (e.g. as a fallback) -- paramiko will try the key first.
            connect_kwargs["password"] = password
    else:
        connect_kwargs["password"] = password

    client.connect(**connect_kwargs)
    return client


def _load_private_key(key_text, passphrase):
    """
    Attempts to parse a private key in any of the common formats paramiko
    supports (Ed25519, ECDSA, RSA, and -- on older paramiko versions that
    still have it -- DSA, which was removed in paramiko 3.2+ since DSA is
    long deprecated/insecure). Raises paramiko.SSHException if the text
    isn't a recognized/parseable key in any supported format.
    """
    key_classes = [paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey]
    dss_key_class = getattr(paramiko, "DSSKey", None)  # not present in modern paramiko
    if dss_key_class is not None:
        key_classes.append(dss_key_class)

    last_error = None
    for key_class in key_classes:
        try:
            return key_class.from_private_key(io.StringIO(key_text), password=(passphrase or None))
        except Exception as exc:
            last_error = exc
            continue
    tried = ", ".join(k.__name__ for k in key_classes)
    raise paramiko.SSHException(f"Could not parse private key (tried {tried}): {last_error}")


def run_ssh_commands(host, port, username, password, commands, timeout, command_log,
                      vendor="generic_linux", config_mode=False, save_config=False,
                      private_key_text=None, private_key_passphrase=None,
                      jump_host=None, jump_port=22, jump_username=None, jump_password=None,
                      jump_private_key_text=None, jump_private_key_passphrase=None,
                      cancel_event=None, show_diff=False, dry_run=False, diff_result=None,
                      backup_configs=False, backup_dir=None, backup_result=None,
                      health_check=False, health_result=None,
                      rollback_safety=False, rollback_snapshot_result=None):
    """
    Generator yielding lines of SSH command output as they arrive
    (for the live log stream), while ALSO appending a structured record
    per command into `command_log` (a list the caller owns) so a full
    structured report / export can be built afterwards. Requires paramiko.

    Uses ONE persistent interactive shell (invoke_shell) for the whole
    connection instead of a separate exec_command() per command, because
    many network devices only allow a single exec-style session and will
    fail every command after the first one if exec_command() is reused.

    If `config_mode` is True, the vendor's "enter configuration mode"
    command is sent automatically before the user's commands, and its
    "return to exec mode" command is sent automatically afterwards --
    the user's own command list can still include sub-mode commands like
    "interface GigabitEthernet0/1" / "exit" to navigate sub-modes, since
    everything runs through the same persistent shell and real device
    prompts are followed exactly like an interactive session would.
    If `save_config` is also True, the vendor's "save configuration"
    command (e.g. "write memory" / "commit") is sent as a final step --
    this is NEVER sent unless explicitly requested.

    If `private_key_text` is provided, key-based authentication is used
    (with `password` as a fallback if the device also wants one).
    If `jump_host` is provided, the connection is tunneled through that
    host first (a standard SSH bastion / proxy-jump setup) using its own
    separate credentials.
    If `cancel_event` (a threading.Event) is set at any point, execution
    stops before the next command is sent -- this is how the UI's "Stop"
    button cooperatively cancels an in-progress run.

    If `show_diff` is True (config_mode only), a full config dump is taken
    before AND after applying the commands, and a line-based diff is
    written into `diff_result` (a dict the caller owns, so it survives
    even if this generator is only partially consumed). This does NOT
    prevent the change -- it shows you exactly what changed as a result.

    If `dry_run` is True AND vendor is Juniper (the only platform with a
    true dry-run mechanism), "commit check" is used to validate the
    candidate configuration WITHOUT activating it, then "rollback 0"
    discards the uncommitted candidate -- so no change is actually made
    to the device. For all other vendors, `dry_run` has no effect (config
    commands apply immediately as they're typed on those platforms; there
    is no vendor-agnostic way to preview first) and a warning is emitted.

    If `backup_configs` is True, the device's running configuration is
    fetched (via the vendor's SHOW_CONFIG_COMMANDS entry) immediately
    after connecting -- BEFORE any config-mode changes or user commands
    run -- and written to a timestamped file under `backup_dir`. This
    happens independently of `config_mode`/`commands`, so backups work
    even on a plain read-only run. Results (file path, byte count, or an
    error) are written into `backup_result` (a dict the caller owns).

    If `rollback_safety` is True (config_mode only), the FULL running
    config is captured immediately before any changes and written into
    `rollback_snapshot_result` (a dict the caller owns) so the caller can
    persist it via storage.save_rollback_snapshot() -- this is what
    powers the one-click "Rollback" button, independent of the optional
    show_diff feature (which only stores a computed diff, not the raw
    before-text).

    If `health_check` is True (config_mode only), a small vendor-specific
    set of read-only "health" commands (CPU, memory, interface status) is
    run both BEFORE and AFTER the change and the two snapshots are
    compared; any clear regression (an interface that went down, a CPU
    spike) is written into `health_result` (a dict the caller owns) so
    the caller can surface a warning/alert even if the config change
    itself technically "succeeded".
    """
    locked, remaining = is_auth_locked_out(host, port)
    if locked:
        yield (f"[ERROR] Skipping SSH: too many recent authentication failures for "
               f"{host}:{port}. Cooling down for {remaining:.0f} more second(s) to avoid "
               f"triggering an account lockout on the device.\n")
        return

    client = None
    jump_client = None
    shell = None
    try:
        if jump_host:
            yield f"[INFO] Connecting to jump host {jump_host}:{jump_port} as '{jump_username}'...\n"
            jump_client = _build_ssh_client(
                jump_host, jump_port, jump_username, jump_password,
                jump_private_key_text, jump_private_key_passphrase, timeout,
            )
            yield "[INFO] Jump host connection established. Tunneling to target device...\n"

        auth_desc = "SSH key" if private_key_text else "password"
        yield f"[INFO] Connecting to {host}:{port} as '{username}' (auth: {auth_desc})...\n"
        client = _build_ssh_client(
            host, port, username, password, private_key_text, private_key_passphrase,
            timeout, jump_client=jump_client,
        )
        yield "[INFO] SSH connection established.\n"
        record_auth_success(host, port)

        yield "[INFO] Opening a single interactive shell session for all commands...\n"
        shell = client.invoke_shell(width=250, height=1000)
        shell.settimeout(timeout)
        max_wait = max(timeout * SHELL_MAX_WAIT_MULTIPLIER, timeout + 5)

        # Drain the initial login banner / MOTD / first prompt.
        _read_until_idle(shell, max_wait)

        paging_cmd = DISABLE_PAGING_COMMANDS.get(vendor)
        if paging_cmd:
            yield from _send_and_capture(shell, paging_cmd, max_wait, command_log, tag_auto=True)

        if backup_configs:
            backup_cmd = SHOW_CONFIG_COMMANDS.get(vendor)
            if not backup_cmd:
                yield f"[WARN] No known 'show config' command for platform '{vendor}'; backup skipped.\n"
                if backup_result is not None:
                    backup_result["status"] = "error"
                    backup_result["error"] = f"No backup command known for platform '{vendor}'."
            else:
                yield f"[INFO] Backing up configuration ('{backup_cmd}')...\n"
                backup_log = []
                yield from _send_and_capture(shell, backup_cmd, max_wait, backup_log, tag_auto=True)
                command_log.extend(backup_log)
                config_text = backup_log[-1]["output"] if backup_log else ""
                if not config_text.strip():
                    yield "[ERROR] Backup produced no output; nothing was saved for this device.\n"
                    if backup_result is not None:
                        backup_result["status"] = "error"
                        backup_result["error"] = "Backup command returned no output."
                else:
                    try:
                        file_path = write_backup_file(backup_dir, host, port, vendor, config_text)
                        yield f"[INFO] Backup saved to '{file_path}' ({len(config_text)} bytes).\n"
                        if backup_result is not None:
                            backup_result["status"] = "ok"
                            backup_result["file_path"] = file_path
                            backup_result["bytes"] = len(config_text)
                    except Exception as exc:
                        yield f"[ERROR] Could not write backup file: {exc}\n"
                        if backup_result is not None:
                            backup_result["status"] = "error"
                            backup_result["error"] = f"Could not write backup file: {exc}"

        is_junos_dry_run = dry_run and vendor == "juniper_junos"
        if dry_run and not is_junos_dry_run and config_mode:
            yield (f"[WARN] True dry-run isn't supported on platform '{vendor}' -- config "
                   f"commands apply immediately as they're typed on this platform. "
                   f"Proceeding as a normal (non-dry-run) config-mode run.\n")

        before_config_text = None
        if config_mode and show_diff:
            show_cmd = SHOW_CONFIG_COMMANDS.get(vendor)
            if show_cmd:
                yield f"[INFO] Capturing configuration BEFORE changes ('{show_cmd}')...\n"
                pre_log = []
                yield from _send_and_capture(shell, show_cmd, max_wait, pre_log, tag_auto=True)
                before_config_text = pre_log[-1]["output"] if pre_log else ""
                command_log.extend(pre_log)
            else:
                yield f"[WARN] No known 'show config' command for platform '{vendor}'; diff skipped.\n"

        # Rollback safety net: snapshot the FULL running-config right
        # before any change is applied, independent of show_diff (which
        # only stores a computed diff, not the raw text needed to
        # actually restore the device). Reuses the before_config_text
        # capture above if show_diff already fetched it (avoids running
        # the same "show config" command twice back-to-back).
        if config_mode and rollback_safety:
            snapshot_text = before_config_text
            if snapshot_text is None:
                show_cmd = SHOW_CONFIG_COMMANDS.get(vendor)
                if show_cmd:
                    yield f"[INFO] Rollback safety net: snapshotting configuration before changes ('{show_cmd}')...\n"
                    snap_log = []
                    yield from _send_and_capture(shell, show_cmd, max_wait, snap_log, tag_auto=True)
                    snapshot_text = snap_log[-1]["output"] if snap_log else ""
                    command_log.extend(snap_log)
                else:
                    yield f"[WARN] No known 'show config' command for platform '{vendor}'; rollback snapshot skipped.\n"
            if snapshot_text and snapshot_text.strip() and rollback_snapshot_result is not None:
                rollback_snapshot_result["before_config"] = snapshot_text
                yield "[INFO] Rollback snapshot captured -- use the Rollback button if this change needs to be undone.\n"

        # Automated health check (BEFORE): a small set of read-only
        # commands (CPU/memory/interface status) run before the change,
        # so we have a baseline to compare against once the change lands.
        health_before = None
        if config_mode and health_check:
            hc_commands = health_checks.get_health_check_commands(vendor)
            yield f"[INFO] Health check (before): running {len(hc_commands)} diagnostic command(s)...\n"
            hc_log = []
            for hc_cmd in hc_commands:
                yield from _send_and_capture(shell, hc_cmd, max_wait, hc_log, tag_auto=True)
            command_log.extend(hc_log)
            health_before = health_checks.parse_health_snapshot(vendor, hc_log)

        if config_mode:
            enter_cmd = ENTER_CONFIG_COMMANDS.get(vendor)
            if enter_cmd:
                yield f"[INFO] Entering configuration mode ('{enter_cmd}')...\n"
                yield from _send_and_capture(shell, enter_cmd, max_wait, command_log, tag_auto=True)
            else:
                yield (f"[WARN] No known configuration-mode command for platform "
                       f"'{vendor}'; sending your commands as-is.\n")

        for cmd in commands:
            if cancel_event is not None and cancel_event.is_set():
                yield "[WARN] Run cancelled by user -- stopping before sending remaining commands.\n"
                break
            yield from _send_and_capture(shell, cmd, max_wait, command_log, tag_auto=False)

        if config_mode:
            if is_junos_dry_run:
                yield f"[INFO] Dry-run: validating candidate config ('{JUNOS_DRY_RUN_CHECK_COMMAND}')...\n"
                yield from _send_and_capture(shell, JUNOS_DRY_RUN_CHECK_COMMAND, max_wait, command_log, tag_auto=True)
                yield f"[INFO] Dry-run: discarding candidate config, no changes applied ('{JUNOS_DRY_RUN_DISCARD_COMMAND}')...\n"
                yield from _send_and_capture(shell, JUNOS_DRY_RUN_DISCARD_COMMAND, max_wait, command_log, tag_auto=True)

            exit_cmd = EXIT_CONFIG_COMMANDS.get(vendor)
            if exit_cmd:
                yield f"[INFO] Returning to exec mode ('{exit_cmd}')...\n"
                yield from _send_and_capture(shell, exit_cmd, max_wait, command_log, tag_auto=True)

            if save_config and not is_junos_dry_run:
                save_cmd = SAVE_CONFIG_COMMANDS.get(vendor)
                if save_cmd:
                    yield f"[INFO] Saving configuration ('{save_cmd}')...\n"
                    yield from _send_and_capture(shell, save_cmd, max_wait, command_log, tag_auto=True)
                else:
                    yield (f"[WARN] No known 'save configuration' command for platform "
                           f"'{vendor}'; configuration was NOT saved automatically.\n")

            if show_diff and before_config_text is not None and not is_junos_dry_run:
                show_cmd = SHOW_CONFIG_COMMANDS.get(vendor)
                yield f"[INFO] Capturing configuration AFTER changes ('{show_cmd}')...\n"
                post_log = []
                yield from _send_and_capture(shell, show_cmd, max_wait, post_log, tag_auto=True)
                after_config_text = post_log[-1]["output"] if post_log else ""
                command_log.extend(post_log)

                diff = _compute_config_diff(before_config_text, after_config_text)
                if diff_result is not None:
                    diff_result["diff"] = diff
                if diff:
                    yield f"[INFO] Configuration diff ({len(diff)} line(s) changed):\n"
                    for entry in diff:
                        yield f"{entry['type']} {entry['line']}\n"
                else:
                    yield "[INFO] No textual difference detected in the configuration.\n"

            # Automated health check (AFTER): re-run the same diagnostic
            # commands post-change and compare against the baseline taken
            # earlier, flagging clear regressions (an interface that went
            # down, a CPU spike) even though the config change itself
            # applied without an SSH-level error.
            if health_check and health_before is not None and not is_junos_dry_run:
                hc_commands = health_checks.get_health_check_commands(vendor)
                yield f"[INFO] Health check (after): running {len(hc_commands)} diagnostic command(s)...\n"
                hc_log = []
                for hc_cmd in hc_commands:
                    yield from _send_and_capture(shell, hc_cmd, max_wait, hc_log, tag_auto=True)
                command_log.extend(hc_log)
                health_after = health_checks.parse_health_snapshot(vendor, hc_log)
                issues = health_checks.compare_health_snapshots(health_before, health_after)
                if health_result is not None:
                    health_result["before"] = health_before
                    health_result["after"] = health_after
                    health_result["issues"] = issues
                if issues:
                    yield f"[WARN] Health check detected {len(issues)} possible regression(s) after the change:\n"
                    for issue in issues:
                        yield f"  - {issue}\n"
                else:
                    yield "[INFO] Health check: no regressions detected after the change.\n"

    except paramiko.AuthenticationException:
        record_auth_failure(host, port)
        yield "[ERROR] Authentication failed. Check username/password/key.\n"
    except (paramiko.SSHException, socket.error, socket.timeout) as exc:
        yield f"[ERROR] SSH connection error: {exc}\n"
    except Exception as exc:  # pragma: no cover - defensive
        yield f"[ERROR] Unexpected SSH error: {exc}\n"
    finally:
        for obj in (shell, client, jump_client):
            try:
                if obj is not None:
                    obj.close()
            except Exception:
                pass


# ==========================================================================
# Per-device orchestration
# ==========================================================================
def precheck_gateway(shared) -> tuple:
    """
    Connection pre-check / fast-fail threshold: if this run shares a
    single common jump host / bastion across every device (the
    `jump_host` field, set once for the whole payload -- not a
    per-device value), do ONE quick TCP reachability probe against it
    BEFORE dispatching to any device at all.

    Without this, a down jump host means EVERY device in the batch
    independently attempts a full SSH connect through it and
    independently waits out its own full `timeout` before failing --
    e.g. 50 devices x a 10s timeout = up to 500 seconds of pure waiting
    to discover the one thing actually wrong. With this pre-check, that
    same scenario fails in about one timeout's worth of time (typically
    a few seconds, well under the user's configured SSH timeout, since a
    TCP-level probe fails much faster than a full SSH handshake) instead
    of once per device.

    Returns (ok: bool, message: str). `ok=True` (with no message) when
    there's no shared jump host to check (nothing to fast-fail on), or
    when the probe succeeds. `ok=False` means the caller should abort
    the entire remaining batch immediately rather than let every device
    independently discover the same failure.
    """
    jump_host = shared.get("jump_host")
    if not jump_host:
        return True, ""
    jump_port = shared.get("jump_port") or 22
    # A short, fixed probe timeout independent of the user's configured
    # per-device SSH timeout -- the whole point is to fail fast, not to
    # wait as long as a real device connection attempt would.
    probe_timeout = min(5.0, float(shared.get("timeout") or 10))
    reachable, detail = check_tcp_port(jump_host, jump_port, probe_timeout)
    if reachable:
        return True, ""
    return False, (
        f"Jump host {jump_host}:{jump_port} is unreachable ({detail}). Every device in this "
        f"run tunnels through this jump host, so the remaining device(s) were skipped "
        f"immediately instead of each independently waiting out its own connect timeout."
    )


def run_device_checks(device, shared, idx, total, results, lock, cancel_event=None, gateway_down_event=None):
    """
    Generator that runs ping + port check + optional SSH commands for a
    SINGLE device, yielding tagged output lines like '[host:port] ...'.
    Appends a rich result summary dict (including per-command output) to
    `results` (thread-safe via `lock`) once finished, success or failure.
    If `cancel_event` is already set when this device's turn comes up
    (sequential mode), the device is skipped entirely and marked SKIPPED.
    If `gateway_down_event` is already set (see precheck_gateway()), SSH
    to this device is skipped immediately (ping/TCP port checks against
    the device itself still run, since those don't depend on the jump
    host) -- fast-failing the SSH step instead of attempting a doomed
    connection through an already-known-down jump host.
    """
    host = device["host"]
    port = device["port"]
    label = f"{host}:{port}"
    started_at = _now_iso()
    device_start_perf = time.time()

    def tag(text):
        return f"[{label}] {text}"

    ping_ok = False
    ping_detail = ""
    port_ok = False
    port_detail = ""
    ssh_status = "SKIPPED"
    command_log = []
    diff_result = {}
    backup_result = {}
    health_result = {}
    rollback_snapshot_result = {}

    try:
        if cancel_event is not None and cancel_event.is_set():
            yield tag(f"[WARN] Skipping device {idx}/{total}: run was cancelled.\n")
            ping_detail = "Skipped (run cancelled before this device started)."
            port_detail = ping_detail
            ssh_status = "SKIPPED (cancelled)"
            return

        yield tag(f"===== Device {idx}/{total}: {host} =====\n")

        yield tag("Running ping reachability check...\n")
        ping_ok, ping_detail = ping_host(host, shared["timeout"])
        for line in ping_detail.splitlines():
            if line.strip():
                yield tag(line + "\n")
        yield tag(f"Ping result: {'OK' if ping_ok else 'FAILED'}\n")

        yield tag(f"Checking TCP port {port}...\n")
        port_ok, port_detail = check_tcp_port(host, port, shared["timeout"])
        yield tag(port_detail + "\n")

        # Per-device credentials (if this device carries its own username/
        # password, e.g. from a CSV upload with mixed logins) override the
        # shared credentials for THIS device only. Falls back to the shared
        # username/password/key when the device doesn't specify its own.
        # secure_credentials.reveal() transparently unwraps a SecureValue
        # (ephemeral mode) back to a plain str, or passes an ordinary str
        # straight through unchanged -- so this code path is identical
        # whether or not ephemeral mode is on.
        effective_username = device.get("username") or shared["username"]
        effective_password = secure_credentials.reveal(device.get("password")) or secure_credentials.reveal(shared["password"])
        using_device_creds = bool(device.get("username") or device.get("password"))

        backup_configs = shared.get("backup_configs", False)

        if gateway_down_event is not None and gateway_down_event.is_set():
            # Connection pre-check / fast-fail: the shared jump host was
            # already found unreachable before this device's turn came
            # up (see precheck_gateway()) -- every device in this run
            # tunnels through it, so an SSH attempt here is guaranteed to
            # fail the same way. Skip it immediately rather than making
            # this device independently wait out its own full connect
            # timeout to rediscover the same already-known problem.
            yield tag("[ERROR] Skipping SSH: the shared jump host for this run is unreachable "
                      "(see the run-level warning above). Fast-failing instead of waiting out "
                      "this device's own connect timeout.\n")
            ssh_status = "FAILED (jump host unreachable)"
        elif shared["run_ssh"]:
            if not PARAMIKO_AVAILABLE:
                yield tag("[WARN] 'paramiko' is not available; SSH step skipped.\n")
                ssh_status = "SKIPPED (no paramiko)"
            elif not shared["commands"] and not backup_configs:
                yield tag("[INFO] No commands provided; SSH step skipped.\n")
                ssh_status = "SKIPPED (no commands)"
            elif not effective_username:
                yield tag("[ERROR] No username configured; cannot run SSH.\n")
                ssh_status = "FAILED (no username)"
            else:
                if using_device_creds:
                    yield tag(f"[INFO] Using per-device credentials (username '{effective_username}') for this device.\n")
                had_error = False
                for line in run_ssh_commands(
                    host, port, effective_username, effective_password,
                    shared["commands"], shared["timeout"], command_log,
                    shared.get("vendor", "generic_linux"),
                    config_mode=shared.get("config_mode", False),
                    save_config=shared.get("save_config", False),
                    private_key_text=secure_credentials.reveal(shared.get("private_key_text")) or None,
                    private_key_passphrase=secure_credentials.reveal(shared.get("private_key_passphrase")),
                    jump_host=shared.get("jump_host"),
                    jump_port=shared.get("jump_port", 22),
                    jump_username=shared.get("jump_username"),
                    jump_password=secure_credentials.reveal(shared.get("jump_password")),
                    jump_private_key_text=secure_credentials.reveal(shared.get("jump_private_key_text")) or None,
                    jump_private_key_passphrase=secure_credentials.reveal(shared.get("jump_private_key_passphrase")),
                    cancel_event=cancel_event,
                    show_diff=shared.get("show_diff", False),
                    dry_run=shared.get("dry_run", False),
                    diff_result=diff_result,
                    backup_configs=backup_configs,
                    backup_dir=shared.get("backup_dir"),
                    backup_result=backup_result,
                    health_check=shared.get("health_check", False),
                    health_result=health_result,
                    rollback_safety=shared.get("rollback_safety", False),
                    rollback_snapshot_result=rollback_snapshot_result,
                ):
                    if "[ERROR]" in line:
                        had_error = True
                    yield tag(line)
                ssh_status = "FAILED" if had_error else "OK"

                # Persist the rollback snapshot (if one was captured) so
                # the "Rollback" button/endpoint can find it later --
                # done here (not inside run_ssh_commands) to keep that
                # function storage-agnostic/testable on its own.
                if rollback_snapshot_result.get("before_config"):
                    try:
                        snap_id = storage.save_rollback_snapshot(
                            host, port, shared.get("vendor", "generic_linux"),
                            rollback_snapshot_result["before_config"],
                        )
                        rollback_snapshot_result["snapshot_id"] = snap_id
                        log_audit("rollback_snapshot_saved", host=host, port=port,
                                  vendor=shared.get("vendor"), snapshot_id=snap_id)
                    except Exception as exc:
                        log.warning("Failed to persist rollback snapshot for %s:%s: %s", host, port, exc)

                # Fire a health-regression alert immediately (per device,
                # as soon as we know) rather than waiting for the whole
                # multi-device run to finish -- so on a large parallel
                # run you're not stuck waiting for the slowest device
                # before an important warning reaches you.
                if health_result.get("issues"):
                    log.warning("Health check regression on %s:%s -- %s", host, port, "; ".join(health_result["issues"]))
                    log_audit("health_regression", host=host, port=port, issues=health_result["issues"])
                    try:
                        maybe_send_alerts(
                            subject=f"Health check regression on {host}:{port}",
                            text=alerts.build_health_regression_alert_text(host, port, health_result["issues"]),
                        )
                    except Exception as exc:
                        log.warning("Failed to send health-regression alert for %s:%s: %s", host, port, exc)

                # Audit every individual config-mode command actually
                # applied to this device (separate from the general
                # command_log, which also includes read-only/auto
                # commands) -- this is the compliance-relevant trail.
                # Every command is redacted (templates_engine.sanitize_for_audit)
                # before being written -- a manually-typed command can
                # contain a secret just as easily as a template-generated
                # one (e.g. "username bob secret hunter2"), so this is NOT
                # limited to template-originated pushes.
                if shared.get("config_mode"):
                    for c in command_log:
                        if not c.get("auto"):
                            log_audit(
                                "config_command", host=host, port=port,
                                vendor=shared.get("vendor"),
                                command=templates_engine.sanitize_for_audit(c.get("command")),
                                success=c.get("success"), triggered_by=shared.get("_triggered_by", "manual"),
                            )
        else:
            if shared["commands"]:
                yield tag(
                    "[WARN] You entered commands but 'execute commands over SSH' is not "
                    "checked, so NO commands were run on this device -- only ping/port "
                    "checks above. Check that box if you want the commands executed.\n"
                )
            ssh_status = "SKIPPED (disabled)"

        device_duration = round(time.time() - device_start_perf, 2)
        cmds_ok = sum(1 for c in command_log if c.get("success"))
        cmds_failed = len(command_log) - cmds_ok
        cmd_summary = f", {len(command_log)} command(s) run ({cmds_ok} ok, {cmds_failed} failed)" if command_log else ""
        yield tag(f"===== Finished device {idx}/{total}: {host} (took {device_duration}s{cmd_summary}) =====\n\n")

    except Exception as exc:  # pragma: no cover - defensive, keep stream alive
        yield tag(f"[ERROR] Unexpected failure while processing this device: {exc}\n\n")

    finally:
        entry = {
            "host": host,
            "port": port,
            "ping": "OK" if ping_ok else "FAILED",
            "ping_detail": ping_detail,
            "tcp_port": "OK" if port_ok else "FAILED",
            "tcp_port_detail": port_detail,
            "ssh": ssh_status,
            "commands": command_log,
            "commands_ok": sum(1 for c in command_log if c.get("success")),
            "commands_failed": sum(1 for c in command_log if not c.get("success")),
            "config_diff": diff_result.get("diff"),
            "backup": backup_result if backup_result else None,
            "health_check": health_result if health_result else None,
            "rollback_snapshot_id": rollback_snapshot_result.get("snapshot_id"),
            "started_at": started_at,
            "finished_at": _now_iso(),
            "duration_seconds": round(time.time() - device_start_perf, 2),
        }
        with lock:
            results.append(entry)


def _build_summary_table(results):
    if not results:
        return "[INFO] No results to summarize.\n"
    ordered = sorted(results, key=lambda r: (r["host"], r["port"]))
    width = 88
    lines = ["=" * width, "SUMMARY".center(width), "=" * width]
    lines.append(f"{'Host':<22}{'Ping':<10}{'TCP Port':<12}{'SSH':<22}{'Commands':<14}{'Time':<8}")
    lines.append("-" * width)
    total_devices_ok = 0
    total_cmds_ok = 0
    total_cmds_failed = 0
    for r in ordered:
        host_label = f"{r['host']}:{r['port']}"
        cmds_ok = r.get("commands_ok", 0)
        cmds_failed = r.get("commands_failed", 0)
        total_cmds_ok += cmds_ok
        total_cmds_failed += cmds_failed
        cmd_label = f"{cmds_ok} ok / {cmds_failed} fail" if (cmds_ok or cmds_failed) else "-"
        duration_label = f"{r.get('duration_seconds', 0):.1f}s"
        if r["ping"] == "OK" and r["tcp_port"] == "OK" and not str(r["ssh"]).startswith("FAILED"):
            total_devices_ok += 1
        lines.append(f"{host_label:<22}{r['ping']:<10}{r['tcp_port']:<12}{r['ssh']:<22}{cmd_label:<14}{duration_label:<8}")
    lines.append("-" * width)
    totals_line = (
        f"TOTALS: {len(ordered)} device(s) | {total_devices_ok} fully OK | "
        f"{total_cmds_ok} command(s) succeeded | {total_cmds_failed} command(s) failed"
    )
    backups_attempted = [r for r in ordered if r.get("backup")]
    if backups_attempted:
        backups_ok = sum(1 for r in backups_attempted if r["backup"].get("status") == "ok")
        backups_failed = len(backups_attempted) - backups_ok
        totals_line += f" | {backups_ok} backup(s) saved / {backups_failed} failed"
    lines.append(totals_line)
    lines.append("=" * width)
    return "\n".join(lines) + "\n"


def _run_sequential(devices, shared, results, lock, total, cancel_event=None, gateway_down_event=None):
    for idx, device in enumerate(devices, start=1):
        if cancel_event is not None and cancel_event.is_set():
            yield f"[WARN] Run cancelled -- skipping remaining {total - idx + 1} device(s).\n"
            break
        yield from run_device_checks(device, shared, idx, total, results, lock,
                                      cancel_event=cancel_event, gateway_down_event=gateway_down_event)


def _run_parallel(devices, shared, results, lock, total, cancel_event=None, gateway_down_event=None):
    """
    Run all devices concurrently using a thread pool. Each worker thread
    pushes its output lines onto a shared queue; the main generator drains
    the queue and yields lines to the client as soon as they arrive, so
    output from multiple devices is interleaved live (each line is tagged
    with its device so it stays readable).
    """
    line_queue: "queue.Queue" = queue.Queue()
    max_workers = max(1, min(shared["max_workers"], total))

    def worker(device, idx):
        try:
            for line in run_device_checks(device, shared, idx, total, results, lock,
                                           cancel_event=cancel_event, gateway_down_event=gateway_down_event):
                line_queue.put(line)
        except Exception as exc:  # pragma: no cover - defensive
            line_queue.put(f"[{device.get('host', '?')}] [ERROR] Worker crashed: {exc}\n")
        finally:
            line_queue.put(None)  # sentinel: this worker is done

    executor = ThreadPoolExecutor(max_workers=max_workers)
    try:
        for idx, device in enumerate(devices, start=1):
            executor.submit(worker, device, idx)

        finished_workers = 0
        while finished_workers < total:
            item = line_queue.get()
            if item is None:
                finished_workers += 1
            else:
                yield item
    finally:
        executor.shutdown(wait=True)


STRUCTURED_START_MARKER = "@@STRUCTURED_REPORT_START@@"
STRUCTURED_END_MARKER = "@@STRUCTURED_REPORT_END@@"
RUN_ID_MARKER = "@@RUN_ID@@"

# Registry of in-progress runs, keyed by a UUID the client receives up
# front, so the "Stop" button can find and signal the right cancel_event
# even though each run's generator is otherwise a self-contained closure.
_active_runs_lock = threading.Lock()
_active_runs = {}  # run_uuid -> threading.Event


def register_run(run_uuid):
    event = threading.Event()
    with _active_runs_lock:
        _active_runs[run_uuid] = event
    return event


def unregister_run(run_uuid):
    with _active_runs_lock:
        _active_runs.pop(run_uuid, None)


def request_cancel(run_uuid) -> bool:
    with _active_runs_lock:
        event = _active_runs.get(run_uuid)
    if event is None:
        return False
    event.set()
    return True


# --------------------------------------------------------------------------
# Global "job currently running" tracker -- Phase 6 (Overview dashboard's
# persistent global run indicator, per the integration strategy doc's "no
# context loss" mechanism #3). Deliberately separate from _active_runs
# above (which only tracks automation runs and only exists to support
# cancellation): this tracks BOTH job kinds and exists purely to answer
# "is anything running right now, and how far along is it" for any tab,
# regardless of which tab is currently active. At most a small handful of
# entries at once in realistic usage, so a plain dict behind a lock is
# more than adequate -- no need for a queue/pubsub mechanism.
# --------------------------------------------------------------------------
_current_jobs_lock = threading.Lock()
_current_jobs = {}  # job_id -> {kind, label, total, completed, started_at}


def _job_start(kind: str, label: str, total: int) -> str:
    job_id = uuid.uuid4().hex
    with _current_jobs_lock:
        _current_jobs[job_id] = {
            "kind": kind, "label": label, "total": total, "completed": 0,
            "started_at": _now_iso(),
        }
    return job_id


def _job_progress(job_id: str, completed: int, total: int):
    with _current_jobs_lock:
        job = _current_jobs.get(job_id)
        if job is not None:
            job["completed"] = completed
            job["total"] = total


def _job_finish(job_id: str):
    with _current_jobs_lock:
        _current_jobs.pop(job_id, None)


def list_current_jobs():
    """Returns a snapshot list of every job currently believed to be
    running, newest-started first -- backs GET /activity/current."""
    with _current_jobs_lock:
        jobs = [dict(job_id=jid, **info) for jid, info in _current_jobs.items()]
    jobs.sort(key=lambda j: j["started_at"], reverse=True)
    return jobs


def stream_multi_device(payload: dict, run_uuid: str, triggered_by: str = "manual", label: str = "", inventory_name: str = ""):
    """
    Main generator that produces the live log stream sent to the browser
    for a (possibly multi-device) automation run, followed by a summary
    table and a machine-readable structured JSON block (wrapped between
    sentinel marker lines so the frontend can pull it out of the stream
    without it cluttering the human-readable log). Every yielded string
    is flushed to the client immediately.

    `run_uuid` is generated by the caller and sent to the client as the
    very first line of the stream so the browser's "Stop" button can
    later call POST /cancel-run/<run_uuid> to cooperatively cancel this
    run (checked between commands/devices, not instantaneous).
    """
    devices = payload["devices"]
    total = len(devices)
    results = []
    lock = threading.Lock()
    run_started_at = _now_iso()
    run_start_perf = time.time()
    cancel_event = register_run(run_uuid)
    job_label = label or f"Automation ({triggered_by})"
    job_id = _job_start("automation", job_label, total)

    # Ephemeral execution (see secure_credentials.py): wrap every
    # credential field in a SecureValue (mutable bytearray) for the
    # duration of this run, then WIPE them in the `finally` below no
    # matter how the run ends (success, exception, or cancellation).
    # Every consumption site downstream (run_device_checks(),
    # run_ssh_commands(), _build_ssh_client()) calls
    # secure_credentials.reveal() at the point of actual use, which
    # transparently handles both ephemeral (SecureValue) and normal
    # (plain str) payloads identically.
    ephemeral = bool(payload.get("ephemeral"))
    if ephemeral:
        secure_credentials.wrap_payload_for_ephemeral(payload)

    try:
        if ephemeral:
            yield "[INFO] Ephemeral mode: credentials are held in RAM only for this run and will be wiped immediately when it finishes.\n"
        yield f"{RUN_ID_MARKER}{run_uuid}\n"
        yield f"[INFO] Starting automation for {total} device(s).\n"
        mode_desc = (
            f"PARALLEL (up to {min(payload['max_workers'], total)} at a time)"
            if payload["parallel"] and total > 1
            else "SEQUENTIAL"
        )
        yield f"[INFO] Execution mode: {mode_desc}\n"

        # Connection pre-check / fast-fail threshold: one quick TCP probe
        # against a shared jump host (if this run has one) BEFORE
        # dispatching to any device, so a down jump host fails once, up
        # front, instead of every device independently discovering the
        # same thing after waiting out its own full connect timeout.
        gateway_down_event = threading.Event()
        gateway_ok, gateway_message = precheck_gateway(payload)
        if not gateway_ok:
            gateway_down_event.set()
            yield f"[ERROR] {gateway_message}\n"
        yield "=" * 70 + "\n\n"

        # Cheap progress tracking: `results` grows by one entry per device
        # as run_device_checks() finishes each one (thread-safe via
        # `lock`), so we just poll its length as lines stream past rather
        # than threading a dedicated callback through two more layers of
        # generators (_run_sequential / _run_parallel / run_device_checks).
        def _run_with_progress(gen):
            for line in gen:
                with lock:
                    done = len(results)
                _job_progress(job_id, done, total)
                yield line

        if payload["parallel"] and total > 1:
            yield from _run_with_progress(
                _run_parallel(devices, payload, results, lock, total,
                              cancel_event=cancel_event, gateway_down_event=gateway_down_event))
        else:
            yield from _run_with_progress(
                _run_sequential(devices, payload, results, lock, total,
                                cancel_event=cancel_event, gateway_down_event=gateway_down_event))

        yield "\n" + _build_summary_table(results)
        if cancel_event.is_set():
            yield "\n[DONE] Automation stopped early by user request.\n"
        else:
            yield "\n[DONE] Automation completed for all devices.\n"

    except Exception as exc:  # Catch-all so the stream never dies silently
        yield f"\n[FATAL ERROR] {exc}\n"
        if results:
            yield "\n" + _build_summary_table(results)
        yield "[DONE] Automation finished with errors.\n"

    finally:
        unregister_run(run_uuid)
        _job_finish(job_id)
        if ephemeral:
            # Actively zero every credential buffer now that the run
            # (this worker/generator) is finishing, regardless of how it
            # ended -- this is the "actively wiped from memory once the
            # worker thread terminates" half of the ephemeral-mode
            # contract (see secure_credentials.py's module docstring for
            # the honest limitation on Python string immutability).
            secure_credentials.wipe_payload(payload)
        devices_ok = sum(
            1 for r in results
            if r.get("ping") == "OK" and r.get("tcp_port") == "OK" and not str(r.get("ssh", "")).startswith("FAILED")
        )
        structured = {
            "meta": {
                "total_devices": total,
                "devices_ok": devices_ok,
                "devices_with_issues": len(results) - devices_ok,
                "total_commands_ok": sum(r.get("commands_ok", 0) for r in results),
                "total_commands_failed": sum(r.get("commands_failed", 0) for r in results),
                "mode": "parallel" if (payload.get("parallel") and total > 1) else "sequential",
                "run_ssh": payload.get("run_ssh", False),
                "config_mode": payload.get("config_mode", False),
                "save_config": payload.get("save_config", False),
                "backup_configs": payload.get("backup_configs", False),
                "backup_dir": payload.get("backup_dir"),
                "health_check": payload.get("health_check", False),
                "cancelled": cancel_event.is_set(),
                "started_at": run_started_at,
                "finished_at": _now_iso(),
                "duration_seconds": round(time.time() - run_start_perf, 2),
            },
            "devices": sorted(results, key=lambda r: (r["host"], r["port"])),
        }
        try:
            storage.save_run(structured, label=label, triggered_by=triggered_by, inventory_name=inventory_name)
        except Exception as exc:  # pragma: no cover - history is best-effort
            print(f"[WARN] Failed to save run history: {exc}")

        run_label = label or f"{triggered_by} run"
        log.info(
            "Run finished: label=%r triggered_by=%s devices=%d ok=%d failed=%d duration=%.2fs",
            run_label, triggered_by, total, devices_ok, len(results) - devices_ok,
            structured["meta"]["duration_seconds"],
        )
        log_audit(
            "run_finished", label=run_label, triggered_by=triggered_by, total_devices=total,
            devices_ok=devices_ok, devices_with_issues=len(results) - devices_ok,
            duration_seconds=structured["meta"]["duration_seconds"], cancelled=cancel_event.is_set(),
        )

        # Global "notify on run failure" alert -- separate from (and in
        # addition to) the existing per-schedule notify_on_failure toggle,
        # so a global email/Slack destination can be notified about ANY
        # run's failures (manual or scheduled) if the user opts in under
        # Settings, not just schedules that individually opted in.
        failed_devices = [
            f"{r['host']}:{r['port']}" for r in results
            if r.get("ping") == "FAILED" or r.get("tcp_port") == "FAILED"
            or str(r.get("ssh", "")).startswith("FAILED")
        ]
        if failed_devices:
            try:
                alert_settings = get_alert_settings(decrypt_secrets=False)
                if alert_settings.get("notify_on_run_failure"):
                    maybe_send_alerts(
                        subject=f"Network automation run failed: {run_label}",
                        text=alerts.build_failure_alert_text(run_label, failed_devices, _build_summary_table(results)),
                    )
            except Exception as exc:
                log.warning("Failed to send run-failure alert: %s", exc)

        yield f"\n{STRUCTURED_START_MARKER}\n"
        yield json.dumps(structured)
        yield f"\n{STRUCTURED_END_MARKER}\n"


# ==========================================================================
# Email / Slack alert settings (global -- see alerts.py for the actual
# send logic). Secrets (SMTP password, Slack webhook URL) are encrypted
# at rest using the same Fernet key as schedule/inventory credentials.
# ==========================================================================
ALERT_SETTINGS_KEY = "alert_settings"


def get_alert_settings(decrypt_secrets: bool = False):
    """
    Returns the saved global alert settings dict:
        {
          "email": {"enabled": bool, "host", "port", "username", "password"(enc),
                     "use_tls", "from_addr", "to_addrs"},
          "slack": {"enabled": bool, "webhook_url"(enc)},
          "notify_on_run_failure": bool,
          "notify_on_health_regression": bool,
        }
    With `decrypt_secrets=False` (default, used when returning settings to
    the browser), secret fields are replaced with a boolean "_set" flag
    instead of their real value. With `decrypt_secrets=True` (used
    internally right before actually sending an alert), secrets are
    decrypted back to plaintext.
    """
    raw = storage.get_setting(ALERT_SETTINGS_KEY, default=None) or {
        "email": {"enabled": False, "host": "", "port": 587, "username": "", "password": None,
                  "use_tls": True, "from_addr": "", "to_addrs": ""},
        "slack": {"enabled": False, "webhook_url": None},
        "notify_on_run_failure": False,
        "notify_on_health_regression": True,
    }
    result = json.loads(json.dumps(raw))  # deep copy
    email = result.setdefault("email", {})
    slack = result.setdefault("slack", {})

    if decrypt_secrets:
        pw = email.get("password")
        if isinstance(pw, dict) and "_encrypted" in pw:
            email["password"] = storage.decrypt_text(pw["_encrypted"])
        webhook = slack.get("webhook_url")
        if isinstance(webhook, dict) and "_encrypted" in webhook:
            slack["webhook_url"] = storage.decrypt_text(webhook["_encrypted"])
    else:
        pw = email.get("password")
        email["password_set"] = bool(isinstance(pw, dict) and pw.get("_encrypted"))
        email["password"] = None
        webhook = slack.get("webhook_url")
        slack["webhook_url_set"] = bool(isinstance(webhook, dict) and webhook.get("_encrypted"))
        slack["webhook_url"] = None
    return result


def save_alert_settings(data: dict):
    """
    Persists global alert settings. Secret fields (email password, Slack
    webhook URL) are only overwritten if a new non-empty value is
    supplied -- an empty value keeps whatever was previously saved
    (mirrors the same "don't clobber a secret with a blank re-save"
    pattern used for inventories/schedules elsewhere in this app).
    """
    existing = get_alert_settings(decrypt_secrets=False)
    new_email = dict(data.get("email") or {})
    new_slack = dict(data.get("slack") or {})

    stored_email = dict(existing.get("email") or {})
    stored_email.update({
        "enabled": bool(new_email.get("enabled")),
        "host": (new_email.get("host") or "").strip(),
        "port": int(new_email.get("port") or 587),
        "username": (new_email.get("username") or "").strip(),
        "use_tls": bool(new_email.get("use_tls", True)),
        "from_addr": (new_email.get("from_addr") or "").strip(),
        "to_addrs": (new_email.get("to_addrs") or "").strip(),
    })
    new_password = new_email.get("password")
    if new_password and ENCRYPTION_AVAILABLE:
        stored_email["password"] = {"_encrypted": storage.encrypt_text(new_password)}
    elif not new_password:
        # keep whichever encrypted blob (if any) was already stored
        old_pw = (storage.get_setting(ALERT_SETTINGS_KEY, default={}) or {}).get("email", {}).get("password")
        stored_email["password"] = old_pw
    else:
        stored_email["password"] = None

    stored_slack = dict(existing.get("slack") or {})
    stored_slack["enabled"] = bool(new_slack.get("enabled"))
    new_webhook = new_slack.get("webhook_url")
    if new_webhook and ENCRYPTION_AVAILABLE:
        stored_slack["webhook_url"] = {"_encrypted": storage.encrypt_text(new_webhook)}
    elif not new_webhook:
        old_webhook = (storage.get_setting(ALERT_SETTINGS_KEY, default={}) or {}).get("slack", {}).get("webhook_url")
        stored_slack["webhook_url"] = old_webhook
    else:
        stored_slack["webhook_url"] = None

    final = {
        "email": stored_email,
        "slack": stored_slack,
        "notify_on_run_failure": bool(data.get("notify_on_run_failure")),
        "notify_on_health_regression": bool(data.get("notify_on_health_regression", True)),
    }
    storage.set_setting(ALERT_SETTINGS_KEY, final)
    return final


def maybe_send_alerts(subject: str, text: str):
    """
    Sends `text` via whichever of email/Slack are enabled in the saved
    global alert settings. Best-effort: logs and returns quietly on any
    failure rather than raising, since alert delivery must never break
    the automation run that triggered it. Returns a small results dict
    for callers that want to report delivery status (e.g. a "Test Alert"
    button), but most callers can ignore the return value.
    """
    settings = get_alert_settings(decrypt_secrets=True)
    results = {"email": None, "slack": None}

    email_cfg = settings.get("email") or {}
    if email_cfg.get("enabled"):
        ok, error = alerts.send_email_alert(email_cfg, subject, text)
        results["email"] = {"ok": ok, "error": error}
        if ok:
            log.info("Alert email sent: %s", subject)
            log_audit("alert_sent", channel="email", subject=subject, ok=True)
        else:
            log.warning("Alert email FAILED: %s -- %s", subject, error)
            log_audit("alert_sent", channel="email", subject=subject, ok=False, error=error)

    slack_cfg = settings.get("slack") or {}
    if slack_cfg.get("enabled"):
        ok, error = alerts.send_slack_alert(slack_cfg.get("webhook_url"), text)
        results["slack"] = {"ok": ok, "error": error}
        if ok:
            log.info("Alert Slack message sent: %s", subject)
            log_audit("alert_sent", channel="slack", subject=subject, ok=True)
        else:
            log.warning("Alert Slack message FAILED: %s -- %s", subject, error)
            log_audit("alert_sent", channel="slack", subject=subject, ok=False, error=error)

    return results


# ==========================================================================
# AI integration helpers (OpenRouter / NVIDIA NIM / Ollama)
# Implemented with urllib only -- no extra pip packages required.
# ==========================================================================
DEFAULT_AI_ENDPOINTS = {
    "openrouter": "https://openrouter.ai/api/v1/chat/completions",
    "nim": "https://integrate.api.nvidia.com/v1/chat/completions",
    "ollama": "http://localhost:11434/api/chat",
}

DEFAULT_AI_MODELS = {
    "openrouter": "openai/gpt-4o-mini",
    "nim": "meta/llama-3.1-70b-instruct",
    "ollama": "llama3",
}


def _call_openai_style(url, api_key, model, messages, timeout):
    """Used for OpenRouter and NVIDIA NIM, both OpenAI-compatible APIs."""
    body = json.dumps({"model": model, "messages": messages, "temperature": 0.3}).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")
    # Optional but recommended identification headers for OpenRouter; harmless elsewhere.
    req.add_header("HTTP-Referer", "http://localhost:5000")
    req.add_header("X-Title", "Network Automation Console")

    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    data = json.loads(raw)
    choices = data.get("choices") or []
    if not choices:
        raise ValueError("The AI provider returned no choices in its response.")
    message = choices[0].get("message") or {}
    content = message.get("content")
    if not content:
        raise ValueError("The AI provider response did not contain any message content.")
    return content.strip()


def _call_ollama(url, model, messages, timeout):
    """Local Ollama server, using its native /api/chat endpoint (non-streaming)."""
    body = json.dumps({"model": model, "messages": messages, "stream": False}).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")

    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    data = json.loads(raw)
    message = data.get("message") or {}
    content = message.get("content")
    if not content:
        raise ValueError("Ollama's response did not contain any message content.")
    return content.strip()


def call_ai_provider(provider, api_key, base_url, model, messages, timeout=AI_REQUEST_TIMEOUT):
    """
    Dispatches to the right provider implementation. Returns (text, None)
    on success or (None, "human readable error") on failure. Never raises.
    """
    url = (base_url or "").strip() or DEFAULT_AI_ENDPOINTS.get(provider)
    model = (model or "").strip() or DEFAULT_AI_MODELS.get(provider)

    try:
        if provider in ("openrouter", "nim"):
            if not api_key:
                return None, f"An API key is required for {provider}."
            text = _call_openai_style(url, api_key, model, messages, timeout)
        elif provider == "ollama":
            text = _call_ollama(url, model, messages, timeout)
        else:
            return None, f"Unknown AI provider '{provider}'."
        return text, None

    except urllib.error.HTTPError as exc:
        try:
            err_body = exc.read().decode("utf-8", errors="replace")
            err_json = json.loads(err_body)
            msg = err_json.get("error", {}).get("message") or err_json.get("error") or err_body
        except Exception:
            msg = str(exc)
        return None, f"AI provider returned HTTP {exc.code}: {msg}"

    except urllib.error.URLError as exc:
        hint = ""
        if provider == "ollama":
            hint = (" Is Ollama installed and running? Try 'ollama serve' in a terminal, "
                    "and make sure the model has been pulled (e.g. 'ollama pull llama3').")
        return None, f"Could not reach {provider} at {url}: {exc.reason}.{hint}"

    except (TimeoutError, socket.timeout):
        return None, f"Request to {provider} timed out after {timeout}s."

    except (ValueError, json.JSONDecodeError) as exc:
        return None, f"Unexpected response from {provider}: {exc}"

    except Exception as exc:  # pragma: no cover - defensive
        return None, f"Unexpected error calling {provider}: {exc}"


def _clean_suggested_commands(text):
    """
    Turn free-form AI text into a clean list of command lines: strips
    markdown code fences, bullet/number prefixes, and blank lines, in
    case the model doesn't perfectly follow the 'one command per line,
    no extra formatting' instruction.
    """
    lines = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("```"):
            continue
        line = re.sub(r"^[\-\*\u2022]\s*", "", line)          # bullet points
        line = re.sub(r"^\d+[\.\)]\s*", "", line)               # "1. " / "1) "
        line = line.strip("`").strip()
        if line:
            lines.append(line)
    return lines


@app.route("/ai-assist", methods=["POST"])
def ai_assist():
    """
    Single endpoint for both AI features:
      mode="suggest_commands": body={provider, api_key, base_url, model, vendor, description}
      mode="analyze_output":   body={provider, api_key, base_url, model, context}
    Returns {"result": "..."} or {"result": "...", "commands": [...]} on
    success, or {"error": "..."} with an appropriate status code on failure.
    The API key (if any) is used only for this single outbound request and
    is never stored or logged by the server.
    """
    try:
        data = request.get_json(force=True, silent=True)
    except Exception:
        data = None
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid or missing JSON body."}), 400

    provider = (data.get("provider") or "").strip().lower()
    mode = (data.get("mode") or "").strip()
    api_key = (data.get("api_key") or "").strip()
    base_url = (data.get("base_url") or "").strip()
    model = (data.get("model") or "").strip()

    if provider not in ALLOWED_AI_PROVIDERS:
        return jsonify({"error": f"Provider must be one of: {', '.join(sorted(ALLOWED_AI_PROVIDERS))}."}), 400
    if mode not in ALLOWED_AI_MODES:
        return jsonify({"error": f"Mode must be one of: {', '.join(sorted(ALLOWED_AI_MODES))}."}), 400

    if provider in ("openrouter", "nim") and not api_key:
        return jsonify({"error": f"An API key is required for {provider}."}), 400

    if mode == "suggest_commands":
        vendor = (data.get("vendor") or "generic").strip()
        description = (data.get("description") or "").strip()
        if not description:
            return jsonify({"error": "Please describe what you want to check or configure."}), 400
        description = description[:AI_MAX_DESCRIPTION_CHARS]
        vendor_label = COMMAND_LIBRARY.get(vendor, {}).get("label", vendor)

        messages = [
            {
                "role": "system",
                "content": (
                    "You are an expert network engineer. Respond with ONLY a plain list of "
                    "CLI commands, one command per line. No explanations, no numbering, no "
                    "markdown, no code fences -- just the raw commands, most relevant first."
                ),
            },
            {
                "role": "user",
                "content": f"Device platform: {vendor_label}\nTask: {description}\n"
                           f"List the most relevant CLI commands to accomplish this.",
            },
        ]
        text, error = call_ai_provider(provider, api_key, base_url, model, messages)
        if error:
            return jsonify({"error": error}), 502
        commands = _clean_suggested_commands(text)[:MAX_COMMANDS]
        return jsonify({"result": text, "commands": commands})

    else:  # analyze_output
        context = (data.get("context") or "").strip()
        if not context:
            return jsonify({"error": "No run output was provided to analyze."}), 400
        truncated = context[-AI_MAX_CONTEXT_CHARS:]
        note = "" if len(context) <= AI_MAX_CONTEXT_CHARS else (
            "[NOTE: earlier output was truncated to keep the request a reasonable size]\n"
        )

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a senior network engineer reviewing the log output of an "
                    "automated network health check across one or more devices. "
                    "Summarize what happened, call out any failures or anomalies, and give "
                    "concise, actionable recommendations. Use short bullet points and be "
                    "specific about which device/command is affected when possible."
                ),
            },
            {"role": "user", "content": note + truncated},
        ]
        text, error = call_ai_provider(provider, api_key, base_url, model, messages)
        if error:
            return jsonify({"error": error}), 502
        return jsonify({"result": text})


# ==========================================================================
# Routes
# ==========================================================================
@app.route("/")
def index():
    return render_template(
        "index.html",
        paramiko_available=PARAMIKO_AVAILABLE,
        netmiko_available=NETMIKO_AVAILABLE,
        encryption_available=ENCRYPTION_AVAILABLE,
        jinja2_available=JINJA2_AVAILABLE,
        audit_available=AUDIT_AVAILABLE,
        max_devices=MAX_DEVICES,
        max_workers_limit=MAX_WORKERS_LIMIT,
        vendors=[{"id": k, "label": v["label"]} for k, v in COMMAND_LIBRARY.items()],
    )


@app.route("/command-suggestions")
def command_suggestions():
    vendor = (request.args.get("vendor") or "").strip()
    entry = COMMAND_LIBRARY.get(vendor)
    if not entry:
        return jsonify({"error": f"Unknown vendor '{vendor}'."}), 404
    return jsonify({
        "vendor": vendor,
        "label": entry["label"],
        "categories": entry["categories"],
        "config_categories": entry.get("config_categories", {}),
    })


@app.route("/run-script", methods=["POST"])
def run_script():
    """
    Validates input first (returns fast JSON 400 on bad input), then, if
    valid, returns a streaming plain-text response with live log output
    covering every device in the request, ending with a structured JSON
    block wrapped in sentinel markers. The very first line of the stream
    is a run-id marker the client uses to later call /cancel-run/<id>.
    """
    try:
        data = request.get_json(force=True, silent=True)
    except Exception:
        data = None

    if data is None:
        return jsonify({"error": "Invalid or missing JSON body."}), 400

    cleaned, error = validate_payload(data)
    if error:
        return jsonify({"error": error}), 400

    run_uuid = uuid.uuid4().hex
    label = (data.get("label") or "").strip()
    response = Response(
        stream_with_context(stream_multi_device(cleaned, run_uuid, triggered_by="manual", label=label)),
        mimetype="text/plain",
    )
    response.headers["Cache-Control"] = "no-cache"
    response.headers["X-Accel-Buffering"] = "no"
    return response


@app.route("/cancel-run/<run_uuid>", methods=["POST"])
def cancel_run(run_uuid):
    """
    Cooperative cancellation: flips a threading.Event that the running
    generator checks between commands/devices. This is NOT instantaneous --
    an in-flight SSH command will finish (or hit its own timeout) before
    the run actually stops, since forcibly killing a mid-command SSH
    session could leave a device in a half-applied configuration state.
    """
    found = request_cancel(run_uuid)
    if not found:
        return jsonify({"error": "No active run found with that id (it may have already finished)."}), 404
    return jsonify({"status": "cancel_requested"})


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "paramiko_available": PARAMIKO_AVAILABLE,
        "netmiko_available": NETMIKO_AVAILABLE,
        "encryption_available": ENCRYPTION_AVAILABLE,
        "jinja2_available": JINJA2_AVAILABLE,
        "audit_available": AUDIT_AVAILABLE,
        "audit_textfsm_available": is_textfsm_installed() if AUDIT_AVAILABLE else False,
    })


# ==========================================================================
# Saved device inventories
# ==========================================================================
@app.route("/inventories", methods=["GET"])
def api_list_inventories():
    return jsonify({"inventories": storage.list_inventories()})


@app.route("/inventories", methods=["POST"])
def api_save_inventory():
    try:
        data = request.get_json(force=True, silent=True)
    except Exception:
        data = None
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid or missing JSON body."}), 400

    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "A name is required to save an inventory."}), 400
    if len(name) > 100:
        return jsonify({"error": "Name is too long (max 100 characters)."}), 400

    payload = data.get("payload")
    if not isinstance(payload, dict):
        return jsonify({"error": "Missing inventory payload."}), 400

    notes = (data.get("notes") or "").strip()[:500]
    tags = (data.get("tags") or "").strip()[:200]
    device_count = len(payload.get("devices") or [])

    # Passwords/keys are only persisted if the caller explicitly opts in
    # AND encryption is available -- otherwise we strip them so nothing
    # sensitive is ever written to disk in plaintext.
    remember_secrets = bool(data.get("remember_secrets")) and ENCRYPTION_AVAILABLE
    stored_payload = dict(payload)
    for secret_field in ("password", "private_key_text", "private_key_passphrase",
                          "jump_password", "jump_private_key_text", "jump_private_key_passphrase"):
        value = stored_payload.get(secret_field)
        if remember_secrets and value:
            stored_payload[secret_field] = {"_encrypted": storage.encrypt_text(value)}
        else:
            stored_payload.pop(secret_field, None)
    stored_payload["_secrets_remembered"] = remember_secrets

    result = storage.save_inventory(name, stored_payload, notes=notes, tags=tags, device_count=device_count)
    return jsonify(result)


@app.route("/inventories/<int:inv_id>/favorite", methods=["POST"])
def api_favorite_inventory(inv_id):
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}
    favorite = bool(data.get("favorite", True))
    ok = storage.set_inventory_favorite(inv_id, favorite)
    if not ok:
        return jsonify({"error": "Inventory not found."}), 404
    return jsonify({"status": "updated", "favorite": favorite})


@app.route("/inventories/<int:inv_id>/duplicate", methods=["POST"])
def api_duplicate_inventory(inv_id):
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}
    new_name = (data.get("new_name") or "").strip()
    if not new_name:
        return jsonify({"error": "A new name is required to duplicate an inventory."}), 400
    try:
        result = storage.duplicate_inventory(inv_id, new_name)
    except Exception as exc:
        return jsonify({"error": f"Could not duplicate: a name conflict or storage error occurred ({exc})."}), 400
    if not result:
        return jsonify({"error": "Inventory not found."}), 404
    return jsonify(result)


@app.route("/inventories/<int:inv_id>", methods=["GET"])
def api_get_inventory(inv_id):
    inv = storage.get_inventory(inv_id)
    if not inv:
        return jsonify({"error": "Inventory not found."}), 404

    data = dict(inv["data"])
    for secret_field in ("password", "private_key_text", "private_key_passphrase",
                          "jump_password", "jump_private_key_text", "jump_private_key_passphrase"):
        value = data.get(secret_field)
        if isinstance(value, dict) and "_encrypted" in value:
            data[secret_field] = storage.decrypt_text(value["_encrypted"])
    inv["data"] = data
    return jsonify(inv)


@app.route("/inventories/<int:inv_id>", methods=["PATCH"])
def api_update_inventory(inv_id):
    """
    Inline-edits an EXISTING inventory (rename, edit device list, edit
    notes/tags) without creating a new row -- unlike POST /inventories,
    which upserts by name and would create a duplicate entry if you
    "saved" a renamed copy under the old save-as-new flow.
    """
    try:
        data = request.get_json(force=True, silent=True)
    except Exception:
        data = None
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid or missing JSON body."}), 400

    existing = storage.get_inventory(inv_id)
    if not existing:
        return jsonify({"error": "Inventory not found."}), 404

    name = None
    if "name" in data:
        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"error": "Name cannot be empty."}), 400
        if len(name) > 100:
            return jsonify({"error": "Name is too long (max 100 characters)."}), 400

    notes = data.get("notes")
    if notes is not None:
        notes = notes.strip()[:500]
    tags = data.get("tags")
    if tags is not None:
        tags = tags.strip()[:200]

    new_data = None
    device_count = None
    if "payload" in data:
        payload = data.get("payload")
        if not isinstance(payload, dict):
            return jsonify({"error": "Invalid payload."}), 400

        # Preserve previously-remembered encrypted secrets unless the
        # caller explicitly supplies new plaintext values to replace them
        # (matching the same opt-in behavior as creating an inventory).
        remember_secrets = bool(data.get("remember_secrets")) and ENCRYPTION_AVAILABLE
        stored_payload = dict(payload)
        old_data = existing["data"]
        for secret_field in ("password", "private_key_text", "private_key_passphrase",
                              "jump_password", "jump_private_key_text", "jump_private_key_passphrase"):
            value = stored_payload.get(secret_field)
            if remember_secrets and value:
                stored_payload[secret_field] = {"_encrypted": storage.encrypt_text(value)}
            elif not value and isinstance(old_data.get(secret_field), dict):
                # Caller didn't touch this field -- keep the old encrypted blob.
                stored_payload[secret_field] = old_data[secret_field]
            else:
                stored_payload.pop(secret_field, None)
        stored_payload["_secrets_remembered"] = remember_secrets or bool(old_data.get("_secrets_remembered"))

        new_data = stored_payload
        device_count = len(payload.get("devices") or [])

    try:
        result = storage.update_inventory_by_id(
            inv_id, name=name, data=new_data, notes=notes, tags=tags, device_count=device_count,
        )
    except Exception as exc:
        return jsonify({"error": f"Could not update inventory (possibly a name conflict): {exc}"}), 400
    if not result:
        return jsonify({"error": "Inventory not found."}), 404
    return jsonify(result)


@app.route("/inventories/<int:inv_id>", methods=["DELETE"])
def api_delete_inventory(inv_id):
    ok = storage.delete_inventory(inv_id)
    if not ok:
        return jsonify({"error": "Inventory not found."}), 404
    return jsonify({"status": "deleted"})


# ==========================================================================
# Run history
# ==========================================================================
@app.route("/history", methods=["GET"])
def api_list_history():
    limit = request.args.get("limit", 50)
    try:
        limit = max(1, min(int(limit), 200))
    except (TypeError, ValueError):
        limit = 50
    triggered_by = (request.args.get("triggered_by") or "").strip() or None
    if triggered_by not in (None, "manual", "schedule"):
        triggered_by = None
    only_failed = (request.args.get("only_failed") or "").lower() in ("1", "true", "yes")
    search = (request.args.get("search") or "").strip()[:200]
    return jsonify({
        "runs": storage.list_runs(limit=limit, triggered_by=triggered_by, only_failed=only_failed, search=search),
        "stats": storage.get_history_stats(),
    })


@app.route("/history/<int:run_id>", methods=["GET"])
def api_get_history_run(run_id):
    run = storage.get_run(run_id)
    if not run:
        return jsonify({"error": "Run not found."}), 404
    return jsonify(run)


@app.route("/history/<int:run_id>", methods=["DELETE"])
def api_delete_history_run(run_id):
    ok = storage.delete_run(run_id)
    if not ok:
        return jsonify({"error": "Run not found."}), 404
    return jsonify({"status": "deleted"})


@app.route("/history", methods=["DELETE"])
def api_delete_all_history():
    count = storage.delete_all_runs()
    return jsonify({"status": "deleted", "count": count})


@app.route("/history/trend", methods=["GET"])
def api_history_trend():
    days = request.args.get("days", 14)
    try:
        days = max(2, min(int(days), 90))
    except (TypeError, ValueError):
        days = 14
    return jsonify({"trend": storage.get_history_trend(days=days)})


# ==========================================================================
# Scheduled jobs (read-only checks only -- enforced in validate_payload
# via allow_config_mode=False, both at creation time and at run time)
# ==========================================================================
def _mask_schedule_secrets(sched: dict) -> dict:
    """Replaces encrypted secret blobs (including per-device password
    overrides -- see _encrypt_schedule_secrets()) with a boolean flag
    before sending a schedule back to the browser -- the UI never needs
    the actual encrypted bytes, only whether a credential is set."""
    masked = dict(sched)
    config = dict(masked.get("config") or {})
    for secret_field in ("password", "private_key_text", "private_key_passphrase",
                          "jump_password", "jump_private_key_text", "jump_private_key_passphrase"):
        value = config.get(secret_field)
        if isinstance(value, dict) and "_encrypted" in value:
            config[secret_field] = None
            config[f"{secret_field}_set"] = True

    devices = config.get("devices")
    if isinstance(devices, list):
        masked_devices = []
        for d in devices:
            if isinstance(d, dict) and isinstance(d.get("password"), dict) and "_encrypted" in d["password"]:
                d = dict(d)
                d["password"] = None
                d["password_set"] = True
            masked_devices.append(d)
        config["devices"] = masked_devices

    masked["config"] = config
    return masked


@app.route("/schedules", methods=["GET"])
def api_list_schedules():
    return jsonify({"schedules": [_mask_schedule_secrets(s) for s in storage.list_schedules()]})


@app.route("/schedules", methods=["POST"])
def api_create_schedule():
    try:
        data = request.get_json(force=True, silent=True)
    except Exception:
        data = None
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid or missing JSON body."}), 400

    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "A name is required for the schedule."}), 400

    interval_raw = data.get("interval_minutes")
    try:
        interval_minutes = int(interval_raw)
    except (TypeError, ValueError):
        return jsonify({"error": "Interval must be a whole number of minutes."}), 400
    if not (MIN_SCHEDULE_INTERVAL_MINUTES <= interval_minutes <= MAX_SCHEDULE_INTERVAL_MINUTES):
        return jsonify({
            "error": f"Interval must be between {MIN_SCHEDULE_INTERVAL_MINUTES} and "
                     f"{MAX_SCHEDULE_INTERVAL_MINUTES} minutes."
        }), 400

    config = data.get("config")
    if not isinstance(config, dict):
        return jsonify({"error": "Missing schedule config (device list + settings)."}), 400

    # Ephemeral ("RAM-only, one-time") execution is fundamentally
    # incompatible with a recurring schedule -- a schedule must be able
    # to retrieve its credentials again on every future firing, which is
    # exactly what ephemeral mode promises NOT to allow. Reject up front
    # with a clear message rather than silently ignoring the flag.
    if config.get("ephemeral"):
        return jsonify({
            "error": "Ephemeral (one-time, RAM-only credential) mode cannot be used for a "
                     "recurring schedule -- a schedule needs its credentials to be retrievable "
                     "again on every future run. Disable 'Ephemeral run' before saving this as "
                     "a schedule."
        }), 400

    # Validate NOW (fail fast with a clear error) AND config-mode is
    # hard-blocked for schedules regardless of what the config contains.
    cleaned, error = validate_payload(config, allow_config_mode=False)
    if error:
        return jsonify({"error": error}), 400

    # Unlike inventories (where remembering a password is opt-in),
    # schedules ALWAYS need to store credentials to run unattended --
    # so encryption is mandatory here, not optional. If it isn't
    # available, refuse rather than silently writing a plaintext
    # password to disk.
    if not ENCRYPTION_AVAILABLE:
        return jsonify({
            "error": "Cannot create a schedule: credential encryption is unavailable "
                     "(the 'cryptography' package could not be installed). Schedules "
                     "require SSH credentials to be stored securely to run unattended."
        }), 503

    stored_config = _encrypt_schedule_secrets(config)

    notify_on_failure = bool(data.get("notify_on_failure"))
    result = storage.create_schedule(name, interval_minutes, stored_config,
                                      notify_on_failure=notify_on_failure, job_type="automation")
    return jsonify(result)


@app.route("/audit/schedules", methods=["POST"])
def api_create_audit_schedule():
    """
    Creates a recurring Audit schedule -- Phase 4 of the integration
    strategy ("scheduler unification"): reuses the exact same `schedules`
    table/row and the exact same background `_scheduler_loop` thread as
    automation schedules, distinguished only by the `job_type` column, so
    there's still only ONE scheduler in the whole app.

    Unlike automation schedules (config-mode is hard-blocked but a
    read-only run can still change nothing on its own), an Audit schedule
    is read-only BY CONSTRUCTION -- every command an Audit Profile can
    send is a "show" command declared in a YAML file, so there's no
    equivalent "allow_config_mode" flag to enforce here.
    """
    if not AUDIT_AVAILABLE:
        return _audit_unavailable_response()
    try:
        data = request.get_json(force=True, silent=True)
    except Exception:
        data = None
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid or missing JSON body."}), 400

    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "A name is required for the schedule."}), 400

    interval_raw = data.get("interval_minutes")
    try:
        interval_minutes = int(interval_raw)
    except (TypeError, ValueError):
        return jsonify({"error": "Interval must be a whole number of minutes."}), 400
    if not (MIN_SCHEDULE_INTERVAL_MINUTES <= interval_minutes <= MAX_SCHEDULE_INTERVAL_MINUTES):
        return jsonify({
            "error": f"Interval must be between {MIN_SCHEDULE_INTERVAL_MINUTES} and "
                     f"{MAX_SCHEDULE_INTERVAL_MINUTES} minutes."
        }), 400

    config = data.get("config")
    if not isinstance(config, dict):
        return jsonify({"error": "Missing schedule config (audit profile + device source)."}), 400

    if config.get("ephemeral"):
        return jsonify({
            "error": "Ephemeral (one-time, RAM-only credential) mode cannot be used for a "
                     "recurring audit schedule -- a schedule needs its credentials to be "
                     "retrievable again on every future run. Disable 'Ephemeral run' before "
                     "saving this as a schedule."
        }), 400

    # Fail fast with the exact same validation the scheduler will re-run
    # on every firing, and that /audit/run uses interactively.
    resolved, error = resolve_audit_config(config)
    if error:
        return jsonify({"error": error}), 400

    has_any_password = bool(resolved.get("password")) or any(
        isinstance(d, dict) and d.get("password") for d in resolved.get("devices", [])
    )
    if not ENCRYPTION_AVAILABLE and has_any_password:
        return jsonify({
            "error": "Cannot create a schedule with a stored password: credential encryption is "
                     "unavailable (the 'cryptography' package could not be installed). Either "
                     "resolve credentials via a saved Inventory that doesn't need one re-typed, "
                     "or install 'cryptography' and try again."
        }), 503

    stored_config = _encrypt_schedule_secrets(config)

    notify_on_failure = bool(data.get("notify_on_failure"))
    result = storage.create_schedule(name, interval_minutes, stored_config,
                                      notify_on_failure=notify_on_failure, job_type="audit")
    return jsonify(result)


SCHEDULE_SECRET_FIELDS = ("password", "private_key_text", "private_key_passphrase",
                          "jump_password", "jump_private_key_text", "jump_private_key_passphrase")


def _encrypt_schedule_secrets(config: dict) -> dict:
    """
    Encrypts every top-level secret field AND every per-device
    username/password override's `password` field before a schedule's
    config is written to disk.

    NOTE (bug found & fixed while wiring up Audit schedules -- Phase 4):
    both api_create_schedule() (automation) and api_create_audit_schedule()
    (audit) previously only encrypted the SHARED top-level `password`, not
    a per-device password supplied via a mixed-credential device list
    (e.g. from a CSV upload, or Audit devices typed with their own
    creds) -- meaning those per-device passwords were written to
    `schedules.config_json` in PLAINTEXT even though the schedule feature
    is documented/marketed as encrypting credentials at rest. Fixed here
    for both job types by also walking `config["devices"]`.
    """
    encrypted = dict(config)
    for secret_field in SCHEDULE_SECRET_FIELDS:
        value = encrypted.get(secret_field)
        if value and not (isinstance(value, dict) and "_encrypted" in value):
            encrypted[secret_field] = {"_encrypted": storage.encrypt_text(value)}

    devices = encrypted.get("devices")
    if isinstance(devices, list):
        new_devices = []
        for d in devices:
            if isinstance(d, dict) and d.get("password") and not (
                    isinstance(d.get("password"), dict) and "_encrypted" in d["password"]):
                d = dict(d)
                d["password"] = {"_encrypted": storage.encrypt_text(d["password"])}
            new_devices.append(d)
        encrypted["devices"] = new_devices
    return encrypted


def _decrypt_schedule_secrets(config: dict) -> dict:
    """Reverses the encryption applied in _encrypt_schedule_secrets()
    before the config is actually used to run SSH commands / an audit."""
    decrypted = dict(config)
    for secret_field in SCHEDULE_SECRET_FIELDS:
        value = decrypted.get(secret_field)
        if isinstance(value, dict) and "_encrypted" in value:
            decrypted[secret_field] = storage.decrypt_text(value["_encrypted"])

    devices = decrypted.get("devices")
    if isinstance(devices, list):
        new_devices = []
        for d in devices:
            if isinstance(d, dict) and isinstance(d.get("password"), dict) and "_encrypted" in d["password"]:
                d = dict(d)
                d["password"] = storage.decrypt_text(d["password"]["_encrypted"])
            new_devices.append(d)
        decrypted["devices"] = new_devices
    return decrypted


@app.route("/schedules/<int:sched_id>", methods=["PATCH"])
def api_update_schedule(sched_id):
    try:
        data = request.get_json(force=True, silent=True)
    except Exception:
        data = None
    if not isinstance(data, dict) or not data:
        return jsonify({"error": "Expected a JSON body with 'enabled' and/or 'interval_minutes'."}), 400

    updated_any = False

    if "enabled" in data:
        ok = storage.update_schedule_enabled(sched_id, bool(data["enabled"]))
        if not ok:
            return jsonify({"error": "Schedule not found."}), 404
        updated_any = True

    if "interval_minutes" in data:
        try:
            interval_minutes = int(data["interval_minutes"])
        except (TypeError, ValueError):
            return jsonify({"error": "Interval must be a whole number of minutes."}), 400
        if not (MIN_SCHEDULE_INTERVAL_MINUTES <= interval_minutes <= MAX_SCHEDULE_INTERVAL_MINUTES):
            return jsonify({
                "error": f"Interval must be between {MIN_SCHEDULE_INTERVAL_MINUTES} and "
                         f"{MAX_SCHEDULE_INTERVAL_MINUTES} minutes."
            }), 400
        ok = storage.update_schedule_interval(sched_id, interval_minutes)
        if not ok:
            return jsonify({"error": "Schedule not found."}), 404
        updated_any = True

    if not updated_any:
        return jsonify({"error": "No recognized fields to update."}), 400
    return jsonify({"status": "updated"})


@app.route("/schedules/<int:sched_id>", methods=["DELETE"])
def api_delete_schedule(sched_id):
    ok = storage.delete_schedule(sched_id)
    if not ok:
        return jsonify({"error": "Schedule not found."}), 404
    return jsonify({"status": "deleted"})


@app.route("/schedules/<int:sched_id>/run-now", methods=["POST"])
def api_run_schedule_now(sched_id):
    """
    Manually triggers a schedule's saved config immediately.

    For an 'automation' schedule (still subject to the same read-only
    restriction as automatic runs) this streams output exactly like a
    normal /run-script call, as before. For an 'audit' schedule this
    instead returns the full JSON report in one response (matching
    /audit/run's own non-streaming shape) since audit runs are already
    handled that way everywhere else in the app.
    """
    sched = storage.get_schedule(sched_id)
    if not sched:
        return jsonify({"error": "Schedule not found."}), 404

    if sched.get("job_type") == "audit":
        if not AUDIT_AVAILABLE:
            return _audit_unavailable_response()
        decrypted_config = _decrypt_schedule_secrets(sched["config"])
        resolved, error = resolve_audit_config(decrypted_config)
        if error:
            return jsonify({"error": f"Saved schedule config is no longer valid: {error}"}), 400
        try:
            report = run_audit_and_save(resolved, triggered_by="schedule",
                                         schedule_id=sched["id"], schedule_name=sched["name"])
        except audit_bridge.AuditBridgeError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            log.exception("Manual run-now of audit schedule '%s' failed unexpectedly", sched["name"])
            return jsonify({"error": f"Audit run failed: {exc}"}), 500
        return jsonify(report)

    decrypted_config = _decrypt_schedule_secrets(sched["config"])
    cleaned, error = validate_payload(decrypted_config, allow_config_mode=False)
    if error:
        return jsonify({"error": f"Saved schedule config is no longer valid: {error}"}), 400

    run_uuid = uuid.uuid4().hex
    response = Response(
        stream_with_context(stream_multi_device(
            cleaned, run_uuid, triggered_by="schedule", label=f"Manual run of schedule '{sched['name']}'",
        )),
        mimetype="text/plain",
    )
    response.headers["Cache-Control"] = "no-cache"
    response.headers["X-Accel-Buffering"] = "no"
    return response


@app.route("/schedules/<int:sched_id>/history", methods=["GET"])
def api_schedule_history(sched_id):
    sched = storage.get_schedule(sched_id)
    if not sched:
        return jsonify({"error": "Schedule not found."}), 404
    limit = request.args.get("limit", 50)
    try:
        limit = max(1, min(int(limit), 200))
    except (TypeError, ValueError):
        limit = 50
    if sched.get("job_type") == "audit":
        return jsonify({"runs": storage.get_audit_schedule_run_history(sched["id"], limit=limit)})
    return jsonify({"runs": storage.get_schedule_run_history(sched["name"], limit=limit)})


# ==========================================================================
# Configuration backups
# ==========================================================================
def _safe_backup_file_path(dir_param: str, filename: str):
    """
    Resolves `filename` inside the backup directory named by `dir_param`,
    rejecting any attempt to escape that directory (e.g. "../../etc/passwd")
    via os.path.realpath + a containment check. Returns the safe absolute
    path, or None if the request is invalid/unsafe.
    """
    backup_dir, error = resolve_backup_dir(dir_param)
    if error or not backup_dir:
        return None
    candidate = os.path.realpath(os.path.join(backup_dir, filename))
    real_dir = os.path.realpath(backup_dir)
    if os.path.commonpath([candidate, real_dir]) != real_dir:
        return None
    return candidate


@app.route("/backups", methods=["GET"])
def api_list_backups():
    """
    Lists .cfg backup files in the given directory (defaults to the app's
    own "backups" folder), newest first, grouped implicitly by filename
    prefix (host_port) so the UI can show "latest backup per device" or
    the full history depending on how it wants to render this.
    """
    dir_param = request.args.get("dir", "")
    backup_dir, error = resolve_backup_dir(dir_param)
    if error:
        return jsonify({"error": error}), 400

    try:
        entries = []
        for fname in os.listdir(backup_dir):
            if not fname.endswith(".cfg"):
                continue
            full_path = os.path.join(backup_dir, fname)
            if not os.path.isfile(full_path):
                continue
            stat = os.stat(full_path)
            entries.append({
                "filename": fname,
                "size_bytes": stat.st_size,
                "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(timespec="seconds"),
            })
        entries.sort(key=lambda e: e["modified_at"], reverse=True)
    except Exception as exc:
        return jsonify({"error": f"Could not list backup folder: {exc}"}), 500

    return jsonify({"dir": backup_dir, "files": entries})


@app.route("/backups/download", methods=["GET"])
def api_download_backup():
    dir_param = request.args.get("dir", "")
    filename = request.args.get("file", "")
    if not filename or "/" in filename or "\\" in filename:
        return jsonify({"error": "Invalid filename."}), 400
    safe_path = _safe_backup_file_path(dir_param, filename)
    if not safe_path or not os.path.isfile(safe_path):
        return jsonify({"error": "Backup file not found."}), 404
    return send_file(safe_path, as_attachment=True, download_name=filename)


@app.route("/backups/delete", methods=["POST"])
def api_delete_backup():
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}
    dir_param = data.get("dir", "")
    filename = data.get("file", "")
    if not filename or "/" in filename or "\\" in filename:
        return jsonify({"error": "Invalid filename."}), 400
    safe_path = _safe_backup_file_path(dir_param, filename)
    if not safe_path or not os.path.isfile(safe_path):
        return jsonify({"error": "Backup file not found."}), 404
    try:
        os.remove(safe_path)
    except Exception as exc:
        return jsonify({"error": f"Could not delete backup file: {exc}"}), 500
    return jsonify({"status": "deleted"})


@app.route("/backups/default-dir", methods=["GET"])
def api_backup_default_dir():
    """Tells the UI what the default backup folder resolves to, so it can
    show a helpful placeholder without the user needing to type anything."""
    return jsonify({"default_dir": DEFAULT_BACKUP_DIR})


# ==========================================================================
# Dynamic configuration generation (Jinja2 templates)
# ==========================================================================
def _redact_and_log_render(template_id: str, vendor: str, rendered: str, has_sensitive_fields: bool):
    """
    Records a template render to the audit trail -- WITH the rendered
    text redacted first (see templates_engine.sanitize_for_audit) so a
    password/community-string/PSK a user typed into a template field
    never ends up sitting in plaintext in logs/audit.log. Best-effort:
    a logging failure must never break a render.
    """
    try:
        log_audit(
            "template_rendered", template_id=template_id, vendor=vendor,
            contains_sensitive_field=has_sensitive_fields,
            rendered_preview=templates_engine.sanitize_for_audit(rendered)[:2000],
        )
    except Exception as exc:
        log.warning("Failed to write template-render audit record: %s", exc)


def _template_has_sensitive_fields(template_id: str) -> bool:
    entry = templates_engine.BUILTIN_TEMPLATES.get(template_id) or {}
    return any(f.get("sensitive") for f in entry.get("fields", []))


@app.route("/templates", methods=["GET"])
def api_list_templates():
    """
    Lists the built-in template library, optionally filtered by free-text
    query / vendor / tag / category (all optional query-string params --
    omit them to get the full library, same as before). Also appends any
    user-saved custom templates (see /templates/user routes) so they show
    up in the same picker.
    """
    if not JINJA2_AVAILABLE:
        return jsonify({"error": "Jinja2 is not available in this environment.", "templates": []}), 200

    query = request.args.get("q", "")
    vendor = request.args.get("vendor") or None
    category = request.args.get("category") or None
    tags_raw = request.args.get("tags") or ""
    tags = [t.strip() for t in tags_raw.split(",") if t.strip()] or None

    if query or vendor or category or tags:
        templates = templates_engine.search_templates(query=query, vendor=vendor, tags=tags, category=category)
    else:
        templates = templates_engine.list_builtin_templates()

    return jsonify({
        "templates": templates,
        "categories": templates_engine.list_categories(),
        "user_templates": storage.list_user_templates(),
    })


@app.route("/templates/render", methods=["POST"])
def api_render_template():
    """
    Renders one of the built-in parameterized templates (VLAN creation,
    bulk interface config, static routes, banner, local user, NTP) for a
    given vendor (or an alias of it), using structured form values --
    NOT raw Jinja2 syntax from the user. Every field is validated against
    its schema first (see templates_engine.validate_all_fields), so bad
    input gets a field-specific message instead of a Jinja2 traceback.

    Always returns a dry-run/preview `summary` alongside the rendered
    text (line/char counts, which interfaces/VLANs it touches, whether it
    looks like it needs config mode, contains a reload or a save-config
    command) so the caller can show what's about to happen before a human
    confirms pushing it for real. If the template has a reversible
    `action` field, an auto-generated `rollback` (the inverse operation)
    is included too.
    """
    if not JINJA2_AVAILABLE:
        return jsonify({"error": "Jinja2 is not available in this environment (install failed)."}), 503
    try:
        data = request.get_json(force=True, silent=True)
    except Exception:
        data = None
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid or missing JSON body."}), 400

    template_id = (data.get("template_id") or "").strip()
    vendor = (data.get("vendor") or "").strip()
    form_values = data.get("values") or {}
    if not isinstance(form_values, dict):
        return jsonify({"error": "'values' must be a JSON object."}), 400

    result, error = templates_engine.render_with_summary(template_id, vendor, form_values)
    if error:
        return jsonify({"error": error}), 400

    rollback_text, rollback_error = templates_engine.render_rollback(template_id, vendor, form_values)
    result["rollback"] = rollback_text
    result["rollback_unavailable_reason"] = rollback_error if not rollback_text else None

    _redact_and_log_render(template_id, vendor, result["rendered"], _template_has_sensitive_fields(template_id))
    return jsonify(result)


@app.route("/templates/render-custom", methods=["POST"])
def api_render_custom_template():
    """Renders arbitrary user-supplied Jinja2 template text + a JSON
    context object (sandboxed -- see templates_engine._get_env()), with
    the same dry-run/preview summary attached as the built-in templates."""
    if not JINJA2_AVAILABLE:
        return jsonify({"error": "Jinja2 is not available in this environment (install failed)."}), 503
    try:
        data = request.get_json(force=True, silent=True)
    except Exception:
        data = None
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid or missing JSON body."}), 400

    template_text = data.get("template_text") or ""
    context_raw = data.get("context")
    if isinstance(context_raw, str):
        try:
            context = json.loads(context_raw) if context_raw.strip() else {}
        except Exception as exc:
            return jsonify({"error": f"Context is not valid JSON: {exc}"}), 400
    elif isinstance(context_raw, dict):
        context = context_raw
    else:
        context = {}

    rendered, error = templates_engine.render_template_text(template_text, context)
    if error:
        return jsonify({"error": error}), 400

    _redact_and_log_render("custom", None, rendered, has_sensitive_fields=False)
    return jsonify({"rendered": rendered, "summary": templates_engine.build_render_summary(rendered)})


@app.route("/templates/variables", methods=["POST"])
def api_template_variables():
    """Returns the list of undeclared variable names a custom Jinja2
    template references, so the UI can render one input field per
    variable instead of requiring the user to already know them."""
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}
    variables = templates_engine.extract_template_variables(data.get("template_text") or "")
    return jsonify({"variables": variables})


@app.route("/templates/batch-render", methods=["POST"])
def api_batch_render_template():
    """
    Renders the SAME built-in template with different per-device form
    values in one call -- e.g. a unique hostname/description per switch.
    Body: {"template_id", "vendor", "devices": [{"hostname", "form_values"}, ...]}
    Returns {hostname: {"rendered": str|None, "error": str|None}}.
    """
    if not JINJA2_AVAILABLE:
        return jsonify({"error": "Jinja2 is not available in this environment (install failed)."}), 503
    try:
        data = request.get_json(force=True, silent=True)
    except Exception:
        data = None
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid or missing JSON body."}), 400

    template_id = (data.get("template_id") or "").strip()
    vendor = (data.get("vendor") or "").strip()
    devices = data.get("devices")
    if not isinstance(devices, list) or not devices:
        return jsonify({"error": "'devices' must be a non-empty list of {hostname, form_values}."}), 400
    if len(devices) > MAX_DEVICES:
        return jsonify({"error": f"Too many devices in one batch. Max allowed is {MAX_DEVICES}."}), 400

    results = templates_engine.render_batch(template_id, vendor, devices)
    for hostname, entry in results.items():
        if entry.get("rendered"):
            _redact_and_log_render(template_id, vendor, entry["rendered"], _template_has_sensitive_fields(template_id))
    return jsonify({"results": results})


@app.route("/templates/diff", methods=["POST"])
def api_template_diff():
    """Compares a pasted/fetched 'current config' against a rendered
    template's text (coarse line-set diff -- see templates_engine.compute_diff)."""
    try:
        data = request.get_json(force=True, silent=True)
    except Exception:
        data = None
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid or missing JSON body."}), 400
    current_config = data.get("current_config") or ""
    rendered_template = data.get("rendered") or ""
    if not current_config.strip() or not rendered_template.strip():
        return jsonify({"error": "Both 'current_config' and 'rendered' are required."}), 400
    return jsonify(templates_engine.compute_diff(current_config, rendered_template))


@app.route("/templates/selftest", methods=["GET"])
def api_template_selftest():
    """
    CI-style hook: renders every built-in template's declared test_cases
    and reports any that don't match their expected output -- lets you
    (or an automated check) confirm the template library still renders
    correctly after an edit, without manually clicking through the UI
    for every template/vendor combination.
    """
    if not JINJA2_AVAILABLE:
        return jsonify({"error": "Jinja2 is not available in this environment."}), 503
    failures = templates_engine.run_template_tests()
    return jsonify({"passed": len(failures) == 0, "failure_count": len(failures), "failures": failures})


# ---- User-saved custom templates (persisted, shown alongside built-ins) ----
@app.route("/templates/user", methods=["GET"])
def api_list_user_templates():
    return jsonify({"templates": storage.list_user_templates()})


@app.route("/templates/user", methods=["POST"])
def api_save_user_template():
    try:
        data = request.get_json(force=True, silent=True)
    except Exception:
        data = None
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid or missing JSON body."}), 400

    name = (data.get("name") or "").strip()
    template_text = data.get("template_text") or ""
    if not name:
        return jsonify({"error": "A name is required to save a template."}), 400
    if len(name) > 100:
        return jsonify({"error": "Name is too long (max 100 characters)."}), 400
    if not template_text.strip():
        return jsonify({"error": "Template text is empty."}), 400
    if len(template_text) > templates_engine.MAX_TEMPLATE_LENGTH:
        return jsonify({"error": f"Template is too long (max {templates_engine.MAX_TEMPLATE_LENGTH} characters)."}), 400

    # Sanity-check it actually parses before saving a broken template.
    ok, syntax_error = templates_engine.check_template_syntax(template_text)
    if not ok:
        return jsonify({"error": f"Template has a syntax error and was not saved: {syntax_error}"}), 400

    result = storage.save_user_template(
        name, template_text,
        description=(data.get("description") or "").strip()[:500],
        category=(data.get("category") or "Custom").strip()[:50],
        tags=(data.get("tags") or "").strip()[:200],
    )
    log.info("User template saved: %s", name)
    return jsonify(result)


@app.route("/templates/user/<int:tid>", methods=["GET"])
def api_get_user_template(tid):
    tmpl = storage.get_user_template(tid)
    if not tmpl:
        return jsonify({"error": "Template not found."}), 404
    return jsonify(tmpl)


@app.route("/templates/user/<int:tid>", methods=["DELETE"])
def api_delete_user_template(tid):
    ok = storage.delete_user_template(tid)
    if not ok:
        return jsonify({"error": "Template not found."}), 404
    return jsonify({"status": "deleted"})


# ==========================================================================
# Rollback safety net
# ==========================================================================
@app.route("/rollback/snapshots", methods=["GET"])
def api_list_rollback_snapshots():
    host = request.args.get("host") or None
    port = request.args.get("port")
    port = int(port) if port else None
    limit = request.args.get("limit", 50)
    try:
        limit = max(1, min(int(limit), 200))
    except (TypeError, ValueError):
        limit = 50
    return jsonify({"snapshots": storage.list_rollback_snapshots(host=host, port=port, limit=limit)})


@app.route("/rollback/snapshots/<int:snap_id>", methods=["GET"])
def api_get_rollback_snapshot(snap_id):
    snap = storage.get_rollback_snapshot(snap_id)
    if not snap:
        return jsonify({"error": "Snapshot not found."}), 404
    return jsonify(snap)


@app.route("/rollback/snapshots/<int:snap_id>", methods=["DELETE"])
def api_delete_rollback_snapshot(snap_id):
    ok = storage.delete_rollback_snapshot(snap_id)
    if not ok:
        return jsonify({"error": "Snapshot not found."}), 404
    return jsonify({"status": "deleted"})


@app.route("/rollback/execute", methods=["POST"])
def api_execute_rollback():
    """
    Best-effort rollback: re-sends a previously-snapshotted FULL
    running-config back to the device through the same config-mode SSH
    path as any other push, line-by-line, inside 'configure terminal' /
    'end'. This is NOT an atomic/transactional rollback (Cisco/Arista/
    Aruba have no such primitive without first staging a full file on
    flash, which this app doesn't do) -- lines that no longer apply
    cleanly may produce a "% Invalid input"-style error on that one line
    while the rest still applies, so the resulting live log / structured
    report should always be reviewed afterwards. Juniper is a partial
    exception: its "commit confirmed" already gives a safety window, but
    a full 'load override' + 'commit' replay is used here for consistency
    across vendors rather than a special-cased 'rollback N'.

    Requires the same explicit `confirm_config: true` flag as any other
    config-mode run, and is fully audited.
    """
    try:
        data = request.get_json(force=True, silent=True)
    except Exception:
        data = None
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid or missing JSON body."}), 400

    snap_id = data.get("snapshot_id")
    if not snap_id:
        return jsonify({"error": "snapshot_id is required."}), 400
    snap = storage.get_rollback_snapshot(int(snap_id))
    if not snap:
        return jsonify({"error": "Snapshot not found."}), 404

    if not bool(data.get("confirm_config")):
        return jsonify({
            "error": "You must explicitly confirm that you want to apply a rollback configuration to a real device."
        }), 400

    # Turn the snapshotted config text into a command list, stripping
    # obviously non-command lines (comments, blank lines, the "Building
    # configuration..." banner if it slipped into the stored text, and
    # a trailing "end") since those would either no-op or error loudly
    # for no reason when replayed.
    raw_lines = snap["before_config"].splitlines()
    skip_line_res = [
        re.compile(r"^\s*!"), re.compile(r"^\s*#"), re.compile(r"^\s*Building configuration"),
        re.compile(r"^\s*Current configuration"), re.compile(r"^\s*end\s*$"),
    ]
    commands = []
    for line in raw_lines:
        if not line.strip():
            continue
        if any(p.search(line) for p in skip_line_res):
            continue
        commands.append(line.rstrip())
    if not commands:
        return jsonify({"error": "The stored snapshot has no usable configuration lines to replay."}), 400

    device = {
        "host": snap["host"], "port": snap["port"],
        "username": (data.get("username") or "").strip(),
        "password": data.get("password") or "",
    }
    payload_in = {
        "devices": [device],
        "username": device["username"],
        "password": device["password"],
        "private_key_text": (data.get("private_key_text") or "").strip() or None,
        "private_key_passphrase": data.get("private_key_passphrase") or "",
        "vendor": snap["vendor"],
        "run_ssh": True,
        "commands": "\n".join(commands),
        "config_mode": True,
        "save_config": bool(data.get("save_config")),
        "confirm_config": True,
        "show_diff": True,
        "timeout": float(data.get("timeout") or 15),
        "parallel": False,
        "max_workers": 1,
    }
    cleaned, error = validate_payload(payload_in)
    if error:
        return jsonify({"error": error}), 400

    storage.mark_rollback_snapshot_used(int(snap_id))
    log_audit("rollback_executed", host=snap["host"], port=snap["port"], vendor=snap["vendor"], snapshot_id=int(snap_id))
    log.warning("Rollback initiated for %s:%s using snapshot #%s", snap["host"], snap["port"], snap_id)

    run_uuid = uuid.uuid4().hex
    response = Response(
        stream_with_context(stream_multi_device(
            cleaned, run_uuid, triggered_by="manual", label=f"Rollback of {snap['host']}:{snap['port']} (snapshot #{snap_id})",
        )),
        mimetype="text/plain",
    )
    response.headers["Cache-Control"] = "no-cache"
    response.headers["X-Accel-Buffering"] = "no"
    return response


# ==========================================================================
# Alert settings (email / Slack) + logs viewer
# ==========================================================================
@app.route("/settings/alerts", methods=["GET"])
def api_get_alert_settings():
    return jsonify(get_alert_settings(decrypt_secrets=False))


@app.route("/settings/alerts", methods=["POST"])
def api_save_alert_settings():
    try:
        data = request.get_json(force=True, silent=True)
    except Exception:
        data = None
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid or missing JSON body."}), 400
    if (data.get("email") or {}).get("enabled") and not ENCRYPTION_AVAILABLE:
        return jsonify({
            "error": "Cannot enable email alerts: credential encryption is unavailable "
                     "(the 'cryptography' package could not be installed)."
        }), 503
    if (data.get("slack") or {}).get("enabled") and not ENCRYPTION_AVAILABLE:
        return jsonify({
            "error": "Cannot enable Slack alerts: credential encryption is unavailable "
                     "(the 'cryptography' package could not be installed)."
        }), 503
    saved = save_alert_settings(data)
    log.info("Alert settings updated (email enabled=%s, slack enabled=%s)",
              saved["email"]["enabled"], saved["slack"]["enabled"])
    return jsonify({"status": "saved"})


@app.route("/settings/alerts/test", methods=["POST"])
def api_test_alert_settings():
    """Sends a small test message through whichever channels are
    currently enabled, WITHOUT waiting for a real failure -- lets the
    user confirm their SMTP/Slack setup actually works."""
    results = maybe_send_alerts(
        subject="Network Automation Console -- test alert",
        text="This is a test alert from the Network Automation Console. If you received this, alerts are configured correctly.",
    )
    if results["email"] is None and results["slack"] is None:
        return jsonify({"error": "No alert channel is currently enabled. Enable email and/or Slack first."}), 400
    return jsonify(results)


@app.route("/logs/<which>", methods=["GET"])
def api_view_logs(which):
    if which not in ("app", "audit"):
        return jsonify({"error": "Unknown log. Expected 'app' or 'audit'."}), 404
    lines = request.args.get("lines", 200)
    try:
        lines = max(10, min(int(lines), 2000))
    except (TypeError, ValueError):
        lines = 200
    return jsonify({"log": which, "content": logging_setup.tail_log_file(which, lines=lines)})


# ==========================================================================
# Audit (read-only inventory/compliance collection -- Phase 1 plumbing of
# the network_inventory_collector integration; see audit_bridge.py and
# /home/user/integration_strategy/INTEGRATION_STRATEGY.md)
# ==========================================================================
def _audit_unavailable_response():
    return jsonify({
        "error": "The Audit feature is unavailable in this session (PyYAML or the vendored "
                 "inventory_collector package failed to load). Automation features are unaffected."
    }), 503


def resolve_audit_config(data: dict):
    """
    Validates + resolves an audit request body into everything
    run_audit_and_save() needs: (resolved_dict, None) on success, or
    (None, "error message") on failure. Shared by the interactive
    /audit/run route AND the scheduler (both schedule creation-time
    validation and each actual scheduled firing) so a saved schedule is
    guaranteed to be re-validated with EXACTLY the same rules every time
    it runs, not a hand-duplicated copy of them.

    Accepts either an inline `devices` list or an `inventory_id` (resolved
    fresh from storage every time this is called -- so if a saved
    Inventory's device list changes, a schedule referencing it by id
    automatically picks up the change on its next run, same as the
    automation scheduler already does for its own saved-Inventory-based
    schedules... except automation schedules actually snapshot the device
    list at creation time. Audit schedules deliberately behave the newer,
    arguably more useful way -- see AUDIT_SCHEDULE_NOTES in the docstring
    of create_audit_schedule's route for the tradeoff -- but an inline
    `devices` list, once saved, is of course still a fixed snapshot.
    """
    if not isinstance(data, dict):
        return None, "Malformed request body."

    profile_id = (data.get("profile_id") or "").strip()
    if not profile_id:
        return None, "An audit profile is required."
    if AUDIT_AVAILABLE:
        # Fail fast on an unknown/broken profile at CREATION time (both
        # for an immediate /audit/run and for a schedule being saved) --
        # otherwise a typo'd profile_id would only surface as a silent
        # failure the next time a schedule happens to fire, hours later.
        try:
            audit_bridge.get_profile(profile_id)
        except audit_bridge.AuditBridgeError as exc:
            return None, str(exc)

    device_type = (data.get("device_type") or "cisco_ios").strip()

    inventory_name = ""
    devices_raw = data.get("devices")
    inventory_id = data.get("inventory_id")
    if inventory_id:
        inv = storage.get_inventory(int(inventory_id))
        if not inv:
            return None, "Selected inventory was not found."
        inventory_name = inv["name"]
        inv_data = inv["data"]
        devices_raw = inv_data.get("devices")
        shared_username = data.get("username") or inv_data.get("username") or ""
        shared_password = data.get("password") or inv_data.get("password") or ""
        if isinstance(shared_password, dict) and "_encrypted" in shared_password:
            shared_password = storage.decrypt_text(shared_password["_encrypted"])
    else:
        shared_username = data.get("username") or ""
        shared_password = data.get("password") or ""

    if not isinstance(devices_raw, list) or not devices_raw:
        return None, "At least one device (or a saved inventory) is required."
    if len(devices_raw) > MAX_DEVICES:
        return None, f"Too many devices in one run. Max allowed is {MAX_DEVICES}."

    devices = []
    for i, raw in enumerate(devices_raw, start=1):
        clean, error = validate_device(raw, i)
        if error:
            return None, error
        devices.append(clean)

    workers_raw = data.get("workers", 10)
    try:
        workers = int(workers_raw)
    except (TypeError, ValueError):
        return None, "workers must be a whole number."
    if not (1 <= workers <= MAX_WORKERS_LIMIT):
        return None, f"workers must be between 1 and {MAX_WORKERS_LIMIT}."

    # Ephemeral execution -- see secure_credentials.py. Same reasoning as
    # the automation Run tab: meaningless (and refused) for a schedule,
    # since a schedule needs to reuse its credentials on every future
    # firing. resolve_audit_config() is shared by both the interactive
    # /audit/run route and schedule creation/firing, so the actual
    # refusal lives in api_create_audit_schedule() (checked before this
    # function is even called for that path) rather than here.
    ephemeral = bool(data.get("ephemeral"))

    return {
        "profile_id": profile_id,
        "device_type": device_type,
        "devices": devices,
        "inventory_id": inventory_id,
        "inventory_name": inventory_name,
        "username": shared_username,
        "password": shared_password,
        "workers": workers,
        "ephemeral": ephemeral,
    }, None


def run_audit_and_save(resolved: dict, triggered_by: str = "manual",
                        schedule_id: int = None, schedule_name: str = ""):
    """
    Actually executes an already-resolved audit config (see
    resolve_audit_config()) and persists it to Audit History -- the one
    place both the interactive /audit/run route and the scheduler call
    into, so both paths save history / fire the audit-log event / return
    errors identically.
    """
    job_id = _job_start("audit", f"Audit: {resolved['profile_id']}", len(resolved["devices"]))
    ephemeral = bool(resolved.get("ephemeral"))
    ephemeral_password = secure_credentials.SecureValue(resolved["password"]) if ephemeral else None
    try:
        # audit_bridge.py deliberately has zero knowledge of
        # secure_credentials.SecureValue (it's the one module that only
        # ever imports inventory_collector.* -- see its own docstring),
        # so ephemeral mode is confined to THIS boundary: reveal the
        # plaintext right at the call, then wipe our own copy immediately
        # after the call returns, success or failure.
        report = audit_bridge.run_audit(
            resolved["profile_id"], resolved["devices"], resolved["device_type"],
            shared_username=resolved["username"],
            shared_password=ephemeral_password.reveal() if ephemeral else resolved["password"],
            workers=resolved["workers"],
            progress_cb=lambda done, total: _job_progress(job_id, done, total),
        )
    finally:
        _job_finish(job_id)
        if ephemeral_password is not None:
            ephemeral_password.wipe()
    run_id = storage.save_audit_run(
        report["profile_name"], report, triggered_by=triggered_by,
        inventory_name=resolved.get("inventory_name", ""),
        output_format=report["output_format"], output_path=report.get("output_path") or "",
        schedule_id=schedule_id, schedule_name=schedule_name,
    )
    log_audit("audit_run", profile=report["profile_name"], device_count=len(resolved["devices"]),
              inventory_name=resolved.get("inventory_name", ""), run_id=run_id,
              triggered_by=triggered_by, schedule_id=schedule_id)
    report["run_id"] = run_id
    return report


@app.route("/audit/profiles", methods=["GET"])
def api_list_audit_profiles():
    if not AUDIT_AVAILABLE:
        return _audit_unavailable_response()
    return jsonify({"profiles": audit_bridge.list_profiles(),
                     "textfsm_available": is_textfsm_installed() if AUDIT_AVAILABLE else False})


@app.route("/audit/run", methods=["POST"])
def api_run_audit():
    """
    Runs one audit profile against a device list supplied inline (same
    shape the Run tab already uses: [{host, port, [username], [password]}])
    or resolved from a saved Inventory id, and returns the FULL structured
    report as JSON (not streamed -- audit runs are read-only / bounded and
    typically fast enough that a single response is simpler for both the
    UI and history storage than reusing the Run tab's line-streaming
    protocol). The report is also saved to Audit History (audit_runs
    table) exactly like an automation Run is saved to History.
    """
    if not AUDIT_AVAILABLE:
        return _audit_unavailable_response()

    try:
        data = request.get_json(force=True, silent=True)
    except Exception:
        data = None

    resolved, error = resolve_audit_config(data)
    if error:
        return jsonify({"error": error}), 400

    try:
        report = run_audit_and_save(resolved, triggered_by="manual")
    except audit_bridge.AuditBridgeError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        log.exception("Audit run failed unexpectedly for profile '%s'", resolved.get("profile_id"))
        return jsonify({"error": f"Audit run failed: {exc}"}), 500

    return jsonify(report)


@app.route("/audit/history", methods=["GET"])
def api_list_audit_history():
    limit = request.args.get("limit", 50)
    try:
        limit = max(1, min(int(limit), 200))
    except (TypeError, ValueError):
        limit = 50
    return jsonify({"runs": storage.list_audit_runs(limit=limit)})


@app.route("/audit/history/<int:run_id>", methods=["GET"])
def api_get_audit_history(run_id):
    run = storage.get_audit_run(run_id)
    if not run:
        return jsonify({"error": "Audit run not found."}), 404

    return jsonify(run)


@app.route("/audit/history/<int:run_id>", methods=["DELETE"])
def api_delete_audit_history(run_id):
    ok = storage.delete_audit_run(run_id)
    if not ok:
        return jsonify({"error": "Audit run not found."}), 404
    return jsonify({"status": "deleted"})


@app.route("/audit/history", methods=["DELETE"])
def api_delete_all_audit_history():
    count = storage.delete_all_audit_runs()
    return jsonify({"status": "deleted", "count": count})


@app.route("/audit/history/<int:run_id>/download", methods=["GET"])
def api_download_audit_report(run_id):
    """
    Generates the downloadable report file ON DEMAND, in memory, from
    the run's stored report_json -- no ./reports/ file is read from or
    written to disk. See audit_bridge.render_report_bytes() and the
    "On-Demand Report Generation Over Disk Writing" note in
    storage.py's save_audit_run(): the JSON payload already persisted in
    automation_console.db is the durable source of truth for a
    completed run, not a same-moment CSV/XLSX/JSON snapshot on disk that
    would otherwise accumulate indefinitely across scheduled runs.
    """
    if not AUDIT_AVAILABLE:
        return _audit_unavailable_response()
    run = storage.get_audit_run(run_id)
    if not run:
        return jsonify({"error": "Audit run not found."}), 404
    try:
        data, mimetype, filename = audit_bridge.render_report_bytes(run["report"])
    except Exception as exc:
        log.exception("Failed to generate on-demand report for audit run #%s", run_id)
        return jsonify({"error": f"Could not generate the report file: {exc}"}), 500
    return send_file(
        io.BytesIO(data), mimetype=mimetype, as_attachment=True, download_name=filename,
    )


@app.route("/audit/history/diff", methods=["GET"])
def api_diff_audit_runs():
    """
    Historical comparison between two completed audit runs (e.g.
    hardware_audit from last week vs. today) -- highlights added/removed
    devices and, for devices present in both runs, exactly which columns
    changed (e.g. a serial number swap, an IOS version upgrade, a new
    interface appearing). See audit_bridge.diff_audit_runs().
    Query params: old_run_id, new_run_id (both required).
    """
    if not AUDIT_AVAILABLE:
        return _audit_unavailable_response()

    old_run_id = request.args.get("old_run_id")
    new_run_id = request.args.get("new_run_id")
    if not old_run_id or not new_run_id:
        return jsonify({"error": "Both old_run_id and new_run_id are required."}), 400
    try:
        old_run_id = int(old_run_id)
        new_run_id = int(new_run_id)
    except ValueError:
        return jsonify({"error": "old_run_id and new_run_id must be integers."}), 400

    old_run = storage.get_audit_run(old_run_id)
    new_run = storage.get_audit_run(new_run_id)
    if not old_run:
        return jsonify({"error": f"Audit run #{old_run_id} not found."}), 404
    if not new_run:
        return jsonify({"error": f"Audit run #{new_run_id} not found."}), 404

    if old_run["report"].get("mode") == "table" or new_run["report"].get("mode") == "table":
        return jsonify({
            "error": "Table-mode reports (e.g. interface_inventory) don't have a stable "
                     "per-row identity across runs and can't be diffed this way."
        }), 400

    diff = audit_bridge.diff_audit_runs(old_run["report"], new_run["report"])
    diff["old_run_id"] = old_run_id
    diff["new_run_id"] = new_run_id
    return jsonify(diff)


@app.route("/activity/recent", methods=["GET"])
def api_recent_activity():
    """Unified automation+audit activity feed backing the Overview
    dashboard's Recent Activity list (see storage.list_unified_activity)."""
    limit = request.args.get("limit", 20)
    try:
        limit = max(1, min(int(limit), 100))
    except (TypeError, ValueError):
        limit = 20
    return jsonify({"activity": storage.list_unified_activity(limit=limit)})


@app.route("/activity/current", methods=["GET"])
def api_current_activity():
    """Backs the persistent global run indicator (Phase 6, "no context
    loss" mechanism #3) -- polled every few seconds regardless of which
    tab is active, so a long-running job stays visible everywhere."""
    return jsonify({"jobs": list_current_jobs()})


@app.route("/overview/summary", methods=["GET"])
def api_overview_summary():
    """
    Everything the Overview dashboard needs in one call: at-a-glance
    stats, the merged 14-day trend, and Health & Compliance Snapshot
    findings derived from the latest security_audit/capacity_audit runs
    (whichever of those two profiles has actually been run at least
    once -- both are optional, findings degrade gracefully to an empty
    list if neither has run yet).
    """
    summary = storage.get_dashboard_summary()
    trend = storage.get_unified_trend(days=14)

    findings = []
    if AUDIT_AVAILABLE:
        security_runs = storage.list_audit_runs(limit=50, profile_name="security_audit")
        capacity_runs = storage.list_audit_runs(limit=50, profile_name="capacity_audit")
        security_report = storage.get_audit_run(security_runs[0]["id"])["report"] if security_runs else None
        capacity_report = storage.get_audit_run(capacity_runs[0]["id"])["report"] if capacity_runs else None
        if security_report or capacity_report:
            try:
                findings = audit_bridge.derive_compliance_findings(security_report, capacity_report)
            except Exception:  # pragma: no cover - dashboard widget must never break the whole page
                findings = []

    return jsonify({
        "summary": summary,
        "trend": trend,
        "compliance_findings": findings,
    })


# ==========================================================================
# Background scheduler
# ==========================================================================
def _consume_stream_and_get_report(generator):
    """
    Drains a generator without caring about its intermediate log lines,
    but captures the structured JSON report block it emits at the end --
    used to run a scheduled job in the background (nothing is watching it
    live) while still letting the scheduler inspect pass/fail afterwards.
    Returns the parsed report dict, or None if it couldn't be extracted.
    """
    full_text = ""
    for chunk in generator:
        full_text += chunk
    start_idx = full_text.find(STRUCTURED_START_MARKER)
    end_idx = full_text.find(STRUCTURED_END_MARKER)
    if start_idx == -1 or end_idx == -1:
        return None
    try:
        return json.loads(full_text[start_idx + len(STRUCTURED_START_MARKER):end_idx].strip())
    except Exception:
        return None


def _fire_automation_schedule(sched: dict) -> tuple:
    """Runs one due 'automation' schedule. Returns (status, failed_device_labels)."""
    decrypted_config = _decrypt_schedule_secrets(sched["config"])
    cleaned, error = validate_payload(decrypted_config, allow_config_mode=False)
    if error:
        log.error("[SCHEDULER] Schedule '%s' (id=%s) has an invalid saved config, "
                  "skipping this run: %s", sched['name'], sched['id'], error)
        log_audit("schedule_skipped", schedule_id=sched["id"], schedule_name=sched["name"], error=error)
        return "error", ""

    # Worker pool isolation (see SCHEDULED_MAX_WORKERS_LIMIT docstring
    # above): cap a scheduled run's concurrency well below what an
    # interactive run is allowed, regardless of what the saved config
    # itself requests, so a big unattended job can't starve an
    # interactive user's SSH worker threads at the same moment.
    if cleaned["max_workers"] > SCHEDULED_MAX_WORKERS_LIMIT:
        log.info("[SCHEDULER] Capping schedule '%s' (id=%s) from %d to %d worker(s) "
                  "(scheduled jobs are capped below interactive runs -- see "
                  "SCHEDULED_MAX_WORKERS_LIMIT).", sched['name'], sched['id'],
                  cleaned["max_workers"], SCHEDULED_MAX_WORKERS_LIMIT)
        cleaned["max_workers"] = SCHEDULED_MAX_WORKERS_LIMIT

    log.info("[SCHEDULER] Running schedule '%s' (id=%s)...", sched['name'], sched['id'])
    log_audit("schedule_run_started", schedule_id=sched["id"], schedule_name=sched["name"],
              device_count=len(cleaned.get("devices", [])), backup_configs=cleaned.get("backup_configs", False))
    run_uuid = uuid.uuid4().hex
    status = "ok"
    failed_device_labels = ""
    try:
        report = _consume_stream_and_get_report(stream_multi_device(
            cleaned, run_uuid, triggered_by="schedule",
            label=f"Scheduled: {sched['name']}",
        ))
        if report:
            failed_devices = [
                f"{d['host']}:{d['port']}" for d in report.get("devices", [])
                if d.get("ping") == "FAILED" or d.get("tcp_port") == "FAILED"
                or str(d.get("ssh", "")).startswith("FAILED")
            ]
            if failed_devices:
                status = "failed"
                failed_device_labels = ", ".join(failed_devices)
                log.warning("[SCHEDULER] Schedule '%s' had failures on: %s",
                            sched['name'], failed_device_labels)
                if sched.get("notify_on_failure"):
                    try:
                        maybe_send_alerts(
                            subject=f"Scheduled run failed: {sched['name']}",
                            text=alerts.build_failure_alert_text(sched['name'], failed_devices),
                        )
                    except Exception as alert_exc:
                        log.warning("[SCHEDULER] Failed to send failure alert for '%s': %s",
                                    sched['name'], alert_exc)
            else:
                log.info("[SCHEDULER] Schedule '%s' completed successfully.", sched['name'])
    except Exception as exc:  # pragma: no cover - defensive
        log.exception("[SCHEDULER] Schedule '%s' run failed with an exception.", sched['name'])
        status = "error"
    log_audit("schedule_run_finished", schedule_id=sched["id"], schedule_name=sched["name"],
              status=status, failed_devices=failed_device_labels)
    return status, failed_device_labels


def _fire_audit_schedule(sched: dict) -> tuple:
    """
    Runs one due 'audit' schedule. Returns (status, failed_device_labels)
    with the same shape _fire_automation_schedule() returns, so the
    shared bookkeeping in _scheduler_loop() (updating next_run_at,
    run_count, last_status) doesn't need to know which job type just ran.
    "Failed" here means AUTH_FAILED/UNREACHABLE/ERROR rows, not a config
    push failure (there is no such thing for a read-only audit).
    """
    if not AUDIT_AVAILABLE:
        log.error("[SCHEDULER] Audit schedule '%s' (id=%s) skipped: Audit feature unavailable.",
                  sched['name'], sched['id'])
        log_audit("schedule_skipped", schedule_id=sched["id"], schedule_name=sched["name"],
                  error="Audit feature unavailable")
        return "error", ""

    decrypted_config = _decrypt_schedule_secrets(sched["config"])
    resolved, error = resolve_audit_config(decrypted_config)
    if error:
        log.error("[SCHEDULER] Audit schedule '%s' (id=%s) has an invalid saved config, "
                  "skipping this run: %s", sched['name'], sched['id'], error)
        log_audit("schedule_skipped", schedule_id=sched["id"], schedule_name=sched["name"], error=error)
        return "error", ""

    # Worker pool isolation -- see SCHEDULED_MAX_WORKERS_LIMIT docstring.
    # A large scheduled audit (e.g. 50 devices with TextFSM table
    # parsing) is exactly the "intensive scheduled job" scenario this
    # cap exists for.
    if resolved["workers"] > SCHEDULED_MAX_WORKERS_LIMIT:
        log.info("[SCHEDULER] Capping audit schedule '%s' (id=%s) from %d to %d worker(s) "
                  "(scheduled jobs are capped below interactive runs).",
                  sched['name'], sched['id'], resolved["workers"], SCHEDULED_MAX_WORKERS_LIMIT)
        resolved["workers"] = SCHEDULED_MAX_WORKERS_LIMIT

    log.info("[SCHEDULER] Running audit schedule '%s' (id=%s, profile=%s)...",
              sched['name'], sched['id'], resolved['profile_id'])
    log_audit("schedule_run_started", schedule_id=sched["id"], schedule_name=sched["name"],
              device_count=len(resolved.get("devices", [])), profile_id=resolved.get("profile_id"))
    status = "ok"
    failed_device_labels = ""
    try:
        report = run_audit_and_save(resolved, triggered_by="schedule",
                                     schedule_id=sched["id"], schedule_name=sched["name"])
        issue_rows = [r for r in report.get("rows", []) if r.get("STATUS") not in (None, "OK")]
        if issue_rows:
            status = "failed"
            failed_device_labels = ", ".join(f"{r.get('TARGET_IP')} ({r.get('STATUS')})" for r in issue_rows)
            log.warning("[SCHEDULER] Audit schedule '%s' had issues on: %s", sched['name'], failed_device_labels)
            if sched.get("notify_on_failure"):
                try:
                    maybe_send_alerts(
                        subject=f"Scheduled audit had issues: {sched['name']}",
                        text=alerts.build_failure_alert_text(sched['name'],
                             [r.get('TARGET_IP', '?') for r in issue_rows]),
                    )
                except Exception as alert_exc:
                    log.warning("[SCHEDULER] Failed to send failure alert for audit schedule '%s': %s",
                                sched['name'], alert_exc)
        else:
            log.info("[SCHEDULER] Audit schedule '%s' completed successfully (%d row(s)).",
                      sched['name'], len(report.get("rows", [])))
    except audit_bridge.AuditBridgeError as exc:
        log.error("[SCHEDULER] Audit schedule '%s' failed: %s", sched['name'], exc)
        status = "error"
    except Exception as exc:  # pragma: no cover - defensive
        log.exception("[SCHEDULER] Audit schedule '%s' run failed with an exception.", sched['name'])
        status = "error"
    log_audit("schedule_run_finished", schedule_id=sched["id"], schedule_name=sched["name"],
              status=status, failed_devices=failed_device_labels)
    return status, failed_device_labels


def _scheduler_loop():
    log.info("[SCHEDULER] Background scheduler thread started (checks every %ss for due jobs, "
              "max %d concurrent scheduled job(s), capped at %d worker(s) each).",
              SCHEDULER_POLL_SECONDS, MAX_CONCURRENT_SCHEDULED_JOBS, SCHEDULED_MAX_WORKERS_LIMIT)
    while True:
        try:
            due = storage.get_due_schedules()
            for sched in due:
                now = datetime.now(timezone.utc)
                next_run = (now + timedelta(minutes=sched["interval_minutes"])).isoformat(timespec="seconds")

                # Worker pool isolation, part 2: only MAX_CONCURRENT_SCHEDULED_JOBS
                # scheduled jobs (across both job types) are allowed to
                # actually be executing at once. The scheduler loop is
                # currently a simple serial for-loop (so this is already
                # naturally true today), but acquiring an explicit
                # semaphore here makes that a real enforced invariant --
                # documented and guaranteed -- rather than an accidental
                # side effect of the loop's current structure that a
                # future change (e.g. firing schedules from a thread
                # pool for better throughput) could silently break.
                _scheduled_job_slot.acquire()
                try:
                    if sched.get("job_type") == "audit":
                        status, failed_device_labels = _fire_audit_schedule(sched)
                    else:
                        status, failed_device_labels = _fire_automation_schedule(sched)
                finally:
                    _scheduled_job_slot.release()

                storage.update_schedule_run_times(
                    sched["id"], now.isoformat(timespec="seconds"), next_run,
                    status=status, failed_devices=failed_device_labels,
                )
        except Exception as exc:  # pragma: no cover - keep the loop alive no matter what
            log.exception("[SCHEDULER] Unexpected error in scheduler loop.")
        time.sleep(SCHEDULER_POLL_SECONDS)


def start_scheduler_thread():
    thread = threading.Thread(target=_scheduler_loop, daemon=True)
    thread.start()


if __name__ == "__main__":
    print("=" * 60)
    print(" Network Automation Web Console (multi-device + AI)")
    print(" Open your browser at: http://localhost:5000")
    print(f" paramiko available: {PARAMIKO_AVAILABLE}")
    print(f" netmiko available:  {NETMIKO_AVAILABLE}")
    print(f" encryption available: {ENCRYPTION_AVAILABLE}")
    print("=" * 60)
    # debug=False is intentional: Flask's debug mode enables the Werkzeug
    # interactive debugger, which allows arbitrary code execution from the
    # browser if an unhandled exception is ever triggered. Since this app
    # binds to 0.0.0.0 (reachable by other devices on your network, not
    # just this machine), leaving debug mode on would expose that risk to
    # your whole LAN. If you're actively developing the app and want Flask's
    # auto-reload-on-save behavior, set FLASK_DEBUG=1 in your own shell
    # before running this script -- just remember to unset it afterwards.
    debug_mode = os.environ.get("FLASK_DEBUG") == "1"

    # Guard against starting the scheduler thread twice: when debug_mode
    # is on, Flask's reloader spawns a second child process and re-runs
    # this whole file, which would otherwise double the scheduler thread.
    if not debug_mode or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        start_scheduler_thread()

    app.run(host="0.0.0.0", port=5000, debug=debug_mode, threaded=True, use_reloader=debug_mode)
