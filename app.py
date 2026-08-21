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

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

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

import storage  # local module, see storage.py -- SQLite persistence + optional encryption

storage.init_db()
ENCRYPTION_AVAILABLE = storage.init_encryption(ensure_package)

# Force all print() calls to flush immediately. Without this, output from
# the background scheduler thread (which prints status on every scheduled
# run) can sit in Python's stdout buffer and not appear in your terminal
# for a long time, making it look like the scheduler isn't doing anything.
print = functools.partial(print, flush=True)

app = Flask(__name__)

# --------------------------------------------------------------------------
# Basic safety limits -- keep the tool well-behaved instead of open-ended.
# --------------------------------------------------------------------------
MAX_DEVICES = 25
MAX_COMMANDS = 60
MAX_COMMAND_LENGTH = 500
CONNECT_TIMEOUT_MIN = 1
CONNECT_TIMEOUT_MAX = 60
MAX_WORKERS_LIMIT = 10
MIN_SCHEDULE_INTERVAL_MINUTES = 5
MAX_SCHEDULE_INTERVAL_MINUTES = 60 * 24 * 7  # 1 week
SCHEDULER_POLL_SECONDS = 20

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
            ],
            "Interfaces": [
                "show ip interface brief", "show interfaces", "show interfaces status",
                "show interfaces description", "show interfaces counters errors",
                "show interfaces counters", "show interfaces summary", "show interfaces trunk",
                "show interfaces switchport", "show ip interface", "show ipv6 interface brief",
                "show cdp neighbors detail", "show cdp neighbors", "show lldp neighbors detail",
                "show lldp neighbors", "show controllers", "show interfaces transceiver",
            ],
            "Routing": [
                "show ip route", "show ip route summary", "show ip protocols",
                "show ip ospf neighbor", "show ip ospf database", "show ip ospf interface",
                "show ip bgp summary", "show ip bgp", "show ip bgp neighbors",
                "show ip eigrp neighbors", "show ip arp", "show ip arp inspection",
                "show ipv6 route", "show ipv6 protocols", "traceroute", "ping",
                "show ip nat translations", "show ip nat statistics",
            ],
            "VLAN / Switching": [
                "show vlan brief", "show vlan", "show spanning-tree", "show spanning-tree summary",
                "show spanning-tree detail", "show mac address-table", "show mac address-table dynamic",
                "show etherchannel summary", "show etherchannel detail",
                "show interfaces trunk", "show port-security", "show port-security address",
            ],
            "Security / ACLs": [
                "show ip access-lists", "show access-lists", "show crypto isakmp sa",
                "show crypto ipsec sa", "show crypto session", "show aaa sessions",
                "show users", "show privilege", "show ip ssh", "show line",
                "show dot1x all", "show authentication sessions",
            ],
            "Diagnostics / Troubleshooting": [
                "show logging", "show logging | include", "show tech-support",
                "show tech-support | redirect", "show debugging", "show processes cpu sorted",
                "show interfaces | include error", "show ip interface brief | exclude unassigned",
                "traceroute", "ping repeat 100", "debug ip packet",
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

    parallel = bool(data.get("parallel"))
    max_workers_raw = data.get("max_workers", 5)
    try:
        max_workers = int(max_workers_raw)
    except (TypeError, ValueError):
        return None, "Max concurrent workers must be a whole number."
    if not (1 <= max_workers <= MAX_WORKERS_LIMIT):
        return None, f"Max concurrent workers must be between 1 and {MAX_WORKERS_LIMIT}."

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
        "parallel": parallel,
        "max_workers": max_workers,
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
SHELL_IDLE_GAP = 0.5          # seconds of silence that means "command finished"
SHELL_MAX_WAIT_MULTIPLIER = 3  # multiply the user's timeout for slow commands

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


def _read_until_idle(shell, timeout, idle_gap=SHELL_IDLE_GAP):
    """
    Reads from an interactive shell channel until no new data has arrived
    for `idle_gap` seconds (i.e. the device has gone quiet, which -- for
    an interactive CLI -- means it's done responding and is back at a
    prompt) or the overall `timeout` is reached. Returns the decoded text
    read so far either way, so a slow/hanging command still surfaces
    whatever partial output the device sent instead of losing it.
    """
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
            if buf and (now - last_data_time) > idle_gap:
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
                      cancel_event=None, show_diff=False, dry_run=False, diff_result=None):
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
def run_device_checks(device, shared, idx, total, results, lock, cancel_event=None):
    """
    Generator that runs ping + port check + optional SSH commands for a
    SINGLE device, yielding tagged output lines like '[host:port] ...'.
    Appends a rich result summary dict (including per-command output) to
    `results` (thread-safe via `lock`) once finished, success or failure.
    If `cancel_event` is already set when this device's turn comes up
    (sequential mode), the device is skipped entirely and marked SKIPPED.
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
        effective_username = device.get("username") or shared["username"]
        effective_password = device.get("password") or shared["password"]
        using_device_creds = bool(device.get("username") or device.get("password"))

        if shared["run_ssh"]:
            if not PARAMIKO_AVAILABLE:
                yield tag("[WARN] 'paramiko' is not available; SSH step skipped.\n")
                ssh_status = "SKIPPED (no paramiko)"
            elif not shared["commands"]:
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
                    private_key_text=shared.get("private_key_text"),
                    private_key_passphrase=shared.get("private_key_passphrase"),
                    jump_host=shared.get("jump_host"),
                    jump_port=shared.get("jump_port", 22),
                    jump_username=shared.get("jump_username"),
                    jump_password=shared.get("jump_password"),
                    jump_private_key_text=shared.get("jump_private_key_text"),
                    jump_private_key_passphrase=shared.get("jump_private_key_passphrase"),
                    cancel_event=cancel_event,
                    show_diff=shared.get("show_diff", False),
                    dry_run=shared.get("dry_run", False),
                    diff_result=diff_result,
                ):
                    if "[ERROR]" in line:
                        had_error = True
                    yield tag(line)
                ssh_status = "FAILED" if had_error else "OK"
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
    lines.append(
        f"TOTALS: {len(ordered)} device(s) | {total_devices_ok} fully OK | "
        f"{total_cmds_ok} command(s) succeeded | {total_cmds_failed} command(s) failed"
    )
    lines.append("=" * width)
    return "\n".join(lines) + "\n"


def _run_sequential(devices, shared, results, lock, total, cancel_event=None):
    for idx, device in enumerate(devices, start=1):
        if cancel_event is not None and cancel_event.is_set():
            yield f"[WARN] Run cancelled -- skipping remaining {total - idx + 1} device(s).\n"
            break
        yield from run_device_checks(device, shared, idx, total, results, lock, cancel_event=cancel_event)


def _run_parallel(devices, shared, results, lock, total, cancel_event=None):
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
            for line in run_device_checks(device, shared, idx, total, results, lock, cancel_event=cancel_event):
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

    try:
        yield f"{RUN_ID_MARKER}{run_uuid}\n"
        yield f"[INFO] Starting automation for {total} device(s).\n"
        mode_desc = (
            f"PARALLEL (up to {min(payload['max_workers'], total)} at a time)"
            if payload["parallel"] and total > 1
            else "SEQUENTIAL"
        )
        yield f"[INFO] Execution mode: {mode_desc}\n"
        yield "=" * 70 + "\n\n"

        if payload["parallel"] and total > 1:
            yield from _run_parallel(devices, payload, results, lock, total, cancel_event=cancel_event)
        else:
            yield from _run_sequential(devices, payload, results, lock, total, cancel_event=cancel_event)

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
        yield f"\n{STRUCTURED_START_MARKER}\n"
        yield json.dumps(structured)
        yield f"\n{STRUCTURED_END_MARKER}\n"


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
    """Replaces encrypted secret blobs with a boolean flag before sending
    a schedule back to the browser -- the UI never needs the actual
    encrypted bytes, only whether a credential is set."""
    masked = dict(sched)
    config = dict(masked.get("config") or {})
    for secret_field in ("password", "private_key_text", "private_key_passphrase",
                          "jump_password", "jump_private_key_text", "jump_private_key_passphrase"):
        value = config.get(secret_field)
        if isinstance(value, dict) and "_encrypted" in value:
            config[secret_field] = None
            config[f"{secret_field}_set"] = True
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

    stored_config = dict(config)
    for secret_field in ("password", "private_key_text", "private_key_passphrase",
                          "jump_password", "jump_private_key_text", "jump_private_key_passphrase"):
        value = stored_config.get(secret_field)
        if value:
            stored_config[secret_field] = {"_encrypted": storage.encrypt_text(value)}

    notify_on_failure = bool(data.get("notify_on_failure"))
    result = storage.create_schedule(name, interval_minutes, stored_config, notify_on_failure=notify_on_failure)
    return jsonify(result)


def _decrypt_schedule_secrets(config: dict) -> dict:
    """Reverses the encryption applied in api_create_schedule() before the
    config is actually used to run SSH commands."""
    decrypted = dict(config)
    for secret_field in ("password", "private_key_text", "private_key_passphrase",
                          "jump_password", "jump_private_key_text", "jump_private_key_passphrase"):
        value = decrypted.get(secret_field)
        if isinstance(value, dict) and "_encrypted" in value:
            decrypted[secret_field] = storage.decrypt_text(value["_encrypted"])
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
    Manually triggers a schedule's saved config immediately (still subject
    to the same read-only restriction as automatic runs), streaming output
    exactly like a normal /run-script call.
    """
    sched = storage.get_schedule(sched_id)
    if not sched:
        return jsonify({"error": "Schedule not found."}), 404

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
    return jsonify({"runs": storage.get_schedule_run_history(sched["name"], limit=limit)})


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


def _scheduler_loop():
    print("[SCHEDULER] Background scheduler thread started "
          f"(checks every {SCHEDULER_POLL_SECONDS}s for due jobs).")
    while True:
        try:
            due = storage.get_due_schedules()
            for sched in due:
                decrypted_config = _decrypt_schedule_secrets(sched["config"])
                cleaned, error = validate_payload(decrypted_config, allow_config_mode=False)
                now = datetime.now(timezone.utc)
                next_run = (now + timedelta(minutes=sched["interval_minutes"])).isoformat(timespec="seconds")
                if error:
                    print(f"[SCHEDULER] Schedule '{sched['name']}' (id={sched['id']}) has an "
                          f"invalid saved config, skipping this run: {error}")
                    storage.update_schedule_run_times(
                        sched["id"], now.isoformat(timespec="seconds"), next_run,
                        status="error", failed_devices="",
                    )
                    continue

                print(f"[SCHEDULER] Running schedule '{sched['name']}' (id={sched['id']})...")
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
                            if sched.get("notify_on_failure"):
                                print(f"[SCHEDULER] ⚠ ALERT: Schedule '{sched['name']}' had failures "
                                      f"on: {failed_device_labels}")
                except Exception as exc:  # pragma: no cover - defensive
                    print(f"[SCHEDULER] Schedule '{sched['name']}' run failed: {exc}")
                    status = "error"
                storage.update_schedule_run_times(
                    sched["id"], now.isoformat(timespec="seconds"), next_run,
                    status=status, failed_devices=failed_device_labels,
                )
        except Exception as exc:  # pragma: no cover - keep the loop alive no matter what
            print(f"[SCHEDULER] Unexpected error in scheduler loop: {exc}")
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
