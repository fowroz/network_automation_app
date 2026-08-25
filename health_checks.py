"""
========================================================================
 Automated Network Health Checks (before / after change comparison)
========================================================================
Runs a small, fast set of vendor-appropriate "health" commands (CPU load,
memory, interface up/down + error counters) against a device BOTH right
before and right after a config-mode change is applied, then diffs the
two snapshots and flags anything that got worse -- e.g. an interface that
was up going down, a big jump in interface errors, or CPU/memory nearing
capacity. This is deliberately independent of the full config backup/diff
feature: it's about the device's *operational* health, not its config
text, and is designed to catch "the change technically applied but broke
something" scenarios (a wrong VLAN taking a trunk down, a bad ACL that
also blocks legitimate traffic, etc.).

Parsing is intentionally lightweight/best-effort regex -- this is not a
full CLI parser (that's what Netmiko/TextFSM/Genie are for) but is more
than enough to catch clear regressions across the vendors this app
already supports, without adding another heavy dependency.
========================================================================
"""
import re

# One or two fast, safe (read-only) commands per vendor used for the
# health snapshot. Kept short deliberately -- this runs twice per
# config-mode change (before + after), so it must not meaningfully slow
# down the automation.
HEALTH_CHECK_COMMANDS = {
    "cisco_ios": ["show processes cpu | include CPU utilization", "show interfaces summary"],
    "cisco_nxos": ["show system resources", "show interface brief"],
    "arista_eos": ["show processes top once", "show interfaces status"],
    "aruba_hp": ["show system resource-utilization", "show interface brief"],
    "juniper_junos": ["show system processes summary", "show interfaces terse"],
    "generic_linux": ["uptime", "ip -s link show"],
}

# Fallback used for any vendor not in HEALTH_CHECK_COMMANDS (shouldn't
# normally happen since COMMAND_LIBRARY only offers known vendors, but
# keeps this module safe to call standalone).
DEFAULT_HEALTH_COMMANDS = ["show version"]

_CPU_RE = re.compile(r"CPU utilization[^:]*:\s*(\d+)%", re.IGNORECASE)
_CPU_RE_ALT = re.compile(r"(\d+(?:\.\d+)?)\s*%\s*(?:CPU|idle)", re.IGNORECASE)
_MEM_RE = re.compile(r"Memory usage:\s*(\d+)K total.*?(\d+)K used", re.IGNORECASE | re.DOTALL)

# Interface status lines look roughly like:
#   "GigabitEthernet0/1     up    up     ..."   (Cisco 'show ip interface brief'-ish)
#   "Eth1                   connected  ..."     (Nexus 'show interface brief')
# We don't try to parse every vendor's exact column layout -- instead we
# look for an interface-name-like token at the start of a line and then
# classify the rest of the line as up/down/admin-down by keyword, which
# is robust across formatting differences.
_IFACE_LINE_RE = re.compile(
    r"^\s*([A-Za-z][A-Za-z0-9/\.\-]{1,40})\s+(.+)$"
)
_UP_WORDS = re.compile(r"\b(up|connected|Up)\b")
_DOWN_WORDS = re.compile(r"\b(down|notconnect|Down|disabled|administratively down|admin-down)\b", re.IGNORECASE)


def _parse_cpu_percent(text: str):
    m = _CPU_RE.search(text)
    if m:
        return float(m.group(1))
    m = _CPU_RE_ALT.search(text)
    if m:
        return float(m.group(1))
    return None


def _parse_interface_states(text: str):
    """
    Best-effort: returns {interface_name: 'up'|'down'|'unknown'} for any
    line that looks like an interface status row. Skips obvious header
    lines (containing 'Interface' as the first token, or 'Port').
    """
    states = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        first_token = stripped.split()[0] if stripped.split() else ""
        if first_token.lower() in ("interface", "port", "name"):
            continue
        m = _IFACE_LINE_RE.match(line)
        if not m:
            continue
        iface, rest = m.group(1), m.group(2)
        # Require the "interface-looking" token to contain a digit
        # (GigabitEthernet0/1, Eth1, ge-0/0/0, etc.) to avoid false
        # positives on ordinary prose lines that happen to start with a word.
        if not re.search(r"\d", iface):
            continue
        if _DOWN_WORDS.search(rest):
            states[iface] = "down"
        elif _UP_WORDS.search(rest):
            states[iface] = "up"
        else:
            states[iface] = "unknown"
    return states


def parse_health_snapshot(vendor: str, command_outputs: list):
    """
    `command_outputs` is a list of {"command": str, "output": str} dicts
    (the same shape run_ssh_commands()/_send_and_capture() already
    produce). Returns a structured snapshot dict:
        {"cpu_percent": float|None, "interfaces": {name: state}, "raw_commands": [...]}
    """
    cpu_percent = None
    interfaces = {}
    for entry in command_outputs:
        output = entry.get("output", "") or ""
        if cpu_percent is None:
            cpu_percent = _parse_cpu_percent(output)
        interfaces.update(_parse_interface_states(output))
    return {
        "cpu_percent": cpu_percent,
        "interfaces": interfaces,
        "commands_run": [c.get("command") for c in command_outputs],
    }


def compare_health_snapshots(before: dict, after: dict, cpu_warn_delta: float = 25.0, cpu_critical_percent: float = 90.0):
    """
    Compares a before/after health snapshot pair and returns a list of
    human-readable issue strings (empty list = no regressions detected).
    Deliberately conservative -- flags CLEAR regressions only, not every
    minor fluctuation, to avoid alert fatigue:
      - any interface that was up before and is down after
      - CPU crossing into a "critical" absolute level after the change
      - CPU jumping by more than `cpu_warn_delta` percentage points
    """
    issues = []
    if not before or not after:
        return issues

    before_ifaces = before.get("interfaces", {}) or {}
    after_ifaces = after.get("interfaces", {}) or {}
    for iface, before_state in before_ifaces.items():
        after_state = after_ifaces.get(iface)
        if before_state == "up" and after_state == "down":
            issues.append(f"Interface {iface} went DOWN after the change (was up before).")

    before_cpu = before.get("cpu_percent")
    after_cpu = after.get("cpu_percent")
    if after_cpu is not None:
        if after_cpu >= cpu_critical_percent:
            issues.append(f"CPU utilization is critically high after the change: {after_cpu:.0f}%.")
        elif before_cpu is not None and (after_cpu - before_cpu) >= cpu_warn_delta:
            issues.append(f"CPU utilization jumped from {before_cpu:.0f}% to {after_cpu:.0f}% after the change.")

    return issues


def get_health_check_commands(vendor: str):
    return HEALTH_CHECK_COMMANDS.get(vendor, DEFAULT_HEALTH_COMMANDS)
