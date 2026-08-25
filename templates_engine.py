"""
========================================================================
 Dynamic configuration generation (Jinja2 templates)
========================================================================
Turns a small set of structured inputs (a VLAN id/name, a list of
interfaces + descriptions, or a fully custom Jinja2 template + JSON/YAML
context) into the actual CLI command lines to push to a device -- so
"create VLAN 50 named Guests on 20 switches" is one form, not fifty
copy-pasted command blocks.

Rendered output is always just a block of text (one command per line,
exactly like the manual "Commands" box elsewhere in the app) -- nothing
here talks to a device directly. The caller pastes/pipes the rendered
result into the normal SSH execution path, so it gets the exact same
validation, config-mode confirmation, diff, health check, and rollback-
snapshot safety net as any other command.

BUILT-IN TEMPLATE LIBRARY
--------------------------
A set of common, parameterized templates per vendor family are bundled
below (VLAN creation, bulk interface config, static routes, banner,
local user accounts, NTP). Each template declares the variables it
needs (name, label, type, default, validation rules) so the frontend
can render a plain form instead of asking the user to hand-write
Jinja2. Templates carry metadata (version, risk level, category, tags,
required privilege) for auditability, and most ship an auto-generated
"rollback" counterpart and a small set of self-test cases (see
run_template_tests()).

Custom templates (arbitrary Jinja2 text + a JSON context blob) are also
supported for anything not covered by the built-ins, and can optionally
be SAVED under a name (see storage.save_user_template) so they show up
alongside the built-in library on future visits.
========================================================================
"""
import ipaddress
import re
import threading

import redaction  # local module -- shared secret-pattern redaction, see redaction.py

try:
    import jinja2
    from jinja2 import StrictUndefined, meta
    from jinja2.sandbox import SandboxedEnvironment
    JINJA2_AVAILABLE = True
except ImportError:  # pragma: no cover - guarded by ensure_package() in app.py
    JINJA2_AVAILABLE = False


MAX_TEMPLATE_LENGTH = 20000
MAX_RENDERED_LENGTH = 100000

# A template that loops more than this many times total (across every
# {% for %} in the template) is almost certainly a mistake (a fat-fingered
# range() bound) or a deliberate loop-bomb -- capped generously above any
# legitimate use case in this app (the largest realistic input is a few
# hundred VLANs/interfaces/routes pasted into a textarea).
MAX_LOOP_ITERATIONS = 20000

# Wall-clock cap on a single render call, enforced via a dedicated daemon
# thread PER RENDER (not a bounded thread pool -- see below) that the
# caller stops waiting on after RENDER_TIMEOUT_SECONDS: this app's Flask
# server runs with threaded=True, and signal.alarm() only works when
# called from the interpreter's main thread -- calling it from a
# request-handling worker thread raises ValueError. A thread-based
# timeout works from any calling thread.
#
# IMPORTANT: this is a "stop waiting" timeout, not a true kill. If the
# runaway render is a pure CPU loop (no I/O), the background thread keeps
# consuming CPU until it finishes on its own -- Python has no supported
# way to forcibly kill another thread. Using a small FIXED-SIZE thread
# POOL for this (the obvious first approach) is actively dangerous here:
# a genuinely stuck render permanently occupies one of the pool's worker
# slots forever, so after N stuck renders (N = pool size) every
# subsequent render request queues indefinitely with no free worker --
# turning one bad template into a total, permanent outage of this
# feature. Spawning a fresh daemon=True thread per call avoids that
# failure mode entirely (each stuck render only ever wastes ONE thread,
# forever, but new renders keep getting fresh threads and are never
# blocked by it) at the cost of leaking OS threads under a sustained
# attack -- an acceptable tradeoff for a local single-user tool, and
# still far better than a full outage. The capped-range() guard above is
# the primary defense (it catches the overwhelming majority of
# accidental large-loop mistakes instantly, with no thread spawned at
# all); this timeout is defense in depth for the remainder (e.g. nested
# loops that individually stay under the cap but multiply into a large
# total, as caught by tests below).
RENDER_TIMEOUT_SECONDS = 5


class _RenderThread(threading.Thread):
    """Runs one template.render() call to completion (or forever, if it
    never returns) on a background daemon thread, capturing either the
    result or the raised exception for the caller to inspect after
    waiting up to RENDER_TIMEOUT_SECONDS via join()."""
    def __init__(self, template, context):
        super().__init__(daemon=True)
        self._template = template
        self._context = context
        self.result = None
        self.exception = None

    def run(self):
        try:
            self.result = self._template.render(**self._context)
        except BaseException as exc:  # noqa: BLE001 - must capture to report across threads
            self.exception = exc


class _CappedRange:
    """
    Drop-in replacement for the `range` builtin exposed inside rendered
    templates: behaves identically to range() but raises a clear error if
    asked to iterate more than MAX_LOOP_ITERATIONS times, so a template
    like `{% for i in range(99999999) %}` fails fast with an actionable
    message instead of hanging the render (or, if it emits any text per
    iteration, blowing past MAX_RENDERED_LENGTH only after doing a lot of
    needless work first).
    """
    def __call__(self, *args):
        r = range(*args)
        if len(r) > MAX_LOOP_ITERATIONS:
            raise ValueError(
                f"range() would iterate {len(r)} times, which exceeds this app's safety "
                f"cap of {MAX_LOOP_ITERATIONS} -- check your template for a mistaken bound "
                f"(e.g. a variable that's larger than expected)."
            )
        return r


def _get_env():
    """
    A SANDBOXED Jinja2 environment -- templates here are user-supplied
    text that gets rendered and then (after a human explicitly confirms)
    sent to real network devices, so we deliberately use Jinja2's sandbox
    (blocks attribute access to dunder/private members, dangerous
    builtins, etc.) rather than a full Environment, even though this is
    a single-user local tool. StrictUndefined makes a missing template
    variable raise immediately with a clear name instead of silently
    rendering as an empty string (which could otherwise generate a
    subtly-wrong command that gets pushed to a real device). A small
    macro library is preloaded (see _MACRO_SOURCE) so templates can
    `{% import '_macros.j2' as m %}` instead of repeating common
    boilerplate (e.g. an interface header block) inline.
    """
    env = SandboxedEnvironment(
        undefined=StrictUndefined, trim_blocks=True, lstrip_blocks=True,
        loader=jinja2.DictLoader({"_macros.j2": _MACRO_SOURCE}) if JINJA2_AVAILABLE else None,
    )
    env.globals["range"] = _CappedRange()
    _register_filters(env)
    return env


# ==========================================================================
# Template composition: a small shared macro library every template (built-
# in or custom) can `{% import '_macros.j2' as m %}` from, so common
# boilerplate (an interface header with an optional description line, a
# vendor-agnostic-ish "no shutdown/shutdown" toggle) doesn't get re-typed
# in every single vendor_templates entry.
# ==========================================================================
_MACRO_SOURCE = """
{% macro interface_header(intf, description=None) -%}
interface {{ intf }}
{% if description %} description {{ description }}
{% endif -%}
{%- endmacro %}

{% macro enable_state(enable=True) -%}
{% if enable %} no shutdown
{% else %} shutdown
{% endif -%}
{%- endmacro %}
"""


# ==========================================================================
# Custom networking-aware Jinja2 filters -- keep templates readable
# (`{{ '10.0.0.0/24' | broadcast }}` instead of hand-rolled bit math).
# ==========================================================================
def _cidr_to_mask_filter(prefix):
    return _prefix_to_mask(int(prefix))


def _ip_add_filter(ip, n):
    return str(ipaddress.ip_address(ip) + int(n))


def _network_filter(cidr):
    return str(ipaddress.ip_network(cidr, strict=False).network_address)


def _broadcast_filter(cidr):
    return str(ipaddress.ip_network(cidr, strict=False).broadcast_address)


def _vlan_range_filter(vlan_ids):
    """[1,2,3,7,8] -> '1-3,7-8' -- the compact VLAN-list syntax most
    vendor CLIs expect for 'switchport trunk allowed vlan' etc."""
    ids = sorted({int(v) for v in vlan_ids})
    if not ids:
        return ""
    ranges = []
    start = prev = ids[0]
    for v in ids[1:]:
        if v == prev + 1:
            prev = v
            continue
        ranges.append(f"{start}-{prev}" if start != prev else str(start))
        start = prev = v
    ranges.append(f"{start}-{prev}" if start != prev else str(start))
    return ",".join(ranges)


_INTF_ABBREV_RE = re.compile(
    r"^(gi|ge|te|tw|fo|hu|fa|eth|et|ens|lo|vlan|po|port-channel)\s*([\d/.:]+)$", re.IGNORECASE
)
_INTF_FULL_NAMES = {
    "gi": "GigabitEthernet", "ge": "GigabitEthernet", "te": "TenGigabitEthernet",
    "tw": "TwentyFiveGigE", "fo": "FortyGigabitEthernet", "hu": "HundredGigE",
    "fa": "FastEthernet", "eth": "Ethernet", "et": "Ethernet", "lo": "Loopback",
    "vlan": "Vlan", "po": "Port-channel", "port-channel": "Port-channel",
}


def _normalize_interface_name(short: str) -> str:
    """'gi0/1' -> 'GigabitEthernet0/1', 'te1/1/1' -> 'TenGigabitEthernet1/1/1'.
    Passes through anything it doesn't recognize unchanged (e.g. Junos-style
    `ge-0/0/0`, which is already in its canonical form)."""
    m = _INTF_ABBREV_RE.match((short or "").strip())
    if not m:
        return short
    prefix, rest = m.group(1).lower(), m.group(2)
    full = _INTF_FULL_NAMES.get(prefix)
    return f"{full}{rest}" if full else short


def _register_filters(env):
    env.filters["cidr_to_mask"] = _cidr_to_mask_filter
    env.filters["ip_add"] = _ip_add_filter
    env.filters["network"] = _network_filter
    env.filters["broadcast"] = _broadcast_filter
    env.filters["vlan_range"] = _vlan_range_filter
    env.filters["normalize_intf"] = _normalize_interface_name
    return env


def render_template_text(template_text: str, context: dict):
    """
    Renders arbitrary Jinja2 template text with the given context dict.
    Returns (rendered_text, None) on success or (None, "error message")
    on failure (syntax error, missing variable, timeout, output too
    large, etc.). Never raises.
    """
    if not JINJA2_AVAILABLE:
        return None, "Jinja2 is not available in this environment (install failed)."
    template_text = (template_text or "").strip()
    if not template_text:
        return None, "Template text is empty."
    if len(template_text) > MAX_TEMPLATE_LENGTH:
        return None, f"Template is too long (max {MAX_TEMPLATE_LENGTH} characters)."
    if not isinstance(context, dict):
        return None, "Template context must be a JSON object."

    try:
        env = _get_env()
        template = env.from_string(template_text)
    except jinja2.exceptions.TemplateSyntaxError as exc:
        return None, _format_syntax_error(template_text, exc)
    except Exception as exc:
        return None, f"Could not parse template: {exc}"

    # See _RenderThread's docstring / the RENDER_TIMEOUT_SECONDS comment
    # above for why this spawns a fresh daemon thread per call instead of
    # using a fixed-size thread pool.
    worker = _RenderThread(template, context)
    worker.start()
    worker.join(timeout=RENDER_TIMEOUT_SECONDS)
    if worker.is_alive():
        return None, (
            f"Template render exceeded {RENDER_TIMEOUT_SECONDS}s and was aborted -- this "
            f"usually means a loop bound is much larger than intended. Check any range()/for "
            f"loops in the template."
        )

    exc = worker.exception
    if exc is not None:
        if isinstance(exc, jinja2.exceptions.UndefinedError):
            return None, f"Template references a variable that wasn't provided: {exc}"
        if isinstance(exc, jinja2.exceptions.TemplateSyntaxError):
            return None, _format_syntax_error(template_text, exc)
        if isinstance(exc, ValueError):
            # Raised by our capped range() guard, or ipaddress filters on bad input.
            return None, str(exc)
        return None, f"Could not render template: {exc}"

    rendered = worker.result
    if len(rendered) > MAX_RENDERED_LENGTH:
        return None, f"Rendered output is too large (max {MAX_RENDERED_LENGTH} characters) -- check for an accidental loop."
    return rendered, None


def _format_syntax_error(template_text: str, exc) -> str:
    """
    Builds a "line N: <message>" error PLUS a small window of the
    surrounding template source (with the offending line marked), so a
    syntax mistake in a 40-line custom template doesn't require scrolling
    to guess which line Jinja2 meant.
    """
    lineno = getattr(exc, "lineno", None)
    message = f"Template syntax error (line {lineno}): {exc.message}" if lineno else f"Template syntax error: {exc.message}"
    if not lineno:
        return message
    lines = template_text.splitlines()
    start = max(0, lineno - 3)
    end = min(len(lines), lineno + 2)
    context_lines = []
    for i in range(start, end):
        marker = ">>" if (i + 1) == lineno else "  "
        context_lines.append(f"{marker} {i + 1:>4}| {lines[i]}")
    return message + "\n" + "\n".join(context_lines)


def check_template_syntax(template_text: str):
    """Parses (but does not render) template_text, returning (True, None)
    if it's syntactically valid Jinja2 or (False, "error message") if
    not -- used before SAVING a user-defined custom template, so a typo
    doesn't get silently persisted as a broken saved template."""
    if not JINJA2_AVAILABLE:
        return False, "Jinja2 is not available in this environment (install failed)."
    try:
        _get_env().parse(template_text or "")
        return True, None
    except jinja2.exceptions.TemplateSyntaxError as exc:
        return False, _format_syntax_error(template_text, exc)
    except Exception as exc:
        return False, str(exc)


def extract_template_variables(template_text: str):
    """
    Returns the sorted list of undeclared variable names a template
    references (via Jinja2's meta.find_undeclared_variables) -- used by
    the frontend to auto-generate an input field per variable for custom
    templates without the user needing to already know Jinja2 syntax.
    """
    if not JINJA2_AVAILABLE:
        return []
    try:
        env = _get_env()
        ast = env.parse(template_text or "")
        return sorted(meta.find_undeclared_variables(ast))
    except Exception:
        return []


# ==========================================================================
# Audit-log redaction -- rendered configuration text (and individual config
# commands logged elsewhere in app.py's audit trail) can legitimately
# contain secrets a user typed into a template field (a local user's
# password, an SNMP community string, an IPsec pre-shared key). None of
# that belongs in a plaintext log file on disk, so every code path that
# writes rendered/command text to logs/audit.log runs it through this
# first. This is a best-effort regex redaction, not a guarantee for
# arbitrary custom templates -- it covers the common vendor keywords this
# app's own built-in templates and command library use.
# ==========================================================================
# The actual regex table now lives in redaction.py (LINE_PATTERNS) so
# storage.py's report_json sanitization and this module's audit-log
# sanitization share exactly one set of patterns instead of two copies
# that could quietly drift apart. This module keeps its own
# `sanitize_for_audit` name (rather than every caller switching to
# `redaction.sanitize_text`) since it's already used at ~a dozen call
# sites across app.py and is the more self-documenting name in THIS
# module's context (Jinja2 template rendering / config-mode commands).
def sanitize_for_audit(rendered_text: str) -> str:
    """Redacts secret-looking lines before writing rendered config text
    (or a single config command) to the audit log. Safe to call on any
    string, including None/empty."""
    return redaction.sanitize_text(rendered_text)


# ==========================================================================
# Field-level validation schema
# ==========================================================================
# Each field in a template's `fields` list may declare, in addition to
# name/label/type/default/required:
#   min, max          -- numeric bounds (type="number")
#   pattern           -- a regex the (string) value must fully match
#   validation_message -- shown instead of a generic message if pattern/
#                          min/max fails
#   sensitive         -- marks the field's value as a secret: the frontend
#                         renders it as type="password" (masked input) and
#                         its value is redacted before ever being written
#                         to a log.
# This lets the frontend validate as-you-type (via the same schema, mirrored
# in JS) AND guarantees the server never accepts something the UI wouldn't
# have allowed either, even if the request bypasses the browser entirely.
def validate_field(field_def: dict, value) -> None:
    """Raises ValueError with a user-facing message if `value` doesn't
    satisfy `field_def`'s schema. Returns None (no exception) if fine."""
    label = field_def.get("label", field_def.get("name", "Field"))
    field_type = field_def.get("type", "text")

    is_empty = value is None or (isinstance(value, str) and not value.strip())
    if field_def.get("required") and field_type != "checkbox" and is_empty:
        raise ValueError(f"{label} is required.")
    if is_empty:
        return  # optional and empty -- nothing further to check

    if field_type == "number":
        str_value = str(value).strip()
        if not re.match(r"^-?\d+$", str_value):
            raise ValueError(field_def.get("validation_message") or f"{label} must be a whole number.")
        num = int(str_value)
        if "min" in field_def and num < field_def["min"]:
            raise ValueError(field_def.get("validation_message") or f"{label} must be >= {field_def['min']}.")
        if "max" in field_def and num > field_def["max"]:
            raise ValueError(field_def.get("validation_message") or f"{label} must be <= {field_def['max']}.")
    elif field_type == "select":
        options = field_def.get("options") or []
        if options and str(value) not in [str(o) for o in options]:
            raise ValueError(field_def.get("validation_message") or f"{label} must be one of: {', '.join(map(str, options))}.")

    pattern = field_def.get("pattern")
    if pattern and not re.match(pattern, str(value)):
        raise ValueError(field_def.get("validation_message") or f"{label} has an invalid format.")


def validate_all_fields(fields: list, form_values: dict) -> None:
    """Validates every field in a template's schema against the supplied
    form values; raises ValueError on the first failure."""
    for field_def in fields:
        validate_field(field_def, form_values.get(field_def["name"]))


# ==========================================================================
# IP/CIDR validation using the stdlib `ipaddress` module -- rejects things
# a hand-rolled regex would accept (999.999.999.999/33, host bits set when
# a network is expected, etc.) and handles IPv6 for free.
# ==========================================================================
def validate_network(cidr_str: str, allow_host: bool = True):
    """
    Validates a 'x.x.x.x/yy' string. With allow_host=True (the default --
    used for SVI/interface addresses, where host bits are expected to be
    set), returns (ip_str, mask_str, prefix_int) for the address AS
    GIVEN. With allow_host=False (used for route/network definitions,
    where the address must be an actual network base), the address must
    have no host bits set (strict=True) or a ValueError is raised.
    Works for both IPv4 and IPv6 (mask_str is None for IPv6, which has no
    dotted-decimal netmask notion -- callers should use prefix_int).
    """
    cidr_str = (cidr_str or "").strip()
    try:
        iface = ipaddress.ip_interface(cidr_str)
    except ValueError as exc:
        raise ValueError(f"Invalid network '{cidr_str}': {exc}")

    if not allow_host:
        try:
            net = ipaddress.ip_network(cidr_str, strict=True)
        except ValueError as exc:
            raise ValueError(
                f"Invalid network '{cidr_str}': {exc} (did you mean "
                f"'{ipaddress.ip_network(cidr_str, strict=False)}'?)"
            )
        mask = str(net.netmask) if net.version == 4 else None
        return str(net.network_address), mask, net.prefixlen

    mask = str(iface.network.netmask) if iface.version == 4 else None
    return str(iface.ip), mask, iface.network.prefixlen


def validate_ip(ip_str: str):
    """Validates a bare IP address (no prefix). Returns the normalized
    string form, or raises ValueError with a clear message."""
    ip_str = (ip_str or "").strip()
    try:
        return str(ipaddress.ip_address(ip_str))
    except ValueError:
        raise ValueError(f"Invalid IP address '{ip_str}'.")


# ==========================================================================
# Vendor aliases -- lets a template's vendor_templates dict cover a family
# of closely-related platforms (Cisco IOS/IOS-XE/Catalyst all use the same
# classic CLI syntax for everything this app's templates touch) without
# duplicating the Jinja2 source under multiple keys.
# ==========================================================================
VENDOR_ALIASES = {
    "cisco_iosxe": "cisco_ios",
    "cisco_catalyst": "cisco_ios",
}


def _get_vendor_template(entry: dict, vendor: str):
    """Returns the Jinja2 source for `vendor` from a template entry,
    falling back through VENDOR_ALIASES if `vendor` isn't a direct key."""
    templates = entry.get("vendor_templates", {})
    if vendor in templates:
        return templates[vendor]
    alias = VENDOR_ALIASES.get(vendor)
    if alias and alias in templates:
        return templates[alias]
    return None


def _supported_vendors(entry: dict):
    """All vendor ids a template can render for, including anything that
    resolves to a supported vendor via VENDOR_ALIASES."""
    direct = set(entry.get("vendor_templates", {}).keys())
    aliased = {alias for alias, target in VENDOR_ALIASES.items() if target in direct}
    return sorted(direct | aliased)


_PREFIX_TO_MASK = {
    8: "255.0.0.0", 16: "255.255.0.0", 24: "255.255.255.0", 30: "255.255.255.252",
    32: "255.255.255.255",
}


def _prefix_to_mask(prefix: int) -> str:
    if prefix in _PREFIX_TO_MASK:
        return _PREFIX_TO_MASK[prefix]
    bits = (0xffffffff << (32 - prefix)) & 0xffffffff
    return ".".join(str((bits >> shift) & 0xff) for shift in (24, 16, 8, 0))


# ==========================================================================
# Built-in parameterized templates
# ==========================================================================
# Each entry follows this shape:
#   {
#     "label", "description", "category", "tags": [...],
#     "version", "risk_level" ("low"/"medium"/"high"), "requires_confirmation",
#     "min_privilege",
#     "fields": [{name, label, type, default, required, help, ...validation}],
#     "vendor_templates": {vendor_id: jinja2_source},
#     "test_cases": [{name, vendor, input, expected_contains, expected_not_contains}],
#   }
# `vendor_templates` maps a COMMAND_LIBRARY vendor id (or an alias -- see
# VENDOR_ALIASES) to the Jinja2 source for that platform; a template not
# covering a given vendor simply isn't offered for it in the UI.
BUILTIN_TEMPLATES = {
    "create_vlan": {
        "label": "Create / Remove VLAN(s)",
        "description": "Creates (or removes) one or more VLANs, optionally with an SVI/L3 interface.",
        "category": "Layer 2",
        "tags": ["layer2", "vlan", "common"],
        "version": "1.1.0",
        "risk_level": "low",
        "requires_confirmation": False,
        "min_privilege": 15,
        "fields": [
            {"name": "action", "label": "Action", "type": "select", "options": ["create", "remove"],
             "default": "create", "required": True,
             "help": "'remove' only needs the VLAN id(s) -- name/SVI columns are ignored."},
            {"name": "vlans", "label": "VLANs (one per line: id,name[,ip/prefix])", "type": "textarea",
             "default": "50,Guests\n60,IoT,10.60.0.1/24", "required": True,
             "help": "Each line: <id>,<name>[,<svi ip/prefix>]. The SVI/IP part is optional and ignored when removing."},
        ],
        "vendor_templates": {
            "cisco_ios": (
                "{% if action == 'remove' %}"
                "{% for v in vlans %}\n"
                "no vlan {{ v.id }}\n"
                "{% if v.ip %}no interface Vlan{{ v.id }}\n{% endif %}"
                "{% endfor %}"
                "{% else %}"
                "{% for v in vlans %}\n"
                "vlan {{ v.id }}\n"
                " name {{ v.name }}\n"
                "exit\n"
                "{% if v.ip %}"
                "interface Vlan{{ v.id }}\n"
                " description {{ v.name }}\n"
                " ip address {{ v.ip }} {{ v.mask }}\n"
                " no shutdown\n"
                "exit\n"
                "{% endif %}"
                "{% endfor %}"
                "{% endif %}"
            ),
            "cisco_nxos": (
                "{% if action == 'remove' %}"
                "{% for v in vlans %}\n"
                "no vlan {{ v.id }}\n"
                "{% if v.ip %}no interface Vlan{{ v.id }}\n{% endif %}"
                "{% endfor %}"
                "{% else %}"
                "{% for v in vlans %}\n"
                "vlan {{ v.id }}\n"
                " name {{ v.name }}\n"
                "exit\n"
                "{% if v.ip %}"
                "interface Vlan{{ v.id }}\n"
                " no shutdown\n"
                " ip address {{ v.ip }}/{{ v.prefix }}\n"
                "exit\n"
                "{% endif %}"
                "{% endfor %}"
                "{% endif %}"
            ),
            "arista_eos": (
                "{% if action == 'remove' %}"
                "{% for v in vlans %}\n"
                "no vlan {{ v.id }}\n"
                "{% if v.ip %}no interface Vlan{{ v.id }}\n{% endif %}"
                "{% endfor %}"
                "{% else %}"
                "{% for v in vlans %}\n"
                "vlan {{ v.id }}\n"
                " name {{ v.name }}\n"
                "exit\n"
                "{% if v.ip %}"
                "interface Vlan{{ v.id }}\n"
                " description {{ v.name }}\n"
                " ip address {{ v.ip }}/{{ v.prefix }}\n"
                " no shutdown\n"
                "exit\n"
                "{% endif %}"
                "{% endfor %}"
                "{% endif %}"
            ),
            "aruba_hp": (
                "{% if action == 'remove' %}"
                "{% for v in vlans %}\n"
                "no vlan {{ v.id }}\n"
                "{% endfor %}"
                "{% else %}"
                "{% for v in vlans %}\n"
                "vlan {{ v.id }}\n"
                " name {{ v.name }}\n"
                "exit\n"
                "{% endfor %}"
                "{% endif %}"
            ),
            "juniper_junos": (
                "{% if action == 'remove' %}"
                "{% for v in vlans %}\n"
                "delete vlans {{ v.name }}\n"
                "{% if v.ip %}delete interfaces irb unit {{ v.id }}\n{% endif %}"
                "{% endfor %}"
                "{% else %}"
                "{% for v in vlans %}\n"
                "set vlans {{ v.name }} vlan-id {{ v.id }}\n"
                "{% if v.ip %}"
                "set interfaces irb unit {{ v.id }} family inet address {{ v.ip }}/{{ v.prefix }}\n"
                "set vlans {{ v.name }} l3-interface irb.{{ v.id }}\n"
                "{% endif %}"
                "{% endfor %}"
                "{% endif %}"
            ),
        },
        "test_cases": [
            {
                "name": "single_vlan_no_svi",
                "vendor": "cisco_ios",
                "input": {"action": "create", "vlans": "50,Guests"},
                "expected_contains": ["vlan 50", "name Guests"],
                "expected_not_contains": ["interface Vlan50"],
            },
            {
                "name": "vlan_with_svi",
                "vendor": "cisco_ios",
                "input": {"action": "create", "vlans": "60,IoT,10.60.0.1/24"},
                "expected_contains": ["interface Vlan60", "ip address 10.60.0.1 255.255.255.0"],
                "expected_not_contains": [],
            },
            {
                "name": "remove_vlan",
                "vendor": "cisco_ios",
                "input": {"action": "remove", "vlans": "50,Guests"},
                "expected_contains": ["no vlan 50"],
                "expected_not_contains": ["name Guests"],
            },
            {
                "name": "iosxe_alias_resolves_to_ios_template",
                "vendor": "cisco_iosxe",
                "input": {"action": "create", "vlans": "70,Test"},
                "expected_contains": ["vlan 70", "name Test"],
                "expected_not_contains": [],
            },
        ],
    },
    "bulk_interfaces": {
        "label": "Configure Interfaces in Bulk",
        "description": "Applies the same access/trunk settings to a list of interfaces in one push.",
        "category": "Layer 2",
        "tags": ["layer2", "interfaces", "common"],
        "version": "1.1.0",
        "risk_level": "medium",
        "requires_confirmation": False,
        "min_privilege": 15,
        "fields": [
            {"name": "interfaces", "label": "Interfaces (one per line)", "type": "textarea",
             "default": "GigabitEthernet0/1\nGigabitEthernet0/2\nGigabitEthernet0/3", "required": True,
             "help": "Short forms like 'gi0/1' are also accepted and normalized automatically."},
            {"name": "mode", "label": "Mode", "type": "select", "options": ["access", "trunk"],
             "default": "access", "required": True},
            {"name": "vlan", "label": "VLAN (access vlan, or trunk native vlan)", "type": "number",
             "default": "50", "required": True, "min": 1, "max": 4094,
             "validation_message": "VLAN must be a number from 1 to 4094."},
            {"name": "trunk_allowed", "label": "Trunk allowed VLANs (trunk mode only)", "type": "text",
             "default": "1-4094", "required": False},
            {"name": "description", "label": "Description to apply", "type": "text",
             "default": "Configured by Network Automation Console", "required": False},
            {"name": "enable", "label": "Enable interfaces (no shutdown)", "type": "checkbox", "default": True},
        ],
        "vendor_templates": {
            "cisco_ios": (
                "{% import '_macros.j2' as m %}"
                "{% for intf in interfaces %}\n"
                "{{ m.interface_header(intf | normalize_intf, description) }}"
                "{% if mode == 'trunk' %}"
                " switchport mode trunk\n"
                " switchport trunk native vlan {{ vlan }}\n"
                " switchport trunk allowed vlan {{ trunk_allowed }}\n"
                "{% else %}"
                " switchport mode access\n"
                " switchport access vlan {{ vlan }}\n"
                "{% endif %}"
                "{{ m.enable_state(enable) }}"
                "exit\n"
                "{% endfor %}"
            ),
            "cisco_nxos": (
                "{% import '_macros.j2' as m %}"
                "{% for intf in interfaces %}\n"
                "{{ m.interface_header(intf | normalize_intf, description) }}"
                "{% if mode == 'trunk' %}"
                " switchport mode trunk\n"
                " switchport trunk native vlan {{ vlan }}\n"
                " switchport trunk allowed vlan {{ trunk_allowed }}\n"
                "{% else %}"
                " switchport mode access\n"
                " switchport access vlan {{ vlan }}\n"
                "{% endif %}"
                "{{ m.enable_state(enable) }}"
                "exit\n"
                "{% endfor %}"
            ),
            "arista_eos": (
                "{% import '_macros.j2' as m %}"
                "{% for intf in interfaces %}\n"
                "{{ m.interface_header(intf | normalize_intf, description) }}"
                "{% if mode == 'trunk' %}"
                " switchport mode trunk\n"
                " switchport trunk native vlan {{ vlan }}\n"
                " switchport trunk allowed vlan {{ trunk_allowed }}\n"
                "{% else %}"
                " switchport mode access\n"
                " switchport access vlan {{ vlan }}\n"
                "{% endif %}"
                "{{ m.enable_state(enable) }}"
                "exit\n"
                "{% endfor %}"
            ),
            "aruba_hp": (
                "{% for intf in interfaces %}\n"
                "interface {{ intf }}\n"
                "{% if description %} description {{ description }}\n{% endif %}"
                "{% if mode == 'trunk' %}"
                " vlan trunk native {{ vlan }}\n"
                " vlan trunk allowed {{ trunk_allowed }}\n"
                "{% else %}"
                " vlan access {{ vlan }}\n"
                "{% endif %}"
                "{% if enable %} no shutdown\n{% else %} shutdown\n{% endif %}"
                "exit\n"
                "{% endfor %}"
            ),
            "juniper_junos": (
                "{% for intf in interfaces %}\n"
                "{% if description %}set interfaces {{ intf }} description \"{{ description }}\"\n{% endif %}"
                "{% if mode == 'trunk' %}"
                "set interfaces {{ intf }} unit 0 family ethernet-switching interface-mode trunk\n"
                "set interfaces {{ intf }} unit 0 family ethernet-switching vlan members {{ trunk_allowed }}\n"
                "{% else %}"
                "set interfaces {{ intf }} unit 0 family ethernet-switching interface-mode access\n"
                "set interfaces {{ intf }} unit 0 family ethernet-switching vlan members {{ vlan }}\n"
                "{% endif %}"
                "{% if enable %}delete interfaces {{ intf }} disable\n{% else %}set interfaces {{ intf }} disable\n{% endif %}"
                "{% endfor %}"
            ),
        },
        "test_cases": [
            {
                "name": "access_mode_short_intf_name",
                "vendor": "cisco_ios",
                "input": {"interfaces": "gi0/1", "mode": "access", "vlan": "10", "enable": True},
                "expected_contains": ["interface GigabitEthernet0/1", "switchport access vlan 10", " no shutdown"],
                "expected_not_contains": ["switchport mode trunk"],
            },
            {
                "name": "trunk_mode",
                "vendor": "cisco_ios",
                "input": {"interfaces": "GigabitEthernet0/2", "mode": "trunk", "vlan": "1", "trunk_allowed": "10,20", "enable": True},
                "expected_contains": ["switchport mode trunk", "switchport trunk allowed vlan 10,20"],
                "expected_not_contains": [],
            },
        ],
    },
    "static_route": {
        "label": "Add / Remove Static Route(s)",
        "description": "Adds or removes one or more static routes.",
        "category": "Layer 3",
        "tags": ["layer3", "routing"],
        "version": "1.1.0",
        "risk_level": "medium",
        "requires_confirmation": False,
        "min_privilege": 15,
        "fields": [
            {"name": "action", "label": "Action", "type": "select", "options": ["create", "remove"],
             "default": "create", "required": True},
            {"name": "routes", "label": "Routes (one per line: network/prefix,next-hop)", "type": "textarea",
             "default": "10.0.0.0/24,192.168.1.1", "required": True},
        ],
        "vendor_templates": {
            "cisco_ios": (
                "{% for r in routes %}\n"
                "{% if action == 'remove' %}no {% endif %}"
                "ip route {{ r.network }} {{ r.mask }} {{ r.next_hop }}\n"
                "{% endfor %}"
            ),
            "cisco_nxos": (
                "{% for r in routes %}\n"
                "{% if action == 'remove' %}no {% endif %}"
                "ip route {{ r.network }}/{{ r.prefix }} {{ r.next_hop }}\n"
                "{% endfor %}"
            ),
            "arista_eos": (
                "{% for r in routes %}\n"
                "{% if action == 'remove' %}no {% endif %}"
                "ip route {{ r.network }}/{{ r.prefix }} {{ r.next_hop }}\n"
                "{% endfor %}"
            ),
            "juniper_junos": (
                "{% for r in routes %}\n"
                "{% if action == 'remove' %}delete {% else %}set {% endif %}"
                "routing-options static route {{ r.network }}/{{ r.prefix }} next-hop {{ r.next_hop }}\n"
                "{% endfor %}"
            ),
        },
        "test_cases": [
            {
                "name": "add_route",
                "vendor": "cisco_ios",
                "input": {"action": "create", "routes": "10.0.0.0/24,192.168.1.1"},
                "expected_contains": ["ip route 10.0.0.0 255.255.255.0 192.168.1.1"],
                "expected_not_contains": ["no ip route"],
            },
            {
                "name": "remove_route",
                "vendor": "cisco_ios",
                "input": {"action": "remove", "routes": "10.0.0.0/24,192.168.1.1"},
                "expected_contains": ["no ip route 10.0.0.0 255.255.255.0 192.168.1.1"],
                "expected_not_contains": [],
            },
            {
                "name": "rejects_invalid_network",
                "vendor": "cisco_ios",
                "input": {"action": "create", "routes": "999.999.999.999/33,192.168.1.1"},
                "expect_error": True,
            },
        ],
    },
    "banner": {
        "label": "Set / Clear Login Banner",
        "description": "Sets (or clears) the device's MOTD/login banner text.",
        "category": "System Services",
        "tags": ["system", "banner"],
        "version": "1.1.0",
        "risk_level": "low",
        "requires_confirmation": False,
        "min_privilege": 15,
        "fields": [
            {"name": "action", "label": "Action", "type": "select", "options": ["set", "clear"],
             "default": "set", "required": True},
            {"name": "text", "label": "Banner text (ignored when clearing)", "type": "textarea",
             "default": "Authorized access only. All activity is monitored and logged.", "required": False},
        ],
        "vendor_templates": {
            "cisco_ios": "{% if action == 'clear' %}no banner motd\n{% else %}banner motd #\n{{ text }}\n#\n{% endif %}",
            "cisco_nxos": "{% if action == 'clear' %}no banner motd\n{% else %}banner motd #\n{{ text }}\n#\n{% endif %}",
            "arista_eos": "{% if action == 'clear' %}no banner motd\n{% else %}banner motd\n{{ text }}\nEOF\n{% endif %}",
            "aruba_hp": "{% if action == 'clear' %}no banner motd\n{% else %}banner motd #\n{{ text }}\n#\n{% endif %}",
            "juniper_junos": "{% if action == 'clear' %}delete system login message\n{% else %}set system login message \"{{ text }}\"\n{% endif %}",
        },
        "test_cases": [
            {
                "name": "set_banner",
                "vendor": "cisco_ios",
                "input": {"action": "set", "text": "Hello"},
                "expected_contains": ["banner motd #", "Hello"],
                "expected_not_contains": ["no banner motd"],
            },
            {
                "name": "clear_banner",
                "vendor": "cisco_ios",
                "input": {"action": "clear", "text": ""},
                "expected_contains": ["no banner motd"],
                "expected_not_contains": ["Hello"],
            },
        ],
    },
    "create_user": {
        "label": "Create / Remove Local User",
        "description": "Creates (or removes) a local device login account with a privilege level.",
        "category": "Security",
        "tags": ["security", "aaa", "users"],
        "version": "1.0.0",
        "risk_level": "high",
        "requires_confirmation": True,
        "min_privilege": 15,
        "fields": [
            {"name": "action", "label": "Action", "type": "select", "options": ["create", "remove"],
             "default": "create", "required": True},
            {"name": "username", "label": "Username", "type": "text", "default": "", "required": True,
             "pattern": r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$",
             "validation_message": "Username must start with a letter and contain only letters, digits, '.', '_', or '-'."},
            {"name": "password", "label": "Password", "type": "password", "sensitive": True,
             "default": "", "required": False,
             "help": "Required when creating a user; ignored when removing one. Never logged or stored in plain text."},
            {"name": "privilege", "label": "Privilege level", "type": "number", "default": "15",
             "required": False, "min": 0, "max": 15,
             "validation_message": "Privilege level must be 0-15."},
        ],
        "vendor_templates": {
            "cisco_ios": (
                "{% if action == 'remove' %}"
                "no username {{ username }}\n"
                "{% else %}"
                "username {{ username }} privilege {{ privilege }} secret {{ password }}\n"
                "{% endif %}"
            ),
            "cisco_nxos": (
                "{% if action == 'remove' %}"
                "no username {{ username }}\n"
                "{% else %}"
                "username {{ username }} password {{ password }} role network-admin\n"
                "{% endif %}"
            ),
            "arista_eos": (
                "{% if action == 'remove' %}"
                "no username {{ username }}\n"
                "{% else %}"
                "username {{ username }} privilege {{ privilege }} secret {{ password }}\n"
                "{% endif %}"
            ),
            "aruba_hp": (
                "{% if action == 'remove' %}"
                "no user {{ username }}\n"
                "{% else %}"
                "user {{ username }} password {{ password }}\n"
                "{% endif %}"
            ),
            "juniper_junos": (
                "{% if action == 'remove' %}"
                "delete system login user {{ username }}\n"
                "{% else %}"
                "set system login user {{ username }} class super-user\n"
                "set system login user {{ username }} authentication plain-text-password {{ password }}\n"
                "{% endif %}"
            ),
        },
        "test_cases": [
            {
                "name": "create_user_has_secret",
                "vendor": "cisco_ios",
                "input": {"action": "create", "username": "netadmin", "password": "Sup3rS3cret!", "privilege": "15"},
                "expected_contains": ["username netadmin privilege 15 secret Sup3rS3cret!"],
                "expected_not_contains": ["no username"],
            },
            {
                "name": "remove_user",
                "vendor": "cisco_ios",
                "input": {"action": "remove", "username": "netadmin"},
                "expected_contains": ["no username netadmin"],
                "expected_not_contains": ["secret"],
            },
            {
                "name": "rejects_bad_username",
                "vendor": "cisco_ios",
                "input": {"action": "create", "username": "1bad name!", "password": "x", "privilege": "15"},
                "expect_error": True,
            },
        ],
    },
    "configure_ntp": {
        "label": "Add / Remove NTP Server(s)",
        "description": "Adds or removes one or more NTP time servers.",
        "category": "System Services",
        "tags": ["system", "ntp", "time"],
        "version": "1.0.0",
        "risk_level": "low",
        "requires_confirmation": False,
        "min_privilege": 15,
        "fields": [
            {"name": "action", "label": "Action", "type": "select", "options": ["create", "remove"],
             "default": "create", "required": True},
            {"name": "ntp_servers", "label": "NTP server IP(s), one per line", "type": "textarea",
             "default": "pool.ntp.org\n10.0.0.1", "required": True,
             "help": "Hostnames or IP addresses -- IP addresses are validated; hostnames are passed through as-is."},
        ],
        "vendor_templates": {
            "cisco_ios": "{% for s in ntp_servers %}{% if action == 'remove' %}no {% endif %}ntp server {{ s }}\n{% endfor %}",
            "cisco_nxos": "{% for s in ntp_servers %}{% if action == 'remove' %}no {% endif %}ntp server {{ s }}\n{% endfor %}",
            "arista_eos": "{% for s in ntp_servers %}{% if action == 'remove' %}no {% endif %}ntp server {{ s }}\n{% endfor %}",
            "aruba_hp": "{% for s in ntp_servers %}{% if action == 'remove' %}no {% endif %}ntp server {{ s }}\n{% endfor %}",
            "juniper_junos": "{% for s in ntp_servers %}{% if action == 'remove' %}delete{% else %}set{% endif %} system ntp server {{ s }}\n{% endfor %}",
        },
        "test_cases": [
            {
                "name": "add_ntp",
                "vendor": "cisco_ios",
                "input": {"action": "create", "ntp_servers": "10.0.0.1\n10.0.0.2"},
                "expected_contains": ["ntp server 10.0.0.1", "ntp server 10.0.0.2"],
                "expected_not_contains": ["no ntp server"],
            },
            {
                "name": "remove_ntp",
                "vendor": "cisco_ios",
                "input": {"action": "remove", "ntp_servers": "10.0.0.1"},
                "expected_contains": ["no ntp server 10.0.0.1"],
                "expected_not_contains": [],
            },
        ],
    },
    "port_security": {
        "label": "Configure Port Security",
        "description": "Enables port-security on a list of access ports with a MAC address cap and violation action.",
        "category": "Security",
        "tags": ["security", "layer2", "interfaces"],
        "version": "1.0.0",
        "risk_level": "medium",
        "requires_confirmation": False,
        "min_privilege": 15,
        "fields": [
            {"name": "action", "label": "Action", "type": "select", "options": ["enable", "disable"],
             "default": "enable", "required": True,
             "help": "'disable' removes port-security from the listed interfaces entirely."},
            {"name": "interfaces", "label": "Interfaces (one per line)", "type": "textarea",
             "default": "GigabitEthernet0/1\nGigabitEthernet0/2", "required": True,
             "help": "Short forms like 'gi0/1' are also accepted and normalized automatically."},
            {"name": "max_mac", "label": "Maximum MAC addresses", "type": "number", "default": "1",
             "required": False, "min": 1, "max": 8192,
             "validation_message": "Maximum MAC addresses must be a number from 1 to 8192."},
            {"name": "violation", "label": "Violation action", "type": "select",
             "options": ["shutdown", "restrict", "protect"], "default": "shutdown", "required": False},
            {"name": "sticky", "label": "Use sticky learning (vs. static)", "type": "checkbox", "default": True},
        ],
        "vendor_templates": {
            "cisco_ios": (
                "{% for intf in interfaces %}\n"
                "interface {{ intf | normalize_intf }}\n"
                "{% if action == 'disable' %}"
                " no switchport port-security\n"
                "{% else %}"
                " switchport mode access\n"
                " switchport port-security\n"
                " switchport port-security maximum {{ max_mac }}\n"
                " switchport port-security violation {{ violation }}\n"
                "{% if sticky %} switchport port-security mac-address sticky\n{% endif %}"
                "{% endif %}"
                "exit\n"
                "{% endfor %}"
            ),
            "cisco_nxos": (
                "{% for intf in interfaces %}\n"
                "interface {{ intf | normalize_intf }}\n"
                "{% if action == 'disable' %}"
                " no switchport port-security\n"
                "{% else %}"
                " switchport port-security\n"
                " switchport port-security maximum {{ max_mac }}\n"
                " switchport port-security violation {{ violation }}\n"
                "{% if sticky %} switchport port-security mac-address sticky\n{% endif %}"
                "{% endif %}"
                "exit\n"
                "{% endfor %}"
            ),
            "arista_eos": (
                "{% for intf in interfaces %}\n"
                "interface {{ intf | normalize_intf }}\n"
                "{% if action == 'disable' %}"
                " no switchport port-security\n"
                "{% else %}"
                " switchport port-security\n"
                " switchport port-security maximum {{ max_mac }}\n"
                " switchport port-security violation {{ violation }}\n"
                "{% endif %}"
                "exit\n"
                "{% endfor %}"
            ),
        },
        "test_cases": [
            {
                "name": "enable_port_security_sticky",
                "vendor": "cisco_ios",
                "input": {"action": "enable", "interfaces": "gi0/1", "max_mac": "2",
                          "violation": "restrict", "sticky": True},
                "expected_contains": ["interface GigabitEthernet0/1", "switchport port-security maximum 2",
                                      "switchport port-security violation restrict",
                                      "switchport port-security mac-address sticky"],
                "expected_not_contains": ["no switchport port-security"],
            },
            {
                "name": "disable_port_security",
                "vendor": "cisco_ios",
                "input": {"action": "disable", "interfaces": "GigabitEthernet0/2", "max_mac": "1",
                          "violation": "shutdown", "sticky": False},
                "expected_contains": ["no switchport port-security"],
                "expected_not_contains": ["switchport port-security maximum"],
            },
        ],
    },
    "ospf_process": {
        "label": "Configure OSPF Routing Process",
        "description": "Creates (or removes) an OSPF process and advertises one or more networks into an area.",
        "category": "Layer 3",
        "tags": ["layer3", "routing", "ospf"],
        "version": "1.0.0",
        "risk_level": "medium",
        "requires_confirmation": False,
        "min_privilege": 15,
        "fields": [
            {"name": "action", "label": "Action", "type": "select", "options": ["create", "remove"],
             "default": "create", "required": True},
            {"name": "process_id", "label": "OSPF process ID", "type": "number", "default": "1",
             "required": True, "min": 1, "max": 65535,
             "validation_message": "Process ID must be a number from 1 to 65535."},
            {"name": "router_id", "label": "Router ID (optional)", "type": "text", "default": "",
             "required": False, "pattern": r"^$|^\d{1,3}(\.\d{1,3}){3}$",
             "validation_message": "Router ID must be a dotted-decimal address, e.g. 1.1.1.1."},
            {"name": "networks", "label": "Networks to advertise (one per line: network/prefix)",
             "type": "textarea", "default": "10.0.0.0/24\n192.168.1.0/24", "required": True},
            {"name": "area", "label": "Area", "type": "text", "default": "0", "required": False},
            {"name": "passive_default", "label": "Make all interfaces passive by default", "type": "checkbox",
             "default": False},
        ],
        "vendor_templates": {
            "cisco_ios": (
                "{% if action == 'remove' %}"
                "no router ospf {{ process_id }}\n"
                "{% else %}"
                "router ospf {{ process_id }}\n"
                "{% if router_id %} router-id {{ router_id }}\n{% endif %}"
                "{% if passive_default %} passive-interface default\n{% endif %}"
                "{% for n in networks %} network {{ n.network }} {{ n.wildcard }} area {{ area }}\n{% endfor %}"
                "exit\n"
                "{% endif %}"
            ),
            "cisco_nxos": (
                "{% if action == 'remove' %}"
                "no router ospf {{ process_id }}\n"
                "{% else %}"
                "router ospf {{ process_id }}\n"
                "{% if router_id %} router-id {{ router_id }}\n{% endif %}"
                "{% if passive_default %} passive-interface default\n{% endif %}"
                "exit\n"
                "{% for n in networks %}interface {{ n.network }}\n ip router ospf {{ process_id }} area {{ area }}\nexit\n{% endfor %}"
                "{% endif %}"
            ),
            "arista_eos": (
                "{% if action == 'remove' %}"
                "no router ospf {{ process_id }}\n"
                "{% else %}"
                "router ospf {{ process_id }}\n"
                "{% if router_id %} router-id {{ router_id }}\n{% endif %}"
                "{% if passive_default %} passive-interface default\n{% endif %}"
                "{% for n in networks %} network {{ n.network }}/{{ n.prefix }} area {{ area }}\n{% endfor %}"
                "exit\n"
                "{% endif %}"
            ),
            "juniper_junos": (
                "{% if action == 'remove' %}"
                "delete protocols ospf area {{ area }}\n"
                "{% else %}"
                "{% for n in networks %}set protocols ospf area {{ area }} interface {{ n.network }}/{{ n.prefix }}\n{% endfor %}"
                "{% if router_id %}set routing-options router-id {{ router_id }}\n{% endif %}"
                "{% endif %}"
            ),
        },
        "test_cases": [
            {
                "name": "create_ospf_with_router_id",
                "vendor": "cisco_ios",
                "input": {"action": "create", "process_id": "10", "router_id": "1.1.1.1",
                          "networks": "10.0.0.0/24", "area": "0", "passive_default": False},
                "expected_contains": ["router ospf 10", "router-id 1.1.1.1",
                                      "network 10.0.0.0 0.0.0.255 area 0"],
                "expected_not_contains": ["no router ospf"],
            },
            {
                "name": "remove_ospf",
                "vendor": "cisco_ios",
                "input": {"action": "remove", "process_id": "10", "networks": "10.0.0.0/24", "area": "0"},
                "expected_contains": ["no router ospf 10"],
                "expected_not_contains": ["network 10.0.0.0"],
            },
            {
                "name": "rejects_bad_router_id",
                "vendor": "cisco_ios",
                "input": {"action": "create", "process_id": "1", "router_id": "not-an-ip",
                          "networks": "10.0.0.0/24", "area": "0"},
                "expect_error": True,
            },
        ],
    },
    "syslog_logging": {
        "label": "Configure Syslog / Remote Logging",
        "description": "Points the device at one or more syslog servers with a minimum severity level.",
        "category": "System Services",
        "tags": ["system", "logging", "syslog"],
        "version": "1.0.0",
        "risk_level": "low",
        "requires_confirmation": False,
        "min_privilege": 15,
        "fields": [
            {"name": "action", "label": "Action", "type": "select", "options": ["create", "remove"],
             "default": "create", "required": True},
            {"name": "servers", "label": "Syslog server IP(s), one per line", "type": "textarea",
             "default": "10.0.0.100", "required": True},
            {"name": "severity", "label": "Minimum severity", "type": "select",
             "options": ["emergencies", "alerts", "critical", "errors", "warnings",
                         "notifications", "informational", "debugging"],
             "default": "informational", "required": False},
            {"name": "source_interface", "label": "Source interface (optional)", "type": "text",
             "default": "", "required": False,
             "help": "e.g. Loopback0 -- ensures syslog messages always come from a stable source address."},
        ],
        "vendor_templates": {
            "cisco_ios": (
                "{% for s in servers %}{% if action == 'remove' %}no {% endif %}logging host {{ s }}\n{% endfor %}"
                "{% if action != 'remove' %}"
                "logging trap {{ severity }}\n"
                "{% if source_interface %}logging source-interface {{ source_interface | normalize_intf }}\n{% endif %}"
                "{% endif %}"
            ),
            "cisco_nxos": (
                "{% for s in servers %}{% if action == 'remove' %}no {% endif %}logging server {{ s }}\n{% endfor %}"
                "{% if action != 'remove' %}"
                "logging level all {{ severity }}\n"
                "{% if source_interface %}logging source-interface {{ source_interface | normalize_intf }}\n{% endif %}"
                "{% endif %}"
            ),
            "arista_eos": (
                "{% for s in servers %}{% if action == 'remove' %}no {% endif %}logging host {{ s }}\n{% endfor %}"
                "{% if action != 'remove' %}logging trap {{ severity }}\n{% endif %}"
            ),
            "juniper_junos": (
                "{% for s in servers %}"
                "{% if action == 'remove' %}delete system syslog host {{ s }}\n"
                "{% else %}set system syslog host {{ s }} any {{ severity }}\n{% endif %}"
                "{% endfor %}"
            ),
        },
        "test_cases": [
            {
                "name": "add_syslog_with_source",
                "vendor": "cisco_ios",
                "input": {"action": "create", "servers": "10.0.0.100\n10.0.0.101",
                          "severity": "warnings", "source_interface": "lo0"},
                "expected_contains": ["logging host 10.0.0.100", "logging host 10.0.0.101",
                                      "logging trap warnings", "logging source-interface Loopback0"],
                "expected_not_contains": ["no logging host"],
            },
            {
                "name": "remove_syslog",
                "vendor": "cisco_ios",
                "input": {"action": "remove", "servers": "10.0.0.100", "severity": "informational",
                          "source_interface": ""},
                "expected_contains": ["no logging host 10.0.0.100"],
                "expected_not_contains": ["logging trap"],
            },
        ],
    },
    "acl_standard": {
        "label": "Create / Remove Standard ACL",
        "description": "Creates (or removes) a numbered/named standard ACL from a list of permit/deny entries.",
        "category": "Security",
        "tags": ["security", "acl", "firewall"],
        "version": "1.0.0",
        "risk_level": "high",
        "requires_confirmation": True,
        "min_privilege": 15,
        "fields": [
            {"name": "action", "label": "Action", "type": "select", "options": ["create", "remove"],
             "default": "create", "required": True},
            {"name": "acl_name", "label": "ACL number or name", "type": "text", "default": "10",
             "required": True, "pattern": r"^[A-Za-z0-9_-]{1,64}$",
             "validation_message": "ACL number/name must be alphanumeric (letters, digits, '_', '-')."},
            {"name": "entries", "label": "Entries (one per line: permit|deny,network/prefix)",
             "type": "textarea", "default": "permit,10.0.0.0/24\ndeny,0.0.0.0/0", "required": True,
             "help": "Use 0.0.0.0/0 for 'any'. Each entry is validated as a real network/prefix."},
        ],
        "vendor_templates": {
            "cisco_ios": (
                "{% if action == 'remove' %}"
                "no ip access-list standard {{ acl_name }}\n"
                "{% else %}"
                "ip access-list standard {{ acl_name }}\n"
                "{% for e in entries %}"
                "{% if e.network == '0.0.0.0' and e.prefix == 0 %} {{ e.verb }} any\n"
                "{% else %} {{ e.verb }} {{ e.network }} {{ e.wildcard }}\n{% endif %}"
                "{% endfor %}"
                "exit\n"
                "{% endif %}"
            ),
            "cisco_nxos": (
                "{% if action == 'remove' %}"
                "no ip access-list {{ acl_name }}\n"
                "{% else %}"
                "ip access-list {{ acl_name }}\n"
                "{% for e in entries %}"
                "{% if e.network == '0.0.0.0' and e.prefix == 0 %} {{ e.verb }} ip any any\n"
                "{% else %} {{ e.verb }} ip {{ e.network }}/{{ e.prefix }} any\n{% endif %}"
                "{% endfor %}"
                "exit\n"
                "{% endif %}"
            ),
            "arista_eos": (
                "{% if action == 'remove' %}"
                "no ip access-list standard {{ acl_name }}\n"
                "{% else %}"
                "ip access-list standard {{ acl_name }}\n"
                "{% for e in entries %}"
                "{% if e.network == '0.0.0.0' and e.prefix == 0 %} {{ e.verb }} any\n"
                "{% else %} {{ e.verb }} {{ e.network }}/{{ e.prefix }}\n{% endif %}"
                "{% endfor %}"
                "exit\n"
                "{% endif %}"
            ),
        },
        "test_cases": [
            {
                "name": "create_acl_with_any",
                "vendor": "cisco_ios",
                "input": {"action": "create", "acl_name": "10",
                          "entries": "permit,10.0.0.0/24\ndeny,0.0.0.0/0"},
                "expected_contains": ["ip access-list standard 10", "permit 10.0.0.0 0.0.0.255", "deny any"],
                "expected_not_contains": ["no ip access-list"],
            },
            {
                "name": "remove_acl",
                "vendor": "cisco_ios",
                "input": {"action": "remove", "acl_name": "10", "entries": "permit,10.0.0.0/24"},
                "expected_contains": ["no ip access-list standard 10"],
                "expected_not_contains": ["permit"],
            },
            {
                "name": "rejects_bad_entry_format",
                "vendor": "cisco_ios",
                "input": {"action": "create", "acl_name": "10", "entries": "permit-only-one-field"},
                "expect_error": True,
            },
        ],
    },
    "spanning_tree": {
        "label": "Configure Spanning Tree (STP Mode / Priority / PortFast)",
        "description": "Sets the spanning-tree protocol mode and per-VLAN bridge priority, and toggles PortFast+BPDU Guard on access ports.",
        "category": "Layer 2",
        "tags": ["layer2", "stp", "loop-prevention"],
        "version": "1.0.0",
        "risk_level": "high",
        "requires_confirmation": True,
        "min_privilege": 15,
        "fields": [
            {"name": "action", "label": "Action", "type": "select", "options": ["create", "remove"],
             "default": "create", "required": True,
             "help": "'remove' reverts the VLAN priority to default and disables PortFast/BPDU Guard on the listed ports; STP mode itself is left as configured (not un-settable)."},
            {"name": "stp_mode", "label": "STP mode", "type": "select",
             "options": ["pvst", "rapid-pvst", "mst"], "default": "rapid-pvst", "required": True},
            {"name": "vlans", "label": "VLAN id(s) for priority (comma or range, e.g. 1,10,20-25)", "type": "text",
             "default": "1", "required": False,
             "help": "Leave blank to only change STP mode / PortFast without touching any VLAN's priority."},
            {"name": "priority", "label": "Bridge priority (multiple of 4096)", "type": "number",
             "default": "4096", "required": False, "min": 0, "max": 61440,
             "validation_message": "Priority must be a multiple of 4096 between 0 and 61440."},
            {"name": "portfast_interfaces", "label": "Access ports for PortFast + BPDU Guard (one per line)",
             "type": "textarea", "default": "", "required": False,
             "help": "Optional -- only end-host access ports should ever get PortFast. Leave blank to skip."},
        ],
        "vendor_templates": {
            "cisco_ios": (
                "spanning-tree mode {{ stp_mode }}\n"
                "{% if vlan_ids %}"
                "{% for vid in vlan_ids %}"
                "{% if action == 'remove' %}no spanning-tree vlan {{ vid }} priority\n"
                "{% else %}spanning-tree vlan {{ vid }} priority {{ priority }}\n{% endif %}"
                "{% endfor %}"
                "{% endif %}"
                "{% for intf in portfast_interfaces %}\n"
                "interface {{ intf | normalize_intf }}\n"
                "{% if action == 'remove' %}"
                " no spanning-tree portfast\n"
                " no spanning-tree bpduguard enable\n"
                "{% else %}"
                " spanning-tree portfast\n"
                " spanning-tree bpduguard enable\n"
                "{% endif %}"
                "exit\n"
                "{% endfor %}"
            ),
            "cisco_nxos": (
                "spanning-tree mode {{ stp_mode }}\n"
                "{% if vlan_ids %}"
                "{% for vid in vlan_ids %}"
                "{% if action == 'remove' %}no spanning-tree vlan {{ vid }} priority\n"
                "{% else %}spanning-tree vlan {{ vid }} priority {{ priority }}\n{% endif %}"
                "{% endfor %}"
                "{% endif %}"
                "{% for intf in portfast_interfaces %}\n"
                "interface {{ intf | normalize_intf }}\n"
                "{% if action == 'remove' %}"
                " no spanning-tree port type edge\n"
                " no spanning-tree bpduguard enable\n"
                "{% else %}"
                " spanning-tree port type edge\n"
                " spanning-tree bpduguard enable\n"
                "{% endif %}"
                "exit\n"
                "{% endfor %}"
            ),
            "arista_eos": (
                "spanning-tree mode {{ stp_mode }}\n"
                "{% if vlan_ids %}"
                "{% for vid in vlan_ids %}"
                "{% if action == 'remove' %}no spanning-tree vlan {{ vid }} priority\n"
                "{% else %}spanning-tree vlan {{ vid }} priority {{ priority }}\n{% endif %}"
                "{% endfor %}"
                "{% endif %}"
                "{% for intf in portfast_interfaces %}\n"
                "interface {{ intf | normalize_intf }}\n"
                "{% if action == 'remove' %}"
                " no spanning-tree portfast\n"
                "{% else %}"
                " spanning-tree portfast\n"
                "{% endif %}"
                "exit\n"
                "{% endfor %}"
            ),
        },
        "test_cases": [
            {
                "name": "set_mode_and_priority",
                "vendor": "cisco_ios",
                "input": {"action": "create", "stp_mode": "rapid-pvst", "vlans": "1,10", "priority": "4096",
                          "portfast_interfaces": ""},
                "expected_contains": ["spanning-tree mode rapid-pvst", "spanning-tree vlan 1 priority 4096",
                                      "spanning-tree vlan 10 priority 4096"],
                "expected_not_contains": ["no spanning-tree"],
            },
            {
                "name": "portfast_bpduguard_enabled",
                "vendor": "cisco_ios",
                "input": {"action": "create", "stp_mode": "rapid-pvst", "vlans": "", "priority": "4096",
                          "portfast_interfaces": "gi0/5"},
                "expected_contains": ["interface GigabitEthernet0/5", "spanning-tree portfast",
                                      "spanning-tree bpduguard enable"],
                "expected_not_contains": ["spanning-tree vlan"],
            },
            {
                "name": "remove_reverts_priority_and_portfast",
                "vendor": "cisco_ios",
                "input": {"action": "remove", "stp_mode": "rapid-pvst", "vlans": "10", "priority": "4096",
                          "portfast_interfaces": "gi0/5"},
                "expected_contains": ["no spanning-tree vlan 10 priority", "no spanning-tree portfast",
                                      "no spanning-tree bpduguard enable"],
                "expected_not_contains": [],
            },
            {
                "name": "rejects_non_multiple_of_4096",
                "vendor": "cisco_ios",
                "input": {"action": "create", "stp_mode": "rapid-pvst", "vlans": "1", "priority": "5000",
                          "portfast_interfaces": ""},
                "expect_error": True,
            },
        ],
    },
    "aaa_tacacs_radius": {
        "label": "Configure AAA (TACACS+/RADIUS) Authentication",
        "description": "Enables aaa new-model and points login/enable authentication at one or more centralized TACACS+ or RADIUS servers, with a local fallback.",
        "category": "Security",
        "tags": ["security", "aaa", "tacacs", "radius"],
        "version": "1.0.0",
        "risk_level": "high",
        "requires_confirmation": True,
        "min_privilege": 15,
        "fields": [
            {"name": "action", "label": "Action", "type": "select", "options": ["create", "remove"],
             "default": "create", "required": True,
             "help": "'remove' deletes the server group and login/enable method lists (falls back to local login)."},
            {"name": "protocol", "label": "Protocol", "type": "select", "options": ["tacacs", "radius"],
             "default": "tacacs", "required": True},
            {"name": "servers", "label": "Server IP(s), one per line", "type": "textarea",
             "default": "10.0.0.50\n10.0.0.51", "required": True},
            {"name": "shared_key", "label": "Shared secret key", "type": "password", "sensitive": True,
             "default": "", "required": False,
             "help": "Required when creating; ignored when removing. Never logged or stored in plain text."},
            {"name": "local_fallback", "label": "Fall back to local auth if servers unreachable",
             "type": "checkbox", "default": True},
        ],
        "vendor_templates": {
            "cisco_ios": (
                "{% if action == 'remove' %}"
                "no aaa authentication login default group {{ protocol }}{{ ' local' if local_fallback else '' }}\n"
                "no aaa authentication enable default group {{ protocol }}{{ ' enable' if local_fallback else '' }}\n"
                "{% for s in servers %}"
                "{% if protocol == 'tacacs' %}no tacacs server TACACS-{{ loop.index }}\n"
                "{% else %}no radius server RADIUS-{{ loop.index }}\n{% endif %}"
                "{% endfor %}"
                "{% else %}"
                "aaa new-model\n"
                "{% for s in servers %}"
                "{% if protocol == 'tacacs' %}"
                "tacacs server TACACS-{{ loop.index }}\n"
                " address ipv4 {{ s }}\n"
                " key {{ shared_key }}\n"
                "exit\n"
                "{% else %}"
                "radius server RADIUS-{{ loop.index }}\n"
                " address ipv4 {{ s }} auth-port 1812 acct-port 1813\n"
                " key {{ shared_key }}\n"
                "exit\n"
                "{% endif %}"
                "{% endfor %}"
                "aaa authentication login default group {{ protocol }}{{ ' local' if local_fallback else '' }}\n"
                "aaa authentication enable default group {{ protocol }}{{ ' enable' if local_fallback else '' }}\n"
                "{% endif %}"
            ),
            "cisco_nxos": (
                "{% if action == 'remove' %}"
                "no aaa authentication login default group {{ protocol }}\n"
                "{% for s in servers %}"
                "no {{ protocol }}-server host {{ s }}\n"
                "{% endfor %}"
                "{% else %}"
                "feature {{ protocol }}\n"
                "{% for s in servers %}"
                "{{ protocol }}-server host {{ s }} key {{ shared_key }}\n"
                "{% endfor %}"
                "aaa group server {{ protocol }} {{ protocol|upper }}-GROUP\n"
                "{% for s in servers %} server {{ s }}\n{% endfor %}"
                "exit\n"
                "aaa authentication login default group {{ protocol|upper }}-GROUP{{ ' local' if local_fallback else '' }}\n"
                "{% endif %}"
            ),
            "arista_eos": (
                "{% if action == 'remove' %}"
                "no aaa authentication login default group {{ protocol }}\n"
                "{% for s in servers %}"
                "no {{ protocol }}-server host {{ s }}\n"
                "{% endfor %}"
                "{% else %}"
                "{% for s in servers %}"
                "{{ protocol }}-server host {{ s }} key {{ shared_key }}\n"
                "{% endfor %}"
                "aaa authentication login default group {{ protocol }}{{ ' local' if local_fallback else '' }}\n"
                "{% endif %}"
            ),
        },
        "test_cases": [
            {
                "name": "create_tacacs_with_fallback",
                "vendor": "cisco_ios",
                "input": {"action": "create", "protocol": "tacacs", "servers": "10.0.0.50",
                          "shared_key": "S3cr3tKey", "local_fallback": True},
                "expected_contains": ["aaa new-model", "tacacs server TACACS-1", "address ipv4 10.0.0.50",
                                      "key S3cr3tKey", "aaa authentication login default group tacacs local"],
                "expected_not_contains": ["no aaa"],
            },
            {
                "name": "create_radius_no_fallback",
                "vendor": "cisco_ios",
                "input": {"action": "create", "protocol": "radius", "servers": "10.0.0.60",
                          "shared_key": "Rad1usKey", "local_fallback": False},
                "expected_contains": ["radius server RADIUS-1", "auth-port 1812", "aaa authentication login default group radius"],
                "expected_not_contains": ["local"],
            },
            {
                "name": "remove_tacacs",
                "vendor": "cisco_ios",
                "input": {"action": "remove", "protocol": "tacacs", "servers": "10.0.0.50",
                          "shared_key": "", "local_fallback": True},
                "expected_contains": ["no aaa authentication login default group tacacs local",
                                      "no tacacs server TACACS-1"],
                "expected_not_contains": ["key"],
            },
            {
                "name": "rejects_missing_key_on_create",
                "vendor": "cisco_ios",
                "input": {"action": "create", "protocol": "tacacs", "servers": "10.0.0.50",
                          "shared_key": "", "local_fallback": True},
                "expect_error": True,
            },
        ],
    },
    "dhcp_snooping": {
        "label": "Configure DHCP Snooping",
        "description": "Enables DHCP snooping on a set of VLANs and marks uplink/trunk ports as trusted, to block rogue DHCP servers on access ports.",
        "category": "Security",
        "tags": ["security", "dhcp", "layer2"],
        "version": "1.0.0",
        "risk_level": "medium",
        "requires_confirmation": False,
        "min_privilege": 15,
        "fields": [
            {"name": "action", "label": "Action", "type": "select", "options": ["enable", "disable"],
             "default": "enable", "required": True},
            {"name": "vlans", "label": "VLAN id(s) (comma or range, e.g. 10,20-25)", "type": "text",
             "default": "10,20", "required": True},
            {"name": "trusted_interfaces", "label": "Trusted (uplink/trunk) interfaces, one per line",
             "type": "textarea", "default": "GigabitEthernet0/24", "required": False,
             "help": "These are the only ports allowed to hand out DHCP offers -- typically uplinks to routers/DHCP servers."},
            {"name": "untrusted_interfaces", "label": "Untrusted (access) interfaces to rate-limit, one per line",
             "type": "textarea", "default": "", "required": False,
             "help": "Optional -- applies the rate limit below to specific access ports. Leave blank to skip rate limiting entirely."},
            {"name": "rate_limit", "label": "Untrusted port rate limit (pps)", "type": "number",
             "default": "15", "required": False, "min": 1, "max": 2048,
             "help": "Only applied to the 'untrusted interfaces' listed above, if any."},
        ],
        "vendor_templates": {
            "cisco_ios": (
                "{% if action == 'disable' %}"
                "no ip dhcp snooping vlan {{ vlan_list }}\n"
                "{% for intf in trusted_interfaces %}\n"
                "interface {{ intf | normalize_intf }}\n"
                " no ip dhcp snooping trust\n"
                "exit\n"
                "{% endfor %}"
                "{% for intf in untrusted_interfaces %}\n"
                "interface {{ intf | normalize_intf }}\n"
                " no ip dhcp snooping limit rate\n"
                "exit\n"
                "{% endfor %}"
                "no ip dhcp snooping\n"
                "{% else %}"
                "ip dhcp snooping\n"
                "ip dhcp snooping vlan {{ vlan_list }}\n"
                "{% for intf in trusted_interfaces %}\n"
                "interface {{ intf | normalize_intf }}\n"
                " ip dhcp snooping trust\n"
                "exit\n"
                "{% endfor %}"
                "{% for intf in untrusted_interfaces %}\n"
                "interface {{ intf | normalize_intf }}\n"
                " ip dhcp snooping limit rate {{ rate_limit }}\n"
                "exit\n"
                "{% endfor %}"
                "{% endif %}"
            ),
            "cisco_nxos": (
                "{% if action == 'disable' %}"
                "no ip dhcp snooping vlan {{ vlan_list }}\n"
                "{% for intf in trusted_interfaces %}\n"
                "interface {{ intf | normalize_intf }}\n"
                " no ip dhcp snooping trust\n"
                "exit\n"
                "{% endfor %}"
                "{% for intf in untrusted_interfaces %}\n"
                "interface {{ intf | normalize_intf }}\n"
                " no ip dhcp snooping limit rate\n"
                "exit\n"
                "{% endfor %}"
                "no ip dhcp snooping\n"
                "{% else %}"
                "feature dhcp\n"
                "ip dhcp snooping\n"
                "ip dhcp snooping vlan {{ vlan_list }}\n"
                "{% for intf in trusted_interfaces %}\n"
                "interface {{ intf | normalize_intf }}\n"
                " ip dhcp snooping trust\n"
                "exit\n"
                "{% endfor %}"
                "{% for intf in untrusted_interfaces %}\n"
                "interface {{ intf | normalize_intf }}\n"
                " ip dhcp snooping limit rate {{ rate_limit }}\n"
                "exit\n"
                "{% endfor %}"
                "{% endif %}"
            ),
            "arista_eos": (
                "{% if action == 'disable' %}"
                "no ip dhcp snooping vlan {{ vlan_list }}\n"
                "{% for intf in trusted_interfaces %}\n"
                "interface {{ intf | normalize_intf }}\n"
                " no ip dhcp snooping trust\n"
                "exit\n"
                "{% endfor %}"
                "no ip dhcp snooping\n"
                "{% else %}"
                "ip dhcp snooping\n"
                "ip dhcp snooping vlan {{ vlan_list }}\n"
                "{% for intf in trusted_interfaces %}\n"
                "interface {{ intf | normalize_intf }}\n"
                " ip dhcp snooping trust\n"
                "exit\n"
                "{% endfor %}"
                "{% endif %}"
            ),
        },
        "test_cases": [
            {
                "name": "enable_with_trust_and_rate_limit",
                "vendor": "cisco_ios",
                "input": {"action": "enable", "vlans": "10,20-22", "trusted_interfaces": "gi0/24",
                          "untrusted_interfaces": "gi0/1\ngi0/2", "rate_limit": "15"},
                "expected_contains": ["ip dhcp snooping\n", "ip dhcp snooping vlan 10,20-22",
                                      "interface GigabitEthernet0/24", "ip dhcp snooping trust",
                                      "interface GigabitEthernet0/1", "ip dhcp snooping limit rate 15"],
                "expected_not_contains": ["no ip dhcp snooping"],
            },
            {
                "name": "disable_untrusts_and_removes",
                "vendor": "cisco_ios",
                "input": {"action": "disable", "vlans": "10", "trusted_interfaces": "gi0/24",
                          "untrusted_interfaces": "gi0/1", "rate_limit": "15"},
                "expected_contains": ["no ip dhcp snooping vlan 10", "no ip dhcp snooping trust",
                                      "no ip dhcp snooping limit rate", "no ip dhcp snooping\n"],
                "expected_not_contains": ["limit rate 15"],
            },
            {
                "name": "enable_without_untrusted_list_skips_rate_limit",
                "vendor": "cisco_ios",
                "input": {"action": "enable", "vlans": "10", "trusted_interfaces": "gi0/24",
                          "untrusted_interfaces": "", "rate_limit": "15"},
                "expected_contains": ["ip dhcp snooping vlan 10"],
                "expected_not_contains": ["limit rate"],
            },
            {
                "name": "rejects_bad_vlan_range",
                "vendor": "cisco_ios",
                "input": {"action": "enable", "vlans": "not-a-vlan", "trusted_interfaces": "",
                          "untrusted_interfaces": "", "rate_limit": "15"},
                "expect_error": True,
            },
        ],
    },
    "port_channel": {
        "label": "Configure Port-Channel (LACP/EtherChannel)",
        "description": "Bundles a list of member interfaces into a Layer 2 or Layer 3 port-channel using LACP (active) or static (on) mode.",
        "category": "Layer 2",
        "tags": ["layer2", "port-channel", "lacp", "interfaces"],
        "version": "1.0.0",
        "risk_level": "medium",
        "requires_confirmation": False,
        "min_privilege": 15,
        "fields": [
            {"name": "action", "label": "Action", "type": "select", "options": ["create", "remove"],
             "default": "create", "required": True},
            {"name": "channel_id", "label": "Port-channel number", "type": "number", "default": "1",
             "required": True, "min": 1, "max": 4096,
             "validation_message": "Port-channel number must be 1-4096."},
            {"name": "members", "label": "Member interfaces, one per line", "type": "textarea",
             "default": "GigabitEthernet0/1\nGigabitEthernet0/2", "required": True},
            {"name": "lacp_mode", "label": "Bundling mode", "type": "select",
             "options": ["active", "passive", "on"], "default": "active", "required": True,
             "help": "'active'/'passive' negotiate LACP; 'on' forces a static bundle with no negotiation protocol."},
            {"name": "layer", "label": "Port-channel type", "type": "select", "options": ["access", "trunk", "routed"],
             "default": "trunk", "required": True},
            {"name": "vlan", "label": "Access/native VLAN (ignored for 'routed')", "type": "number",
             "default": "1", "required": False, "min": 1, "max": 4094},
        ],
        "vendor_templates": {
            "cisco_ios": (
                "{% if action == 'remove' %}"
                "{% for intf in members %}\n"
                "interface {{ intf | normalize_intf }}\n"
                " no channel-group {{ channel_id }}\n"
                "exit\n"
                "{% endfor %}"
                "no interface Port-channel{{ channel_id }}\n"
                "{% else %}"
                "{% for intf in members %}\n"
                "interface {{ intf | normalize_intf }}\n"
                "{% if layer == 'routed' %} no switchport\n{% endif %}"
                " channel-group {{ channel_id }} mode {{ lacp_mode }}\n"
                "exit\n"
                "{% endfor %}"
                "interface Port-channel{{ channel_id }}\n"
                "{% if layer == 'trunk' %}"
                " switchport mode trunk\n"
                " switchport trunk native vlan {{ vlan }}\n"
                "{% elif layer == 'access' %}"
                " switchport mode access\n"
                " switchport access vlan {{ vlan }}\n"
                "{% else %}"
                " no switchport\n"
                "{% endif %}"
                " no shutdown\n"
                "exit\n"
                "{% endif %}"
            ),
            "cisco_nxos": (
                "{% if action == 'remove' %}"
                "{% for intf in members %}\n"
                "interface {{ intf | normalize_intf }}\n"
                " no channel-group {{ channel_id }} force mode {{ lacp_mode }}\n"
                "exit\n"
                "{% endfor %}"
                "no interface port-channel{{ channel_id }}\n"
                "{% else %}"
                "{% for intf in members %}\n"
                "interface {{ intf | normalize_intf }}\n"
                " channel-group {{ channel_id }} force mode {{ lacp_mode }}\n"
                "exit\n"
                "{% endfor %}"
                "interface port-channel{{ channel_id }}\n"
                "{% if layer == 'trunk' %}"
                " switchport mode trunk\n"
                " switchport trunk native vlan {{ vlan }}\n"
                "{% elif layer == 'access' %}"
                " switchport mode access\n"
                " switchport access vlan {{ vlan }}\n"
                "{% else %}"
                " no switchport\n"
                "{% endif %}"
                " no shutdown\n"
                "exit\n"
                "{% endif %}"
            ),
            "arista_eos": (
                "{% if action == 'remove' %}"
                "{% for intf in members %}\n"
                "interface {{ intf | normalize_intf }}\n"
                " no channel-group {{ channel_id }} mode {{ lacp_mode }}\n"
                "exit\n"
                "{% endfor %}"
                "no interface Port-Channel{{ channel_id }}\n"
                "{% else %}"
                "{% for intf in members %}\n"
                "interface {{ intf | normalize_intf }}\n"
                " channel-group {{ channel_id }} mode {{ lacp_mode }}\n"
                "exit\n"
                "{% endfor %}"
                "interface Port-Channel{{ channel_id }}\n"
                "{% if layer == 'trunk' %}"
                " switchport mode trunk\n"
                " switchport trunk native vlan {{ vlan }}\n"
                "{% elif layer == 'access' %}"
                " switchport mode access\n"
                " switchport access vlan {{ vlan }}\n"
                "{% else %}"
                " no switchport\n"
                "{% endif %}"
                " no shutdown\n"
                "exit\n"
                "{% endif %}"
            ),
        },
        "test_cases": [
            {
                "name": "create_trunk_port_channel_active",
                "vendor": "cisco_ios",
                "input": {"action": "create", "channel_id": "5", "members": "gi0/1\ngi0/2",
                          "lacp_mode": "active", "layer": "trunk", "vlan": "99"},
                "expected_contains": ["interface GigabitEthernet0/1", "channel-group 5 mode active",
                                      "interface Port-channel5", "switchport trunk native vlan 99"],
                "expected_not_contains": ["no channel-group"],
            },
            {
                "name": "create_routed_port_channel_static",
                "vendor": "cisco_ios",
                "input": {"action": "create", "channel_id": "6", "members": "gi0/3\ngi0/4",
                          "lacp_mode": "on", "layer": "routed", "vlan": "1"},
                "expected_contains": ["channel-group 6 mode on", "no switchport"],
                "expected_not_contains": ["switchport access vlan"],
            },
            {
                "name": "remove_port_channel",
                "vendor": "cisco_ios",
                "input": {"action": "remove", "channel_id": "5", "members": "gi0/1\ngi0/2",
                          "lacp_mode": "active", "layer": "trunk", "vlan": "99"},
                "expected_contains": ["no channel-group 5", "no interface Port-channel5"],
                "expected_not_contains": ["switchport mode trunk"],
            },
            {
                "name": "rejects_missing_members",
                "vendor": "cisco_ios",
                "input": {"action": "create", "channel_id": "5", "members": "",
                          "lacp_mode": "active", "layer": "trunk", "vlan": "99"},
                "expect_error": True,
            },
        ],
    },
    "custom": {
        "label": "Custom Jinja2 Template",
        "description": "Write your own Jinja2 template + JSON context for anything not covered above.",
        "category": "Custom",
        "tags": ["custom"],
        "version": "1.0.0",
        "risk_level": "medium",
        "requires_confirmation": False,
        "min_privilege": 15,
        "fields": [],
        "vendor_templates": {},
    },
}


def list_builtin_templates():
    """Returns the template library in a JSON-safe shape for the frontend
    (id, label, description, category, tags, risk metadata, fields, and
    which vendors it supports -- including anything reachable only via a
    VENDOR_ALIASES entry)."""
    result = []
    for tid, entry in BUILTIN_TEMPLATES.items():
        result.append({
            "id": tid,
            "label": entry["label"],
            "description": entry["description"],
            "category": entry.get("category", "Custom"),
            "tags": entry.get("tags", []),
            "version": entry.get("version"),
            "risk_level": entry.get("risk_level"),
            "requires_confirmation": entry.get("requires_confirmation", False),
            "min_privilege": entry.get("min_privilege"),
            "fields": entry["fields"],
            "vendors": _supported_vendors(entry) if tid != "custom" else "all",
        })
    return result


def search_templates(query: str = "", vendor: str = None, tags: list = None, category: str = None):
    """Filters the built-in template library by free-text query (matched
    against label/description), vendor support, tag overlap, and/or exact
    category -- used as the library grows past a handful of entries."""
    results = []
    for entry in list_builtin_templates():
        if vendor and vendor not in (entry["vendors"] if entry["vendors"] != "all" else [vendor]):
            continue
        if category and entry["category"] != category:
            continue
        if tags and not set(tags) & set(entry.get("tags", [])):
            continue
        if query:
            haystack = f"{entry['label']} {entry['description']} {' '.join(entry.get('tags', []))}".lower()
            if query.lower() not in haystack:
                continue
        results.append(entry)
    return results


def list_categories():
    """Distinct categories across the built-in library, for grouping the
    template picker in the UI (e.g. optgroups)."""
    seen = []
    for entry in BUILTIN_TEMPLATES.values():
        cat = entry.get("category", "Custom")
        if cat not in seen:
            seen.append(cat)
    return seen


_CIDR_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$")


def _parse_vlans_field(raw_text: str):
    """Parses the 'create_vlan' template's textarea field
    ('id,name[,ip/prefix]' per line) into structured dicts. Uses the
    stdlib `ipaddress` module (via validate_network) for the optional
    SVI address so invalid IPs/prefixes are rejected the same way they
    would be anywhere else in this app."""
    vlans = []
    for i, line in enumerate((raw_text or "").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 2:
            raise ValueError(f"Line {i}: expected 'id,name[,ip/prefix]', got '{line}'.")
        vlan_id_str, name = parts[0], parts[1]
        if not vlan_id_str.isdigit() or not (1 <= int(vlan_id_str) <= 4094):
            raise ValueError(f"Line {i}: VLAN id must be a number 1-4094, got '{vlan_id_str}'.")
        entry = {"id": int(vlan_id_str), "name": name, "ip": None, "mask": None, "prefix": None}
        if len(parts) >= 3 and parts[2]:
            try:
                ip, mask, prefix = validate_network(parts[2], allow_host=True)
            except ValueError as exc:
                raise ValueError(f"Line {i}: {exc}")
            entry["ip"], entry["mask"], entry["prefix"] = ip, mask, prefix
        vlans.append(entry)
    if not vlans:
        raise ValueError("No VLANs were provided.")
    return vlans


def _parse_routes_field(raw_text: str):
    routes = []
    for i, line in enumerate((raw_text or "").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) != 2:
            raise ValueError(f"Line {i}: expected 'network/prefix,next-hop', got '{line}'.")
        net_part, next_hop = parts
        try:
            network, mask, prefix = validate_network(net_part, allow_host=False)
            next_hop = validate_ip(next_hop)
        except ValueError as exc:
            raise ValueError(f"Line {i}: {exc}")
        routes.append({"network": network, "prefix": prefix, "mask": mask, "next_hop": next_hop})
    if not routes:
        raise ValueError("No routes were provided.")
    return routes


def _parse_interfaces_field(raw_text: str):
    interfaces = [line.strip() for line in (raw_text or "").splitlines() if line.strip()]
    if not interfaces:
        raise ValueError("No interfaces were provided.")
    return interfaces


def _parse_ntp_field(raw_text: str):
    servers = []
    for line in (raw_text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        # Best-effort: validate anything that LOOKS like an IP address;
        # pass hostnames (pool.ntp.org, etc.) through unchanged.
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", line):
            servers.append(validate_ip(line))
        else:
            servers.append(line)
    if not servers:
        raise ValueError("No NTP servers were provided.")
    return servers


def _parse_ospf_networks_field(raw_text: str):
    """Parses the 'ospf_process' template's textarea ('network/prefix'
    per line) into structured dicts, including a computed wildcard mask
    (inverse of the netmask) since classic 'router ospf' network
    statements use wildcard masks, not dotted-decimal netmasks."""
    networks = []
    for i, line in enumerate((raw_text or "").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            network, mask, prefix = validate_network(line, allow_host=False)
        except ValueError as exc:
            raise ValueError(f"Line {i}: {exc}")
        wildcard = str(ipaddress.ip_network(f"{network}/{prefix}", strict=True).hostmask)
        networks.append({"network": network, "mask": mask, "prefix": prefix, "wildcard": wildcard})
    if not networks:
        raise ValueError("At least one network is required.")
    return networks


def _parse_acl_entries_field(raw_text: str):
    """Parses the 'acl_standard' template's textarea
    ('permit|deny,network/prefix' per line) into structured dicts."""
    entries = []
    for i, line in enumerate((raw_text or "").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) != 2:
            raise ValueError(f"Line {i}: expected 'permit|deny,network/prefix', got '{line}'.")
        verb, net_part = parts
        if verb not in ("permit", "deny"):
            raise ValueError(f"Line {i}: action must be 'permit' or 'deny', got '{verb}'.")
        try:
            network, mask, prefix = validate_network(net_part, allow_host=False)
        except ValueError as exc:
            raise ValueError(f"Line {i}: {exc}")
        wildcard = str(ipaddress.ip_network(f"{network}/{prefix}", strict=True).hostmask)
        entries.append({"verb": verb, "network": network, "mask": mask, "prefix": prefix, "wildcard": wildcard})
    if not entries:
        raise ValueError("At least one ACL entry is required.")
    return entries


_VLAN_TOKEN_RE = re.compile(r"^\d{1,4}(-\d{1,4})?$")


def _parse_vlan_list_field(raw_text: str, label: str = "VLAN"):
    """Parses a comma-separated VLAN list/range string (e.g. '1,10,20-25')
    used by 'spanning_tree' and 'dhcp_snooping'. Returns
    (normalized_string, expanded_ids) where normalized_string is the
    input with whitespace stripped around commas (for embedding verbatim
    into a single CLI 'vlan <list>' argument) and expanded_ids is every
    individual VLAN id as an int (for looping per-VLAN, e.g. bridge
    priority). Every id (and every end of a range) is validated to be
    1-4094; a range's low end must not exceed its high end."""
    raw_text = (raw_text or "").strip()
    if not raw_text:
        return "", []
    tokens = [t.strip() for t in raw_text.split(",") if t.strip()]
    if not tokens:
        return "", []
    expanded = []
    for tok in tokens:
        if not _VLAN_TOKEN_RE.match(tok):
            raise ValueError(f"Invalid {label} entry '{tok}': expected a number (1-4094) or a range like '20-25'.")
        if "-" in tok:
            lo_s, hi_s = tok.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if not (1 <= lo <= 4094 and 1 <= hi <= 4094):
                raise ValueError(f"Invalid {label} range '{tok}': ids must be 1-4094.")
            if lo > hi:
                raise ValueError(f"Invalid {label} range '{tok}': start must not exceed end.")
            expanded.extend(range(lo, hi + 1))
        else:
            vid = int(tok)
            if not (1 <= vid <= 4094):
                raise ValueError(f"Invalid {label} id '{tok}': must be 1-4094.")
            expanded.append(vid)
    return ",".join(tokens), sorted(set(expanded))


def _parse_server_list_field(raw_text: str, label: str = "server"):
    """Generic 'one IP/hostname per line' parser (syslog servers, etc.)
    -- shares the same IP-if-it-looks-like-one / passthrough-otherwise
    logic as _parse_ntp_field, just under a configurable error label."""
    servers = []
    for line in (raw_text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", line):
            servers.append(validate_ip(line))
        else:
            servers.append(line)
    if not servers:
        raise ValueError(f"No {label}(s) were provided.")
    return servers


def _build_context(template_id: str, form_values: dict) -> dict:
    """Parses raw form_values into the structured Jinja2 context for one
    of the compound (textarea-driven) built-in templates. Raises
    ValueError with a user-facing message on bad input."""
    if template_id == "port_security":
        return {
            "action": (form_values.get("action") or "enable").strip(),
            "interfaces": _parse_interfaces_field(form_values.get("interfaces", "")),
            "max_mac": int(form_values.get("max_mac") or 1),
            "violation": (form_values.get("violation") or "shutdown").strip(),
            "sticky": bool(form_values.get("sticky", True)),
        }
    if template_id == "ospf_process":
        router_id = (form_values.get("router_id") or "").strip()
        return {
            "action": (form_values.get("action") or "create").strip(),
            "process_id": int(form_values.get("process_id") or 1),
            "router_id": router_id,
            "networks": _parse_ospf_networks_field(form_values.get("networks", "")),
            "area": (form_values.get("area") or "0").strip(),
            "passive_default": bool(form_values.get("passive_default", False)),
        }
    if template_id == "syslog_logging":
        return {
            "action": (form_values.get("action") or "create").strip(),
            "servers": _parse_server_list_field(form_values.get("servers", ""), label="syslog server"),
            "severity": (form_values.get("severity") or "informational").strip(),
            "source_interface": (form_values.get("source_interface") or "").strip(),
        }
    if template_id == "acl_standard":
        return {
            "action": (form_values.get("action") or "create").strip(),
            "acl_name": (form_values.get("acl_name") or "").strip(),
            "entries": _parse_acl_entries_field(form_values.get("entries", "")),
        }
    if template_id == "spanning_tree":
        vlan_list, vlan_ids = _parse_vlan_list_field(form_values.get("vlans", ""), label="VLAN")
        priority = int(form_values.get("priority") or 4096)
        if priority % 4096 != 0:
            raise ValueError("Bridge priority must be a multiple of 4096 (e.g. 0, 4096, 8192, ... 61440).")
        return {
            "action": (form_values.get("action") or "create").strip(),
            "stp_mode": (form_values.get("stp_mode") or "rapid-pvst").strip(),
            "vlan_list": vlan_list,
            "vlan_ids": vlan_ids,
            "priority": priority,
            "portfast_interfaces": _parse_interfaces_field(form_values.get("portfast_interfaces", "")) if (form_values.get("portfast_interfaces") or "").strip() else [],
        }
    if template_id == "aaa_tacacs_radius":
        action = (form_values.get("action") or "create").strip()
        shared_key = form_values.get("shared_key") or ""
        if action == "create" and not shared_key:
            raise ValueError("Shared secret key is required when creating an AAA server group.")
        return {
            "action": action,
            "protocol": (form_values.get("protocol") or "tacacs").strip(),
            "servers": _parse_server_list_field(form_values.get("servers", ""), label="AAA server"),
            "shared_key": shared_key,
            "local_fallback": bool(form_values.get("local_fallback", True)),
        }
    if template_id == "dhcp_snooping":
        vlan_list, _ = _parse_vlan_list_field(form_values.get("vlans", ""), label="VLAN")
        if not vlan_list:
            raise ValueError("At least one VLAN id/range is required.")
        return {
            "action": (form_values.get("action") or "enable").strip(),
            "vlan_list": vlan_list,
            "trusted_interfaces": _parse_interfaces_field(form_values.get("trusted_interfaces", "")) if (form_values.get("trusted_interfaces") or "").strip() else [],
            "untrusted_interfaces": _parse_interfaces_field(form_values.get("untrusted_interfaces", "")) if (form_values.get("untrusted_interfaces") or "").strip() else [],
            "rate_limit": int(form_values.get("rate_limit") or 15),
        }
    if template_id == "port_channel":
        return {
            "action": (form_values.get("action") or "create").strip(),
            "channel_id": int(form_values.get("channel_id") or 1),
            "members": _parse_interfaces_field(form_values.get("members", "")),
            "lacp_mode": (form_values.get("lacp_mode") or "active").strip(),
            "layer": (form_values.get("layer") or "trunk").strip(),
            "vlan": int(form_values.get("vlan") or 1),
        }
    if template_id == "create_vlan":
        return {
            "action": (form_values.get("action") or "create").strip(),
            "vlans": _parse_vlans_field(form_values.get("vlans", "")),
        }
    if template_id == "bulk_interfaces":
        context = {
            "interfaces": _parse_interfaces_field(form_values.get("interfaces", "")),
            "mode": (form_values.get("mode") or "access").strip(),
            "vlan": (form_values.get("vlan") or "").strip(),
            "trunk_allowed": (form_values.get("trunk_allowed") or "1-4094").strip(),
            "description": (form_values.get("description") or "").strip(),
            "enable": bool(form_values.get("enable", True)),
        }
        if not context["vlan"]:
            raise ValueError("A VLAN id is required.")
        return context
    if template_id == "static_route":
        return {
            "action": (form_values.get("action") or "create").strip(),
            "routes": _parse_routes_field(form_values.get("routes", "")),
        }
    if template_id == "banner":
        action = (form_values.get("action") or "set").strip()
        text = (form_values.get("text") or "").strip()
        if action == "set" and not text:
            raise ValueError("Banner text is required when setting a banner.")
        return {"action": action, "text": text}
    if template_id == "create_user":
        action = (form_values.get("action") or "create").strip()
        password = form_values.get("password") or ""
        if action == "create" and not password:
            raise ValueError("Password is required when creating a user.")
        return {
            "action": action,
            "username": (form_values.get("username") or "").strip(),
            "password": password,
            "privilege": int(form_values.get("privilege") or 15),
        }
    if template_id == "configure_ntp":
        return {
            "action": (form_values.get("action") or "create").strip(),
            "ntp_servers": _parse_ntp_field(form_values.get("ntp_servers", "")),
        }
    raise ValueError(f"No field-parsing logic registered for template '{template_id}'.")


def render_builtin_template(template_id: str, vendor: str, form_values: dict):
    """
    Renders one of the BUILTIN_TEMPLATES for the given vendor (or an alias
    of it -- see VENDOR_ALIASES), using structured form input rather than
    raw Jinja2 context (form_values keys/types follow each template's
    `fields` list). Every field is validated against its schema (see
    validate_all_fields) before the template-specific parsing runs, so a
    bad value gets a clear, field-specific error instead of a confusing
    Jinja2 traceback. Returns (rendered_text, None) or (None, "error message").
    """
    if not JINJA2_AVAILABLE:
        return None, "Jinja2 is not available in this environment (install failed)."
    entry = BUILTIN_TEMPLATES.get(template_id)
    if not entry:
        return None, f"Unknown template '{template_id}'."
    if template_id == "custom":
        return None, "Use /templates/render-custom for the custom template."

    template_text = _get_vendor_template(entry, vendor)
    if not template_text:
        return None, f"The '{entry['label']}' template doesn't support platform '{vendor}' yet."

    try:
        validate_all_fields(entry["fields"], form_values)
        context = _build_context(template_id, form_values)
    except ValueError as exc:
        return None, str(exc)

    return render_template_text(template_text, context)


# ==========================================================================
# Rollback (undo) templates -- for every built-in template that supports
# it, this maps the SAME parsed context back through an inverse Jinja2
# template, so a preview/push can offer "here's what applying this looks
# like, and here's the undo" side by side. Templates that are already
# reversible via their own `action` field (create_vlan, static_route,
# banner, create_user, configure_ntp) don't need a SEPARATE rollback
# entry -- rendering the same template with action flipped IS the
# rollback. `bulk_interfaces` has no clean single inverse (the "previous"
# state -- old VLAN, old description -- isn't known from the form alone),
# so it's intentionally left out here; use the automatic pre-change
# config snapshot (see app.py's rollback safety net) for that one instead.
# ==========================================================================
_ACTION_FLIP = {"create": "remove", "remove": "create", "set": "clear", "clear": "set",
                "enable": "disable", "disable": "enable"}


def render_rollback(template_id: str, vendor: str, form_values: dict):
    """
    For action-based templates, renders the inverse operation (flips
    'create'<->'remove' or 'set'<->'clear' and re-renders). Returns
    (rollback_text, None) on success, or (None, "reason") if this
    template doesn't support an automatic rollback.
    """
    entry = BUILTIN_TEMPLATES.get(template_id)
    if not entry or template_id == "custom":
        return None, "No rollback is available for this template."
    action_field = next((f for f in entry["fields"] if f["name"] == "action"), None)
    if not action_field:
        return None, "This template has no reversible 'action' field -- use the automatic pre-change snapshot on the Rollback tab instead."

    flipped_values = dict(form_values)
    current_action = (form_values.get("action") or action_field.get("default") or "create").strip()
    flipped_values["action"] = _ACTION_FLIP.get(current_action, current_action)
    return render_builtin_template(template_id, vendor, flipped_values)


def render_with_rollback(template_id: str, vendor: str, form_values: dict):
    """Convenience wrapper bundling the forward render with its rollback
    (if available) into a single {"apply":..., "rollback":...} result,
    used by the /templates/render endpoint."""
    rendered, error = render_builtin_template(template_id, vendor, form_values)
    if error:
        return None, error
    rollback_text, rollback_error = render_rollback(template_id, vendor, form_values)
    return {"apply": rendered, "rollback": rollback_text if not rollback_error else None,
            "rollback_unavailable_reason": rollback_error}, None


# ==========================================================================
# Dry-run / preview summary -- a quick "what does this actually do" report
# computed from the rendered text itself (no device contact needed), shown
# before a human confirms pushing it for real.
# ==========================================================================
_INTERFACE_LINE_RE = re.compile(r"^\s*(?:set interfaces |delete interfaces )?interface\s+(\S+)", re.IGNORECASE | re.MULTILINE)
_JUNOS_INTERFACE_RE = re.compile(r"^\s*(?:set|delete) interfaces\s+(\S+)", re.IGNORECASE | re.MULTILINE)
_VLAN_LINE_RE = re.compile(r"^\s*(?:no\s+)?vlan\s+(\d+)\b", re.IGNORECASE | re.MULTILINE)
_JUNOS_VLAN_RE = re.compile(r"^\s*(?:set|delete) vlans\s+(\S+)", re.IGNORECASE | re.MULTILINE)
_CONFIG_MODE_HINTS_RE = re.compile(
    r"^\s*(vlan\s+\d|interface\s|no\s|router\s|ip route|ip access-list|username\s|banner|ntp server|set\s|delete\s)",
    re.IGNORECASE | re.MULTILINE,
)


def _extract_interfaces(rendered: str):
    found = set(_INTERFACE_LINE_RE.findall(rendered)) | set(_JUNOS_INTERFACE_RE.findall(rendered))
    return sorted(found)


def _extract_vlans(rendered: str):
    found = set(_VLAN_LINE_RE.findall(rendered)) | set(_JUNOS_VLAN_RE.findall(rendered))
    return sorted(found, key=lambda v: (len(v), v))


def _detects_config_mode(rendered: str) -> bool:
    """Heuristic: does this rendered output look like it needs config
    mode to apply (as opposed to being pure read-only 'show' commands)?
    Used only for the preview summary -- the Run tab's actual config_mode
    checkbox is still the real, authoritative switch."""
    return bool(_CONFIG_MODE_HINTS_RE.search(rendered))


def build_render_summary(rendered: str) -> dict:
    """Computes the dry-run/preview summary for a rendered template:
    size, whether it looks like it needs config mode, which interfaces/
    VLANs it touches, and whether it contains a reload or a save-config
    command (both worth calling out before a human confirms a push)."""
    return {
        "line_count": len(rendered.splitlines()),
        "char_count": len(rendered),
        "config_mode_required": _detects_config_mode(rendered),
        "affects_interfaces": _extract_interfaces(rendered),
        "affects_vlans": _extract_vlans(rendered),
        "contains_reload": bool(re.search(r"\breload\b", rendered, re.IGNORECASE)),
        "contains_save": bool(re.search(r"\b(write\s+mem|copy run\S*\s+start\S*|commit)\b", rendered, re.IGNORECASE)),
    }


def render_with_summary(template_id: str, vendor: str, form_values: dict):
    """Renders a built-in template and attaches the dry-run/preview
    summary (see build_render_summary) -- lets a caller show "this will
    touch 3 interfaces and 2 VLANs, no reload, config mode required"
    before a human clicks confirm. Returns ({"rendered":..., "summary":...}, None)
    or (None, "error")."""
    rendered, error = render_builtin_template(template_id, vendor, form_values)
    if error:
        return None, error
    return {"rendered": rendered, "summary": build_render_summary(rendered)}, None


# ==========================================================================
# Diff preview against a device's CURRENT configuration (pasted in or
# fetched separately, e.g. from a recent backup) -- shows exactly which
# lines the template would ADD vs which existing lines it doesn't touch
# (a coarse, line-set-based diff; not a true config-aware merge, but
# enough to sanity-check "am I about to duplicate something that's
# already there" before pushing).
# ==========================================================================
def compute_diff(current_config: str, rendered_template: str) -> dict:
    """Returns {"to_add": [...], "to_remove": [...], "unchanged": N} by
    comparing the SET of non-blank lines in each text -- to_remove is
    lines present in current_config but not in the rendered template
    (informational only: the template doesn't necessarily intend to
    remove them, it just doesn't mention them)."""
    current = set(line.strip() for line in (current_config or "").splitlines() if line.strip())
    new = set(line.strip() for line in (rendered_template or "").splitlines() if line.strip())
    return {
        "to_add": sorted(new - current),
        "to_remove": sorted(current - new),
        "unchanged": len(new & current),
    }


# ==========================================================================
# Multi-device batch rendering -- the same template, different per-device
# values (e.g. a unique hostname/description per switch), in one call.
# ==========================================================================
def render_batch(template_id: str, vendor: str, device_contexts: list):
    """
    `device_contexts` = [{"hostname": "sw1", "form_values": {...}}, ...]
    Returns {hostname: {"rendered": str|None, "error": str|None}} -- a
    failure on one device's values doesn't stop the others from
    rendering.
    """
    results = {}
    for dc in device_contexts:
        hostname = dc.get("hostname") or f"device_{len(results) + 1}"
        rendered, error = render_builtin_template(template_id, vendor, dc.get("form_values") or {})
        results[hostname] = {"rendered": rendered, "error": error}
    return results


# ==========================================================================
# Config-mode auto-wrap -- optionally prepends/appends the vendor's
# config-mode enter/exit/save commands directly onto rendered output, for
# callers that want a fully self-contained script (e.g. to save as a
# stand-alone .txt file to push later via the "upload commands file"
# feature) rather than relying on the Run tab's own config-mode handling
# (which already does this automatically and is the recommended path --
# this helper exists for the export/offline use case specifically, so
# it's opt-in and never applied by the normal render endpoints by default).
# ==========================================================================
CONFIG_MODE_WRAPPERS = {
    "cisco_ios": ("configure terminal\n", "end\n", "write memory\n"),
    "cisco_nxos": ("configure terminal\n", "end\n", "copy running-config startup-config\n"),
    "arista_eos": ("configure\n", "end\n", "write\n"),
    "aruba_hp": ("configure terminal\n", "end\n", "write memory\n"),
    "juniper_junos": ("configure\n", "commit\n", ""),
}


def wrap_config_mode(rendered: str, vendor: str, save: bool = False) -> str:
    """Wraps `rendered` with the vendor's config-mode entry/exit (and,
    if save=True, its save-config command). Returns `rendered` unchanged
    for an unrecognized vendor."""
    wrapper = CONFIG_MODE_WRAPPERS.get(vendor)
    if not wrapper:
        return rendered
    enter, exit_cmd, save_cmd = wrapper
    body = rendered if rendered.endswith("\n") else rendered + "\n"
    result = enter + body + exit_cmd
    if save and save_cmd:
        result += save_cmd
    return result


# ==========================================================================
# Template self-tests -- every built-in template with `test_cases` gets
# exercised here; run_template_tests() is a CI-style hook (also reachable
# via GET /templates/selftest in app.py) that renders each case and checks
# expected substrings appear/don't appear, or that an error was raised
# when `expect_error: True` is set. Returns a list of failure strings
# (empty list = everything passed).
# ==========================================================================
def run_template_tests():
    failures = []
    for tid, entry in BUILTIN_TEMPLATES.items():
        for tc in entry.get("test_cases", []):
            case_label = f"{tid}/{tc['name']}"
            rendered, err = render_builtin_template(tid, tc["vendor"], tc["input"])
            if tc.get("expect_error"):
                if not err:
                    failures.append(f"{case_label}: expected an error but render succeeded")
                continue
            if err:
                failures.append(f"{case_label}: unexpected error: {err}")
                continue
            for needle in tc.get("expected_contains", []):
                if needle not in rendered:
                    failures.append(f"{case_label}: missing expected text {needle!r}\n--- rendered ---\n{rendered}")
            for needle in tc.get("expected_not_contains", []):
                if needle in rendered:
                    failures.append(f"{case_label}: unexpectedly contains {needle!r}\n--- rendered ---\n{rendered}")
    return failures
