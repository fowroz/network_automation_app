# 🌐 Network Console — Automation + Audit, Unified

A **browser-based network operations console** that combines two things in one app:

1. **Automation** — running health checks, executing SSH commands, pushing configuration changes, and scheduling recurring jobs across one or many network devices (Cisco IOS/IOS-XE, Cisco NX-OS, Arista EOS, Aruba/HP, Juniper Junos, and generic Linux hosts).
2. **Audit** — read-only, configuration-driven inventory and compliance data collection (hardware/asset tracking, security posture, capacity headroom, per-interface tables) via declarative YAML "Audit Profiles," with zero code changes needed to add a new field.

Both share the same saved device inventories, the same credential handling, the same run history, and the same recurring-schedule engine — surfaced through one unified dashboard (**🏠 Overview**) and one grouped navigation bar (**Act / Observe / Manage**), so you never have to context-switch between two separate tools.

No Docker, no Node.js, no build step, no separate database server to install. Everything runs from one Python process plus a handful of small local modules, with all data stored locally in a single SQLite file.

---

## Table of Contents

- [Features](#features)
- [Architecture / Project Structure](#architecture--project-structure)
- [Installation](#installation)
- [Running the App](#running-the-app)
- [How to Use It](#how-to-use-it)
  - [0. Overview — the unified dashboard](#0-overview--the-unified-dashboard)
  - [1. Run tab — basic checks & SSH commands](#1-run-tab--basic-checks--ssh-commands)
  - [2. Configuration Mode (pushing changes)](#2-configuration-mode-pushing-changes)
  - [3. Configuration Backups](#3-configuration-backups)
  - [4. Automated Health Checks (before/after)](#4-automated-health-checks-beforeafter)
  - [5. Rollback Safety Net](#5-rollback-safety-net)
  - [6. Dynamic Configuration Templates (Jinja2)](#6-dynamic-configuration-templates-jinja2)
  - [7. Parallel Execution / Scaling to Many Devices](#7-parallel-execution--scaling-to-many-devices)
  - [8. Saved Inventories](#8-saved-inventories)
  - [9. Run History](#9-run-history)
  - [10. 🔍 Audit — read-only inventory & compliance collection](#10--audit--read-only-inventory--compliance-collection)
  - [11. Scheduled Jobs (automation *and* audit)](#11-scheduled-jobs-automation-and-audit)
  - [12. Email / Slack Alerts](#12-email--slack-alerts)
  - [13. Logging & Audit Trail](#13-logging--audit-trail)
  - [14. AI Assistant (optional)](#14-ai-assistant-optional)
  - [15. 🔒 Ephemeral (RAM-only) Execution](#15--ephemeral-ram-only-execution)
  - [16. Report Diffing Across Audit Runs](#16-report-diffing-across-audit-runs)
- [Command Library](#command-library)
- [Config Templates Reference](#config-templates-reference)
- [Audit Profiles Reference](#audit-profiles-reference)
- [Security Notes](#security-notes)
- [Backend Architecture & Resilience Notes](#backend-architecture--resilience-notes)
- [API Reference (all endpoints)](#api-reference-all-endpoints)
- [Data Storage](#data-storage)
- [Troubleshooting / FAQ](#troubleshooting--faq)
- [Known Limitations](#known-limitations)
- [Changelog](#changelog)

---

## Features

### Core automation
- ✅ **Ping + TCP port checks** for any number of devices.
- ✅ **SSH command execution** using a single persistent interactive shell per device (works reliably against real network OS CLIs, unlike naive `exec_command()`-per-line approaches), with a **prompt-aware read loop** that correctly captures slow/large output (e.g. `show running-config` on a big config) instead of truncating it.
- ✅ **Multi-vendor support**: Cisco IOS/IOS-XE, Cisco NX-OS, Arista EOS, Aruba/HP (ArubaOS-CX & ProCurve), Juniper Junos, and generic Linux hosts.
- ✅ **Multi-threaded / parallel execution** — run against up to **200 devices** with up to **50 concurrent workers**, turning a 10-minute sequential job into a few seconds.
- ✅ **Per-device credential overrides** — mix devices with different logins in a single run (manual toggle or CSV/TXT upload).
- ✅ **SSH key authentication** and **jump-host / bastion tunneling**.
- ✅ **Cooperative run cancellation** (Stop button mid-run).
- ✅ **Auth-failure lockout protection** — automatically backs off after repeated failed logins to a device to avoid triggering account lockouts.
- ✅ **Connection pre-check / fast-fail** — when a run shares a common jump host, one quick TCP probe against it happens before dispatching to any device; if it's down, the *entire remaining batch* fails immediately instead of every device independently waiting out its own full connect timeout (a 50-device run with a dead jump host now fails in seconds, not tens of minutes).
- ✅ **🔒 Ephemeral (RAM-only) execution** — an opt-in toggle for a one-time run whose credentials are held in a wipeable in-memory buffer instead of an ordinary string and are actively zeroed the instant the run finishes. See [§15](#15--ephemeral-ram-only-execution).

### Configuration management
- ✅ **Configuration Mode** — push single or multiple config commands, with vendor-aware enter/exit/save handling and an explicit human confirmation step (never runs unattended).
- ✅ **Push config from a text file** — upload a `.txt`/`.cfg` file of commands directly into the commands box.
- ✅ **Dynamic configuration generation (Jinja2 templates)** — generate VLANs, bulk interface configs, static routes, banners, or fully custom templates from a simple form instead of hand-writing CLI for every device. See [§6](#6-dynamic-configuration-templates-jinja2) for the full feature set (validation, dry-run preview, auto-rollback, saved custom templates, etc.).
- ✅ **Before/after configuration diff** — see exactly what changed as a result of a config-mode run.
- ✅ **Dry-run** support (true dry-run on Juniper via `commit check` + `rollback 0`).
- ✅ **Configuration backups** — snapshot every device's running-config to a custom folder (or the default one), before any change, with a built-in backup browser (list/download/delete).
- ✅ **Rollback safety net** — every config-mode run automatically snapshots the full running-config beforehand; one click replays it back to undo a bad change.
- ✅ **Automated health checks (before/after)** — CPU, memory, and interface-status snapshots taken before and after a config change, automatically flagging regressions (e.g. an interface going down, a CPU spike).

### 🔍 Audit — read-only inventory & compliance collection *(new)*
- ✅ **Declarative "Audit Profiles"** — a YAML file per report type declares exactly which CLI command(s) to run and which regex/TextFSM field to extract into which output column. Adding a new data point to a report is a **YAML edit, never a code change**.
- ✅ **7 built-in profiles**: `hardware_audit` (asset/refresh tracking), `security_audit` (SSH/AAA/telnet/ACL/password-encryption compliance), `capacity_audit` (CPU/memory/interface headroom), `interface_inventory` (table mode — one row per interface via TextFSM), `vlan_audit` (VLAN inventory/hygiene), `routing_audit` (routing protocol/FHRP posture), `neighbor_discovery` (table mode — one row per CDP neighbor, for topology mapping). See [Audit Profiles Reference](#audit-profiles-reference).
- ✅ **Table mode** — parse a single command's output (e.g. `show ip interface brief`, `show cdp neighbors`) into multiple output rows per device via TextFSM/ntc-templates, instead of one row per device. TextFSM/ntc-templates are loaded **lazily** on first actual use (see [Backend Architecture & Resilience Notes](#backend-architecture--resilience-notes)) — regex-only profiles never pay that startup cost.
- ✅ **Command de-duplication** — if multiple fields need the same CLI command, it's sent to the device exactly once per run.
- ✅ **Sensitive-field redaction** — a field flagged `sensitive: true` (e.g. an SNMP community string) is redacted to `<REDACTED>` in every output row and log, while still confirming a value is present. This redaction is now also applied structurally to every report before it's persisted to SQLite (not just to the live audit-log trail) — see Security Notes.
- ✅ **Graceful per-device failure** — a device that's unreachable, has bad credentials, or returns unparseable output is marked `UNREACHABLE`/`AUTH_FAILED`/`PARTIAL`/`ERROR` in its own row; it never aborts the rest of the run.
- ✅ **Reuses saved Inventories** as its device source ("Audit Targets"), or accepts a typed-in device list — same credential-resolution rules as the Run tab.
- ✅ **CSV / XLSX / JSON output, generated on demand** — a report file is built **in memory** (`io.BytesIO`) the moment you click download, straight from the run's stored JSON; nothing is written to `./reports/` by default anymore, so months of scheduled runs never fill up your disk. See [Backend Architecture & Resilience Notes](#backend-architecture--resilience-notes).
- ✅ **Concurrent collection** via its own thread pool, deliberately capped lower than interactive runs when triggered by a schedule — see [Worker Pool Isolation](#backend-architecture--resilience-notes).
- ✅ **Report diffing across runs** — compare any two completed runs of the same profile (e.g. `hardware_audit` last week vs. today) and see exactly which devices changed, what changed on them (serial swap, IOS upgrade, new interface), and which devices appeared/disappeared. See [§16](#16-report-diffing-across-audit-runs).

### Unified dashboard & navigation *(new)*
- ✅ **🏠 Overview** landing page — at-a-glance stat cards, a Quick Actions grid, a **merged Recent Activity feed** (automation + audit runs interleaved chronologically), a **Health & Compliance Snapshot** widget (derived live from the latest `security_audit`/`capacity_audit` runs, with "⚡ Act on this" links straight into Config Templates), and a merged 14-day trend chart.
- ✅ **Grouped navigation** — **Act** (Overview, Run, Config Templates), **Observe** (Audit), **Manage** (Inventories, History, Schedules, Rollback, Settings) — with a responsive collapse on narrow screens.
- ✅ **Persistent global run indicator** — a small floating status box, visible from *any* tab, showing live device-completion progress ("6 / 12 devices complete") for whatever automation or audit job is currently running, with a one-click jump back to it.
- ✅ **Cross-linking, not just cross-referencing** — every "View →" / "Act on this →" link passes real state (device list, inventory id, profile id) into the destination tab instead of just switching tabs blind.
- ✅ **Deep-linking (`history.pushState`)** — every tab has its own addressable URL (e.g. `#auditView`), so the back/forward buttons and page reloads/bookmarks land on the right view. If a run or audit is actively streaming, navigating away (back/forward button, closing the tab, refreshing) prompts a confirmation first so you don't lose sight of it mid-flight.
- ✅ **Live-stream severity filtering** — `[All] / [⚠ Warnings Only] / [✕ Errors Only]` toggles above the Live Log let you instantly narrow a large (e.g. 50-device) run's output down to just what needs attention, without waiting for the run to finish.
- ✅ **Paginated report tables** — the Audit results table and Structured Report use client-side pagination (100 rows/page) plus an instant text filter, so a 2,400-row `interface_inventory`/`neighbor_discovery` run across 50 switches stays smooth and responsive instead of freezing the browser.

### Operations & reliability
- ✅ **Scheduled recurring jobs** — for **both** automation checks and audit collection, on one shared scheduler thread (see [§11](#11-scheduled-jobs-automation-and-audit)). Automation schedules are hard-restricted to read-only operations for safety; audit schedules are read-only by construction (an Audit Profile can never enter config mode). Configuration-mode changes always require a human to click "Run Now" on the Run tab.
- ✅ **Email & Slack alerts** — get notified when a run fails, an audit turns up device issues, or a health check detects a regression.
- ✅ **Professional logging** — rotating `logs/app.log` (general activity/errors) and a JSON-lines `logs/audit.log` (every config command, backup, rollback, and audit run, for compliance review), viewable right from the UI.
- ✅ **Run history** with search/filter, a 7/14/30-day trend chart, and per-schedule history — for both automation and audit runs.
- ✅ **Saved inventories** (device lists + settings) with inline editing, tags, notes, favorites, and duplication — shared by the Run tab *and* the Audit tab.
- ✅ **Optional AI assistant** (OpenRouter / NVIDIA NIM / local Ollama) for suggesting commands and analyzing run output — fully optional, nothing is sent anywhere unless you turn it on.
- ✅ **Worker pool isolation** — a scheduled job (either type) is capped at a much lower concurrent-worker limit than an interactive run, and at most one scheduled job runs at a time, so an intensive background audit never starves an interactive user's SSH threads. See [Worker Pool Isolation](#backend-architecture--resilience-notes).
- ✅ **Automated database pruning & compaction** — beyond the existing history/rollback row caps, the SQLite database now runs an incremental `PRAGMA incremental_vacuum` once at every startup, reclaiming disk space freed by already-deleted rows instead of letting the `.db` file only ever grow.

### Safety by design
- Configuration-mode changes always require an explicit on-screen confirmation checkbox.
- Scheduled jobs can **never** run configuration-mode changes — automation schedules are restricted to read-only checks/backups, and Audit Profiles can never contain a config-mode command in the first place.
- Scheduled jobs can **never** use ephemeral (RAM-only) credential mode — a schedule must be able to reuse its credentials on every future firing, which is the opposite of what ephemeral mode promises; both schedule-creation routes reject the combination outright.
- Credentials are **never stored** unless you explicitly opt in, and are then encrypted at rest (Fernet/AES via the `cryptography` package) — including per-device credential overrides nested inside a saved schedule's device list, not just the shared top-level username/password.
- An Audit Profile can only ever declare read commands — there is no code path from the Audit engine that can enter configuration mode on a device.
- Secret-looking values (passwords, SNMP community strings) are redacted both in `logs/audit.log` **and**, structurally, in every report persisted to `automation_console.db` — see Security Notes.
- Path-traversal protections on all file-serving endpoints (backups download/delete; audit report download is now generated in-memory and never touches a path at all).
- The Flask debug/reloader is off by default (prevents the Werkzeug interactive debugger — a code-execution risk — from being exposed on your network).

---

## Architecture / Project Structure

```
network_automation_app/
├── app.py                     # Main Flask application: routes, SSH execution engine,
│                               # validation, scheduler (automation + audit), command
│                               # library, alert dispatch, global job-progress tracker
├── storage.py                  # SQLite persistence layer (inventories, run history,
│                               # audit run history, schedules, rollback snapshots,
│                               # settings) + credential encryption + unified
│                               # activity/trend queries for the Overview dashboard
├── audit_bridge.py              # The ONLY module that imports inventory_collector/ --
│                               # profile discovery, the saved-Inventory -> collector
│                               # device-shape bridge, running an audit + saving the
│                               # report, deriving Overview's compliance findings,
│                               # generating on-demand report bytes, and diffing runs
├── redaction.py                  # Shared secret-pattern/key redaction, used by both
│                               # storage.py (report_json before it hits SQLite) and
│                               # templates_engine.py (logs/audit.log sanitization)
├── secure_credentials.py          # Ephemeral (RAM-only, actively-wiped) credential
│                               # wrapper for the opt-in one-time-run toggle
├── inventory_collector/         # Vendored read-only audit/inventory collection engine
│   ├── fields.py                 # Field definitions: regex/TextFSM extraction, transforms
│   ├── profile.py                 # YAML "Audit Profile" loading & validation
│   ├── inventory.py                # Device inventory CSV/YAML loading + filtering
│   ├── credentials.py              # Credential resolution (per-device / env var)
│   ├── textfsm_support.py           # TextFSM/ntc-templates structured parsing --
│   │                                # LAZILY imported on first actual use, not at startup
│   ├── collect.py                   # Per-device collection engine (device mode)
│   ├── table_mode.py                 # Per-device collection engine (table mode)
│   ├── runner.py                      # Concurrent multi-device collection + progress hook
│   ├── output.py                       # CSV / XLSX / JSON writers -- both the original
│   │                                    # disk-writing functions (still used by the
│   │                                    # standalone CLI) AND newer render_*_bytes()
│   │                                    # in-memory functions used by the web app
│   └── logging_setup.py                 # (unused standalone-CLI logging; app.py's own
│                                        # logging_setup.py is used when run inside the app)
├── audit_profiles/                # Built-in Audit Profile YAML manifests
│   ├── hardware_audit.yaml
│   ├── security_audit.yaml
│   ├── capacity_audit.yaml
│   ├── interface_inventory.yaml    # table mode example (TextFSM, per-interface rows)
│   ├── vlan_audit.yaml              # VLAN inventory/hygiene (regex only)
│   ├── routing_audit.yaml            # Routing protocol / FHRP posture (regex only)
│   ├── neighbor_discovery.yaml        # table mode (TextFSM, per-CDP-neighbor rows)
│   ├── poe_audit.yaml                  # table mode (TextFSM, per-PoE-port rows)
│   ├── mac_address_table.yaml            # table mode (TextFSM, per-MAC-entry rows)
│   └── aaa_audit.yaml                     # Centralized-auth (TACACS+/RADIUS) posture (regex only)
├── health_checks.py             # Before/after health-check command sets + regression comparison
├── alerts.py                     # Email (SMTP) and Slack (webhook) alert delivery
├── templates_engine.py            # Jinja2 dynamic configuration generation (sandboxed)
├── logging_setup.py                # Rotating app.log + JSON-lines audit.log setup
├── requirements.txt                 # Optional — for manual `pip install -r requirements.txt`
├── templates/
│   └── index.html                    # The entire single-page frontend (HTML + CSS + vanilla JS) --
│                                     # Overview dashboard, grouped nav, Run/Audit/Templates/
│                                     # Inventories/History/Schedules/Rollback/Settings tabs
├── automation_console.db            # SQLite database (created automatically on first run)
├── secret.key                        # Local encryption key for stored credentials (auto-generated)
├── logs/
│   ├── app.log                        # General application log (rotates at 5MB × 5 backups)
│   └── audit.log                       # JSON-lines audit trail (rotates at 5MB × 10 backups)
└── backups/                           # Default folder for configuration backups (auto-created)
```

No frontend build step — `templates/index.html` is plain HTML/CSS/JavaScript served directly by Flask, so there's no npm/webpack/Vite involved anywhere. `inventory_collector/` is vendored (a plain copy of the standalone `network_inventory_collector` project's engine, unmodified apart from an added optional `progress_cb` hook and the lazy-TextFSM-loading change) rather than installed as a pip dependency, so the whole app remains a single self-contained folder.

> Note: a `reports/` folder is **no longer created by default** — Audit report files (CSV/XLSX/JSON) are generated on demand, in memory, when you click "download" (see [Backend Architecture & Resilience Notes](#backend-architecture--resilience-notes)), so nothing accumulates on disk across scheduled runs. `reports/` still exists as a fallback location if you ever call `audit_bridge.run_audit(..., write_report_file=True)` yourself outside the web UI.

---

## Installation

### Requirements
- **Python 3.9+** (developed/tested on Python 3.13)
- Internet access on first run (to auto-install missing packages) — or run `pip install -r requirements.txt` yourself beforehand if you're offline

### Steps

1. **Get the code** — place the `network_automation_app/` folder wherever you like.

2. **(Optional) Create a virtual environment** — recommended but not required:
   ```bash
   python3 -m venv venv
   source venv/bin/activate        # Windows: venv\Scripts\activate
   ```

3. **Run it:**
   ```bash
   cd network_automation_app
   python3 app.py
   ```
   The first run automatically installs any missing dependencies (`Flask`, `paramiko`, `netmiko`, `cryptography`, `Jinja2`, `PyYAML`, `openpyxl`, `textfsm`, `ntc-templates`) using `pip`. You do **not** need to run `pip install` manually — though you can with `pip install -r requirements.txt` if you prefer to pre-install everything (e.g. for an offline/air-gapped environment where you've mirrored the packages).

4. **Open your browser** to:
   ```
   http://localhost:5000
   ```

That's it — no database setup, no Docker, no Node.js.

### What gets auto-installed
| Package | Required for | If missing |
|---|---|---|
| `Flask` | The web server itself | App cannot start (fatal) |
| `paramiko` | SSH command execution | SSH features disabled with a clear warning; ping/port checks still work |
| `netmiko` | Reserved for future extensibility | No effect on current features |
| `cryptography` | Encrypting saved passwords/keys at rest | "Remember credentials" and scheduling (both job types) are disabled (schedules require secure credential storage) |
| `Jinja2` | Dynamic configuration templates | The Templates tab is disabled with a clear message |
| `PyYAML` | Audit Profiles (YAML manifests) | The entire Audit tab is disabled with a clear message; automation features are unaffected |
| `openpyxl` | Audit XLSX report output | XLSX output format unavailable for Audit runs; CSV/JSON still work |
| `textfsm` + `ntc-templates` | `parser: textfsm` / table-mode Audit Profiles (`interface_inventory`, `neighbor_discovery`) | Regex-based Audit Profiles (`hardware_audit`, `security_audit`, `capacity_audit`, `vlan_audit`, `routing_audit`) still work fully; only TextFSM-parsed profiles are affected. **Not auto-installed at app startup** — these two packages are comparatively heavy (ntc-templates alone bundles hundreds of vendor template files), so they're only imported the *first time* a TextFSM/table-mode profile is actually run, not on every app launch. `/health`'s `audit_textfsm_available` field reflects whether they're present on disk without importing them. |

---

## Running the App

```bash
cd network_automation_app
python3 app.py
```

You'll see startup output like:
```
============================================================
 Network Automation Web Console (multi-device + AI)
 Open your browser at: http://localhost:5000
 paramiko available: True
 netmiko available:  True
 encryption available: True
============================================================
[SCHEDULER] Background scheduler thread started (checks every 20s for due jobs).
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
```

The app binds to `0.0.0.0:5000`, so it's reachable from other machines on your network at `http://<your-machine-ip>:5000` as well as `localhost`.

**To stop it:** `Ctrl+C` in the terminal.

**Advanced flags (environment variables):**
| Variable | Purpose | Default |
|---|---|---|
| `FLASK_DEBUG=1` | Enables Flask's debug/auto-reload mode for development | off |
| `AUTOMATION_LOG_LEVEL=DEBUG` | More verbose logging in `logs/app.log` | `INFO` |

> ⚠️ Don't set `FLASK_DEBUG=1` on a machine reachable by others — Flask's debug mode exposes an interactive in-browser debugger that allows arbitrary code execution if an unhandled exception occurs.

---

## How to Use It

### 0. Overview — the unified dashboard

**🏠 Overview** is the default landing tab. It gives you:
- **At-a-glance stat cards** — total devices across saved inventories, saved inventory count, active/total schedules, and the outcome of the most recent automation run and most recent audit run.
- **Quick Actions** — one click into Run Automation, Run an Audit Profile, Push a Config Template, or Schedule a Recurring Job.
- **Recent Activity** — the last several automation *and* audit runs, interleaved by time, each clickable straight into its own detail view.
- **Health & Compliance Snapshot** — as soon as you've run `security_audit` and/or `capacity_audit` at least once, this shows live findings (telnet still enabled on VTY lines, missing password-encryption, high CPU devices) pulled from the most recent report, with a link to view them and — where relevant — an "⚡ Act on this" shortcut straight into Config Templates.
- **14-Day Trend** — a small merged bar chart of automation vs. audit run volume.

A small floating indicator (bottom-right) appears automatically whenever an automation or audit job is running, on **any** tab, showing live progress and a one-click jump back to it.

### 1. Run tab — basic checks & SSH commands

1. Add one or more devices (host/IP + port) — manually, via **bulk paste**, or by **uploading a CSV/TXT file**.
   - CSV columns recognized (any order, header optional): `host`/`hostname`/`ip`, `port`, `username`, `password`.
   - Headerless CSV assumes `host,port,username,password` column order.
   - TXT format: one device per line, `host[:port[:username[:password]]]`.
   - Per-device username/password (from the file, or the 🔑 toggle on a device row) override the shared credentials for that device only — useful for mixed-credential environments.
2. Choose the device **vendor/platform** — this drives which command library and vendor-specific behavior (paging, config-mode entry/exit, etc.) is used.
3. Enter shared **credentials** (username/password, or an SSH private key) — or rely entirely on per-device credentials.
4. (Optional) Configure a **jump host / bastion** if your devices aren't directly reachable.
5. Type or paste **commands** into the commands box (one per line), or use:
   - **📖 Browse** — searchable library of common commands for the selected vendor.
   - **⬆ Upload .txt** — push configuration from a text file.
   - **✨ Ask AI to suggest commands** — describe a task in plain English (requires an AI provider configured).
6. Check **"execute commands over SSH"**, choose sequential or **parallel** execution (and how many workers), and click **▶ Run Automation**.
7. Watch the **Live Log** stream in real time, or switch to the **Structured Report** tab for a clean per-device summary once the run finishes.

### 2. Configuration Mode (pushing changes)

Check **"⚠ Enable Configuration Mode"** on the Run tab. This unlocks:
- Automatic vendor-appropriate entry (`configure terminal` / `configure`) and exit (`end` / `exit`) around your commands.
- **Save configuration** — persist the change to NVRAM/startup-config (`write memory` / `commit`, never sent unless you check this).
- **Show before/after config diff** — captures the full config before and after, and shows a line-by-line diff.
- **Dry-run** — true dry-run on Juniper only (`commit check` + `rollback 0`); other platforms show a warning since they apply config immediately as typed.
- **🩺 Automated health check** — see [section 4](#4-automated-health-checks-beforeafter).
- A **mandatory confirmation checkbox** — you must explicitly acknowledge you're changing real device configuration before the run will start. This cannot be bypassed, including on schedules (config-mode is never allowed on scheduled jobs).

A full configuration snapshot is **always** taken automatically before any config-mode change (regardless of whether you enabled the diff option) — see [Rollback Safety Net](#5-rollback-safety-net).

### 3. Configuration Backups

Check **"💾 Back up device configuration"** on the Run tab (works with or without config-mode — a pure backup run is completely read-only and safe to schedule):
- Fetches each device's running-config and saves it as a timestamped `.cfg` file (`<host>_<port>_<timestamp>.cfg`).
- Choose a custom save folder, or leave blank for the built-in default (`network_automation_app/backups/`).
- Browse, download, and delete saved backups directly from the **📂 Browse saved backups** button.
- Works great combined with **Scheduled Jobs** for automatic daily backups.

### 4. Automated Health Checks (before/after)

Check **"🩺 Run automated health check before & after"** (requires Configuration Mode). Before applying your commands, the app runs a small set of fast, read-only diagnostic commands (CPU load, memory, interface status) appropriate for the device's platform, then runs them again after the change and compares the two snapshots. It flags clear regressions:
- Any interface that was **up** before and is **down** after.
- CPU utilization crossing a critical threshold, or jumping sharply, after the change.

Regressions are shown in the live log/report immediately (per device, as soon as detected — not after the whole run finishes) and can trigger an [alert](#12-email--slack-alerts).

### 5. Rollback Safety Net

Every configuration-mode run automatically snapshots the device's full running-config immediately before any change — no extra steps needed. Go to the **🛟 Rollback** tab to:
- See every snapshot taken (per device, with timestamp and size).
- **👁 View** the raw snapshotted configuration.
- **↩ Rollback** — re-pushes the snapshot back to the device through the same config-mode SSH path, line by line.
- **🗑 Delete** old snapshots you no longer need (the app also automatically prunes to the 10 most recent per device).

> ⚠️ Rollback is a **best-effort replay**, not an atomic/transactional rollback (most vendors don't offer one without staging a whole file to flash first). A line that no longer applies cleanly may show a small error while the rest of the rollback still applies — always review the resulting log/diff.

### 6. Dynamic Configuration Templates (Jinja2)

The **🧩 Config Templates** tab lets you generate the exact CLI to push instead of hand-typing it for every device. **15 built-in templates** (14 parameterized + a custom/freeform option) are provided out of the box — see the [Config Templates Reference](#config-templates-reference) table for the full list — including:
- **Create / Remove VLAN(s)** — one or more VLANs (and optional SVI/L3 interface) from a simple `id,name[,ip/prefix]` list; an `action` field lets the same template create or remove.
- **Configure Interfaces in Bulk** — apply the same access/trunk settings to a list of interfaces at once (short names like `gi0/1` are auto-normalized to `GigabitEthernet0/1`).
- **Add / Remove Static Route(s)**, **Set / Clear Login Banner**, **Add / Remove NTP Server(s)**, **Configure OSPF Routing Process**, **Configure Port Security**, **Configure Syslog / Remote Logging**, **Create / Remove Standard ACL**.
- **Configure Spanning Tree** — STP mode, per-VLAN bridge priority (validated as a multiple of 4096), and PortFast + BPDU Guard on a list of access ports; **requires extra confirmation** (a loop-prevention misconfiguration can take a whole network down).
- **Configure Port-Channel (LACP/EtherChannel)** — bundles a list of member interfaces into an access/trunk/routed port-channel using LACP (`active`/`passive`) or a static (`on`) bundle.
- **Configure AAA (TACACS+/RADIUS) Authentication** — centralizes login/enable authentication against one or more TACACS+ or RADIUS servers with an optional local fallback; the shared secret key field is masked and **redacted before ever being written to `logs/audit.log`**; **requires extra confirmation**.
- **Configure DHCP Snooping** — enables DHCP snooping on a VLAN list, trusts uplink ports, and optionally rate-limits a *separate* list of untrusted access ports (no hardcoded interface ranges — every interface you want rate-limited is explicit).
- **Create / Remove Local User** — a local device login account; the password field is masked (never shown in plaintext) and is **redacted before ever being written to `logs/audit.log`** (see Security Notes).
- **Custom Jinja2 Template** — write your own template with `{{ variable }}` placeholders and a JSON context object; a "🔍 Detect variables" button finds the variables for you, and you can **save it under a name** to reuse later without retyping it.
- **Search / filter** the library by name, description, tag, vendor, or category; templates are grouped into categories (Layer 2, Layer 3, System Services, Security, Custom) in the picker.

Every render also shows a **dry-run preview summary** (line/char count, whether it looks like it needs config mode, which interfaces/VLANs it touches, and whether it contains a `reload` or save-config command) and, for any template with a reversible action, an **auto-generated rollback** (the inverse operation) you can load into the Run tab with one click.

Click **▶ Use in Run tab** to load the generated commands straight into the Run tab's commands box, where they go through the exact same validation, confirmation, diff, health-check, and rollback-snapshot flow as any manually-typed command. Templates render in a **sandboxed** Jinja2 environment (dangerous attribute access is blocked) with a **5-second render timeout** and a capped loop-iteration limit to protect against a runaway/malicious template hanging the app. Field values are validated against each template's schema (type, min/max, regex pattern) both in the browser and on the server before rendering — IP/network fields specifically use Python's `ipaddress` module, so invalid addresses, bad prefixes, or "host bits set where a network was expected" are rejected with a clear message instead of silently producing a broken command.

### 7. Parallel Execution / Scaling to Many Devices

On the Run tab, check **"Run devices in parallel"** and set **"Max concurrent devices"** (up to 50). Instead of connecting to devices one at a time, the app opens up to N simultaneous SSH sessions using a thread pool, streaming interleaved (but clearly tagged) output from all of them live. Up to **200 devices** are supported per run. In testing, 30 devices that took ~83 seconds sequentially completed in **under 3 seconds** in parallel. The Audit engine ([§10](#10--audit--read-only-inventory--compliance-collection)) uses the same thread-pool pattern independently, with its own worker-count setting.

### 8. Saved Inventories

Save a device list + settings under a name (**💾 Save Inventory**) so you don't have to re-enter it every time:
- Optionally **remember credentials**, encrypted at rest (only if you explicitly opt in).
- **Inline editing** — rename, edit devices, tags, and notes without creating a duplicate entry.
- **Favorite**, **duplicate**, and **delete** inventories from the Inventories tab.
- Load an inventory back into the Run tab with one click.
- **Shared with the Audit tab** — pick a saved Inventory as an "Audit Target" and its device list + credentials are reused directly (per-device credential overrides on the inventory always take priority over shared audit credentials, exactly like on the Run tab).

### 9. Run History

Every run (manual or scheduled) is recorded with its full structured report. The **History** tab offers:
- Search/filter by trigger type (manual/scheduled) and failure status.
- A visual **trend chart** (7/14/30 days) of run volume and failure counts.
- Per-run detail view (re-opens the structured report).
- Clear all / delete individual runs.

(Audit runs have their own equivalent history list inside the **🔍 Audit** tab itself — see below — and both histories are what feed the Overview dashboard's merged Recent Activity feed.)

### 10. 🔍 Audit — read-only inventory & compliance collection

The **🔍 Audit** tab runs a declarative, read-only **Audit Profile** against a device list — never changes configuration. Click the **"? Audit vs. Run"** badge on the tab itself for a quick side-by-side explanation of how it differs from the Run tab.

**To run an audit:**
1. Pick an **Audit Profile** from the dropdown (see [Audit Profiles Reference](#audit-profiles-reference) below for what each one collects) — a hint shows how many fields/columns it produces and which unique CLI commands it will send.
2. Pick the target **platform** (Netmiko-style `device_type`, e.g. `cisco_ios`) so the right command syntax is used.
3. Choose an **Audit Target**: either a saved Inventory (reuses its device list + credentials), or type devices in directly below.
4. Supply shared credentials if your devices don't carry their own, set a worker count, and click **▶ Run Audit**.
5. The full structured report renders as a table (STATUS/MISSING_FIELDS/ERROR metadata columns plus every profile-declared data column), with a download link to the CSV/XLSX/JSON file that was also written to `reports/`.
6. Click **📅 Schedule this Audit** to save the exact same configuration as a recurring job — see [§11](#11-scheduled-jobs-automation-and-audit).

**Audit History** (below the run form on the same tab) lists every past audit run — view, delete individually, clear all, or **check two runs of the same profile and click "🔍 Compare Selected Runs"** to see what changed between them (see [§16](#16-report-diffing-across-audit-runs)).

**What an Audit Profile actually is:** a YAML file under `audit_profiles/` declaring a list of `fields`, each with a `name`, output `column`, the exact CLI `command` to run, and either a `regex` (with optional capture `group`, `occurrence` reduction — first/last/all/join/count —, `transform`, and a `default` for "no match") or `parser: textfsm` (structured parsing via ntc-templates or a custom `.textfsm` file). A field can be marked `required` (missing data marks the row `PARTIAL`), `sensitive` (redacted in output), or restricted to specific `platforms`. **Adding a new column to a report never requires touching Python** — just add a field to the YAML.

### 11. Scheduled Jobs (automation *and* audit)

Both job types share **one** background scheduler thread and **one** `schedules` table (distinguished internally by a `job_type` column), so the Schedules tab shows one unified list with a type badge (▶ Automation / 🔍 Audit) per row.

**Automation schedules** — create from the Schedules tab (**+ New Schedule**) or the Run tab's **💾 Save as Scheduled Task** button:
- **Restricted to read-only operations** for safety: ping/port checks, show commands, and config **backups** (backups are safe/read-only from the device's perspective). Configuration-mode changes can never be scheduled — always require a human on the Run tab.

**Audit schedules** — create from the Audit tab's **📅 Schedule this Audit** button:
- Read-only **by construction** — an Audit Profile has no config-mode code path at all, so there's no separate restriction to enforce.
- "Run Now" and "History" on an audit schedule's row correctly show the audit-shaped report/history (device counts + OK/Issue counts) instead of the automation-shaped one.

Both types support: optional **notify on failure/issues** (per schedule), a global "notify on any run failure" option under Settings, viewing a schedule's own run history, editing its interval, running it immediately on demand, enabling/disabling, and deleting it. Credentials saved with a schedule — including per-device credential overrides inside a mixed-credential device list, not just the shared username/password — are always encrypted at rest; schedule creation is refused (with a clear error) if the `cryptography` package isn't available and a password would need to be stored.

### 12. Email / Slack Alerts

Configure under the **⚙ Settings** tab:
- **Email** — SMTP host/port/credentials, from/to addresses, STARTTLS or implicit TLS.
- **Slack** — an Incoming Webhook URL.
- Choose when to be notified: on any run failure (automation or audit), and/or immediately on a health-check regression.
- **📨 Send Test Alert** to verify your configuration works before relying on it.

Credentials (SMTP password, Slack webhook URL) are encrypted at rest the same way as saved inventory/schedule credentials.

### 13. Logging & Audit Trail

Also under **⚙ Settings**:
- **`logs/app.log`** — rotating general application log (connections, errors, scheduler activity for both job types, alert delivery).
- **`logs/audit.log`** — a JSON-lines compliance trail: every individual config-mode command applied (with success/failure), every backup taken, every rollback executed, every **Audit Profile run** (manual or scheduled, with device count and outcome), and every alert sent — each tagged with host/port/vendor (or profile name), and whether it was manual or scheduled.

View the last few hundred lines of either log directly from the UI (**View app.log** / **View audit.log** buttons), or open the files directly for deeper analysis/archival.

### 14. AI Assistant (optional)

Fully optional — if you leave the AI provider set to "None", none of this code path runs. When configured (OpenRouter, NVIDIA NIM, or a local Ollama install), you get:
- **✨ Ask AI to suggest commands** — describe what you want to check/configure in plain English, get back a list of relevant CLI commands for the selected vendor.
- **✨ AI Assistant** output tab — after a run, ask the AI to analyze the log/report and summarize failures/anomalies with recommendations.

API keys you enter are sent directly from your browser to the local Flask server for a single request, forwarded to the provider you chose, and are **never stored or logged**.

### 15. 🔒 Ephemeral (RAM-only) Execution

Check **"🔒 Ephemeral run"** on the Run tab's Credentials step (or the equivalent checkbox on the Audit tab) for a one-time run whose credentials are held differently in memory for the duration of that single request:
- Every credential field (password, private key text/passphrase, jump-host password/key) is wrapped in a `SecureValue` — a mutable `bytearray`-backed buffer — instead of an ordinary Python string, for as long as the run is executing.
- The instant the run finishes (success, failure, or cancellation — enforced via a `finally` block), every one of those buffers is **actively overwritten with zeros** and dropped.
- This is **not available for saved Schedules** of either type — a schedule needs to reuse its credentials on every future firing, which is the opposite of what ephemeral mode promises; both schedule-creation routes reject the combination with a clear error.

> **Honest limitation:** Python strings are immutable, and paramiko/netmiko's own authentication calls require a real `str` at the moment they actually connect — so a brief, garbage-collected plaintext copy unavoidably exists for that instant, exactly as it would with any pure-Python SSH client. What ephemeral mode actually guarantees is that **outside** that unavoidable instant, the credential lives in a buffer this app can (and does) synchronously zero on completion, rather than sitting as an ordinary string for the entire lifetime of the request/payload object. See `secure_credentials.py`'s module docstring for the full explanation.

### 16. Report Diffing Across Audit Runs

In the Audit tab's **Audit History** table, check exactly **two** runs of the same profile (e.g. `hardware_audit` from last week and today) and click **🔍 Compare Selected Runs**:
- **Changed devices** — a table of every field that differs between the two runs for a device present in both (e.g. a serial number swap after a hardware replacement, an IOS version upgrade, a new interface appearing), old value vs. new value side by side.
- **New devices** — present in the newer run but not the older one.
- **Removed devices** — present in the older run but missing from the newer one (decommissioned, renamed, or unreachable).
- **Unchanged count** — a quick sanity check that most of your fleet is stable.

Devices are matched across runs by hostname (falling back to IP if the profile didn't collect one) so this stays correct even if a device's IP changed between runs. Table-mode profiles (`interface_inventory`, `neighbor_discovery`) aren't diffable this way — they don't have a single stable per-row identity across runs — the comparison route returns a clear error if you try.

---

## Command Library

Built-in, searchable command libraries are provided per vendor, split into **Show/Verification** commands (read-only) and **Config-mode** commands, auto-switching based on whether Configuration Mode is checked.

### Cisco IOS / IOS-XE — Show / Verification
| Category | Commands |
|---|---|
| **Show / Verification** | `show version`, `show running-config`, `show startup-config`, `show inventory`, `show processes cpu`, `show processes memory`, `show memory statistics`, `show clock`, `show environment[ all]`, `show boot`, `show file systems`, `show license[ all]`, `show module`, `show diag`, `show platform`, `show redundancy`, `show flash`, `show switch`, `show ntp status`, `show ntp associations`, `show power inline`, `show bootvar` |
| **Interfaces** | `show ip interface[ brief]`, `show interfaces[ status\|description\|counters[ errors]\|summary\|trunk\|switchport\|transceiver]`, `show ipv6 interface brief`, `show cdp neighbors[ detail]`, `show lldp neighbors[ detail]`, `show controllers`, `show interfaces status err-disabled`, `show interfaces stats`, `show lacp neighbor`, `show pagp neighbor`, `clear counters` |
| **Routing** | `show ip route[ summary]`, `show ip protocols`, `show ip ospf neighbor`, `show ip ospf database`, `show ip ospf interface`, `show ip bgp[ summary\|neighbors]`, `show ip eigrp neighbors`, `show ip arp[ inspection]`, `show ipv6 route`, `show ipv6 protocols`, `traceroute`, `ping`, `show ip nat translations`, `show ip nat statistics`, `show standby brief`, `show vrrp brief`, `show ip cef`, `show ip eigrp topology`, `show ip route ospf`, `show ip route bgp`, `show ip mroute` |
| **VLAN / Switching** | `show vlan[ brief]`, `show spanning-tree[ summary\|detail]`, `show mac address-table[ dynamic]`, `show etherchannel[ summary\|detail]`, `show port-security[ address]`, `show vtp status`, `show errdisable recovery`, `show spanning-tree blockedports` |
| **Security / ACLs** | `show ip access-lists`, `show access-lists`, `show crypto isakmp sa`, `show crypto ipsec sa`, `show crypto session`, `show aaa sessions`, `show users`, `show privilege`, `show ip ssh`, `show line`, `show dot1x all`, `show authentication sessions`, `show ip dhcp snooping binding`, `show ip source binding`, `show crypto ikev2 sa`, `show radius statistics` |
| **Diagnostics / Troubleshooting** | `show logging[ \| include]`, `show tech-support[ \| redirect]`, `show debugging`, `show processes cpu sorted`, `undebug all`, `show processes cpu history`, `show logging \| count`, `test cable-diagnostics tdr interface` |

### Cisco IOS / IOS-XE — Configuration
| Category | Commands |
|---|---|
| **Enter / Exit / Save** | `configure terminal`, `end`, `exit`, `write memory`, `copy running-config startup-config`, `copy running-config tftp`, `show running-config`, `reload` |
| **Interface Config** | `interface <name>`, `interface range <range>`, `description`, `ip address` / `no ip address`, `switchport mode access\|trunk`, `switchport access vlan`, `switchport trunk allowed/native vlan`, `speed/duplex auto`, `no shutdown` / `shutdown`, `spanning-tree portfast`, `channel-group 1 mode active`, `mtu 9000`, `ipv6 address dhcp`, `ipv6 address autoconfig`, `power inline auto`, `power inline never`, `storm-control broadcast level 10.0`, `spanning-tree bpduguard enable` |
| **VLAN Config** | `vlan`, `name`, `vlan database`, `interface vlan`, `ip address dhcp` |
| **Routing Config** | `router ospf/bgp/eigrp`, `network ... area 0`, `ip route 0.0.0.0 0.0.0.0 <next-hop>` (static default route), `neighbor ... remote-as`, `default-information originate`, `passive-interface default`, `ipv6 unicast-routing`, `standby 1 ip`, `standby 1 priority 110` |
| **Security / AAA / ACL** | `ip access-list extended/standard`, `permit/deny ip any any`, `line vty 0 4`, `login local`, `transport input ssh`, `username ... secret`, `enable secret`, `aaa new-model`, `ip ssh version 2`, `crypto key generate rsa`, `service password-encryption` |
| **System / Hostname** | `hostname`, `banner motd`, `ntp server`, `logging host`, `snmp-server community`, `clock timezone`, `ip domain-name` |
| **Services / Management** | `ip dhcp pool <name>`, `ip domain name <domain>`, `ip name-server <ip>` |

Equivalent (platform-appropriate) libraries are also built in for **Cisco NX-OS**, **Arista EOS**, **Aruba/HP**, **Juniper Junos**, and **generic Linux hosts** — accessible via the same **📖 Browse** button and autocomplete once you select that vendor.

---

## Config Templates Reference

| Template | Category | Risk | Confirmation Required | Reversible (`action` field) | Notes |
|---|---|---|---|---|---|
| `create_vlan` | Layer 2 | low | no | yes (create/remove) | Optional SVI/L3 interface per VLAN |
| `bulk_interfaces` | Layer 2 | medium | no | no* | *No single clean inverse from form data alone — use the automatic pre-change Rollback snapshot instead |
| `static_route` | Layer 3 | medium | no | yes (create/remove) | Validated via `ipaddress` (rejects host-bits-set, bad prefixes) |
| `ospf_process` | Layer 3 | medium | no | yes (create/remove) | Advertises 1+ networks into an area; auto-computes wildcard masks |
| `banner` | System Services | low | no | yes (set/clear) | |
| `configure_ntp` | System Services | low | no | yes (create/remove) | Validates IP servers; passes hostnames through as-is |
| `syslog_logging` | System Services | low | no | yes (create/remove) | Optional stable source-interface |
| `create_user` | Security | **high** | **yes** | yes (create/remove) | Password field masked + redacted from `logs/audit.log` |
| `port_security` | Security | medium | no | yes (enable/disable) | Sticky or static MAC learning, configurable violation action |
| `acl_standard` | Security | **high** | **yes** | no | Every entry validated as a real network/prefix (or `0.0.0.0/0` for "any") |
| `spanning_tree` | Layer 2 | **high** | **yes** | yes (create/remove) | STP mode + per-VLAN bridge priority (validated as a multiple of 4096) + PortFast/BPDU Guard on a list of access ports |
| `port_channel` | Layer 2 | medium | no | yes (create/remove) | Bundles member interfaces into an access/trunk/routed LACP or static (`on`) port-channel |
| `aaa_tacacs_radius` | Security | **high** | **yes** | yes (create/remove) | Centralized TACACS+/RADIUS login+enable auth with optional local fallback; shared key field masked + redacted |
| `dhcp_snooping` | Security | medium | no | yes (enable/disable) | Trusts uplink ports, optionally rate-limits a separate list of untrusted access ports |
| `custom` | Custom | medium | no | no | Freeform Jinja2 + JSON context, optionally saved under a name |

Every template ships with **self-test cases** (see `templates_engine.run_template_tests()` / the `GET /templates/selftest` endpoint) that render each vendor variant with known input and assert on the output — run automatically whenever you check the Templates tab's self-test, and part of the standard regression pass whenever a template is added or changed.

**Adding your own template:** add an entry to `BUILTIN_TEMPLATES` in `templates_engine.py` (label, fields schema, per-vendor Jinja2 source, test cases) following the pattern of any existing entry — no other file needs to change, and it appears in the picker automatically.

---

## Audit Profiles Reference

| Profile | Mode | Purpose | Fields | Unique Commands | Notes |
|---|---|---|---|---|---|
| `hardware_audit` | device | Asset / refresh tracking — model, PID, serial, IOS version, uptime, config register, last config change | 9 | 4 | Good starting point for a lifecycle/EOL inventory export |
| `security_audit` | device | Compliance checks — SSH version, telnet-on-VTY, AAA model, banner presence, password-encryption, ACL count, local user count, SNMP RO community (redacted) | 9 | 9 | Feeds the Overview dashboard's Health & Compliance Snapshot |
| `capacity_audit` | device | Performance / headroom — CPU (5s/1m/5m), memory free, interface up/down counts, CRC error lines | 9 | 5 | Also feeds the Compliance Snapshot's high-CPU finding |
| `interface_inventory` | **table** | One row per interface (not per device) — interface name, IP, status, protocol | 4 columns | 1 | Demonstrates TextFSM/ntc-templates table mode; requires `textfsm` + `ntc-templates` |
| `vlan_audit` | device | VLAN inventory/hygiene — total/active/suspended VLAN counts, whether VLAN 1 still carries access ports, VTP mode | 6 | 3 | Regex-only; flags a common security/best-practice finding (VLAN 1 in active use) |
| `routing_audit` | device | Routing posture — which of OSPF/BGP/EIGRP are running, default-route presence, route-table size, redistribution and FHRP (HSRP/VRRP) configuration | 8 | 6 | Regex-only; redistribution is a common unintentional routing-loop/leak risk worth tracking over time |
| `neighbor_discovery` | **table** | One row per CDP neighbor (not per device) — neighbor name, local/remote interface, platform, capabilities | 5 columns | 1 | For building/validating a physical topology map or spotting unexpected devices; requires `textfsm` + `ntc-templates` |
| `poe_audit` | **table** | One row per PoE-capable port — admin/operational status, power draw, connected device class, per-port wattage ceiling | 7 columns | 1 | Capacity planning before adding more phones/APs/cameras; requires `textfsm` + `ntc-templates` |
| `mac_address_table` | **table** | One row per learned MAC address — VLAN, MAC, type (dynamic/static), port | 4 columns | 1 | Finest-grained L2 visibility; useful for rogue-MAC investigations and flap troubleshooting; requires `textfsm` + `ntc-templates` |
| `aaa_audit` | device | Centralized-auth posture — whether `aaa new-model` + TACACS+/RADIUS actually drive login/enable (not just whether it's enabled), local-fallback presence, server counts, command accounting | 8 | 8 | Drills deeper than `security_audit`'s single AAA flag into which method is actually authoritative and how much server redundancy exists |

Every profile also always includes 5 automatic metadata columns: `TIMESTAMP`, `TARGET_IP`, `STATUS` (`OK`/`PARTIAL`/`UNREACHABLE`/`AUTH_FAILED`/`ERROR`), `MISSING_FIELDS`, `ERROR`.

**Adding your own profile:** copy one of the existing YAML files in `audit_profiles/`, change its `profile:` name and `fields:` list, and it will automatically appear in the Audit tab's profile dropdown next time you load the page (or immediately via a page refresh) — no restart or code change required beyond adding the file.

---

## Security Notes

- **Credentials are never written to disk** unless you explicitly opt in (saving an inventory with "remember password" checked, or creating a schedule of either type — schedules always require encryption to be available since they must run unattended).
- Stored secrets are encrypted with **Fernet (AES-128-CBC + HMAC)** via the `cryptography` package, using a locally-generated key file (`secret.key`, created with owner-only permissions on POSIX systems). This includes **per-device credential overrides nested inside a schedule's device list** (e.g. a mixed-credential audit schedule), not just the shared top-level username/password.
- **🔒 Ephemeral execution mode** (opt-in, one-time runs only) holds credentials in an actively-zeroable in-memory buffer instead of an ordinary string for the run's duration, wiped the instant it finishes. See [§15](#15--ephemeral-ram-only-execution) for exactly what this does and does not guarantee.
- **Structural report redaction** — every automation run's report and every audit run's report is passed through `redaction.sanitize_structure()` (in `storage.py`) before being written to `automation_console.db`: any dict value under a recognized secret-sounding KEY (`password`, `secret`, `community`, `api_key`, etc.) is replaced outright with `<REDACTED>`, and every string VALUE (e.g. a captured `show running-config` backup, or a manually-typed command) is scanned with the same keyword-anchored patterns used for `logs/audit.log`. This is a belt-and-suspenders net on top of (not a replacement for) `sensitive: true` field-level redaction and the existing audit-log sanitization — the app already avoided storing credentials almost everywhere; this specifically catches a secret that shows up *incidentally* inside otherwise-legitimate captured output.
- API keys for AI features are used for a single outbound request only and are never logged or stored.
- Custom Jinja2 templates render in a **sandboxed environment** — dangerous attribute/dunder access is blocked, loop iteration counts are capped, and a render that runs longer than 5 seconds is abandoned.
- Any config-mode command containing a recognizable secret keyword (`password`, `secret`, `snmp-server community`, `pre-shared-key`, etc.) — whether typed manually or generated by a template — is **redacted to `<REDACTED>` before being written to `logs/audit.log`**, so a device password never sits in plaintext in a log file. The full run-history report stored in `automation_console.db` is now ALSO redacted (see above) rather than preserving exact plaintext for troubleshooting — treat the database file with the same care as any file containing device credentials regardless.
- **Audit Profiles are read-only by construction** — a field's `command` can be any CLI string, but the Audit engine never enters configuration mode, and a `sensitive: true` field (e.g. SNMP community) is redacted to `<REDACTED>` in every output row/format and never appears in `logs/audit.log`.
- An Audit Profile YAML file cannot execute arbitrary Python — `transform` values are looked up in a small pre-approved registry (`upper`/`lower`/`strip`/`int`/`float`/`cidr_to_mask`), never `eval`/`exec`'d.
- All backup file-serving endpoints have **path-traversal protection** (both literal `../` and URL-encoded `%2F` attempts are rejected). Audit report downloads no longer touch the filesystem at all (generated in memory on demand — see [Backend Architecture & Resilience Notes](#backend-architecture--resilience-notes)), so there's no path to protect in the first place.
- Devices get **temporarily locked out** (SSH skipped) after repeated authentication failures, to avoid triggering a real account lockout policy on the device.
- Flask's debug/interactive-debugger mode is **off by default** — do not enable it (`FLASK_DEBUG=1`) on a network-reachable machine.
- This app is intended for **local/trusted-network use** by a single operator — it has no built-in user authentication/multi-user access control of its own.

---

## Backend Architecture & Resilience Notes

**Lazy loading for heavy parsing dependencies.** `textfsm` and `ntc-templates` (needed only by `parser: textfsm` / table-mode Audit Profiles) are no longer imported — or auto-installed — at application startup. `inventory_collector/textfsm_support.py` now defers the real `import textfsm` / `from ntc_templates.parse import parse_output` to the *first actual call* to `parse_with_ntc_templates()`/`parse_with_custom_template()`, i.e. the first time a profile that needs them is actually executed. `is_textfsm_installed()` provides a fast, import-free presence check (via `importlib.util.find_spec`) for the `/health` and `/audit/profiles` "is this available" badges, so checking availability never pays the loading cost.

**Worker pool isolation.** Automation and Audit runs already each spin up their own fresh `ThreadPoolExecutor` per invocation — they never literally share one pool object. The real risk was concurrency *budget*: an intensive scheduled job (e.g. a 50-device audit with TextFSM table parsing, fired unattended in the background) could claim just as many concurrent SSH worker threads as an interactive user's manual action happening at the same moment. Two guards address this in `app.py`:
- `SCHEDULED_MAX_WORKERS_LIMIT` (10) hard-caps the worker count for **any** schedule-triggered run — automation or audit — regardless of what the schedule's saved config requests, applied in `_fire_automation_schedule()`/`_fire_audit_schedule()` right before the run actually starts.
- `MAX_CONCURRENT_SCHEDULED_JOBS` (1) is an explicit `threading.Semaphore` acquired around every scheduled firing in `_scheduler_loop()`, guaranteeing at most one scheduled job (of either type) executes at a time — an enforced invariant now, not just an accidental side effect of the loop currently being a simple for-loop.

Interactive (manual) runs are never subject to either limit — they always get the full `MAX_WORKERS_LIMIT` (50) and never wait on the scheduled-job semaphore.

**Connection pre-checks & fast-fail thresholds.** When a run shares a single common jump host across every device, `precheck_gateway()` performs ONE quick TCP reachability probe against it (capped at 5 seconds, independent of the configured per-device SSH timeout) *before* dispatching to any device at all. If the jump host is down, every remaining device in the batch is marked `FAILED (jump host unreachable)` immediately — via a shared `gateway_down_event` threaded through both `_run_sequential()` and `_run_parallel()` — instead of each device independently opening a doomed connection attempt and waiting out its own full connect timeout. A 50-device run with a dead jump host now fails in a few seconds total instead of `50 × timeout` seconds.

**On-demand report generation over disk writing.** `audit_bridge.run_audit()` now defaults to `write_report_file=False` — the web app never writes a CSV/XLSX/JSON file to `./reports/` on a normal run. Since `storage.save_audit_run()` already persists the full structured report as JSON in `automation_console.db` (the actual durable source of truth), `GET /audit/history/<id>/download` instead calls `audit_bridge.render_report_bytes()`, which builds the requested format **entirely in memory** (`io.StringIO`/`io.BytesIO` via new `inventory_collector.output.render_csv_bytes()`/`render_json_bytes()`/`render_xlsx_bytes()` functions) at download time. This eliminates the "reports/ directory fills up over months of scheduled runs" problem entirely — nothing accumulates on disk regardless of how many scheduled audits run.

**Automated database pruning & compaction.** `save_run()`/`save_audit_run()`/`save_rollback_snapshot()` already prune old rows beyond their respective caps, but a plain SQLite `DELETE` doesn't shrink the `.db` file on disk (freed pages are just marked reusable). `storage.py` now switches the database to `PRAGMA auto_vacuum = INCREMENTAL` mode (a one-time change, requiring one full `VACUUM` the very first time — subsequent app starts skip that) and runs `storage.compact_database()` (a cheap `PRAGMA incremental_vacuum`) once at every startup, so disk space freed by previously-deleted history/snapshot rows actually gets reclaimed instead of the file only ever growing.

---

## API Reference (all endpoints)

### Core / Automation
| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Main UI |
| GET | `/health` | Health/capability check (paramiko/netmiko/encryption/Jinja2/Audit/TextFSM availability) |
| GET | `/command-suggestions?vendor=` | Command library for a vendor |
| POST | `/run-script` | Start a (streaming) automation run |
| POST | `/cancel-run/<run_uuid>` | Cancel an in-progress run |
| POST | `/ai-assist` | AI command suggestions / run analysis |

### Inventories (shared by Run and Audit)
| Method | Endpoint | Purpose |
|---|---|---|
| GET/POST | `/inventories` | List / save an inventory |
| GET/PATCH/DELETE | `/inventories/<id>` | Get / inline-edit / delete an inventory |
| POST | `/inventories/<id>/favorite` | Toggle favorite |
| POST | `/inventories/<id>/duplicate` | Duplicate an inventory |

### History
| Method | Endpoint | Purpose |
|---|---|---|
| GET/DELETE | `/history` | List automation run history / clear all |
| GET/DELETE | `/history/<id>` | Get / delete one automation run |
| GET | `/history/trend?days=` | Automation-only trend chart data |

### 🔍 Audit
| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/audit/profiles` | List available Audit Profiles (with field/command counts, validity) |
| POST | `/audit/run` | Run an Audit Profile against typed devices or a saved Inventory; returns the full structured report |
| GET/DELETE | `/audit/history` | List audit run history / clear all |
| GET/DELETE | `/audit/history/<id>` | Get / delete one audit run |
| GET | `/audit/history/<id>/download` | Generate and download that run's report file **on demand, in memory** (CSV/XLSX/JSON) |
| GET | `/audit/history/diff?old_run_id=&new_run_id=` | Compare two completed runs of the same profile — see [§16](#16-report-diffing-across-audit-runs) |
| POST | `/audit/schedules` | Create a recurring Audit schedule |

### Schedules (both job types)
| Method | Endpoint | Purpose |
|---|---|---|
| GET/POST | `/schedules` | List all schedules (automation + audit) / create an automation schedule |
| PATCH/DELETE | `/schedules/<id>` | Update (enable/interval) / delete a schedule of either type |
| POST | `/schedules/<id>/run-now` | Trigger a schedule immediately (streams for automation, returns JSON for audit) |
| GET | `/schedules/<id>/history` | That schedule's own run history (shape depends on its job type) |

### Overview dashboard
| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/overview/summary` | At-a-glance stats + merged 14-day trend + Health & Compliance Snapshot findings |
| GET | `/activity/recent?limit=` | Merged automation+audit activity feed, newest first |
| GET | `/activity/current` | Currently-running job(s) with live progress, for the persistent global indicator |

### Configuration management
| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/backups?dir=` | List backup files |
| GET | `/backups/download?dir=&file=` | Download a backup file |
| POST | `/backups/delete` | Delete a backup file |
| GET | `/backups/default-dir` | Default backup folder path |
| GET | `/templates` | List built-in + saved custom Jinja2 templates |
| POST | `/templates/render` | Render a built-in template |
| POST | `/templates/render-custom` | Render a custom Jinja2 template |
| POST | `/templates/variables` | Detect variables in a custom template |
| POST | `/templates/batch-render` | Render one template across multiple devices |
| POST | `/templates/diff` | Diff a rendered template against a current config |
| GET | `/templates/selftest` | Run every built-in template's self-test cases |
| GET/POST | `/templates/user` | List / save a custom named template |
| GET/DELETE | `/templates/user/<id>` | Get / delete a saved custom template |
| GET | `/rollback/snapshots` | List rollback snapshots |
| GET/DELETE | `/rollback/snapshots/<id>` | View / delete a snapshot |
| POST | `/rollback/execute` | Execute a rollback |

### Settings & logs
| Method | Endpoint | Purpose |
|---|---|---|
| GET/POST | `/settings/alerts` | Get / save alert settings |
| POST | `/settings/alerts/test` | Send a test alert |
| GET | `/logs/<app\|audit>?lines=` | Tail a log file |

---

## Data Storage

Everything is stored **locally** — nothing leaves your machine except optional AI-assist calls and alert deliveries (email/Slack) that you explicitly configure.

| File/Folder | Contents |
|---|---|
| `automation_console.db` | SQLite database: inventories, automation run history, **audit run history**, schedules (both job types), rollback snapshots, alert settings — with an incremental auto-vacuum run once at every startup to reclaim space from pruned/deleted rows |
| `secret.key` | Local Fernet encryption key (auto-generated, owner-only permissions) |
| `logs/app.log` | Rotating general application log |
| `logs/audit.log` | Rotating JSON-lines audit trail (config commands, backups, rollbacks, **audit profile runs**, alerts) |
| `backups/` | Default folder for `.cfg` configuration backup files |

Audit report files (CSV/XLSX/JSON) are **no longer written to disk by default** — they're generated in memory on demand when you click download, straight from the run's data already stored in `automation_console.db` (see [Backend Architecture & Resilience Notes](#backend-architecture--resilience-notes)). A `reports/` folder is only created if you explicitly call `audit_bridge.run_audit(..., write_report_file=True)` outside the web UI (e.g. from your own script).

To fully reset the app to a clean state, stop it and delete `automation_console.db`, `secret.key`, `logs/`, and `backups/` — they'll all be recreated automatically on the next run.

---

## Troubleshooting / FAQ

**Q: Ping always shows "FAILED" with a `socktype: SOCK_RAW` / "Operation not permitted" error.**
A: This happens in sandboxed/containerized environments (including this app's own dev sandbox) that don't grant the `cap_net_raw` capability needed for raw ICMP sockets. It's an environment limitation, not a bug — TCP port checks and SSH command execution (and Audit runs) are unaffected. On a normal machine/VM with standard networking permissions, ping works normally.

**Q: I get "Config backup requires 'execute commands over SSH' to be enabled."**
A: Backups (and all config-mode operations) run over the SSH command-execution path, so that checkbox must be on even if your commands box is empty.

**Q: Why can't I schedule a configuration-mode change?**
A: By design — scheduled/unattended automation jobs are hard-restricted to read-only operations (checks and backups) so nothing can push configuration changes to real devices without a human explicitly clicking "Run Now" and confirming. Audit schedules don't have a config-mode option at all, for the same reason.

**Q: The Audit tab says "The Audit feature is unavailable in this session."**
A: PyYAML (or the vendored `inventory_collector` package) failed to import — check the console output at startup for a `[SETUP]` error. Automation features are completely unaffected; only the Audit tab and audit-type schedules are disabled until this is resolved (usually just re-running `python3 app.py` with internet access so PyYAML can auto-install).

**Q: An Audit Profile field always shows the default value / "N/A".**
A: Its regex isn't matching the device's actual output for that command — this is expected, graceful behavior (the row is marked `PARTIAL` if the field was `required`), not a crash. Check the exact command/regex in the profile's YAML file against real output from one of your devices; a small platform/software-version difference in output formatting is the most common cause.

**Q: "Cannot enable email/Slack alerts... credential encryption is unavailable."**
A: The `cryptography` package couldn't be installed (usually no internet access on first run, or a restricted environment). Alerts and schedules (either job type) that need to store credentials require it. Try `pip install cryptography` manually and restart the app.

**Q: The rollback didn't fully restore the device.**
A: Rollback is a best-effort line-by-line replay, not an atomic/transactional rollback (most vendors don't support one without a full flash-file staging step). Review the resulting live log/diff — a line that no longer applies cleanly (e.g. a VLAN that already exists) may show a small error while the rest of the rollback still applies correctly.

**Q: Where do I see what changed / who did what?**
A: The **⚙ Settings → 📜 Application Logs** section, or open `logs/audit.log` directly — every config-mode command, backup, rollback, and Audit Profile run is recorded there with a timestamp, device (or profile), and outcome.

**Q: Why can't I enable "Ephemeral run" when saving a schedule?**
A: By design — a schedule's whole purpose is running again later, which requires its credentials to be retrievable (encrypted at rest); ephemeral mode's whole purpose is guaranteeing the opposite (credentials wiped the moment the run ends). The two are mutually exclusive, and both schedule-creation routes reject the combination with a clear error. Disable "Ephemeral run" before saving as a schedule.

**Q: A 50-device run failed almost instantly with "jump host unreachable" for every device — is that a bug?**
A: No — that's the connection pre-check / fast-fail feature working correctly. If your run has a shared jump host and it's down, the app now probes it once (a few seconds) and fails the whole remaining batch immediately instead of letting each of the 50 devices independently wait out its own full connect timeout. Check the jump host's reachability/credentials first.

**Q: My download of an Audit report is slow / times out for a huge report.**
A: Report files are generated in memory on demand when you click download (not pre-written to disk), so a very large report (many thousands of rows) takes a moment to render into CSV/XLSX/JSON at download time rather than being instantly available. This trades a small amount of download-time latency for eliminating disk accumulation across scheduled runs — see [Backend Architecture & Resilience Notes](#backend-architecture--resilience-notes).

---

## Known Limitations

- Single-user tool — no built-in login/authentication or per-user permissions.
- Rollback is best-effort (line replay), not a true atomic/transactional rollback except conceptually on Juniper (which has its own native rollback primitive, not specially wired in here — it uses the same generic replay path as other vendors for consistency).
- Health-check output parsing is intentionally lightweight regex-based (not a full CLI parser like TextFSM/Genie) — it reliably catches clear regressions (interface down, CPU spike) but isn't a substitute for a dedicated monitoring platform.
- The Health & Compliance Snapshot on the Overview dashboard is keyed to the specific column names the built-in `security_audit`/`capacity_audit` profiles declare — if you heavily rewrite those YAML files with different column names, the snapshot's findings simply stop appearing (no error), since it's a small set of known-interesting conditions, not a generic report analyzer.
- Table-mode Audit Profiles (`interface_inventory`, `neighbor_discovery`) require the optional `textfsm` + `ntc-templates` packages; without them, only regex-based (device-mode) profiles work.
- Ephemeral execution mode cannot fully eliminate the brief, unavoidable moment a plaintext credential exists as a normal Python string at the instant paramiko/netmiko actually authenticates — see [§15](#15--ephemeral-ram-only-execution) for the precise, honest guarantee it does make.
- Report diffing (`/audit/history/diff`) only supports device-mode profiles — table-mode reports (`interface_inventory`, `neighbor_discovery`) have no single stable per-row identity across runs to diff against.
- The connection pre-check / fast-fail feature only applies to a **shared jump host** (one bastion for the whole run); it doesn't pre-check each individual target device's reachability before dispatching (that's what the existing per-device ping/TCP-port checks already do, just not as a whole-batch short-circuit).
- Intended for a trusted local network / single operator — do not expose this app directly to the public internet.

---

## Changelog

**Content Expansion II — more templates & audit profiles (this revision)**:
- **4 new Config Templates** added, bringing the built-in library to **15** (14 parameterized + `custom`):
  - `spanning_tree` — STP mode + per-VLAN bridge priority (validated as a multiple of 4096) + PortFast/BPDU Guard on a list of access ports. **High risk, requires confirmation.**
  - `port_channel` — bundles member interfaces into an access/trunk/routed LACP (`active`/`passive`) or static (`on`) port-channel; cisco_ios/cisco_nxos/arista_eos.
  - `aaa_tacacs_radius` — centralizes login/enable authentication against TACACS+/RADIUS servers with an optional local fallback; shared-key field masked + redacted. **High risk, requires confirmation.**
  - `dhcp_snooping` — enables DHCP snooping on a VLAN list, trusts uplink ports, and rate-limits a separate, explicit list of untrusted access ports.
  - New shared helper `_parse_vlan_list_field()` in `templates_engine.py` parses/validates a comma+range VLAN expression (`"10,20-25"`) once, reused by both `spanning_tree` and `dhcp_snooping`.
- **3 new Audit Profiles** added, bringing the built-in library to **10**:
  - `poe_audit` (table mode) — one row per PoE-capable port: admin/operational status, power draw, connected device class, per-port wattage ceiling. Requires `textfsm`/`ntc-templates`.
  - `mac_address_table` (table mode) — one row per learned MAC address: VLAN, MAC, type, port. Requires `textfsm`/`ntc-templates`.
  - `aaa_audit` (device mode) — drills into which AAA method (TACACS+/RADIUS vs. local-only) is actually authoritative for login/enable, local-fallback presence, TACACS+/RADIUS server counts (redundancy risk), and command-accounting status — a deeper companion to `security_audit`'s single AAA flag.
- **Bugs found & fixed during this work** (all caught via live rendering/self-test/mock-SSH runs before being shipped):
  - `redaction.py`'s `LINE_PATTERNS` had no pattern for a bare `key <value>` config line (the TACACS+/RADIUS shared-secret sub-command syntax, e.g. `key S3cr3t`) — a real secret-redaction gap for the new `aaa_tacacs_radius` template's rendered output and any future profile/template touching keychain or AAA-server config. Fixed by adding a line-start-anchored `^(\s*key)\s+\S+` pattern (deliberately anchored to the start of the line, not `\b`-bounded, so it can't misfire on the word "key" appearing mid-sentence in unrelated output).
  - `aaa_tacacs_radius`'s Cisco IOS Jinja2 source used `{% if local_fallback %} local{% endif %}\n` immediately followed by another line — with `trim_blocks=True` (the environment's global setting), the newline right after `{% endif %}` was silently swallowed, concatenating two config lines onto one (e.g. `aaa authentication login default group tacacs localaaa authentication enable default group tacacs enable`) in both the forward-render and the auto-generated rollback. Fixed by replacing the `{% if %}...{% endif %}` block with an inline `{{ ' local' if local_fallback else '' }}` expression, which doesn't interact with `trim_blocks`.
  - `dhcp_snooping`'s first draft hardcoded a hypothetical `interface range GigabitEthernet0/1 - 23` for untrusted-port rate limiting — wrong on its face (assumes a range that may not exist on the real device) and it also broke the dry-run preview's interface-detection regex (which parsed "range" as a bogus interface name). Redesigned with an explicit, separate `untrusted_interfaces` textarea field so every rate-limited port is one the operator actually typed in.
- All 4 new templates' self-tests, all 3 new profiles' YAML validation, and full end-to-end live tests (mock paramiko SSH server serving real `show power inline` / `show mac address-table` / AAA `show run` fragments) were run and verified before this revision was finalized; existing 15-template/10-profile counts confirmed live via `/templates`, `/audit/profiles`, `/templates/selftest`, and a jsdom-driven real-DOM render of both pickers.

**Security, Resilience & Content Expansion (previous revision)**:
- **Security & Secrets Governance**: added `redaction.py` (shared secret-pattern/key redaction) and wired it into `storage.save_run()`/`save_audit_run()` so every report persisted to SQLite is now structurally redacted, not just the `logs/audit.log` trail. Added `secure_credentials.py` and a new **🔒 Ephemeral run** opt-in toggle (Run tab + Audit tab) for one-time, RAM-only credential handling, actively wiped when the run completes; both schedule-creation routes reject the combination with ephemeral mode.
- **Backend Architecture & Execution Resilience**: `textfsm`/`ntc-templates` are no longer imported at app startup — `inventory_collector/textfsm_support.py` now lazily imports them on first actual use of a TextFSM/table-mode profile (`is_textfsm_installed()` provides a fast, import-free availability check). Added worker-pool isolation (`SCHEDULED_MAX_WORKERS_LIMIT`, `MAX_CONCURRENT_SCHEDULED_JOBS` semaphore) so a heavy scheduled job can't starve an interactive run's SSH threads. Added a connection pre-check / fast-fail (`precheck_gateway()`) that probes a shared jump host once before dispatching to any device, failing the whole remaining batch immediately if it's down instead of every device independently waiting out its own timeout.
- **Data Management & Reporting Lifecycle**: Audit report files are now generated **on demand, in memory** (`audit_bridge.render_report_bytes()`, new `inventory_collector.output.render_*_bytes()` functions) instead of being written to `./reports/` on every run — `write_report_file` now defaults to `False`. Added automated SQLite incremental-vacuum compaction (`storage.compact_database()`) run once at every startup. Added **report diffing across audit runs** (`audit_bridge.diff_audit_runs()`, `GET /audit/history/diff`) with a UI comparison view in Audit History.
- **Frontend & UX**: added client-side pagination + instant filtering to the Audit results table (handles large table-mode reports, e.g. 2,400+ rows, without freezing the browser). Added live-stream severity filtering (`[All] / [⚠ Warnings Only] / [✕ Errors Only]`) above the Live Log panel. Added `history.pushState`-based deep-linking for every tab plus an active-execution navigation guard (confirms before you navigate away — back/forward, tab close, or reload — while a run or audit is actively streaming).
- **Content expansion**: added 4 new Config Templates (`port_security`, `ospf_process`, `syslog_logging`, `acl_standard` — bringing the built-in library to 11) and 3 new Audit Profiles (`vlan_audit`, `routing_audit`, `neighbor_discovery` — bringing the built-in library to 7, with `neighbor_discovery` demonstrating table-mode CDP-neighbor parsing).
- **Bugs found & fixed during this work**: `_ACTION_FLIP` (auto-generated template rollback) didn't know about the `enable`/`disable` action pair used by the new `port_security` template, so its rollback silently re-rendered the same "apply" text instead of the inverse — fixed by adding `enable`/`disable` to the flip table. Several `routing_audit.yaml` regexes were refined after live testing against a real device revealed capture-group and anchor mismatches (`show ip protocols` protocol-detection patterns, the `show ip route | count` total-routes pattern, and the default-route detection pattern).

**Integration Phase 1–6 (previous revision)** — merged the standalone `network_inventory_collector` project into this app as a unified console:
- Vendored the read-only inventory/audit collection engine as `inventory_collector/` + `audit_profiles/`, exposed through a single new bridge module (`audit_bridge.py`).
- Added a full **🔍 Audit** tab: profile picker, Audit Target (saved Inventory or typed devices), run + history, report download.
- Extended `schedules` with a `job_type` column so **one** scheduler thread now runs both automation and audit recurring jobs.
- Added a new **🏠 Overview** dashboard (stat cards, Quick Actions, merged Recent Activity feed, Health & Compliance Snapshot, merged 14-day trend) and a **persistent global run indicator** visible from any tab.
- Regrouped navigation into **Act / Observe / Manage** clusters.
- **Security fixes found during this work**: per-device credential overrides nested in a saved schedule's device list are now correctly encrypted at rest (previously only the shared top-level password was); an Audit schedule referencing an unknown/broken profile is now rejected at creation time instead of only failing (silently, until checked) the next time it happened to fire.
