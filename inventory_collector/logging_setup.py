"""
Per-run logging (FR-9).

Every invocation gets its own timestamped log file under `logs/` capturing
device/command/match-or-no-match/timing/errors, in addition to a console
handler. `--debug` raises the level to DEBUG, which additionally includes
raw CLI output in the log (useful for troubleshooting a regex that isn't
matching) -- see collect.py's `LOG.debug(...)` calls.
"""
from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path


def setup_logging(log_dir: Path, debug: bool = False, run_label: str = "run") -> Path:
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = log_dir / f"{run_label}_{stamp}.log"

    level = logging.DEBUG if debug else logging.INFO
    root = logging.getLogger("collector")
    root.setLevel(level)
    root.handlers.clear()  # idempotent -- safe if called more than once in a process (e.g. tests)

    formatter = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)
    root.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S"))
    console_handler.setLevel(level)
    root.addHandler(console_handler)

    root.info("Logging to %s (level=%s)", log_path, logging.getLevelName(level))
    return log_path
