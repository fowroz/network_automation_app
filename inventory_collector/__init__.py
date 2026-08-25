"""
Dynamic, configuration-driven network inventory & audit collector.

Nothing about *what* gets collected is hardcoded here -- every data point
(the CLI command, the regex/TextFSM parser, the CSV column name, transforms,
etc.) is declared in an external YAML "profile" file and loaded at runtime
by `inventory_collector.profile.load_profile()`. This package is the
engine; `collector.py` at the repo root is the thin CLI entry point.
"""
__version__ = "1.0.0"
