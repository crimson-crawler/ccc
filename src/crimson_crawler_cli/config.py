"""Config-file discovery and loading for the Crimson Crawler CLI.

The CLI reads a single TOML file at ``~/.crimson-crawler/config.toml`` when the
``CRIMSON_CRAWLER_API_KEY`` env var is not set. The schema is intentionally
minimal — one top-level ``api_key`` field — and will grow as commands need
server preferences (default ``include`` set, base URL override).
"""

from __future__ import annotations

import os
import stat
import tomllib
from pathlib import Path
from typing import Any

CONFIG_DIR: Path = Path.home() / ".crimson-crawler"
CONFIG_FILE: Path = CONFIG_DIR / "config.toml"


def _validate_permissions(file_descriptor: int) -> None:
    if os.name != "posix":
        return

    file_stat = os.fstat(file_descriptor)
    if file_stat.st_uid != os.getuid():
        raise PermissionError(
            f"Refusing to read {CONFIG_FILE}: the file is not owned by the current user. "
            "Change its owner before retrying."
        )
    if stat.S_IMODE(file_stat.st_mode) & 0o077:
        raise PermissionError(
            f"Refusing to read {CONFIG_FILE}: group and other permissions must be removed. "
            "Run chmod 600 on the file before retrying."
        )


def load_config_file() -> dict[str, Any] | None:
    """Return parsed TOML config, or ``None`` if the file does not exist.

    Re-reads ``CONFIG_FILE`` from this module on every call so tests can
    ``monkeypatch.setattr`` the constant and have it take effect.
    """
    try:
        with CONFIG_FILE.open("rb") as fh:
            _validate_permissions(fh.fileno())
            return tomllib.load(fh)
    except FileNotFoundError:
        return None


__all__ = [
    "CONFIG_DIR",
    "CONFIG_FILE",
    "load_config_file",
]
