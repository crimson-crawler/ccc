"""Config-file discovery and loading for the Crimson Crawler CLI.

The CLI reads a single TOML file at ``~/.crimson-crawler/config.toml`` when the
``CRIMSON_CRAWLER_API_KEY`` env var is not set. The schema is intentionally
minimal — one top-level ``api_key`` field — and will grow as commands need
server preferences (default ``include`` set, base URL override).

A file that exists but cannot be read or parsed raises :class:`ConfigFileError`
(exit 64) with the mistake and the fix named. Only a *missing* file is silent —
the env var is the other supported source.
"""

from __future__ import annotations

import os
import stat
import tomllib
from pathlib import Path
from typing import Any

from .exceptions import ConfigFileError, ConfigPermissionError

CONFIG_DIR: Path = Path.home() / ".crimson-crawler"
CONFIG_FILE: Path = CONFIG_DIR / "config.toml"

# The one-line file the CLI actually wants, quoted in every diagnostic below so
# a user never has to leave the error message to find the fix.
EXPECTED_SHAPE = 'api_key = "your-api-key"'


def _validate_permissions(file_descriptor: int) -> None:
    if os.name != "posix":
        return

    file_stat = os.fstat(file_descriptor)
    if file_stat.st_uid != os.getuid():
        raise ConfigPermissionError(
            f"Refusing to read {CONFIG_FILE}: the file is not owned by the current user. "
            "Change its owner before retrying."
        )
    if stat.S_IMODE(file_stat.st_mode) & 0o077:
        raise ConfigPermissionError(
            f"Refusing to read {CONFIG_FILE}: group and other permissions must be removed. "
            "Run chmod 600 on the file before retrying."
        )


def _syntax_hint(text: str) -> str:
    """Name the specific mistake when the file's shape gives it away.

    Two shapes account for nearly every malformed config, and tomllib reports
    both as a bare ``Invalid value at line L column C``:

    * ``CRIMSON_CRAWLER_API_KEY=<value>`` — the env-var name and shell syntax,
      copied from an ``export`` line or a ``.env`` file.
    * ``api_key = your-key`` — right field, unquoted value. TOML has no bare
      strings.

    Only the *key* is ever quoted back, never the value: the value is the
    secret, and this message reaches a terminal and any log scraping it.
    """
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key.isupper():
            return (
                f"The line starting `{key}=` is shell/.env syntax, not TOML — "
                f"`{key}` is the environment-variable name, and in this file the field is `api_key`. "
            )
        if key == "api_key" and value[:1] not in {'"', "'"}:
            return "The `api_key` value must be quoted — TOML has no bare strings. "
    return ""


def _malformed_config_message(text: str, detail: str) -> str:
    return (
        f"{CONFIG_FILE} is not valid TOML ({detail}). "
        f"{_syntax_hint(text)}"
        f"The file should contain exactly one line:\n\n    {EXPECTED_SHAPE}\n\n"
        "To use the environment variable instead, `export CRIMSON_CRAWLER_API_KEY=your-api-key` "
        "and delete the config file."
    )


def load_config_file() -> dict[str, Any] | None:
    """Return parsed TOML config, or ``None`` if the file does not exist.

    Re-reads ``CONFIG_FILE`` from this module on every call so tests can
    ``monkeypatch.setattr`` the constant and have it take effect.

    Raises :class:`ConfigFileError` when the file exists but cannot be parsed.
    A missing file is not an error — the env var is the other supported source.
    """
    try:
        with CONFIG_FILE.open("rb") as fh:
            _validate_permissions(fh.fileno())
            raw = fh.read()
    except FileNotFoundError:
        return None

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigFileError(
            f"{CONFIG_FILE} is not valid UTF-8 text. It should be a plain TOML file containing:\n\n    {EXPECTED_SHAPE}"
        ) from exc

    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigFileError(_malformed_config_message(text, str(exc))) from exc


__all__ = [
    "CONFIG_DIR",
    "CONFIG_FILE",
    "EXPECTED_SHAPE",
    "load_config_file",
]
