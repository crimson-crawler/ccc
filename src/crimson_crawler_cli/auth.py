"""API-key resolution for the Crimson Crawler CLI.

Resolution order:

1. ``CRIMSON_CRAWLER_API_KEY`` env var → ``source="env"``.
2. ``~/.crimson-crawler/config.toml`` ``api_key`` field → ``source="config"``.
3. Neither → :class:`MissingCredentialsError` (exit code 2).

A config file that exists but cannot be parsed raises :class:`ConfigFileError`
(exit code 64) from :mod:`config` instead — that is a broken file, not an
absent key, and conflating the two sends a CI wrapper down the "prompt for a
key" path when the key is already there and merely misformatted.

This matches the SDK's env var name on purpose — keys are interchangeable
between ``ccc`` CLI usage and ``CrawlerClient`` SDK usage.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Literal

from . import config
from .exceptions import MissingCredentialsError

ENV_API_KEY = "CRIMSON_CRAWLER_API_KEY"

AuthSource = Literal["env", "config"]


@dataclass(frozen=True)
class ResolvedAuth:
    """The API key plus where it came from. Never log ``key`` directly."""

    source: AuthSource
    key: str = field(repr=False)
    source_detail: str

    @property
    def key_tail(self) -> str:
        """Last 4 characters of the key. Safe to display."""
        return self.key[-4:] if len(self.key) >= 4 else self.key

    @property
    def masked_key(self) -> str:
        """Key with everything but the last 4 chars replaced by ``•``."""
        if len(self.key) <= 4:
            return self.key
        return "•" * (len(self.key) - 4) + self.key_tail


def _no_usable_key_message(loaded: dict[str, object]) -> str:
    """Explain a config file that parsed cleanly but carries no usable key.

    Valid TOML with the wrong *field* is the quiet twin of the malformed-TOML
    case :mod:`config` handles: ``CRIMSON_CRAWLER_API_KEY = "abc"`` parses
    perfectly and resolves to nothing, so say which field was expected instead
    of falling back to the generic "no API key found".
    """
    reason = f"{config.CONFIG_FILE} has no usable `api_key` field."
    if ENV_API_KEY in loaded:
        reason = (
            f"{config.CONFIG_FILE} defines `{ENV_API_KEY}` — that is the environment-variable "
            "name; in this file the field is `api_key`."
        )
    elif "api_key" in loaded:
        reason = f"{config.CONFIG_FILE} has an `api_key` field, but it is not a non-empty string."
    return f"{reason} Expected:\n\n    {config.EXPECTED_SHAPE}\n\nOr set {ENV_API_KEY} in the environment."


def resolve_auth() -> ResolvedAuth:
    """Return the first available API key, or raise :class:`MissingCredentialsError`."""
    env_value = os.environ.get(ENV_API_KEY)
    if env_value:
        return ResolvedAuth(source="env", key=env_value, source_detail=ENV_API_KEY)

    loaded = config.load_config_file()
    if loaded is not None:
        key = loaded.get("api_key")
        if isinstance(key, str) and key:
            return ResolvedAuth(
                source="config",
                key=key,
                source_detail=str(config.CONFIG_FILE),
            )
        raise MissingCredentialsError(_no_usable_key_message(loaded))

    raise MissingCredentialsError(
        f"No API key found. Set {ENV_API_KEY} or write '{config.EXPECTED_SHAPE}' to {config.CONFIG_FILE}."
    )


def credential_origin() -> str | None:
    """Where the key the CLI just used came from, for a rejected-key message.

    Deliberately non-raising and side-effect-free: it runs while an error is
    already being rendered, so a second failure here (an unreadable or
    malformed config) must degrade to ``None`` rather than replace the API
    error the user is actually being told about.
    """
    if os.environ.get(ENV_API_KEY):
        return f"the {ENV_API_KEY} environment variable"
    try:
        loaded = config.load_config_file()
    except Exception:  # noqa: BLE001 — see docstring; any failure means "can't say"
        return None
    if loaded and isinstance(loaded.get("api_key"), str) and loaded["api_key"]:
        return str(config.CONFIG_FILE)
    return None


__all__ = [
    "ENV_API_KEY",
    "AuthSource",
    "ResolvedAuth",
    "credential_origin",
    "resolve_auth",
]
