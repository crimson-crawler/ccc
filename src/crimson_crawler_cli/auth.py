"""API-key resolution for the Crimson Crawler CLI.

Resolution order:

1. ``CRIMSON_CRAWLER_API_KEY`` env var → ``source="env"``.
2. ``~/.crimson-crawler/config.toml`` ``api_key`` field → ``source="config"``.
3. Neither → :class:`MissingCredentialsError` (exit code 2).

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

    raise MissingCredentialsError(
        f"No API key found. Set {ENV_API_KEY} or write 'api_key = \"...\"' to {config.CONFIG_FILE}."
    )


__all__ = [
    "ENV_API_KEY",
    "AuthSource",
    "ResolvedAuth",
    "resolve_auth",
]
