"""Command-line interface for the Crimson Crawler API.

The ``ccc`` console script exposes local auth and inventory collection, typed
enrichment conveniences, scan-to-briefing ingestion, async artifact enrichment,
and the Artifact Manager, Inventory Manager, and Report Generator command groups.
Every network call flows through :class:`crimson_crawler_client.CrawlerClient`.

Configuration:

- ``CRIMSON_CRAWLER_API_KEY`` env var, or ``api_key`` in
  ``~/.crimson-crawler/config.toml``. Required.

See ``cli`` for the Typer app entry point and ``commands`` for the command
implementations.
"""

from __future__ import annotations

try:
    from importlib.metadata import version as _pkg_version

    __version__ = _pkg_version("crimson-crawler-cli")
except Exception:  # noqa: BLE001 — fall back when running from source without metadata
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
