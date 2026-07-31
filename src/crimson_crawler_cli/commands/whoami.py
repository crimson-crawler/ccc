"""``ccc whoami`` — local config + auth-source check, no network call.

Reports which source the API key came from (env var or config file) and a
masked tail of the key. A ``--verify`` flag that hits the API to confirm the
key is accepted will land later — today the enrichment commands themselves
exercise the live key.
"""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.table import Table

from .. import auth, output


def whoami() -> None:
    """Print resolved auth source + masked key tail.

    Exits 0 on success, 1 (via :class:`MissingCredentialsError`) when no key
    is configured.
    """
    resolved = auth.resolve_auth()

    payload: dict[str, Any] = {
        "source": resolved.source,
        "source_detail": resolved.source_detail,
        "api_key_tail": resolved.key_tail,
        "api_key_masked": resolved.masked_key,
        "config_file": resolved.source_detail if resolved.source == "config" else None,
    }
    output.render(payload, _table_view)


def _table_view(console: Console, payload: dict[str, Any]) -> None:
    source = payload["source"]
    source_label = {
        "env": f"environment variable ({payload['source_detail']})",
        "config": f"config file ({payload['source_detail']})",
    }.get(source, source)

    table = Table(title="Crimson Crawler — auth", title_justify="center", show_header=False)
    table.add_column("field", style="bold")
    table.add_column("value")
    table.add_row("Source", source_label)
    table.add_row("API key", payload["api_key_masked"])
    table.add_row("Config file", payload["config_file"] or "not present")
    console.print(table)


__all__ = ["whoami"]
