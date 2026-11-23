"""``ccc whoami`` — local config + auth-source check, no network call.

Reports which source the API key came from (env var or config file), a masked
tail of the key, and the config file's own state — stat'ed independently of
which source won, so a present-but-unused or present-but-refused file is
visible instead of collapsing into "not present" (#252). A ``--verify`` flag
that hits the API to confirm the key is accepted will land later — today the
enrichment commands themselves exercise the live key.
"""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.table import Table

from .. import auth, config, output


def whoami() -> None:
    """Print resolved auth source, masked key tail, and config-file state.

    Exits 0 on success, 1 (via :class:`MissingCredentialsError`) when no key
    is configured. A refused config file behind a set env var is reported, not
    fatal — the key resolved, and the row is where the user sees why the file
    was skipped.
    """
    resolved = auth.resolve_auth()

    # Four states. `resolve_auth` short-circuits on the env var, so `refused` only ever
    # coexists with `source == "env"` — with the env var unset the loader raises first.
    status, detail = config.config_file_status()
    if status == "present":
        status = "in_use" if resolved.source == "config" else "unused"

    payload: dict[str, Any] = {
        "source": resolved.source,
        "source_detail": resolved.source_detail,
        "api_key_tail": resolved.key_tail,
        "api_key_masked": resolved.masked_key,
        "config_file": None if status == "absent" else str(config.CONFIG_FILE),
        "config_file_status": status,
        "config_file_detail": detail,
    }
    output.render(payload, _table_view)


def _table_view(console: Console, payload: dict[str, Any]) -> None:
    source = payload["source"]
    source_label = {
        "env": f"environment variable ({payload['source_detail']})",
        "config": f"config file ({payload['source_detail']})",
    }.get(source, source)

    path = payload["config_file"]
    config_label = {
        "absent": "not present",
        "in_use": path,
        "unused": f"{path} — present but unused (the environment variable wins)",
        "refused": f"{path} — present but REFUSED: {payload['config_file_detail']}",
    }[payload["config_file_status"]]

    table = Table(title="Crimson Crawler — auth", title_justify="center", show_header=False)
    table.add_column("field", style="bold")
    table.add_column("value")
    table.add_row("Source", source_label)
    table.add_row("API key", payload["api_key_masked"])
    table.add_row("Config file", config_label)
    console.print(table)


__all__ = ["whoami"]
