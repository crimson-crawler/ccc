"""``ccc ingest <format> <file>`` — parse a scan, enrich discovered assets, emit a briefing.

A thin shell over the SDK's scan→briefing workflow: read the file, call
``client.inventory_manager.ingest_scan(content, format)`` — which parses the scan
server-side into asset items (all 11 formats), enriches them against the
``/v1/inventory-enrich`` KEV-first ranking engine, and returns a structured briefing —
then render a Markdown playbook (or the raw JSON briefing under ``--json``, the shared
:data:`output.JsonFlag` trailing twin of the global flag).

All 11 scan/inventory formats are supported (json/sbom/csv/nmap/list/grype/trivy/depcheck/nessus/gvm/xlsx);
the parsing + ranking now live server-side / in the SDK, so the CLI owns only the
Markdown rendering (:func:`playbook.render_briefing`). ``--expand`` (shared
:data:`output.ExpandFlag`) lifts the per-finding CVE-description cap. The single
``/v1/inventory-enrich`` submit is the only billable call (cheaper than enriching each
product separately).
"""

from __future__ import annotations

import json as _jsonlib
import sys
from pathlib import Path
from typing import Annotated, Any

import typer

from .. import auth, output, paths, playbook
from .. import ingest as ingest_lib
from ..client_factory import build_client
from ..exceptions import BadInputError, handle_errors
from . import _formatters

# The 11 scan/inventory formats the parse endpoint accepts (no auto-detection — you PICK one).
FORMATS = ["json", "sbom", "csv", "nmap", "list", "grype", "trivy", "depcheck", "nessus", "gvm", "xlsx"]


@handle_errors
def ingest_command(
    scan_format: Annotated[
        str,
        typer.Argument(help=f"Scan/inventory format — one of: {', '.join(FORMATS)}.", show_default=False),
    ],
    scan_file: Annotated[
        Path,
        typer.Argument(
            exists=True,
            dir_okay=False,
            readable=True,
            help="The scan/inventory file to ingest.",
            show_default=False,
        ),
    ],
    output_path: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the briefing to a file instead of stdout."),
    ] = None,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Parse (server-side, all formats) → enrich (ranking engine) → render briefing."""
    if output_path is not None:
        paths.ensure_writable_output(output_path)  # fail before any billable API work
    fmt = scan_format.lower()
    if fmt not in FORMATS:
        raise BadInputError(f"Unknown format '{scan_format}'. One of: {', '.join(FORMATS)}.")
    # xlsx is binary — read bytes (the SDK base64-encodes them); the other formats are text.
    content: str | bytes = (
        scan_file.read_bytes() if fmt == "xlsx" else scan_file.read_text(encoding="utf-8", errors="replace")
    )
    resolved = auth.resolve_auth()

    def _call(on_progress: Any) -> Any:
        async def _inner() -> dict[str, Any]:
            async with build_client(resolved) as client:
                return await ingest_lib.ingest_scan(client.inventory_manager, content, fmt, on_progress=on_progress)

        return _inner()

    briefing = _formatters.with_live_progress(f"Ingesting {scan_file.name} ({fmt})", _call)

    if output.is_json_mode():
        rendered = _jsonlib.dumps(briefing, indent=2, sort_keys=True) + "\n"
    else:
        rendered = playbook.render_briefing(briefing, scan_file=scan_file.name, expand=output.is_expand_mode())

    if output_path is not None:
        paths.write_atomic(output_path, rendered)
        if not output.is_json_mode():
            output.get_error_console().print(f"Briefing written to {output_path}")
    else:
        sys.stdout.write(rendered)


__all__ = ["ingest_command", "FORMATS"]
