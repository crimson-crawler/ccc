"""``ccc crawl`` — collect a dependency/software inventory (no enrichment).

Two sources, one output shape:

  * ``ccc crawl project <dir>`` — walk a project directory's manifests
    (see :mod:`crimson_crawler_cli.crawl`).
  * ``ccc crawl endpoint`` — enumerate the local host's installed software
    (see :mod:`crimson_crawler_cli.endpoint`; Linux only for now).

Both emit the same :mod:`crimson_crawler_cli.inventory` **CycloneDX 1.6 JSON**
document (``bomFormat`` / ``specVersion`` / ``components``) to stdout, or to a
file with ``--output``. This is collection only. Feed the result to
``ccc ingest sbom <file>`` or ``ccc inventory-manager import <file> --format
sbom`` for enrichment.
"""

from __future__ import annotations

import datetime
import json
import platform
import sys
from pathlib import Path
from typing import Annotated

import typer

from .. import __version__, endpoint, inventory, output
from .. import crawl as crawl_mod
from ..exceptions import BadInputError, handle_errors

app = typer.Typer(
    name="crawl",
    help="Collect a dependency/software inventory from a project or this host.",
    no_args_is_help=True,
)


def _emit(doc: dict, output_path: Path | None) -> None:
    """Write the inventory JSON to a file or stdout."""
    rendered = json.dumps(doc, indent=2) + "\n"
    if output_path is not None:
        output_path.write_text(rendered, encoding="utf-8")
        output.get_error_console().print(f"Inventory written to {output_path}")
    else:
        sys.stdout.write(rendered)


def _timestamp() -> str:
    """CycloneDX ``metadata.timestamp`` — RFC3339 UTC, e.g. 2026-06-26T14:03:00Z."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@app.command("project", help="Crawl a project directory's manifests into an inventory.")
@handle_errors
def project_command(
    target_dir: Annotated[
        Path,
        typer.Argument(
            exists=True, file_okay=False, dir_okay=True, help="Project directory to crawl.", show_default=False
        ),
    ],
    output_path: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the inventory to a file instead of stdout."),
    ] = None,
    include_dev: Annotated[
        bool,
        typer.Option(
            "--include-dev",
            help="Include dev/test/docs dependency groups (excluded by default — "
            "they're tooling, not the deployed runtime surface).",
        ),
    ] = False,
) -> None:
    """Walk → dedup → emit CycloneDX SBOM."""
    assets, _n_files = crawl_mod.crawl(target_dir, include_dev=include_dev)
    _emit(inventory.build_inventory(assets, _timestamp(), tool_version=__version__), output_path)


@app.command("endpoint", help="Crawl the LOCAL host's installed software into an inventory (Linux only).")
@handle_errors
def endpoint_command(
    output_path: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the inventory to a file instead of stdout."),
    ] = None,
) -> None:
    """Enumerate installed software → dedup → emit CycloneDX SBOM."""
    if platform.system() != "Linux":
        raise BadInputError(f"ccc crawl endpoint supports Linux only for now (this host is {platform.system()}).")
    assets = inventory.dedup(endpoint.collect())
    _emit(inventory.build_inventory(assets, _timestamp(), tool_version=__version__), output_path)


__all__ = ["app", "endpoint_command", "project_command"]
