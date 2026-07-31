"""Typer entry point for the ``ccc`` console script.

Registers global flags (``--json``, ``--expand``, ``--version``) and the shipped
commands. Every ``/v1`` operation is reachable: the ``enrich``, ``search``, and
``assess`` groups cover the 29 synchronous endpoints, and the two async engines
(``artifact-enrich``, ``inventory-enrich``) are groups whose callback submits and
whose ``status ID`` subcommand reads the job back. ``search-techniques`` remains
as a deprecated top-level alias for ``ccc search techniques``.

Every data command also declares :data:`output.JsonFlag` and
:data:`output.ExpandFlag` so the trailing forms (``ccc enrich cve X --json``,
``ccc enrich cve X --expand``) work alongside the global prefix forms.
Command functions are decorated with :func:`handle_errors` (from
:mod:`exceptions`) which renders :class:`CLIError` subclasses through
:mod:`output` and exits with ``error.exit_code``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from . import __version__, output
from .commands import artifact_manager as artifact_manager_cmd
from .commands import assess as assess_cmd
from .commands import crawl as crawl_cmd
from .commands import enrich as enrich_cmd
from .commands import enrich_artifact as enrich_artifact_cmd
from .commands import enrich_inventory as enrich_inventory_cmd
from .commands import ingest as ingest_cmd
from .commands import inventory_manager as inventory_manager_cmd
from .commands import reports as reports_cmd
from .commands import search as search_cmd
from .commands import search_techniques as search_techniques_cmd
from .commands import whoami as whoami_cmd
from .exceptions import ExitCode, handle_errors

app = typer.Typer(
    name="ccc",
    help="Command-line interface for the Crimson Crawler API.",
    no_args_is_help=True,
    add_completion=False,
)

# The two async engines are command groups rather than leaf commands: the group
# callback IS the submit (so `ccc artifact-enrich --text …` keeps working exactly
# as it shipped) and `status ID` reads the job back. `invoke_without_command`
# plus `no_args_is_help=False` is what makes a bare group invocation run the
# callback instead of printing help.
artifact_enrich_app = typer.Typer(
    name="artifact-enrich",
    help="Run the async Artifact Enricher engine on free text + files → one graded report.",
    invoke_without_command=True,
    no_args_is_help=False,
)
inventory_enrich_app = typer.Typer(
    name="inventory-enrich",
    help="Submit an asset list to the Threat Inventory Enricher engine (see also: ccc ingest).",
    invoke_without_command=True,
    no_args_is_help=False,
)

app.add_typer(enrich_cmd.app, name="enrich")
app.add_typer(search_cmd.app, name="search")
app.add_typer(assess_cmd.app, name="assess")
app.add_typer(artifact_enrich_app, name="artifact-enrich")
app.add_typer(inventory_enrich_app, name="inventory-enrich")
app.add_typer(artifact_manager_cmd.app, name="artifact-manager")
app.add_typer(inventory_manager_cmd.app, name="inventory-manager")
app.add_typer(reports_cmd.app, name="reports")
app.add_typer(crawl_cmd.app, name="crawl")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit(code=ExitCode.OK)


@app.callback()
def _root(
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Emit machine-readable JSON instead of Rich-formatted output.",
        ),
    ] = False,
    expand: Annotated[
        bool,
        typer.Option(
            "--expand",
            help="Show full, untruncated fields and all sub-table rows (no-op with --json).",
        ),
    ] = False,
    _version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Show the CLI version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """Configure global output flags before dispatching to a subcommand."""
    output.set_json_mode(json_output)
    output.set_expand_mode(expand)


@app.command("whoami", help="Show which API key the CLI will use and where it came from.")
@handle_errors
def whoami(_json: output.JsonFlag = False, _expand: output.ExpandFlag = False) -> None:
    """Resolve auth locally and print the source + masked key tail."""
    whoami_cmd.whoami()


@artifact_enrich_app.callback(invoke_without_command=True)
@handle_errors
def artifact_enrich(
    ctx: typer.Context,
    text: Annotated[
        str | None,
        typer.Option("--text", help="Pasted free text to enrich.", show_default=False),
    ] = None,
    files: Annotated[
        list[Path] | None,
        typer.Option(
            "--file",
            exists=True,
            dir_okay=False,
            readable=True,
            show_default=False,
            help="Artifact file to upload (repeatable). Read as bytes, base64-encoded.",
        ),
    ] = None,
    depth: Annotated[
        enrich_artifact_cmd.Depth,
        typer.Option(
            "--depth",
            help="Enrichment depth: fast (minimal include) or full (the engine default).",
            case_sensitive=False,
        ),
    ] = enrich_artifact_cmd.Depth.full,
    output_path: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the full report JSON to a file instead of summarizing."),
    ] = None,
    save: Annotated[
        bool,
        typer.Option("--save", help="Save the finished report into your Artifact Manager library (usage-exempt)."),
    ] = False,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Submit text + files to the Artifact Enricher engine unless a subcommand was named."""
    if ctx.invoked_subcommand is not None:
        return
    enrich_artifact_cmd.artifact_enrich_command(text=text, files=files, depth=depth, output_path=output_path, save=save)


@artifact_enrich_app.command("status", help="Read one artifact-enrichment job's status and stages.")
@handle_errors
def artifact_enrich_status(
    enrichment_id: Annotated[
        str,
        typer.Argument(help="The enrichment id returned by the submit.", show_default=False),
    ],
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Forward to :func:`enrich_artifact_cmd.artifact_enrich_status_command`."""
    enrich_artifact_cmd.artifact_enrich_status_command(enrichment_id)


@inventory_enrich_app.callback(invoke_without_command=True)
@handle_errors
def inventory_enrich(
    ctx: typer.Context,
    items_file: enrich_inventory_cmd.ItemsFileOption = None,
    products: enrich_inventory_cmd.ProductOption = None,
    include: Annotated[
        list[str] | None,
        typer.Option("--include", help="Response layer to include, repeatable (default: the server's).",
                     show_default=False),
    ] = None,
    attachments_text: Annotated[
        str | None,
        typer.Option("--attachments-text", help="Free text for the engine's artifact-enrichment stage.",
                     show_default=False),
    ] = None,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Submit the asset list to the Threat Inventory Enricher unless a subcommand was named."""
    if ctx.invoked_subcommand is not None:
        return
    enrich_inventory_cmd.inventory_enrich_command(
        items_file=items_file,
        products=products,
        include=include,
        attachments_text=attachments_text,
    )


@inventory_enrich_app.command("status", help="Read one inventory-enrichment job's status and stages.")
@handle_errors
def inventory_enrich_status(
    enrichment_id: Annotated[
        str,
        typer.Argument(help="The enrichment id returned by the submit.", show_default=False),
    ],
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Forward to :func:`enrich_inventory_cmd.inventory_enrich_status_command`."""
    enrich_inventory_cmd.inventory_enrich_status_command(enrichment_id)


@app.command(
    "ingest",
    help="Parse a scan/inventory file (any of 11 formats), enrich the assets, and emit a ranked briefing.",
)
@handle_errors
def ingest(
    scan_format: Annotated[
        str,
        typer.Argument(
            help="Scan/inventory format: json/sbom/csv/nmap/list/grype/trivy/depcheck/nessus/gvm/xlsx.",
            show_default=False,
        ),
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
    """Forward to :func:`ingest_cmd.ingest_command`."""
    ingest_cmd.ingest_command(scan_format=scan_format, scan_file=scan_file, output_path=output_path)


@app.command(
    "search-techniques",
    help="Deprecated — use `ccc search techniques`. Keyword search across the ATT&CK knowledge base.",
)
@handle_errors
def search_techniques(
    keyword: Annotated[str, typer.Argument(help="Search term (e.g. 'credential dumping')", show_default=False)],
    limit: Annotated[
        int,
        typer.Option("--limit", min=1, max=100, help="Maximum number of results to return."),
    ] = 20,
    _json: output.JsonFlag = False,
    _expand: output.ExpandFlag = False,
) -> None:
    """Forward to :func:`search_techniques_cmd.search_techniques_command`.

    Deprecated top-level alias for ``ccc search techniques``. It shipped in
    v4.0.0, before the ``search`` group existed, so it stays wired to the same
    implementation — scripts pinned to the old spelling keep working unchanged.
    """
    search_techniques_cmd.search_techniques_command(keyword, limit=limit)
