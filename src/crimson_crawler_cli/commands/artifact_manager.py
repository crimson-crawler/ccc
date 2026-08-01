"""``ccc artifact-manager`` — your Artifact Manager over the key-authed Artifact Manager API.

Every subcommand routes through the SDK's hand-written ``client.artifact_manager``
namespace (:class:`crimson_crawler_client.ArtifactManagerAPI`) — never the raw
escape hatch — satisfying the convenience-surface invariant. Artifact Manager calls are
**usage-exempt**: they never count toward the monthly API quota.
"""

from __future__ import annotations

import base64
import mimetypes
from enum import Enum
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from .. import auth, output, paths
from ..client_factory import build_client
from ..exceptions import BadInputError, handle_errors
from ._formatters import with_status

app = typer.Typer(
    name="artifact-manager",
    help="Your Artifact Manager library — list/upload/update/copy/delete artifacts, export, compare, "
    "rate, and organize folders (usage-exempt). Inventories live under `ccc inventory-manager`.",
    no_args_is_help=True,
)

_WINDOWS_RESERVED_FILENAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"} | {f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)}
)


class ArtifactKind(str, Enum):
    """Artifact kinds accepted by ``ccc artifact-manager list --kind``."""

    input = "input"
    artifact_enrichment = "artifact_enrichment"
    report = "report"
    inventory_enrichment = "inventory_enrichment"  # saved inventory enrichments
    inventory_asset = "inventory_asset"  # inventories


def _fmt_bytes(n: object) -> str:
    if not isinstance(n, (int, float)) or n <= 0:
        return "—"
    value = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"


def _ensure_new_output(path: Path) -> None:
    paths.ensure_writable_output(path)
    if path.exists():
        raise BadInputError(f"Output file already exists: {path}")


# -- list ------------------------------------------------------------------- #


def _render_artifacts(console: Console, payload: dict[str, Any]) -> None:
    artifacts = payload.get("artifacts", [])
    if not artifacts:
        console.print("[dim]No artifacts found.[/dim]")
        return
    table = Table(title=f"Artifacts ({len(artifacts)})")
    table.add_column("ID", overflow="fold")
    table.add_column("Kind")
    table.add_column("Name", overflow="fold")
    table.add_column("Size", justify="right")
    table.add_column("★", justify="center")
    table.add_column("Created")
    for a in artifacts:
        table.add_row(
            escape(str(a.get("id", ""))),
            escape(str(a.get("kind", ""))),
            escape(str(a.get("name", ""))),
            _fmt_bytes(a.get("byte_size")),
            "★" if a.get("favorite") else "",
            escape(str(a.get("created_at", ""))[:19]),
        )
    console.print(table)


@app.command("list", help="List your saved artifacts (newest first).")
@handle_errors
def list_command(
    kind: Annotated[
        ArtifactKind | None,
        typer.Option("--kind", help="Filter by artifact kind.", case_sensitive=False),
    ] = None,
    folder: Annotated[
        str | None,
        typer.Option("--folder", help="A folder id, or __root__ for un-filed artifacts."),
    ] = None,
) -> None:
    """List the caller's artifacts via ``client.artifact_manager.list_artifacts``."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            artifacts = await client.artifact_manager.list_artifacts(
                kind=kind.value if kind else None,
                folder=folder,
            )
            return {"artifacts": artifacts}

    payload = with_status("Listing artifacts…", _call())
    output.render(payload, _render_artifacts)


# -- upload ----------------------------------------------------------------- #


def _render_upload(console: Console, payload: dict[str, Any]) -> None:
    ids = payload.get("ids", [])
    console.print(f"[green]Uploaded {len(ids)} artifact(s).[/green]")
    for aid in ids:
        console.print(f"  {escape(str(aid))}")
    if payload.get("folderId"):
        console.print(f"[dim]Filed into folder {escape(str(payload['folderId']))}[/dim]")


@app.command("upload", help="Upload files into your Artifact Manager as input artifacts (max 20).")
@handle_errors
def upload_command(
    file_paths: Annotated[
        list[Path],
        typer.Argument(help="Files to upload (text uploads as paste, binary as base64).", show_default=False),
    ],
    folder_name: Annotated[
        str | None,
        typer.Option("--folder", help="File the uploads into this folder (created if missing)."),
    ] = None,
) -> None:
    """Upload one or more files via ``client.artifact_manager.upload_artifacts``."""
    if len(file_paths) > 20:
        raise BadInputError("At most 20 artifacts per upload.")
    artifacts: list[dict[str, Any]] = []
    for path in file_paths:
        if not path.is_file():
            raise BadInputError(f"Not a file: {path}")
        data = path.read_bytes()
        try:
            text = data.decode("utf-8")
            artifacts.append(
                {
                    "name": path.name,
                    "content": text,
                    "format": "paste",
                    "mime": mimetypes.guess_type(path.name)[0] or "text/plain",
                }
            )
        except UnicodeDecodeError:
            artifacts.append(
                {
                    "name": path.name,
                    "content": base64.b64encode(data).decode(),
                    "format": "file",
                    "mime": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
                }
            )
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return await client.artifact_manager.upload_artifacts(artifacts, new_folder_name=folder_name)

    payload = with_status(f"Uploading {len(artifacts)} artifact(s)…", _call())
    output.render(payload, _render_upload)


# -- get -------------------------------------------------------------------- #


@app.command("get", help="Fetch one artifact's content (stdout, or -o FILE).")
@handle_errors
def get_command(
    artifact_id: Annotated[str, typer.Argument(help="Artifact id.", show_default=False)],
    out: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the content to this file instead of stdout."),
    ] = None,
) -> None:
    """Stream an artifact's raw content via ``client.artifact_manager.get_artifact_raw``."""
    if out is not None:
        paths.ensure_writable_output(out)  # fail before the API call (clean error, not a write traceback)
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return await client.artifact_manager.get_artifact_raw(artifact_id)

    raw = with_status("Fetching artifact…", _call())
    if out is not None:
        out.write_text(raw["content"], encoding="utf-8")
        summary = {k: raw[k] for k in ("id", "kind", "name", "format", "mime")}
        summary["saved_to"] = str(out)
        summary["bytes"] = len(raw["content"].encode())
        output.render(
            summary,
            lambda c, p: c.print(
                f"[green]Saved[/green] {escape(str(p['name'] or p['id']))} → "
                f"{escape(str(p['saved_to']))} ({_fmt_bytes(p['bytes'])})"
            ),
        )
    elif output.is_json_mode():
        output.render(raw, lambda c, p: None)
    else:
        # Raw content to stdout — pipe-friendly, no Rich markup interpretation.
        typer.echo(raw["content"])


# -- exports ---------------------------------------------------------------- #


@app.command("exports", help="List a saved enrichment's machine-export formats.")
@handle_errors
def exports_command(
    enrichment_id: Annotated[str, typer.Argument(help="Scan artifact id.", show_default=False)],
) -> None:
    """List export formats via ``client.artifact_manager.list_exports``."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return {"formats": await client.artifact_manager.list_exports(enrichment_id)}

    payload = with_status("Listing exports…", _call())
    output.render(payload, lambda c, p: c.print(" ".join(p["formats"]) or "[dim]none[/dim]"))


def _safe_response_filename(filename: object, fallback: str) -> Path:
    """Reduce the server-sent Content-Disposition filename to a safe local name.

    The default ``export`` target comes straight from the API response, so treat
    it as untrusted: accept it only when it is a cross-platform plain basename.
    Traversal, control characters, Windows device/alternate-stream syntax, and
    platform-invalid names fall back to a name derived from the CLI arguments.
    An explicit ``--output`` bypasses this entirely because the user's own path
    is authoritative.
    """
    raw_name = str(filename or "")
    name = raw_name.strip()
    windows_stem = name.rstrip(". ").split(".", 1)[0].upper()
    if (
        not name
        or raw_name != name
        or name in {".", ".."}
        or name.endswith((".", " "))
        or windows_stem in _WINDOWS_RESERVED_FILENAMES
        or any(ord(character) < 32 for character in name)
        or any(character in '<>:"/\\|?*' for character in name)
        or name != Path(name).name
    ):
        return Path(fallback)
    return Path(name)


@app.command("export", help="Download one machine export of a saved enrichment (stix, misp, csaf, vex, csv, …).")
@handle_errors
def export_command(
    enrichment_id: Annotated[str, typer.Argument(help="Scan artifact id.", show_default=False)],
    format: Annotated[str, typer.Argument(help="Export format (`ccc artifact-manager exports`).", show_default=False)],  # noqa: A002
    out: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output path (default: the export's own filename, e.g. stix.json)."),
    ] = None,
) -> None:
    """Download one export via ``client.artifact_manager.get_export``."""
    if out is not None:
        _ensure_new_output(out)
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return await client.artifact_manager.get_export(enrichment_id, format)

    exp = with_status(f"Downloading {format} export…", _call())
    target = out if out is not None else _safe_response_filename(exp["filename"], f"{enrichment_id}.{format}")
    _ensure_new_output(target)
    # Write the authoritative RAW bytes — correct for text formats AND the binary XLSX deliverables
    # (emass/workbook); `exp["content"]` is a lossy text decode that would corrupt a spreadsheet.
    target.write_bytes(exp["bytes"])
    payload = {
        "saved_to": str(target),
        "filename": exp["filename"],
        "content_type": exp["content_type"],
        "bytes": len(exp["bytes"]),
    }
    output.render(
        payload,
        lambda c, p: c.print(
            f"[green]Saved[/green] {escape(str(p['filename']))} → "
            f"{escape(str(p['saved_to']))} ({_fmt_bytes(p['bytes'])})"
        ),
    )


@app.command("export-all", help="Download ALL of a saved enrichment's machine exports as one .zip.")
@handle_errors
def export_all_command(
    enrichment_id: Annotated[str, typer.Argument(help="Scan artifact id.", show_default=False)],
    out: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output path (default: <id>-exports.zip)."),
    ] = None,
) -> None:
    """Download every machine export as one .zip via ``client.artifact_manager.download_all_exports``."""
    target = out if out is not None else Path(f"{enrichment_id}-exports.zip")
    _ensure_new_output(target)
    resolved = auth.resolve_auth()

    async def _call() -> bytes:
        async with build_client(resolved) as client:
            return await client.artifact_manager.download_all_exports(enrichment_id)

    data = with_status("Downloading all exports…", _call())
    target = out if out is not None else Path(f"{enrichment_id}-exports.zip")
    target.write_bytes(data)
    payload = {"saved_to": str(target), "bytes": len(data)}
    output.render(
        payload,
        lambda c, p: c.print(
            f"[green]Saved[/green] all exports → {escape(str(p['saved_to']))} ({_fmt_bytes(p['bytes'])})"
        ),
    )


# -- compare ---------------------------------------------------------------- #


def _render_matrix(console: Console, payload: dict[str, Any]) -> None:
    matrix = payload.get("matrix", {})
    counts = matrix.get("counts", {})
    console.print(
        f"[bold]Change:[/bold] "
        f"[green]{counts.get('new', 0)} new[/green] · "
        f"[cyan]{counts.get('resolved', 0)} resolved[/cyan] · "
        f"[yellow]{counts.get('changed', 0)} changed[/yellow] · "
        f"[dim]{counts.get('persistent', 0)} persistent[/dim]"
    )
    rows = matrix.get("rows", [])[:20]
    if not rows:
        return
    columns = matrix.get("columns", [])
    table = Table(title=f"Findings ({len(matrix.get('rows', []))} total, showing {len(rows)})")
    table.add_column("Finding", overflow="fold")
    table.add_column("Status")
    for col in columns:
        table.add_column(escape(str(col.get("name", ""))[:24]), justify="right")
    for row in rows:
        cells = ["—" if c is None else escape(str(c.get("score", "·"))) for c in row.get("cells", [])]
        table.add_row(escape(str(row.get("value", ""))), escape(str(row.get("status", ""))), *cells)
    console.print(table)


@app.command("compare", help="Difference matrix across 2-12 of your saved enrichments.")
@handle_errors
def compare_command(
    enrichment_ids: Annotated[
        list[str],
        typer.Argument(help="Two to twelve enrichment artifact ids.", show_default=False),
    ],
) -> None:
    """Build the enrichment-difference matrix via ``client.artifact_manager.compare_enrichments``."""
    if not 2 <= len(enrichment_ids) <= 12:
        raise BadInputError("Pass between 2 and 12 enrichment ids.")
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return {"matrix": await client.artifact_manager.compare_enrichments(enrichment_ids)}

    payload = with_status("Comparing enrichments…", _call())
    output.render(payload, _render_matrix)


# -- save-enrichment -------------------------------------------------------- #


@app.command("save-enrichment", help="Save a COMPLETED artifact enrichment into your library by its enrichment id.")
@handle_errors
def save_enrichment_command(
    enrichment_id: Annotated[
        str, typer.Argument(help="The enrichment id from `ccc artifact-enrich`.", show_default=False)
    ],
    folder: Annotated[str | None, typer.Option("--folder", help="File it into an existing folder id.")] = None,
    new_folder: Annotated[
        str | None, typer.Option("--new-folder", help="Create (or reuse) a folder by name and file it there.")
    ] = None,
) -> None:
    """Persist a finished enrichment via ``client.artifact_manager.save_enrichment`` — the standalone
    'Save enrichment' (the engine returns the report but never saves it). Idempotent."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return await client.artifact_manager.save_enrichment(
                enrichment_id, folder_id=folder, new_folder_name=new_folder
            )

    payload = with_status("Saving enrichment…", _call())
    output.render(
        payload,
        lambda c, p: c.print(
            "[yellow]Already saved.[/yellow]"
            if p.get("already_persisted")
            else f"[green]Saved[/green] enrichment → {p.get('enrichment_artifact_id', '')}"
        ),
    )


# -- delete ----------------------------------------------------------------- #


@app.command("delete", help="Delete one or more artifacts from your Artifact Manager.")
@handle_errors
def delete_command(
    ids: Annotated[
        list[str],
        typer.Argument(help="Artifact id(s) to delete (max 200).", show_default=False),
    ],
) -> None:
    """Delete artifacts via ``client.artifact_manager.bulk_delete`` (single or bulk)."""
    if len(ids) > 200:
        raise BadInputError("At most 200 artifacts per delete.")
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return {"count": await client.artifact_manager.bulk_delete(ids), "ids": ids}

    payload = with_status(f"Deleting {len(ids)} artifact(s)…", _call())
    output.render(payload, lambda c, p: c.print(f"[green]Deleted[/green] {p['count']} artifact(s)"))


# -- move ------------------------------------------------------------------- #


@app.command("move", help="Move one or more artifacts into a folder (or to root).")
@handle_errors
def move_command(
    ids: Annotated[
        list[str],
        typer.Argument(help="Artifact id(s) to move (max 200).", show_default=False),
    ],
    folder: Annotated[str | None, typer.Option("--folder", help="Target folder id.")] = None,
    root: Annotated[bool, typer.Option("--root", help="Move to root (no folder).")] = False,
) -> None:
    """Bulk move artifacts via ``client.artifact_manager.move_to_folder``."""
    if root == (folder is not None):
        raise BadInputError("Pass exactly one of --folder or --root.")
    if len(ids) > 200:
        raise BadInputError("At most 200 artifacts per move.")
    folder_id = None if root else folder
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return {"count": await client.artifact_manager.move_to_folder(ids, folder_id)}

    dest = "root" if root else folder
    payload = with_status(f"Moving {len(ids)} artifact(s)…", _call())
    output.render(payload, lambda c, p: c.print(f"[green]Moved[/green] {p['count']} artifact(s) → {dest}"))


# -- favorite --------------------------------------------------------------- #


@app.command("favorite", help="Star or unstar one or more artifacts.")
@handle_errors
def favorite_command(
    ids: Annotated[
        list[str],
        typer.Argument(help="Artifact id(s) to star/unstar (max 200).", show_default=False),
    ],
    on: Annotated[bool, typer.Option("--on/--off", help="Star (--on) or unstar (--off).")] = True,
) -> None:
    """Bulk star/unstar artifacts via ``client.artifact_manager.bulk_set_favorite``."""
    if len(ids) > 200:
        raise BadInputError("At most 200 artifacts per call.")
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return {"count": await client.artifact_manager.bulk_set_favorite(ids, on)}

    verb = "Starred" if on else "Unstarred"
    payload = with_status(f"Updating {len(ids)} artifact(s)…", _call())
    output.render(payload, lambda c, p: c.print(f"[green]{verb}[/green] {p['count']} artifact(s)"))


# -- folders ---------------------------------------------------------------- #


def _render_folders(console: Console, payload: dict[str, Any]) -> None:
    folders = payload.get("folders", [])
    if not folders:
        console.print("[dim]No folders.[/dim]")
        return
    table = Table(title=f"Folders ({len(folders)})")
    table.add_column("ID", overflow="fold")
    table.add_column("Name")
    table.add_column("Artifacts", justify="right")
    for f in folders:
        table.add_row(
            escape(str(f.get("id", ""))),
            escape(str(f.get("name", ""))),
            escape(str(f.get("artifact_count", 0))),
        )
    console.print(table)


@app.command("folders", help="List your Artifact Manager folders.")
@handle_errors
def folders_command() -> None:
    """List folders via ``client.artifact_manager.list_folders``."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return {"folders": await client.artifact_manager.list_folders()}

    payload = with_status("Listing folders…", _call())
    output.render(payload, _render_folders)


@app.command("create-folder", help="Create a new folder.")
@handle_errors
def create_folder_command(
    name: Annotated[str, typer.Argument(help="Folder name.", show_default=False)],
) -> None:
    """Create a folder via ``client.artifact_manager.create_folder``. Returns its id."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return {"id": await client.artifact_manager.create_folder(name)}

    payload = with_status("Creating folder…", _call())
    output.render(payload, lambda c, p: c.print(f"[green]Created[/green] folder {p.get('id', '')}."))


@app.command("rename-folder", help="Rename one of your folders.")
@handle_errors
def rename_folder_command(
    folder_id: Annotated[str, typer.Argument(help="Folder id.", show_default=False)],
    name: Annotated[str, typer.Argument(help="New folder name.", show_default=False)],
) -> None:
    """Rename a folder via ``client.artifact_manager.rename_folder``."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return {"folder": await client.artifact_manager.rename_folder(folder_id, name)}

    payload = with_status("Renaming folder…", _call())
    output.render(payload, lambda c, _p: c.print(f"[green]Renamed[/green] folder {folder_id}."))


@app.command("delete-folder", help="Delete a folder (its artifacts move back to root, never deleted).")
@handle_errors
def delete_folder_command(
    folder_id: Annotated[str, typer.Argument(help="Folder id.", show_default=False)],
) -> None:
    """Delete a folder via ``client.artifact_manager.delete_folder``. Artifacts inside move back to root."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return {"deleted": await client.artifact_manager.delete_folder(folder_id), "id": folder_id}

    payload = with_status("Deleting folder…", _call())
    output.render(payload, lambda c, _p: c.print(f"[green]Deleted[/green] folder {folder_id}."))


# -- update ----------------------------------------------------------------- #


@app.command("update", help="Rename, star/unstar, or move an artifact between folders.")
@handle_errors
def update_command(
    artifact_id: Annotated[str, typer.Argument(help="Artifact id.", show_default=False)],
    name: Annotated[str | None, typer.Option("--name", help="New display name.")] = None,
    favorite: Annotated[bool | None, typer.Option("--favorite/--no-favorite", help="Star or unstar.")] = None,
    folder: Annotated[str | None, typer.Option("--folder", help="Move into this folder id.")] = None,
    root: Annotated[bool, typer.Option("--root", help="Move back to root (no folder).")] = False,
) -> None:
    """Partial update via ``client.artifact_manager.update_artifact`` (rename / favorite / move)."""
    if root and folder is not None:
        raise BadInputError("Pass either --folder or --root, not both.")
    if name is None and favorite is None and folder is None and not root:
        raise BadInputError("Nothing to update — pass --name, --favorite/--no-favorite, --folder, or --root.")
    kwargs: dict[str, Any] = {}
    if name is not None:
        kwargs["name"] = name
    if favorite is not None:
        kwargs["favorite"] = favorite
    if root:
        kwargs["folder_id"] = None
    elif folder is not None:
        kwargs["folder_id"] = folder
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return {"artifact": await client.artifact_manager.update_artifact(artifact_id, **kwargs)}

    payload = with_status("Updating artifact…", _call())
    output.render(payload, lambda c, p: c.print(f"[green]Updated[/green] {p['artifact'].get('name') or artifact_id}"))


# -- copy ------------------------------------------------------------------- #


@app.command("copy", help="Duplicate an artifact as 'Copy of …'.")
@handle_errors
def copy_command(
    artifact_id: Annotated[str, typer.Argument(help="Artifact id.", show_default=False)],
) -> None:
    """Duplicate an artifact via ``client.artifact_manager.copy_artifact``."""
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            return {"id": await client.artifact_manager.copy_artifact(artifact_id)}

    payload = with_status("Copying artifact…", _call())
    output.render(payload, lambda c, p: c.print(f"[green]Copied[/green] → {p['id']}"))


# -- bundle downloads ------------------------------------------------------- #


@app.command("download-folder", help="Download every artifact in a folder as one .zip.")
@handle_errors
def download_folder_command(
    folder_id: Annotated[str, typer.Argument(help="Folder id.", show_default=False)],
    out: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output path (default: <folder>.zip)."),
    ] = None,
) -> None:
    """Download a whole folder as one .zip via ``client.artifact_manager.download_folder``."""
    target = out if out is not None else Path(f"{folder_id}-folder.zip")
    _ensure_new_output(target)
    resolved = auth.resolve_auth()

    async def _call() -> bytes:
        async with build_client(resolved) as client:
            return await client.artifact_manager.download_folder(folder_id)

    data = with_status("Downloading folder…", _call())
    target = out if out is not None else Path(f"{folder_id}-folder.zip")
    target.write_bytes(data)
    payload = {"saved_to": str(target), "bytes": len(data)}
    output.render(
        payload, lambda c, p: c.print(f"[green]Saved[/green] folder → {p['saved_to']} ({_fmt_bytes(p['bytes'])})")
    )


@app.command("download-bundle", help="Bundle a set of artifacts into one .zip (the bulk Download .zip).")
@handle_errors
def download_bundle_command(
    artifact_ids: Annotated[list[str], typer.Argument(help="Artifact ids to bundle.", show_default=False)],
    out: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output path (default: artifacts.zip)."),
    ] = None,
) -> None:
    """Bundle the given artifacts into one .zip via ``client.artifact_manager.download_bundle``."""
    target = out if out is not None else Path("artifacts.zip")
    _ensure_new_output(target)
    resolved = auth.resolve_auth()

    async def _call() -> bytes:
        async with build_client(resolved) as client:
            return await client.artifact_manager.download_bundle(artifact_ids)

    data = with_status("Bundling artifacts…", _call())
    target = out if out is not None else Path("artifacts.zip")
    target.write_bytes(data)
    payload = {"saved_to": str(target), "bytes": len(data), "count": len(artifact_ids)}
    output.render(
        payload,
        lambda c, p: c.print(
            f"[green]Saved[/green] {p['count']} artifact(s) → {p['saved_to']} ({_fmt_bytes(p['bytes'])})"
        ),
    )


# -- rating ----------------------------------------------------------------- #


class RatingValue(str, Enum):
    """Values for ``ccc artifact-manager rating --set``."""

    up = "up"
    down = "down"
    clear = "clear"


def _render_rating(console: Console, payload: dict[str, Any]) -> None:
    counts = payload.get("counts", {})
    console.print(
        f"Your rating: [bold]{payload.get('rating') or '—'}[/bold]  "
        f"([green]↑{counts.get('up', 0)}[/green] [red]↓{counts.get('down', 0)}[/red])"
    )


@app.command("rating", help="Show or set your thumbs rating on a saved enrichment.")
@handle_errors
def rating_command(
    enrichment_id: Annotated[str, typer.Argument(help="Scan artifact id.", show_default=False)],
    set_: Annotated[
        RatingValue | None,
        typer.Option("--set", help="Set your rating (up/down) or clear it.", case_sensitive=False),
    ] = None,
) -> None:
    """Get (default) or set an enrichment's rating via ``client.artifact_manager.get_rating``/``set_rating``."""
    resolved = auth.resolve_auth()

    if set_ is None:

        async def _call() -> dict[str, Any]:
            async with build_client(resolved) as client:
                return await client.artifact_manager.get_rating(enrichment_id)

        payload = with_status("Fetching rating…", _call())
    else:
        rating = None if set_ is RatingValue.clear else set_.value

        async def _call() -> dict[str, Any]:
            async with build_client(resolved) as client:
                return await client.artifact_manager.set_rating(enrichment_id, rating)

        payload = with_status("Setting rating…", _call())

    output.render(payload, _render_rating)


__all__ = ["app"]
