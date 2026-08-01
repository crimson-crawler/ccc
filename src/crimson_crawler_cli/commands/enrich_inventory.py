"""``ccc inventory-enrich`` — submit an asset list to the Threat Inventory Enricher.

The raw ``/v1/inventory-enrich`` pair: :func:`inventory_enrich_command` posts the
assets and returns the ``202`` acknowledgement (an ``enrichment_id`` plus queue
status), and :func:`inventory_enrich_status_command` reads that job back. The
submit does not poll — that keeps the command a 1:1 mapping of the endpoint and
leaves the caller free to check in later, script the wait, or walk away.

For the batteries-included path use ``ccc ingest <format> <file>``, which parses
a scan, submits it, polls to completion, and renders a ranked briefing; or
``ccc inventory-manager enrich``, which does the same for a saved inventory.
This command exists for the case those two don't cover: an ad-hoc asset list.

The submit counts toward API usage (it is enrichment compute); the status read
is the engine's own poll and does not.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer

from .. import auth, output
from ..client_factory import build_client
from ..exceptions import BadInputError
from . import _formatters


def _parse_asset(token: str) -> dict[str, str]:
    """Parse ``[vendor/]product[@version]`` into an inventory-asset dict.

    The same shorthand ``ccc enrich product`` accepts, so the CLI teaches one
    syntax for naming a product. Only ``product`` is required by the API; vendor
    and version are left out of the body when absent rather than sent empty.

    Branching on whether each separator was actually present is what makes a
    half-written token an error instead of a silent reinterpretation: without it
    ``apache/`` parses as the product "apache" (vendor dropped) and ``@1.2.3``
    as a product literally named "1.2.3".
    """
    remainder, at_sign, version = token.rpartition("@")
    if not at_sign:  # no "@" — rpartition put the whole token in `version`
        remainder, version = version, ""
    vendor, slash, product = remainder.partition("/")
    if not slash:  # no "/" — the single segment is the product
        vendor, product = "", vendor
    product, vendor, version = product.strip(), vendor.strip(), version.strip()
    if not product or (slash and not vendor) or (at_sign and not version):
        raise BadInputError(f"Malformed --product {token!r} (expected [vendor/]name[@version]).")
    asset: dict[str, str] = {"product": product}
    if vendor:
        asset["vendor"] = vendor
    if version:
        asset["version"] = version
    return asset


def _load_assets(items_file: Path | None, products: list[str] | None) -> list[dict[str, Any]]:
    """Collect inventory assets from a JSON file and/or repeated ``--product`` flags.

    The file form accepts a bare JSON array or the ``{"items": [...]}`` envelope
    and reaches the full asset model (``ecosystem``, ``cpe``, ``criticality``,
    ``environment``, ``exposure``, ``tags``, …); ``--product`` covers the quick
    case. ``product`` is the one required field, so that is what is checked.
    """
    assets: list[dict[str, Any]] = []
    if items_file is not None:
        try:
            loaded = json.loads(items_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise BadInputError(f"{items_file} is not valid JSON: {exc}") from exc
        if isinstance(loaded, dict):
            loaded = loaded.get("items")
        if not isinstance(loaded, list):
            raise BadInputError(f"{items_file} must hold a JSON array of assets, or {{'items': [...]}}.")
        for entry in loaded:
            if not isinstance(entry, dict) or not entry.get("product"):
                raise BadInputError(f"Each asset needs a 'product': {entry!r}")
            assets.append(entry)
    assets.extend(_parse_asset(token) for token in products or [])
    if not assets:
        raise BadInputError("Provide at least one --product, or an assets --file.")
    return assets


def inventory_enrich_command(
    *,
    items_file: Path | None = None,
    products: list[str] | None = None,
    include: list[str] | None = None,
    attachments_text: str | None = None,
) -> None:
    """Submit assets to the ``/v1/inventory-enrich`` engine and print the job id."""
    assets = _load_assets(items_file, products)
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            response = await client.inventory_enrich(
                assets,
                include=include,
                attachments_text=attachments_text,
            )
            return response.to_dict()

    payload = _formatters.with_status(f"Submitting {len(assets)} assets…", _call())
    output.render(payload, _render_submit)


def _render_submit(console: Any, payload: dict[str, Any]) -> None:
    """Render the submit acknowledgement with this engine's poll command."""
    _formatters.render_submit(console, payload, poll_hint="ccc inventory-enrich status")


def inventory_enrich_status_command(enrichment_id: str) -> None:
    """Read one inventory-enrichment job's status, stages, and result readiness."""
    if not enrichment_id.strip():
        raise BadInputError("Pass the enrichment id returned by the submit.")
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            response = await client.inventory_enrich_status(enrichment_id)
            return response.to_dict()

    payload = _formatters.with_status(f"Reading {enrichment_id}…", _call())
    output.render(payload, _formatters.render_job)


ItemsFileOption = Annotated[
    Path | None,
    typer.Option(
        "--file",
        exists=True,
        dir_okay=False,
        readable=True,
        help='JSON file holding an array of inventory assets, or {"items": [...]}.',
        show_default=False,
    ),
]
ProductOption = Annotated[
    list[str] | None,
    typer.Option(
        "--product",
        help="Asset as [vendor/]name[@version], repeatable (e.g. apache/httpd@2.4.51).",
        show_default=False,
    ),
]


__all__ = [
    "ItemsFileOption",
    "ProductOption",
    "inventory_enrich_command",
    "inventory_enrich_status_command",
]
