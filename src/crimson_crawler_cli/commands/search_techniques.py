"""``ccc search-techniques`` — keyword search across the ATT&CK knowledge base.

Calls the SDK's :meth:`CrawlerClient.search_techniques` convenience method,
which wraps the generated ``search_cti`` endpoint scoped to ATT&CK
attack-patterns (``sources=["attack"]``, ``types=["attack-pattern"]``) and
owns the enum-not-string serialisation footgun internally.
"""

from __future__ import annotations

from functools import partial
from typing import Annotated, Any

import typer

from .. import auth, output
from ..client_factory import build_client
from ..exceptions import BadInputError
from . import _formatters


def search_techniques_command(
    keyword: Annotated[str, typer.Argument(help="Search term (e.g. 'credential dumping')", show_default=False)],
    limit: Annotated[
        int,
        typer.Option("--limit", min=1, max=100, help="Maximum number of results to return."),
    ] = 20,
) -> None:
    """Run a keyword search against the ATT&CK knowledge base."""
    if not keyword.strip():
        raise BadInputError("Search keyword must not be empty.")
    resolved = auth.resolve_auth()

    async def _call() -> dict[str, Any]:
        async with build_client(resolved) as client:
            response = await client.search_techniques(keyword, limit=limit)
            return response.to_dict()

    payload = _formatters.with_status(f"Searching techniques for '{keyword}'…", _call())
    output.render(payload, partial(_formatters.render_search_cti, requested_keyword=keyword))


__all__ = ["search_techniques_command"]
