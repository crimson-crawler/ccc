"""Collect one streamed OSV advisory walk under an explicit serialized-byte ceiling.

``enrich cve`` and ``assess vulnerability-exposure`` page their OSV advisories behind a snapshot
cursor. The SDK iterators stream the pages; this module is the CLI's only collector. Page zero is
the whole response; every later page is an OSV-only continuation, so only its advisories and errors
are merged. Collection is bounded by compact UTF-8 JSON bytes (not RSS) and an overflow aborts with
``osv_walk_too_large`` before anything is printed, so a partial walk is never presented as complete.

``osv_advisories_truncated`` is true on every page that still has a cursor, so a completed walk
recomputes it: the walk is complete only when the collected distinct rows equal the exact
``osv_advisories_total``, no row is ``projection_truncated``, no page reported an unreadable
advisory or an over-budget row, and the final page itself is not marked incomplete.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack
from typing import Any

from ..exceptions import CLIError

DEFAULT_MAX_BYTES = 256 * 1024 * 1024

_ENCODER = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _bytes_remaining(value: Any, remaining: int) -> int:
    for chunk in _ENCODER.iterencode(value):
        remaining -= len(chunk.encode("utf-8"))
        if remaining < 0:
            raise CLIError("osv_walk_too_large: OSV walk results exceed --max-bytes")
    return remaining


def _walk_incomplete(payload: dict[str, Any], *, final_page_truncated: bool) -> bool:
    rows = [row for row in payload.get("osv_advisories") or [] if isinstance(row, dict)]
    total = payload.get("osv_advisories_total")
    if not isinstance(total, int) or isinstance(total, bool):
        return True
    return (
        final_page_truncated
        or len({row.get("id") for row in rows}) < total
        or any(row.get("projection_truncated") for row in rows)
        or any(
            isinstance(error, dict)
            and (error.get("step") == "read_osv_advisory" or error.get("error") == "row_exceeds_page_budget")
            for error in payload.get("errors") or []
        )
    )


async def collect_osv_walk(pages: AsyncIterator[Any], *, max_bytes: int) -> dict[str, Any]:
    """Merge a complete OSV walk into page zero's payload, or raise without a partial result."""
    payload: dict[str, Any] | None = None
    remaining = max_bytes
    walked = False
    final_page_truncated = False
    async with AsyncExitStack() as stack:
        aclose = getattr(pages, "aclose", None)
        if aclose is not None:
            stack.push_async_callback(aclose)
        async for response in pages:
            page = response.to_dict()
            if payload is None:
                payload = page
                remaining = _bytes_remaining(payload, remaining)
                continue
            walked = True
            final_page_truncated = bool(page.get("osv_advisories_truncated"))
            for advisory in page.get("osv_advisories") or []:
                remaining = _bytes_remaining(advisory, remaining - 1)
                payload.setdefault("osv_advisories", []).append(advisory)
            for error in page.get("errors") or []:
                if error not in payload.setdefault("errors", []):
                    remaining = _bytes_remaining(error, remaining - 1)
                    payload["errors"].append(error)
            if page.get("osv_advisories_total") is not None:
                payload["osv_advisories_total"] = page["osv_advisories_total"]
    if payload is None:
        raise ValueError("OSV walk returned no pages")
    if walked:
        payload["osv_advisories_truncated"] = _walk_incomplete(payload, final_page_truncated=final_page_truncated)
    for cursor in ("osv_next_offset", "osv_snapshot_id"):
        payload.pop(cursor, None)
    return payload
