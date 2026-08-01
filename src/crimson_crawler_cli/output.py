"""Console + output mode singleton for the Crimson Crawler CLI.

Commands call :func:`render` with both a JSON-ready dict and a callable that
draws the Rich-table view. :func:`render` dispatches based on the global
``--json`` flag toggled by :func:`set_json_mode`.

Keeping the flag as a module-level singleton (rather than a parameter) keeps
subcommand signatures clean across the growing command surface.
"""

from __future__ import annotations

import json
import sys
from typing import Annotated, Any, Callable

import typer
from rich.console import Console

_console = Console()
_error_console = Console(stderr=True)
_json_mode: bool = False
_expand_mode: bool = False


def set_json_mode(enabled: bool) -> None:
    """Toggle JSON output for all subsequent :func:`render` / :func:`render_error` calls."""
    global _json_mode
    _json_mode = enabled


def set_expand_mode(enabled: bool) -> None:
    """Toggle expanded (untruncated) Rich output for all subsequent renderer calls."""
    global _expand_mode
    _expand_mode = enabled


def _json_flag_callback(value: bool) -> None:
    """Parameter callback: flip JSON mode on, never off.

    The root callback already ran ``set_json_mode(json_output)`` by the time
    Typer parses subcommand params, so an absent trailing flag (``value`` is
    ``False``) must not undo a global ``ccc --json …``.
    """
    if value:
        set_json_mode(True)


# Trailing twin of the global ``--json`` flag. Typer only matches callback
# options placed *before* the subcommand, so every data command declares this
# (unused) parameter to make `ccc enrich cve X --json` work the way people
# naturally type it. The callback does the mode flip; command bodies keep
# reading `is_json_mode()` and never touch the parameter value.
JsonFlag = Annotated[
    bool,
    typer.Option(
        "--json",
        help="Emit machine-readable JSON instead of Rich-formatted output (same as the global --json).",
        callback=_json_flag_callback,
    ),
]


def _expand_flag_callback(value: bool) -> None:
    """Parameter callback: flip expand mode on, never off.

    Mirrors :func:`_json_flag_callback` — the root callback already ran
    ``set_expand_mode(expand)`` by the time Typer parses subcommand params, so
    an absent trailing flag (``value`` is ``False``) must not undo a global
    ``ccc --expand …``.
    """
    if value:
        set_expand_mode(True)


# Trailing twin of the global ``--expand`` flag (mirror of :data:`JsonFlag`).
# Every data command declares this (unused) parameter so that
# `ccc enrich cve X --expand` works the way people naturally type it. The
# callback does the mode flip; renderers keep reading `is_expand_mode()`.
ExpandFlag = Annotated[
    bool,
    typer.Option(
        "--expand",
        help="Show full, untruncated fields and all sub-table rows (no-op with --json).",
        callback=_expand_flag_callback,
    ),
]


def is_json_mode() -> bool:
    """Return whether the CLI is currently in JSON output mode."""
    return _json_mode


def is_expand_mode() -> bool:
    """Return whether the CLI is currently in expanded (untruncated) output mode."""
    return _expand_mode


def get_console() -> Console:
    """Return the shared stdout Rich console."""
    return _console


def get_error_console() -> Console:
    """Return the shared stderr Rich console."""
    return _error_console


def render(payload: dict[str, Any], table_view: Callable[[Console, dict[str, Any]], None]) -> None:
    """Render ``payload`` as JSON or as a Rich table depending on global mode.

    Args:
        payload: JSON-serializable mapping describing the result.
        table_view: Callable that draws the human-friendly view to a Rich console.
    """
    if _json_mode:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        sys.stdout.flush()
    else:
        table_view(_console, payload)


def render_error(payload: dict[str, Any], human_message: str) -> None:
    """Render an error in JSON mode or as a human-readable stderr message."""
    if _json_mode:
        sys.stderr.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        sys.stderr.flush()
    else:
        _error_console.print(f"[red]Error:[/red] {human_message}")


__all__ = [
    "ExpandFlag",
    "JsonFlag",
    "get_console",
    "get_error_console",
    "is_expand_mode",
    "is_json_mode",
    "render",
    "render_error",
    "set_expand_mode",
    "set_json_mode",
]
