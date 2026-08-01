"""Pre-flight validation for ``--output`` destinations.

Commands that write their result to a file (``ingest nmap``, ``workspace get``,
``workspace export``) call :func:`ensure_writable_output` *before* any network
work so a bad path fails fast — exit 64 with a clean message — instead of
wasting API usage and then raising a raw :class:`OSError` at the final write.

This lives in its own module (not ``output.py``) on purpose: ``exceptions.py``
already does ``from . import output``, so a helper that raises
:class:`BadInputError` can't live in ``output`` without a circular import.
The dependency order here is ``paths → exceptions → output`` — no cycle.
"""

from __future__ import annotations

import os
from pathlib import Path

from .exceptions import BadInputError


def ensure_writable_output(path: Path) -> None:
    """Fail fast (:class:`BadInputError` → exit 64) if ``path`` can't be written as a file.

    Validates the destination *before* any API call so a bad ``--output`` never
    wastes usage. Checks, in order: not a symlink, not an existing directory,
    parent exists, parent is a directory, parent is writable.

    The symlink check is a confinement guard, not a convenience. ``Path.write_text``
    follows a symlink and truncates its *target*, so an ``--output`` pointing at a
    planted link overwrote whatever it referenced while leaving the link itself
    intact — the write reported success and exit 0. That matters most where the
    path is not the operator's own choice: a CI job templating ``--output`` from a
    branch name or ticket field, or any wrapper that writes into a shared or
    world-writable directory. Refuse the link and make the caller name a real
    file; the target being writable is not the same as the caller intending to
    write there.
    """
    if path.is_symlink():
        raise BadInputError(
            f"Output path is a symlink, refusing to write through it: {path}. Pass the real destination file instead."
        )
    if path.is_dir():
        raise BadInputError(f"Output path is a directory, not a file: {path}")
    parent = path.parent  # bare "file.md" → Path('.'), which exists + is writable
    if not parent.exists():
        raise BadInputError(f"Output directory does not exist: {parent}")
    if not parent.is_dir():
        raise BadInputError(f"Output parent is not a directory: {parent}")
    if not os.access(parent, os.W_OK):
        raise BadInputError(f"Output directory is not writable: {parent}")


__all__ = ["ensure_writable_output"]
