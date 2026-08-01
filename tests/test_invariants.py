"""Architecture invariants for the CLI command layer.

The governing rule for the CLI: **every CLI command is
backed by an SDK convenience method — no raw ``client.api`` / ``_generated``
imports in command code.** The convenience surface is the contract; the raw
generated client stays an SDK-only escape hatch for Python scripting.

This test promotes that rule from a reviewer's manual grep into a
blocking gate, so a future command can't silently reach through the escape
hatch and pass CI green.
"""

from __future__ import annotations

import pathlib

import pytest

_COMMANDS_DIR = pathlib.Path(__file__).parent.parent / "src" / "crimson_crawler_cli" / "commands"
_FORBIDDEN = ("client.api", "_generated")


@pytest.mark.parametrize("module", sorted(_COMMANDS_DIR.glob("*.py")), ids=lambda p: p.name)
def test_command_code_has_no_raw_escape_hatch(module: pathlib.Path) -> None:
    """No command module may reference the raw ``client.api`` / ``_generated`` escape hatch."""
    source = module.read_text(encoding="utf-8")
    leaked = [token for token in _FORBIDDEN if token in source]
    assert not leaked, (
        f"{module.name} references the SDK escape hatch {leaked} — CLI commands must route "
        f"through a hand-written SDK convenience method. Add a wrapper to the SDK "
        f"instead of reaching into client.api / _generated from command code."
    )
