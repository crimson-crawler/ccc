"""Allow ``python -m crimson_crawler_cli`` to invoke the same Typer app as ``ccc``.

Useful when the console script isn't on PATH (CI containers, broken venv
activation, debugging). The ``ccc`` entry point in ``pyproject.toml`` remains
the canonical surface; this just exposes the module form as a fallback.
"""

from __future__ import annotations

from .cli import app

if __name__ == "__main__":
    app()
