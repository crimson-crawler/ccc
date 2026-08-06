"""Unit tests for ``output.render_error`` — the shared error-rendering path.

Why these live in a test rather than in the semgrep rule: that rule's taint
sources are dict-field reads, and ``render_error`` takes ``human_message`` as a
plain ``str`` parameter, so no source pattern can match it. See
``output.render_error``'s own docstring for what the escape is defending.
"""

from __future__ import annotations

import json

import pytest
from rich.console import Console

from crimson_crawler_cli import output


def _capture_error(monkeypatch: pytest.MonkeyPatch, human_message: str, width: int = 200) -> str:
    console = Console(record=True, width=width, color_system=None, stderr=True)
    monkeypatch.setattr(output, "_error_console", console)
    output.render_error({"error": "APIError", "message": human_message}, human_message)
    return console.export_text()


@pytest.mark.parametrize(
    "payload",
    [
        # malformed: an unbalanced tag would raise MarkupError inside the handler.
        "boom [/] unbalanced",
        # style-forgery: the body must not be able to claim success in green.
        "[green]Success: nothing wrong[/green]",
        # link: must not become a real OSC-8 terminal hyperlink.
        "[link=file:///etc/passwd]click[/link]",
    ],
    ids=["malformed", "style-forgery", "link"],
)
def test_render_error_renders_server_text_verbatim(monkeypatch: pytest.MonkeyPatch, payload: str) -> None:
    """Escaped markup renders back to its literal text; interpreted markup does not."""
    assert payload in _capture_error(monkeypatch, payload)


def test_render_error_keeps_its_own_error_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only the message is escaped — the literal ``[red]`` prefix still renders."""
    text = _capture_error(monkeypatch, "plain failure")
    assert text.startswith("Error: plain failure")


def test_render_error_json_mode_is_unaffected(capsys: pytest.CaptureFixture[str]) -> None:
    """JSON mode writes the raw payload to stderr — no markup involved, no escaping."""
    output.set_json_mode(True)
    output.render_error({"error": "APIError", "message": "[red]x[/red]"}, "[red]x[/red]")
    parsed = json.loads(capsys.readouterr().err)
    assert parsed["message"] == "[red]x[/red]"
