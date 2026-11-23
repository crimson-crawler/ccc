"""Rejected-key wording in :mod:`crimson_crawler_cli.exceptions`.

``Crimson Crawler API returned status 401`` reads like a server fault; it is
almost always a stale, revoked, or wrong-origin key.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from crimson_crawler_cli import exceptions, output
from crimson_crawler_cli.exceptions import ExitCode, describe_api_status


def test_401_names_the_rejected_key_and_its_origin(monkeypatch: pytest.MonkeyPatch, clean_env: Path) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "env-key-abcd")

    message = describe_api_status(401)

    assert "rejected your API key" in message
    assert "CRIMSON_CRAWLER_API_KEY environment variable" in message
    assert "env-key-abcd" not in message


def test_402_names_the_missing_ai_provider_and_the_fix(clean_env: Path) -> None:
    message = describe_api_status(402)
    assert "AI Provider" in message
    assert "Dashboard" in message


@pytest.mark.parametrize("status", [400, 404, 422, 500])
def test_other_statuses_keep_the_neutral_phrasing(status: int, clean_env: Path) -> None:
    assert describe_api_status(status) == f"Crimson Crawler API returned status {status}"


def test_origin_lookup_never_replaces_the_api_error(secure_config_file: Path) -> None:
    """A broken config found while describing a 401 must not mask the 401.

    ``credential_origin`` runs inside the error path, so it degrades to "no
    origin" rather than raising the very ``ConfigFileError`` this change also
    introduces.
    """
    secure_config_file.write_text("CRIMSON_CRAWLER_API_KEY=broken\n", encoding="utf-8")

    message = describe_api_status(401)

    assert "rejected your API key" in message
    assert "The key came from" not in message


def test_handle_errors_renders_401_and_keeps_the_json_payload(
    clean_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """SDK ``UnexpectedStatus`` → ``APIError`` → rendered message, ``--json`` intact."""
    from crimson_crawler_client import UnexpectedStatus

    @exceptions.handle_errors
    def command() -> None:
        raise UnexpectedStatus(401, b'{"message": "Invalid authentication credentials"}')

    output.set_json_mode(True)
    with pytest.raises(Exception) as exc_info:  # typer.Exit
        command()

    assert getattr(exc_info.value, "exit_code", None) == ExitCode.API_ERROR
    payload = json.loads(capsys.readouterr().err)
    assert payload["status"] == 401
    assert payload["body"] == {"message": "Invalid authentication credentials"}
    assert "rejected your API key" in payload["message"]


def test_api_error_message_carries_the_server_reason_except_for_auth_statuses() -> None:
    """A human saw only ``returned status 400`` and never the rule that failed; ``--json`` alone had it."""
    from crimson_crawler_cli.exceptions import APIError

    assert str(APIError(400, {"error": "Daily report requires daily enrichment —\n enable monitoring first."})) == (
        "Crimson Crawler API returned status 400: Daily report requires daily enrichment — enable monitoring first."
    )
    assert str(APIError(404, {"detail": "x" * 400})).endswith("x" * 300 + "…")
    assert str(APIError(500, "plain text body")) == "Crimson Crawler API returned status 500"
    assert "No API key found" not in str(APIError(401, {"message": "No API key found in request"}))


@pytest.mark.parametrize(
    ("status", "reason", "guidance"),
    [
        (409, "snapshot_expired", "Restart the walk without a cursor."),
        (503, "snapshot_unavailable", "Retry later."),
    ],
)
def test_api_error_reports_nested_paging_reason(status: int, reason: str, guidance: str) -> None:
    from crimson_crawler_cli.exceptions import APIError

    assert str(APIError(status, {"detail": {"error": reason}})).endswith(guidance)
    assert str(APIError(status, {"detail": reason})).endswith(f": {reason}")
    assert str(APIError(status, {"detail": {"error": "x" * 400}})).endswith("x" * 300 + "…")
    assert str(APIError(status, {"detail": {"error": ["not a reason"]}})).endswith(f"status {status}")


@pytest.mark.parametrize("nested", [False, True])
def test_server_errors_cannot_emit_terminal_controls(
    nested: bool, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from io import StringIO

    from rich.console import Console

    from crimson_crawler_cli.exceptions import APIError

    bidi_controls = "".join(
        chr(code) for code in (0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A))
    )
    reason = f"\x1b[2J\x9b2J\x1b]0;title\x1b\\\x1b]0;title\x07\x7f{bidi_controls}\r[red]literal[/red]\nline\tend"
    body = {"detail": {"error": reason}} if nested else {"detail": reason}
    stream = StringIO()
    monkeypatch.setattr(output, "_error_console", Console(file=stream, force_terminal=True, color_system=None))
    output.set_json_mode(False)
    output.render_error({"body": body}, str(APIError(400, body)))
    rendered = stream.getvalue()
    assert not any(char in rendered for char in ("\x1b", "\x9b", "\x07", "\x7f", "\r", *bidi_controls))
    assert "[red]literal[/red]" in rendered
    output.set_json_mode(True)
    try:
        output.render_error({"body": body}, str(APIError(400, body)))
        assert json.loads(capsys.readouterr().err)["body"] == body
    finally:
        output.set_json_mode(False)
