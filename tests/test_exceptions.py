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
