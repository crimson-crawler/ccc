"""End-to-end tests for the nine ``ccc enrich`` entity commands plus ``batch`` and ``poc-source``.

The nine entity commands (atlas, campaign, capec, defend, disarm, group,
location, sector, software) share one shape — a direct id *or* ``--search``,
optionally a ``--framework`` — so they are covered by parametrized cases over
:data:`_ENTITIES` rather than nine near-identical copies. What differs per
command (which SDK method it calls, which payload key holds the entity, whether
the id space has a canonical format worth rejecting locally) is data in that
table, so a mis-wired command fails its own case.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from crimson_crawler_cli.cli import app
from crimson_crawler_cli.exceptions import ExitCode
from crimson_crawler_client import UnexpectedStatus

# command, SDK method, entity payload key, id field, valid id, malformed id
# (None = slug-shaped id space with no local format check), framework support.
_ENTITIES = [
    ("atlas", "enrich_atlas_full", "technique", "technique_id", "AML.T0043", "AML-T0043", False),
    ("campaign", "enrich_campaign_full", "campaign", "campaign_id", "C0028", "C28", True),
    ("capec", "enrich_capec_full", "attack_pattern", "capec_id", "CAPEC-66", "CAPEC66", False),
    ("defend", "enrich_defend_full", "d3fend", "d3fend_id", "D3-AL", None, False),
    ("disarm", "enrich_disarm_full", "technique", "technique_id", "T0001", "TT0001", False),
    ("group", "enrich_group_full", "group", "group_id", "G0016", "G16", True),
    ("location", "enrich_location_full", "location", "location_id", "L0001", None, False),
    ("sector", "enrich_sector_full", "sector", "sector_id", "financial-services", None, False),
    ("software", "enrich_software_full", "software", "software_id", "S0154", "S154", True),
]

_IDS = [entity[0] for entity in _ENTITIES]


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def _stub_response(payload: dict) -> MagicMock:
    response = MagicMock()
    response.to_dict.return_value = payload
    return response


def _entity_payload(key: str, id_field: str, identifier: str) -> dict:
    return {
        key: {
            id_field: identifier,
            "name": "Example Entity",
            "description": "A representative description.",
            "aliases": ["Alias One"],
            "url": "https://example.test/entity",
        },
        "techniques": [{"technique_id": "T1190", "name": "Exploit Public-Facing App", "tactics": ["initial-access"]}],
        "errors": [],
    }


# -- the nine entity commands --------------------------------------------------- #


@pytest.mark.parametrize("command,method,key,id_field,valid,_bad,_fw", _ENTITIES, ids=_IDS)
def test_entity_direct_id_renders_table(
    command: str,
    method: str,
    key: str,
    id_field: str,
    valid: str,
    _bad: str | None,
    _fw: bool,
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    clean_env: Path,
    mock_sdk,
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    getattr(mock_sdk, method).return_value = _stub_response(_entity_payload(key, id_field, valid))

    result = runner.invoke(app, ["enrich", command, valid])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "Example Entity" in result.stdout
    assert "T1190" in result.stdout  # the shared linked-techniques sub-table
    getattr(mock_sdk, method).assert_awaited_once()


@pytest.mark.parametrize("command,method,key,id_field,valid,_bad,framework", _ENTITIES, ids=_IDS)
def test_entity_passes_identifier_and_framework(
    command: str,
    method: str,
    key: str,
    id_field: str,
    valid: str,
    _bad: str | None,
    framework: bool,
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    clean_env: Path,
    mock_sdk,
) -> None:
    """The positional lands as the SDK's first arg; ``--framework`` only where it exists."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mocked = getattr(mock_sdk, method)
    mocked.return_value = _stub_response(_entity_payload(key, id_field, valid))

    result = runner.invoke(app, ["enrich", command, valid])

    assert result.exit_code == 0, result.stdout + result.stderr
    args, kwargs = mocked.call_args
    assert args == (valid,)
    assert kwargs["search"] is None
    if framework:
        assert kwargs["framework"] == "enterprise"
    else:
        assert "framework" not in kwargs


@pytest.mark.parametrize("command,method,key,id_field,valid,_bad,_fw", _ENTITIES, ids=_IDS)
def test_entity_json_round_trip(
    command: str,
    method: str,
    key: str,
    id_field: str,
    valid: str,
    _bad: str | None,
    _fw: bool,
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    clean_env: Path,
    mock_sdk,
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    payload = _entity_payload(key, id_field, valid)
    getattr(mock_sdk, method).return_value = _stub_response(payload)

    result = runner.invoke(app, ["--json", "enrich", command, valid])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == payload


@pytest.mark.parametrize("command,method,key,id_field,_valid,_bad,_fw", _ENTITIES, ids=_IDS)
def test_entity_search_renders_matches(
    command: str,
    method: str,
    key: str,
    id_field: str,
    _valid: str,
    _bad: str | None,
    _fw: bool,
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    clean_env: Path,
    mock_sdk,
) -> None:
    """``--search`` sends no identifier and renders the ``search_results`` table."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mocked = getattr(mock_sdk, method)
    mocked.return_value = _stub_response(
        {"search_results": [{id_field: "X0001", "name": "Matched Entity"}], "errors": []}
    )

    result = runner.invoke(app, ["enrich", command, "--search", "example query"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "Matched Entity" in result.stdout
    args, kwargs = mocked.call_args
    assert args == (None,)
    assert kwargs["search"] == "example query"


@pytest.mark.parametrize("command,method,_key,_id_field,_valid,_bad,_fw", _ENTITIES, ids=_IDS)
def test_entity_requires_id_or_search_exits_64(
    command: str,
    method: str,
    _key: str,
    _id_field: str,
    _valid: str,
    _bad: str | None,
    _fw: bool,
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    clean_env: Path,
    mock_sdk,
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["enrich", command])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    getattr(mock_sdk, method).assert_not_awaited()


@pytest.mark.parametrize("command,method,_key,_id_field,valid,_bad,_fw", _ENTITIES, ids=_IDS)
def test_entity_rejects_id_and_search_together_exits_64(
    command: str,
    method: str,
    _key: str,
    _id_field: str,
    valid: str,
    _bad: str | None,
    _fw: bool,
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    clean_env: Path,
    mock_sdk,
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["enrich", command, valid, "--search", "also this"])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    getattr(mock_sdk, method).assert_not_awaited()


@pytest.mark.parametrize(
    "command,method,bad",
    [(entity[0], entity[1], entity[5]) for entity in _ENTITIES if entity[5] is not None],
    ids=[entity[0] for entity in _ENTITIES if entity[5] is not None],
)
def test_entity_malformed_id_exits_64_without_network(
    command: str,
    method: str,
    bad: str,
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    clean_env: Path,
    mock_sdk,
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["enrich", command, bad])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    getattr(mock_sdk, method).assert_not_awaited()


@pytest.mark.parametrize(
    "command,method,lowered,expected",
    [
        ("atlas", "enrich_atlas_full", "aml.t0043", "AML.T0043"),
        ("campaign", "enrich_campaign_full", "c0028", "C0028"),
        ("group", "enrich_group_full", "g0016", "G0016"),
        ("software", "enrich_software_full", "s0154", "S0154"),
    ],
)
def test_entity_canonical_ids_are_upper_cased(
    command: str,
    method: str,
    lowered: str,
    expected: str,
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    clean_env: Path,
    mock_sdk,
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mocked = getattr(mock_sdk, method)
    mocked.return_value = _stub_response({"errors": []})

    result = runner.invoke(app, ["enrich", command, lowered])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert mocked.call_args.args == (expected,)


def test_entity_slug_id_sent_verbatim(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """Slug id spaces (sector/location/D3FEND) must not be case-mangled."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_sector_full.return_value = _stub_response({"errors": []})

    result = runner.invoke(app, ["enrich", "sector", "financial-services"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert mock_sdk.enrich_sector_full.call_args.args == ("financial-services",)


def test_entity_empty_response_reports_no_data(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """A shape-complete-but-empty response must not render an empty detail table."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_group_full.return_value = _stub_response({"group": None, "search_results": [], "errors": []})

    result = runner.invoke(app, ["enrich", "group", "G0016"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "No data found" in result.stdout


def test_entity_framework_flag_forwarded(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_software_full.return_value = _stub_response({"errors": []})

    result = runner.invoke(app, ["enrich", "software", "S0154", "--framework", "ics"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert mock_sdk.enrich_software_full.call_args.kwargs["framework"] == "ics"


def test_entity_missing_credentials_exits_2(runner: CliRunner, clean_env: Path, mock_sdk) -> None:
    result = runner.invoke(app, ["enrich", "capec", "CAPEC-66"])

    assert result.exit_code == int(ExitCode.MISSING_CREDENTIALS)
    mock_sdk.enrich_capec_full.assert_not_awaited()


def test_entity_api_error_exits_3(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_atlas_full.side_effect = UnexpectedStatus(422, b'{"detail":"bad request"}', None)

    result = runner.invoke(app, ["--json", "enrich", "atlas", "AML.T0043"])

    assert result.exit_code == int(ExitCode.API_ERROR)
    payload = json.loads(result.stderr)
    assert payload["status"] == 422


# -- ccc enrich batch ----------------------------------------------------------- #

_BATCH_RESULT = {
    "results": [
        {"index": 0, "type": "cve", "identifier": "CVE-2024-3400", "status": "ok", "errors": []},
        {"index": 1, "type": "package", "identifier": "PyPI/requests", "status": "error", "errors": [{"error": "x"}]},
    ],
    "errors": [],
}


def test_batch_inline_items(runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_batch.return_value = _stub_response(_BATCH_RESULT)

    result = runner.invoke(
        app,
        ["enrich", "batch", "--item", '{"type":"cve","cve_id":"CVE-2024-3400"}', "--item", '{"type":"atlas"}'],
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "CVE-2024-3400" in result.stdout
    mock_sdk.enrich_batch.assert_awaited_once_with([{"type": "cve", "cve_id": "CVE-2024-3400"}, {"type": "atlas"}])


def test_batch_items_file_array(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk, tmp_path: Path
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_batch.return_value = _stub_response(_BATCH_RESULT)
    items = tmp_path / "items.json"
    items.write_text(json.dumps([{"type": "cwe", "cwe_id": "CWE-79"}]), encoding="utf-8")

    result = runner.invoke(app, ["enrich", "batch", str(items)])

    assert result.exit_code == 0, result.stdout + result.stderr
    mock_sdk.enrich_batch.assert_awaited_once_with([{"type": "cwe", "cwe_id": "CWE-79"}])


def test_batch_items_file_envelope_and_inline_combine(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk, tmp_path: Path
) -> None:
    """``{"items": [...]}`` is accepted, and ``--item`` appends to the file's list."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_batch.return_value = _stub_response(_BATCH_RESULT)
    items = tmp_path / "items.json"
    items.write_text(json.dumps({"items": [{"type": "cwe", "cwe_id": "CWE-79"}]}), encoding="utf-8")

    result = runner.invoke(app, ["enrich", "batch", str(items), "--item", '{"type":"group","group_id":"G0016"}'])

    assert result.exit_code == 0, result.stdout + result.stderr
    mock_sdk.enrich_batch.assert_awaited_once_with(
        [{"type": "cwe", "cwe_id": "CWE-79"}, {"type": "group", "group_id": "G0016"}]
    )


def test_batch_json_round_trip(runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_batch.return_value = _stub_response(_BATCH_RESULT)

    result = runner.invoke(app, ["--json", "enrich", "batch", "--item", '{"type":"atlas"}'])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == _BATCH_RESULT


def test_batch_output_file_write(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk, tmp_path: Path
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_batch.return_value = _stub_response(_BATCH_RESULT)
    out = tmp_path / "batch.json"

    result = runner.invoke(app, ["enrich", "batch", "--item", '{"type":"atlas"}', "--output", str(out)])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert json.loads(out.read_text()) == _BATCH_RESULT
    assert result.stdout == ""


def test_batch_no_items_exits_64(runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["enrich", "batch"])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.enrich_batch.assert_not_awaited()


def test_batch_invalid_inline_json_exits_64(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["enrich", "batch", "--item", "{not json"])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.enrich_batch.assert_not_awaited()


def test_batch_item_without_type_exits_64(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """Every item carries a ``type`` discriminator; a missing one is a local 422."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["enrich", "batch", "--item", '{"cve_id":"CVE-2024-3400"}'])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.enrich_batch.assert_not_awaited()


def test_batch_over_fifty_items_exits_64(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk, tmp_path: Path
) -> None:
    """The server's 50-item cap is enforced locally so the 51st never costs a request."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    items = tmp_path / "items.json"
    items.write_text(json.dumps([{"type": "cve", "cve_id": f"CVE-2000-00{n:02d}"} for n in range(51)]), "utf-8")

    result = runner.invoke(app, ["enrich", "batch", str(items)])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.enrich_batch.assert_not_awaited()


def test_batch_bad_output_path_exits_64_before_call(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk, tmp_path: Path
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    missing = tmp_path / "nope" / "batch.json"

    result = runner.invoke(app, ["enrich", "batch", "--item", '{"type":"atlas"}', "--output", str(missing)])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.enrich_batch.assert_not_awaited()


# -- ccc enrich poc-source ------------------------------------------------------ #


def test_poc_source_happy_path(runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_poc_source.return_value = _stub_response(
        {
            "repo_url": "https://github.com/amlweems/xzbot",
            "summary": {
                "trigger": "Malicious SSH certificate payload.",
                "affected_path": "liblzma/liblzma.so",
                "mitigation": "Upgrade to 5.6.2.",
                "preconditions": ["sshd linked against liblzma"],
            },
            "errors": [],
        }
    )

    result = runner.invoke(app, ["enrich", "poc-source", "https://github.com/amlweems/xzbot"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "liblzma" in result.stdout
    mock_sdk.enrich_poc_source.assert_awaited_once_with("https://github.com/amlweems/xzbot")


def test_poc_source_json_round_trip(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    payload = {"repo_url": "https://github.com/o/r", "summary": {"trigger": "t"}, "errors": []}
    mock_sdk.enrich_poc_source.return_value = _stub_response(payload)

    result = runner.invoke(app, ["--json", "enrich", "poc-source", "https://github.com/o/r"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == payload


def test_poc_source_no_summary_reports_no_data(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_poc_source.return_value = _stub_response(
        {"repo_url": "https://github.com/o/r", "summary": None, "errors": []}
    )

    result = runner.invoke(app, ["enrich", "poc-source", "https://github.com/o/r"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "No data found" in result.stdout


@pytest.mark.parametrize("bad", ["github.com/o/r", "http://github.com/o/r", "https://gitlab.com/o/r", "not-a-url"])
def test_poc_source_malformed_url_exits_64(
    bad: str, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["enrich", "poc-source", bad])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.enrich_poc_source.assert_not_awaited()
