"""End-to-end tests for ``ccc enrich`` — ``cve``, ``product``, ``package``, ``ioc``, ``cwe``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from crimson_crawler_cli import output
from crimson_crawler_cli.cli import app
from crimson_crawler_cli.commands import _includes
from crimson_crawler_cli.exceptions import APIError, ExitCode, handle_errors
from crimson_crawler_client import UnexpectedStatus, presets


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def _stub_response(payload: dict) -> MagicMock:
    if "product" in payload:
        payload = {"snapshot_id": "a" * 32, **payload}
    response = MagicMock()
    response.to_dict.return_value = payload
    return response


# -- ccc enrich cve ----------------------------------------------------------- #


def test_enrich_cve_happy_path_table(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.return_value = _stub_response(
        {
            "cve": {
                "cve_id": "CVE-2024-3400",
                "cvss_v3_score": 9.8,
                "cvss_v3_severity": "CRITICAL",
                "description": "PAN-OS authentication bypass.",
                "has_public_exploit": True,
                "poc_count": 3,
            },
            "epss": {"score": 0.94, "percentile": 0.99},
            "kev": {"vendor_inventory": "Palo Alto"},
            "weaknesses": [{"cwe_id": "CWE-77"}],
            "techniques": [
                {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "tactics": ["execution"]}
            ],
            "errors": [],
        }
    )

    result = runner.invoke(app, ["enrich", "cve", "CVE-2024-3400"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "CVE-2024-3400" in result.stdout
    assert "9.8" in result.stdout
    mock_sdk.enrich_cve_full.assert_awaited_once_with(
        "CVE-2024-3400", include=[*presets.CVE_FULL_WALK, "poc"], osv_offset=0, osv_snapshot_id=None
    )


def test_enrich_cve_json_round_trip(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    payload = {"cve": {"cve_id": "CVE-2024-3400"}, "errors": []}
    mock_sdk.enrich_cve_full.return_value = _stub_response(payload)

    result = runner.invoke(app, ["--json", "enrich", "cve", "CVE-2024-3400"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == payload


def test_enrich_cve_lowercase_normalised(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.return_value = _stub_response({"cve": {"cve_id": "CVE-2024-3400"}})

    result = runner.invoke(app, ["enrich", "cve", "cve-2024-3400"])

    assert result.exit_code == 0
    mock_sdk.enrich_cve_full.assert_awaited_once_with(
        "CVE-2024-3400", include=[*presets.CVE_FULL_WALK, "poc"], osv_offset=0, osv_snapshot_id=None
    )


def test_enrich_cve_requests_poc_include(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """The cve command must layer ``poc`` onto the walk so PoC count populates (#193).

    Guards against a future preset edit silently dropping the explicit ``poc`` include.
    """
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.return_value = _stub_response({"cve": {"cve_id": "CVE-2024-3400"}})

    result = runner.invoke(app, ["enrich", "cve", "CVE-2024-3400"])

    assert result.exit_code == 0, result.stdout + result.stderr
    include = mock_sdk.enrich_cve_full.await_args.kwargs["include"]
    assert "poc" in include


def test_enrich_cve_malformed_exits_64(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["enrich", "cve", "not-a-cve"])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    assert "Malformed" in result.stderr
    mock_sdk.enrich_cve_full.assert_not_awaited()


def test_enrich_cve_missing_credentials_exits_2(runner: CliRunner, clean_env: Path, mock_sdk) -> None:
    result = runner.invoke(app, ["enrich", "cve", "CVE-2024-3400"])

    assert result.exit_code == int(ExitCode.MISSING_CREDENTIALS)
    assert "CRIMSON_CRAWLER_API_KEY" in result.stderr
    mock_sdk.enrich_cve_full.assert_not_awaited()


def test_enrich_cve_unauthorized_exits_3(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.side_effect = UnexpectedStatus(
        401, b'{"detail": "invalid key"}', "Crimson Crawler API 401"
    )

    result = runner.invoke(app, ["--json", "enrich", "cve", "CVE-2024-3400"])

    assert result.exit_code == int(ExitCode.API_ERROR)
    payload = json.loads(result.stderr)
    assert payload["status"] == 401
    assert payload["body"] == {"detail": "invalid key"}


def test_enrich_cve_unprocessable_decoded_text_body(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.side_effect = UnexpectedStatus(422, b"validation: failed", None)

    result = runner.invoke(app, ["--json", "enrich", "cve", "CVE-2024-3400"])

    assert result.exit_code == int(ExitCode.API_ERROR)
    payload = json.loads(result.stderr)
    assert payload["status"] == 422
    assert payload["body"] == "validation: failed"


def test_enrich_cve_none_body_serializes_null(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.side_effect = UnexpectedStatus(503, None, None)

    result = runner.invoke(app, ["--json", "enrich", "cve", "CVE-2024-3400"])

    assert result.exit_code == int(ExitCode.API_ERROR)
    payload = json.loads(result.stderr)
    assert payload["status"] == 503
    assert payload["body"] is None


def test_enrich_cve_non_utf8_body_hex_fallback(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.side_effect = UnexpectedStatus(500, b"\xff\xfe", None)

    result = runner.invoke(app, ["--json", "enrich", "cve", "CVE-2024-3400"])

    assert result.exit_code == int(ExitCode.API_ERROR)
    payload = json.loads(result.stderr)
    assert payload["status"] == 500
    assert payload["body"] == b"\xff\xfe".hex()


def test_enrich_cve_whitespace_body_serializes_null(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.side_effect = UnexpectedStatus(502, b"   ", None)

    result = runner.invoke(app, ["--json", "enrich", "cve", "CVE-2024-3400"])

    assert result.exit_code == int(ExitCode.API_ERROR)
    payload = json.loads(result.stderr)
    assert payload["status"] == 502
    assert payload["body"] is None


def test_enrich_cve_generic_exception_internal_error(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.side_effect = RuntimeError("boom")

    result = runner.invoke(app, ["--json", "enrich", "cve", "CVE-2024-3400"])

    assert result.exit_code == int(ExitCode.GENERIC_ERROR)
    payload = json.loads(result.stderr)
    assert payload["error"] == "InternalError"


def test_decode_unexpected_body_str_and_passthrough() -> None:
    """``_decode_unexpected_body`` handles already-decoded str + non-bytes/str inputs.

    ``UnexpectedStatus.body`` is bytes in practice, but the decoder also accepts a
    plain ``str`` (parsed/returned verbatim) and passes any other type through
    untouched. Covers the ``elif isinstance(raw, str)`` / ``else`` branches.
    """
    from crimson_crawler_cli.exceptions import _decode_unexpected_body

    assert _decode_unexpected_body('{"detail": "x"}') == {"detail": "x"}
    assert _decode_unexpected_body("plain text") == "plain text"
    sentinel = {"already": "decoded"}
    assert _decode_unexpected_body(sentinel) is sentinel


def test_handle_errors_renders_apierror_status_and_body(capsys: pytest.CaptureFixture[str]) -> None:
    """A directly-raised APIError (not via UnexpectedStatus) flows through the CLIError branch."""
    import typer

    from crimson_crawler_cli import output

    output.set_json_mode(True)
    try:

        @handle_errors
        def _boom() -> None:
            raise APIError(500, {"detail": "boom"})

        with pytest.raises(typer.Exit) as excinfo:
            _boom()
    finally:
        output.set_json_mode(False)

    assert excinfo.value.exit_code == int(ExitCode.API_ERROR)
    payload = json.loads(capsys.readouterr().err)
    assert payload["error"] == "APIError"
    assert payload["status"] == 500
    assert payload["body"] == {"detail": "boom"}


# -- ccc enrich product ------------------------------------------------------- #


def _assert_forwarded(mock: Any, *, args: tuple = (), **kwargs: Any) -> None:
    """Assert a CLI→SDK call by VALUE, not by exact kwarg set.

    The behavior these tests own is "which values did the command forward" (vendor/product
    inference, version pass-through). An exact-kwarg pin breaks on every new optional flag — the
    ``--include`` override did exactly that — so the meaningful values are compared instead, and
    the new `include` override is pinned to its omitted default here.
    """
    call = mock.await_args
    assert call.args == args, f"positional args: {call.args!r}"
    for key, value in kwargs.items():
        assert call.kwargs.get(key) == value, f"{key}={call.kwargs.get(key)!r}"
    assert call.kwargs.get("include") is None, "omitted --include must leave the SDK preset in place"


def test_enrich_product_vendor_slash_product(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_product_full.return_value = _stub_response(
        {"product": "nginx", "vendor": "nginx", "cves": [], "errors": []}
    )

    result = runner.invoke(app, ["enrich", "product", "nginx/nginx"])

    assert result.exit_code == 0, result.stdout + result.stderr
    _assert_forwarded(mock_sdk.enrich_product_full, args=("nginx",), version=None, vendor="nginx")


def test_enrich_product_collects_pages(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_product_full.side_effect = [
        _stub_response(
            {
                "product": "nginx",
                "cves": [{"cve": {"cve_id": "CVE-2024-0001"}}],
                "version_unconfirmed_cves": [],
                "errors": [],
                "cves_next_offset": 5,
            }
        ),
        _stub_response(
            {
                "product": "nginx",
                "cves": [{"cve": {"cve_id": "CVE-2024-0002"}}],
                "version_unconfirmed_cves": [],
                "errors": [],
                "cves_next_offset": None,
            }
        ),
    ]
    result = runner.invoke(app, ["enrich", "product", "nginx", "--json"])
    assert result.exit_code == 0, result.stdout + result.stderr
    data = json.loads(result.stdout)
    assert [row["cve"]["cve_id"] for row in data["cves"]] == ["CVE-2024-0001", "CVE-2024-0002"]
    assert data["cves_next_offset"] is None


def test_enrich_product_restarts_expired_snapshot(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    def response(snapshot, identifier, offset):
        return _stub_response(
            {
                "product": "nginx",
                "snapshot_id": snapshot,
                "cves_next_offset": offset,
                "cves": [{"cve": {"cve_id": identifier}}],
                "version_unconfirmed_cves": [],
                "errors": [],
            }
        )

    mock_sdk.enrich_product_full.side_effect = [
        response("a" * 32, "CVE-2024-0001", 2),
        UnexpectedStatus(409, b'{"detail":{"error":"snapshot_expired"}}'),
        response("b" * 32, "CVE-2024-0002", None),
    ]
    result = runner.invoke(app, ["enrich", "product", "nginx", "--json"])
    assert result.exit_code == 0, result.stdout + result.stderr
    data = json.loads(result.stdout)
    assert [row["cve"]["cve_id"] for row in data["cves"]] == ["CVE-2024-0002"]


def test_enrich_product_flag_overrides(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_product_full.return_value = _stub_response({"product": "nginx"})

    result = runner.invoke(
        app,
        ["enrich", "product", "apache/httpd", "--vendor", "nginx", "--product", "nginx", "--version", "1.25.0"],
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    _assert_forwarded(mock_sdk.enrich_product_full, args=("nginx",), version="1.25.0", vendor="nginx")


def test_enrich_product_plain_string(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_product_full.return_value = _stub_response({"product": "openssl"})

    result = runner.invoke(app, ["enrich", "product", "openssl"])

    assert result.exit_code == 0, result.stdout + result.stderr
    _assert_forwarded(mock_sdk.enrich_product_full, args=("openssl",), version=None, vendor=None)


def test_enrich_product_requires_product_name(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["enrich", "product"])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.enrich_product_full.assert_not_awaited()


def test_enrich_product_unauthorized_exits_3(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_product_full.side_effect = UnexpectedStatus(401, b'{"detail":"bad key"}', None)

    result = runner.invoke(app, ["enrich", "product", "nginx"])

    assert result.exit_code == int(ExitCode.API_ERROR)
    assert "401" in result.stderr


# -- ccc enrich package ------------------------------------------------------- #


def test_enrich_package_requires_both_args(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["enrich", "package", "npm"])  # missing the package name

    assert result.exit_code != 0


# -- ccc enrich ioc ----------------------------------------------------------- #


def test_enrich_ioc_default_type_wiring(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """No ``--type`` → the SDK receives the ``ip-dst`` default (matches API default)."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_ioc_full.return_value = _stub_response(
        {
            "value": "1.2.3.4",
            "type": "ip-dst",
            "misp_attributes": [{"value": "1.2.3.4", "type": "ip-dst"}],
            "techniques": [{"technique_id": "T1071", "name": "Application Layer Protocol", "tactics": ["c2"]}],
            "threat_assessment": {"verdict": "malicious", "threat_score": 78.0},
            "errors": [],
        }
    )

    result = runner.invoke(app, ["enrich", "ioc", "1.2.3.4"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "1.2.3.4" in result.stdout
    assert "malicious" in result.stdout
    mock_sdk.enrich_ioc_full.assert_awaited_once_with(
        "1.2.3.4", ioc_type="ip-dst", include=[*presets.IOC_FULL_WALK, "warninglist", "sightings", "cves"]
    )


def test_enrich_ioc_explicit_type_flag(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """``--type sha256`` is forwarded to the SDK as the ``ioc_type`` kwarg."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_ioc_full.return_value = _stub_response(
        {"value": "abc123", "type": "sha256", "misp_attributes": [{"value": "abc123"}]}
    )

    result = runner.invoke(app, ["enrich", "ioc", "abc123", "--type", "sha256"])

    assert result.exit_code == 0, result.stdout + result.stderr
    mock_sdk.enrich_ioc_full.assert_awaited_once_with(
        "abc123", ioc_type="sha256", include=[*presets.IOC_FULL_WALK, "warninglist", "sightings", "cves"]
    )


def test_enrich_ioc_json_round_trip(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    payload = {"value": "evil.example.com", "type": "domain", "misp_attributes": [], "errors": []}
    mock_sdk.enrich_ioc_full.return_value = _stub_response(payload)

    result = runner.invoke(app, ["--json", "enrich", "ioc", "evil.example.com", "--type", "domain"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == payload


def test_enrich_ioc_invalid_type_exits_nonzero(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """An unknown ``--type`` is rejected by Typer before any SDK call."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["enrich", "ioc", "1.2.3.4", "--type", "bogus"])

    assert result.exit_code != 0
    mock_sdk.enrich_ioc_full.assert_not_awaited()


def test_enrich_ioc_unauthorized_exits_3(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_ioc_full.side_effect = UnexpectedStatus(401, b'{"detail":"bad key"}', None)

    result = runner.invoke(app, ["enrich", "ioc", "1.2.3.4"])

    assert result.exit_code == int(ExitCode.API_ERROR)
    assert "401" in result.stderr


# -- ccc enrich cwe ----------------------------------------------------------- #


def test_enrich_cwe_happy_path_table(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cwe_full.return_value = _stub_response(
        {
            "weakness": {
                "cwe_id": "CWE-79",
                "name": "Cross-site Scripting",
                "description": "Improper neutralization of input.",
                "abstraction": "Base",
                "status": "Stable",
            },
            "attack_patterns": [{"capec_id": "CAPEC-63"}],
            "techniques": [{"technique_id": "T1059", "name": "Command", "tactics": ["execution"]}],
            "errors": [],
        }
    )

    result = runner.invoke(app, ["enrich", "cwe", "CWE-79"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "CWE-79" in result.stdout
    assert "Cross-site Scripting" in result.stdout
    assert "T1059" in result.stdout
    mock_sdk.enrich_cwe_full.assert_awaited_once_with("CWE-79", search=None, include=[*presets.CWE_FULL_WALK, "cves"])


def test_enrich_cwe_json_round_trip(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    payload = {"weakness": {"cwe_id": "CWE-79"}, "errors": []}
    mock_sdk.enrich_cwe_full.return_value = _stub_response(payload)

    result = runner.invoke(app, ["--json", "enrich", "cwe", "CWE-79"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == payload


def test_enrich_cwe_lowercase_normalised(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cwe_full.return_value = _stub_response({"weakness": {"cwe_id": "CWE-79"}})

    result = runner.invoke(app, ["enrich", "cwe", "cwe-79"])

    assert result.exit_code == 0
    mock_sdk.enrich_cwe_full.assert_awaited_once_with("CWE-79", search=None, include=[*presets.CWE_FULL_WALK, "cves"])


def test_enrich_cwe_malformed_exits_64_no_network(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["enrich", "cwe", "79"])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    assert "Malformed" in result.stderr
    mock_sdk.enrich_cwe_full.assert_not_awaited()


def test_enrich_cwe_missing_credentials_exits_2(runner: CliRunner, clean_env: Path, mock_sdk) -> None:
    result = runner.invoke(app, ["enrich", "cwe", "CWE-79"])

    assert result.exit_code == int(ExitCode.MISSING_CREDENTIALS)
    assert "CRIMSON_CRAWLER_API_KEY" in result.stderr
    mock_sdk.enrich_cwe_full.assert_not_awaited()


# -- --expand flag wiring ----------------------------------------------------- #
# (output-mode singletons reset per-test by conftest's _reset_output_modes)


def test_enrich_cve_trailing_expand_flips_mode(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """Trailing ``--expand`` (after the positional) flips expand mode via the callback."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.return_value = _stub_response({"cve": {"cve_id": "CVE-2024-3400"}})

    result = runner.invoke(app, ["enrich", "cve", "CVE-2024-3400", "--expand"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert output.is_expand_mode() is True


def test_enrich_cve_prefix_expand_flips_mode(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """Global prefix ``--expand`` (before the subcommand) flips expand mode too."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.return_value = _stub_response({"cve": {"cve_id": "CVE-2024-3400"}})

    result = runner.invoke(app, ["--expand", "enrich", "cve", "CVE-2024-3400"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert output.is_expand_mode() is True


# ---------------------------------------------------------------------------
# #466 batch 1 — `--include` help names the new opt-ins
# ---------------------------------------------------------------------------


def test_include_help_lists_batch1_tokens(runner: CliRunner) -> None:
    cve = runner.invoke(app, ["enrich", "cve", "--help"])
    assert cve.exit_code == 0, cve.output
    for token in ("affected_chipsets", "android_bulletin", "weakness_ranks"):
        assert token in cve.output
    technique = runner.invoke(app, ["enrich", "technique", "--help"])
    assert technique.exit_code == 0
    assert "framework_mappings" in technique.output
    assert "asset_classes" in technique.output
    ioc = runner.invoke(app, ["enrich", "ioc", "--help"])
    assert ioc.exit_code == 0
    assert "hashlookup" in ioc.output


@pytest.mark.parametrize(
    "command,family",
    [
        ("cve", "CVE"),
        ("product", "PRODUCT"),
        ("package", "PACKAGE"),
        ("technique", "TECHNIQUE"),
        ("ioc", "IOC"),
        ("cwe", "CWE"),
        ("atlas", "ATLAS"),
        ("campaign", "CAMPAIGN"),
        ("capec", "CAPEC"),
        ("cloak", "CLOAK"),
        ("defend", "D3FEND"),
        ("disarm", "DISARM"),
        ("f3", "F3"),
        ("group", "GROUP"),
        ("location", "LOCATION"),
        ("sector", "SECTOR"),
        ("software", "SOFTWARE"),
    ],
)
def test_include_help_lists_endpoint_defaults_and_allowed_values(runner: CliRunner, command: str, family: str) -> None:
    result = runner.invoke(app, ["enrich", command, "--help"])
    assert result.exit_code == 0, result.output
    text = " ".join(result.output.replace("│", " ").split())
    accepted = text.split("Options: ", 1)[1].split(".", 1)[0].split(", ")
    defaults = text.split("API defaults: ", 1)[1].split(".", 1)[0].split(", ")
    assert set(accepted) == set(getattr(_includes, f"{family}_INCLUDES"))
    assert set(defaults) == set(getattr(_includes, f"{family}_DEFAULTS"))
    cli_defaults = text.split("CLI defaults: ", 1)[1].split(".", 1)[0].split(", ")
    expected_cli = {
        "CVE": [*presets.CVE_FULL_WALK, "poc"],
        "PRODUCT": presets.PRODUCT_FULL,
        "PACKAGE": presets.PACKAGE_FULL,
        "TECHNIQUE": [*presets.TECHNIQUE_FULL, "cves"],
        "IOC": [*presets.IOC_FULL_WALK, "warninglist", "sightings", "cves"],
        "CWE": [*presets.CWE_FULL_WALK, "cves"],
        "ATLAS": presets.ATLAS_FULL,
        "CAMPAIGN": presets.CAMPAIGN_FULL,
        "CAPEC": presets.CAPEC_FULL,
        "CLOAK": presets.CLOAK_FULL,
        "D3FEND": presets.DEFEND_FULL,
        "DISARM": presets.DISARM_FULL,
        "F3": presets.F3_FULL,
        "GROUP": presets.GROUP_FULL,
        "LOCATION": presets.LOCATION_FULL,
        "SECTOR": presets.SECTOR_FULL,
        "SOFTWARE": presets.SOFTWARE_FULL,
    }
    assert cli_defaults == expected_cli[family]


def test_include_help_is_per_family(runner: CliRunner) -> None:
    cve = runner.invoke(app, ["enrich", "cve", "--help"]).output
    technique = runner.invoke(app, ["enrich", "technique", "--help"]).output
    ioc = runner.invoke(app, ["enrich", "ioc", "--help"]).output
    assert "hashlookup" not in cve and "framework_mappings" not in cve and "asset_classes" not in cve
    assert "asset_classes" not in ioc and "framework_mappings" not in ioc
    assert "asset_classes" in technique and "hashlookup" not in technique


# ---------------------------------------------------------------------------
# #466 batch 2 — CVSS-BT threat line
# ---------------------------------------------------------------------------


def _cve_payload(**extra: Any) -> dict:
    return {
        "cve": {"cve_id": "CVE-2024-3400", "description": "Test", "has_public_exploit": False},
        **extra,
    }


def test_render_cve_shows_cvss_bt_threat(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.return_value = _stub_response(
        _cve_payload(cvss_bt={"cvss_bt_threat": 9.8, "cvss_bt_severity": "CRITICAL"})
    )
    result = runner.invoke(app, ["enrich", "cve", "CVE-2024-3400"])
    assert result.exit_code == 0, result.output
    assert "CVSS-BT threat" in result.output
    assert "9.8" in result.output


def test_render_cve_omits_cvss_bt_when_absent(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.return_value = _stub_response(_cve_payload())
    result = runner.invoke(app, ["enrich", "cve", "CVE-2024-3400"])
    assert result.exit_code == 0, result.output
    assert "CVSS-BT threat" not in result.output


# ---------------------------------------------------------------------------
# #466 alternate routes — `--include` help names the new opt-ins
# ---------------------------------------------------------------------------


def test_include_help_lists_alternate_source_tokens(runner: CliRunner) -> None:
    cve = runner.invoke(app, ["enrich", "cve", "--help"]).output
    technique = runner.invoke(app, ["enrich", "technique", "--help"]).output
    for token in ("cellular_core", "jvn"):
        assert token in cve
    product = runner.invoke(app, ["enrich", "product", "--help"]).output
    for token in ("cellular_core", "jvn"):
        assert token in product, f"{token} is accepted on enrich/product"
    for token in ("fight", "lolbas"):
        assert token in technique
    assert "fight" not in cve and "jvn" not in technique


# ---------------------------------------------------------------------------
# #466 alternate routes — table rows appear only when the token returned rows
# ---------------------------------------------------------------------------


def test_render_cve_shows_alternate_source_rows(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.return_value = _stub_response(
        _cve_payload(
            cellular_core_entries=[{"cve_id": "CVE-2024-24446", "implementation": "OpenAirInterface (5G)"}],
        )
    )
    result = runner.invoke(app, ["enrich", "cve", "CVE-2024-24446"])
    assert result.exit_code == 0, result.output
    assert "Cellular core" in result.output and "OpenAirInterface (5G)" in result.output


def test_render_cve_shows_certfr_advisories_with_scada_marker(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """`[SCADA]` is Rich markup: the row is escaped, so the marker prints instead of styling the line."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.return_value = _stub_response(
        _cve_payload(
            certfr_advisories=[
                {"id": "CERTFR-2025-AVI-0269", "scada": True},
                {"id": "CERTFR-2026-ALE-013", "scada": False},
            ],
            jvn_advisories=[{"jvndb_id": "JVNDB-2025-014105"}],
        )
    )
    result = runner.invoke(app, ["enrich", "cve", "CVE-2024-24446"])
    assert result.exit_code == 0, result.output
    assert "CERT-FR advisories" in result.output
    assert "CERTFR-2025-AVI-0269 [SCADA]" in result.output
    assert "CERTFR-2026-ALE-013" in result.output and "CERTFR-2026-ALE-013 [SCADA]" not in result.output
    assert "JVN advisories" in result.output and "JVNDB-2025-014105" in result.output


def test_render_cve_shows_ot_vendor_advisories_and_escapes_markup(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """The row is Rich markup: a bracket in an advisory id must print, not become a style tag."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.return_value = _stub_response(
        _cve_payload(ot_vendor_advisories=[{"source": "rockwell", "advisory_id": "SD[1801]"}])
    )
    result = runner.invoke(app, ["enrich", "cve", "CVE-2024-24446"])
    assert result.exit_code == 0, result.output
    assert "OT vendor advisories" in result.output
    assert "rockwell:SD[1801]" in result.output


def test_render_cve_omits_alternate_source_rows_when_absent(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.return_value = _stub_response(_cve_payload())
    result = runner.invoke(app, ["enrich", "cve", "CVE-2024-24446"])
    assert result.exit_code == 0, result.output
    assert (
        "CERT-FR advisories" not in result.output
        and "JVN advisories" not in result.output
        and "Cellular core" not in result.output
    )


def test_render_technique_shows_alternate_source_rows(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_technique_full.return_value = _stub_response(
        {
            "techniques": [{"technique_id": "T1014", "name": "Rootkit", "tactics": ["defense-evasion"]}],
            "fight_techniques": [{"id": "FGT1014", "name": "Rootkit", "attack_id": "T1014"}],
            "lolbas_binaries": [{"name": "Certutil.exe", "technique_ids": ["T1105"]}],
            "gtfobins_binaries": [{"name": "ash", "technique_ids": ["T1059"]}],
            "hijacklibs_entries": [{"name": "aclui.dll", "vendor": "Microsoft", "technique_ids": ["T1574.002"]}],
        }
    )
    result = runner.invoke(app, ["enrich", "technique", "T1014"])
    assert result.exit_code == 0, result.output
    assert "FiGHT techniques" in result.output and "FGT1014" in result.output
    assert "LOLBAS binaries" in result.output and "1" in result.output
    assert "GTFOBins tools" in result.output and "ash" in result.output
    assert "HijackLibs DLLs" in result.output and "aclui.dll" in result.output


# ---------------------------------------------------------------------------
# #466 surface coverage — the remaining new sources render, not only under --json
# ---------------------------------------------------------------------------


def test_render_cve_prints_chipsets_weakness_sigma_emb3d_vulnrichment_rows(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.return_value = _stub_response(
        _cve_payload(
            weakness_ranks=[{"list": "cwe_top25", "rank": 3, "year": 2025, "cwe_id": "CWE-79"}],
            sigma_rules=[{"rule_id": "r1", "title": "rule"}],
            emb3d_threats=[{"id": "emb3d--1", "name": "Firmware tampering"}],
            affected_chipsets=[{"vendor": "qualcomm", "product": "snapdragon"}],
            vulnrichment={"cve_id": "CVE-2024-3400", "kev": True},
        )
    )
    result = runner.invoke(app, ["enrich", "cve", "CVE-2024-3400"])
    assert result.exit_code == 0, result.output
    assert "Top weakness rank" in result.output
    assert "CWE-79" in result.output
    assert "Sigma rules" in result.output
    assert "EMB3D threats" in result.output
    assert "Affected chipsets" in result.output
    assert "Vulnrichment KEV" in result.output


def test_render_cve_omits_chipsets_weakness_sigma_emb3d_vulnrichment_when_absent(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.return_value = _stub_response(_cve_payload())
    result = runner.invoke(app, ["enrich", "cve", "CVE-2024-3400"])
    assert result.exit_code == 0, result.output
    for label in ("Top weakness rank", "Sigma rules", "EMB3D threats", "Affected chipsets", "Vulnrichment KEV"):
        assert label not in result.output


def test_render_product_prints_lifecycle(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_product_full.return_value = _stub_response(
        {
            "product": "nginx",
            "cves": [{"cve": {"cve_id": "CVE-2024-3400"}}],
            "cpe_matches": ["cpe:2.3:a:nginx:nginx"],
            "lifecycle": {"product": "nginx", "cycle": "1.25", "eol": "2026-01-01", "latest": "1.25.4"},
        }
    )
    result = runner.invoke(app, ["enrich", "product", "nginx"])
    assert result.exit_code == 0, result.output
    assert "Lifecycle" in result.output
    assert "2026-01-01" in result.output


def test_render_technique_prints_sigma_framework_mappings_asset_classes(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_technique_full.return_value = _stub_response(
        {
            "techniques": [{"technique_id": "T1190", "name": "Exploit Public-Facing Application"}],
            "sigma_rules": [{"rule_id": "r1", "title": "rule"}],
            "framework_mappings": [{"framework": "aws", "control_id": "AC-1", "control_name": "Policy"}],
            "asset_classes": [{"id": "asset--1", "name": "PLC"}],
        }
    )
    result = runner.invoke(app, ["enrich", "technique", "T1190"])
    assert result.exit_code == 0, result.output
    assert "Sigma rules" in result.output
    assert "Framework mappings" in result.output
    assert "aws" in result.output
    assert "Asset classes" in result.output
    assert "PLC" in result.output


def test_render_ioc_prints_hashlookup_verdict(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_ioc_full.return_value = _stub_response(
        {
            "value": "d41d8cd98f00b204e9800998ecf8427e",
            "type": "md5",
            "misp_attributes": [{"value": "d41d8cd98f00b204e9800998ecf8427e"}],
            "hashlookup": {
                "hash": "d41d8cd98f00b204e9800998ecf8427e",
                "hash_type": "md5",
                "known": True,
                "nsrl": True,
                "trust": 90,
                "status": "ok",
            },
        }
    )
    result = runner.invoke(app, ["enrich", "ioc", "d41d8cd98f00b204e9800998ecf8427e", "--type", "md5"])
    assert result.exit_code == 0, result.output
    assert "Hashlookup" in result.output
    assert "known-good" in result.output


# ---------------------------------------------------------------------------
# #466 SURF-34 — the alternate CVE sources and LOLDrivers have table rows
# ---------------------------------------------------------------------------


def test_render_cve_prints_android_bulletin_vince_euvd_cellular_rows(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.return_value = _stub_response(
        _cve_payload(
            android_bulletin={
                "asb_id": "ASB-A-295000000",
                "url": "https://osv.dev/vulnerability/ASB-A-295000000",
                "aliases": ["CVE-2024-3400"],
                "component": "Media Framework",
                "severity": "High",
            },
            vince_advisories=[
                {"vuid": "VU#123456", "title": "PAN-OS command injection", "url": "https://kb.cert.org/vuls/id/123456"},
            ],
            euvd={"euvd_id": "EUVD-2024-12345", "exploited": True, "cvss_score": 9.8},
            cellular_annotations=[
                {"cve_id": "CVE-2024-3400", "tags": ["5G"], "native_5g": True, "lte": False, "auxiliary": False},
            ],
        )
    )
    result = runner.invoke(app, ["enrich", "cve", "CVE-2024-3400"])
    assert result.exit_code == 0, result.output
    assert "Android bulletin" in result.output and "ASB-A-295000000" in result.output
    assert "Media Framework" in result.output
    assert "CERT/CC notes" in result.output and "VU#123456" in result.output
    assert "EUVD" in result.output and "EUVD-2024-12345" in result.output
    assert "9.8" in result.output
    assert "Cellular dataset" in result.output and "5G" in result.output


def test_render_cve_omits_android_bulletin_vince_euvd_cellular_rows_when_absent(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.return_value = _stub_response(_cve_payload())
    result = runner.invoke(app, ["enrich", "cve", "CVE-2024-3400"])
    assert result.exit_code == 0, result.output
    for label in ("Android bulletin", "CERT/CC notes", "EUVD", "Cellular dataset"):
        assert label not in result.output


def test_render_cve_escapes_server_markup(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.return_value = _stub_response(
        _cve_payload(vince_advisories=[{"vuid": "VU#1", "title": "[bold red]x[/]"}])
    )
    result = runner.invoke(app, ["enrich", "cve", "CVE-2024-3400"])
    assert result.exit_code == 0, result.output
    # Escaped exactly once: Rich consumes the escape, so the literal text survives with no stray
    # backslash left in the table cell.
    assert "[bold red]x[/]" in result.output
    assert "\\[" not in result.output


def test_render_technique_prints_lol_drivers(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_technique_full.return_value = _stub_response(
        {
            "techniques": [{"technique_id": "T1068", "name": "Exploitation for Privilege Escalation"}],
            "lol_drivers": [{"id": "loldrivers--1", "name": "Vulnerable driver", "category": "vulnerable"}],
        }
    )
    result = runner.invoke(app, ["enrich", "technique", "T1068"])
    assert result.exit_code == 0, result.output
    assert "LOLDrivers" in result.output
    assert "Vulnerable driver" in result.output


def test_render_technique_omits_lol_drivers_when_absent(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_technique_full.return_value = _stub_response(
        {"techniques": [{"technique_id": "T1190", "name": "Exploit Public-Facing Application"}]}
    )
    result = runner.invoke(app, ["enrich", "technique", "T1190"])
    assert result.exit_code == 0, result.output
    assert "LOLDrivers" not in result.output


def test_render_technique_prints_lol_drivers_from_the_live_response(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """Verbatim saved response: `techniques: []` + 648 `lol_drivers`. The row must still render."""
    payload = json.loads((Path(__file__).parent / "fixtures" / "lotl-technique-response.json").read_text())
    assert payload["techniques"] == [] and len(payload["lol_drivers"]) == 648
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_technique_full.return_value = _stub_response(payload)
    result = runner.invoke(app, ["enrich", "technique", "T1068"])
    assert result.exit_code == 0, result.output
    assert "LOLDrivers" in result.output
    assert "648" in result.output
    assert payload["lol_drivers"][0]["name"] in result.output


def test_render_technique_no_data_only_when_everything_is_empty(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_technique_full.return_value = _stub_response({"techniques": [], "lol_drivers": []})
    result = runner.invoke(app, ["enrich", "technique", "T9999"])
    assert result.exit_code == 0, result.output
    assert "No data" in result.output
    assert "LOLDrivers" not in result.output


def test_render_technique_prints_atomic_red_team_tests(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """`atomic_tests` is a corpus opt-in: it renders with no `techniques` row, capped + total."""
    payload = json.loads((Path(__file__).parent / "fixtures" / "atomic-red-team-technique-response.json").read_text())
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_technique_full.return_value = _stub_response(payload)
    result = runner.invoke(app, ["enrich", "technique", "T1053.005", "--include", "atomic_red_team"])
    assert result.exit_code == 0, result.output
    assert "Atomic Red Team tests" in result.output
    assert "2 of 14" in result.output
    # Rich folds the long cell across lines and boxes it; compare with layout characters removed.
    flat = "".join(ch for ch in result.output if ch not in " \n│")
    assert payload["atomic_tests"][0]["name"].replace(" ", "") in flat
    assert "powershell" in result.output


def test_render_technique_escapes_atomic_test_markup(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """Upstream test names and executor names are untrusted: Rich markup must print literally."""
    payload = {
        "techniques": [],
        "atomic_tests": [
            {
                "technique_id": "T1547",
                "name": "[bold]Evil[/bold]",
                "auto_generated_guid": "g1",
                "executor_name": "[red]sh",
            }
        ],
        "atomic_tests_total": 1,
    }
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_technique_full.return_value = _stub_response(payload)
    result = runner.invoke(app, ["enrich", "technique", "T1547"])
    assert result.exit_code == 0, result.output
    flat = "".join(ch for ch in result.output if ch not in " \n│")
    assert "[bold]Evil[/bold]" in flat
    assert "[red]sh" in flat


def test_render_technique_omits_atomic_tests_when_absent(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_technique_full.return_value = _stub_response(
        {"techniques": [{"technique_id": "T1190", "name": "Exploit Public-Facing Application"}]}
    )
    result = runner.invoke(app, ["enrich", "technique", "T1190"])
    assert result.exit_code == 0, result.output
    assert "Atomic Red Team tests" not in result.output


# -- ccc enrich cve: OSV advisory continuation --------------------------------- #

_SNAPSHOT = "b" * 32


def _osv_page(
    ids: list[str], *, next_offset: int | None, total: int | None, first: bool = False, **extra: Any
) -> MagicMock:
    payload: dict[str, Any] = {
        "osv_advisories": [{"id": identifier} for identifier in ids],
        "osv_advisories_total": total,
        "osv_advisories_truncated": next_offset is not None,
        "osv_next_offset": next_offset,
        "osv_snapshot_id": _SNAPSHOT if next_offset is not None else None,
        "errors": [],
        **extra,
    }
    if first:
        payload["cve"] = {"cve_id": "CVE-2024-3400"}
    return _stub_response(payload)


def test_enrich_cve_follows_osv_cursor_and_merges_pages(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """Later pages are OSV-only: page zero keeps every other section, rows concatenate, cursor clears."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.side_effect = [
        _osv_page(["GHSA-1"], next_offset=0, total=3, first=True),
        _osv_page(["GHSA-2"], next_offset=2, total=3, errors=[{"service": "osv", "error": "malformed_field"}]),
        _osv_page(["GHSA-3"], next_offset=None, total=3, errors=[{"service": "osv", "error": "malformed_field"}]),
    ]

    result = runner.invoke(app, ["--json", "enrich", "cve", "CVE-2024-3400", "--include", "osv_restricted"])

    assert result.exit_code == 0, result.stdout + result.stderr
    data = json.loads(result.stdout)
    assert data["cve"] == {"cve_id": "CVE-2024-3400"}
    assert [row["id"] for row in data["osv_advisories"]] == ["GHSA-1", "GHSA-2", "GHSA-3"]
    assert data["osv_advisories_total"] == 3
    assert "osv_next_offset" not in data and "osv_snapshot_id" not in data
    assert data["osv_advisories_truncated"] is False
    assert data["errors"] == [{"service": "osv", "error": "malformed_field"}]
    calls = mock_sdk.enrich_cve_full.await_args_list
    assert [(c.kwargs["osv_offset"], c.kwargs["osv_snapshot_id"]) for c in calls] == [
        (0, None),
        (0, _SNAPSHOT),
        (2, _SNAPSHOT),
    ]
    # The licence opt-in the caller named is replayed verbatim on every continuation.
    assert {tuple(c.kwargs["include"]) for c in calls} == {("osv_restricted",)}


def test_enrich_cve_unreadable_osv_row_keeps_truncated_after_walk(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """A row that consumed a cursor position but could not be read is reported, not papered over."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    unreadable = {"step": "read_osv_advisory", "service": "osv", "error": "malformed_field", "detail": "GHSA-2.x"}
    mock_sdk.enrich_cve_full.side_effect = [
        _osv_page(["GHSA-1"], next_offset=1, total=3, first=True),
        _osv_page(["GHSA-3"], next_offset=None, total=3, errors=[unreadable]),
    ]

    result = runner.invoke(app, ["--json", "enrich", "cve", "CVE-2024-3400"])

    assert result.exit_code == 0, result.stdout + result.stderr
    data = json.loads(result.stdout)
    assert data["osv_advisories_truncated"] is True
    assert data["errors"] == [unreadable]


def test_enrich_cve_osv_truncation_survives_merge_and_is_announced(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.side_effect = [
        _osv_page(["GHSA-1"], next_offset=1, total=3, first=True),
        _osv_page(["GHSA-3"], next_offset=None, total=3, osv_advisories_truncated=True),
    ]

    result = runner.invoke(app, ["enrich", "cve", "CVE-2024-3400"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert "OSV advisories incomplete: 2 of 3 shown" in result.stdout.replace("\n", " ")


def test_enrich_cve_osv_completeness_handles_a_missing_total(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """A server that omits the exact total still gets a warning, and never a fabricated count."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.side_effect = [
        _osv_page(["GHSA-1"], next_offset=None, total=None, first=True, osv_advisories_truncated=True),
    ]

    result = runner.invoke(app, ["enrich", "cve", "CVE-2024-3400"])

    assert result.exit_code == 0, result.stdout + result.stderr
    text = result.stdout.replace("\n", " ")
    assert "OSV advisories incomplete: 1 shown" in text
    assert "1 of" not in text


def test_enrich_cve_osv_walk_over_max_bytes_prints_nothing(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.side_effect = [
        _osv_page(["GHSA-1"], next_offset=1, total=2, first=True),
        _osv_page(["GHSA-2" + "x" * 500], next_offset=None, total=2),
    ]

    result = runner.invoke(app, ["--json", "enrich", "cve", "CVE-2024-3400", "--max-bytes", "600"])

    assert result.exit_code != 0
    assert result.stdout == ""
    assert "osv_walk_too_large" in result.stderr


def test_enrich_cve_expired_osv_snapshot_exits_with_restart_guidance(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_cve_full.side_effect = [
        _osv_page(["GHSA-1"], next_offset=1, total=2, first=True),
        UnexpectedStatus(409, b'{"detail":{"error":"snapshot_expired"}}', None),
    ]

    result = runner.invoke(app, ["enrich", "cve", "CVE-2024-3400"])

    assert result.exit_code == int(ExitCode.API_ERROR)
    assert result.stdout == ""
    assert "Snapshot expired" in result.stderr


def test_enrich_cve_max_bytes_must_be_positive(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["enrich", "cve", "CVE-2024-3400", "--max-bytes", "0"])

    assert result.exit_code == int(ExitCode.BAD_INPUT)
    mock_sdk.enrich_cve_full.assert_not_awaited()
