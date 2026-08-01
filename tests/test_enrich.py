"""End-to-end tests for ``ccc enrich`` — ``cve``, ``product``, ``package``, ``ioc``, ``cwe``."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from crimson_crawler_cli import output
from crimson_crawler_cli.cli import app
from crimson_crawler_cli.exceptions import APIError, ExitCode, handle_errors
from crimson_crawler_client import UnexpectedStatus, presets


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def _stub_response(payload: dict) -> MagicMock:
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
                "cvss_score": 9.8,
                "cvss_severity": "CRITICAL",
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
    mock_sdk.enrich_cve_full.assert_awaited_once_with("CVE-2024-3400", include=[*presets.CVE_FULL_WALK, "poc"])


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
    mock_sdk.enrich_cve_full.assert_awaited_once_with("CVE-2024-3400", include=[*presets.CVE_FULL_WALK, "poc"])


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


def test_enrich_product_vendor_slash_product(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_product_full.return_value = _stub_response(
        {"product": "nginx", "vendor": "nginx", "cves": [], "errors": []}
    )

    result = runner.invoke(app, ["enrich", "product", "nginx/nginx"])

    assert result.exit_code == 0, result.stdout + result.stderr
    mock_sdk.enrich_product_full.assert_awaited_once_with("nginx", version=None, vendor="nginx")


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
    mock_sdk.enrich_product_full.assert_awaited_once_with("nginx", version="1.25.0", vendor="nginx")


def test_enrich_product_plain_string(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_product_full.return_value = _stub_response({"product": "openssl"})

    result = runner.invoke(app, ["enrich", "product", "openssl"])

    assert result.exit_code == 0, result.stdout + result.stderr
    mock_sdk.enrich_product_full.assert_awaited_once_with("openssl", version=None, vendor=None)


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


def test_enrich_package_two_positionals(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_package_full.return_value = _stub_response(
        {
            "ecosystem": "npm",
            "package": "lodash",
            "cves": [],
            "advisories": [{"id": "GHSA-x", "summary": "s"}],
            "errors": [],
        }
    )

    result = runner.invoke(app, ["enrich", "package", "npm", "lodash"])

    assert result.exit_code == 0, result.stdout + result.stderr
    mock_sdk.enrich_package_full.assert_awaited_once_with("npm", "lodash", version=None)


def test_enrich_package_with_version(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_package_full.return_value = _stub_response({"ecosystem": "PyPI", "package": "django"})

    result = runner.invoke(app, ["enrich", "package", "PyPI", "django", "--version", "4.0"])

    assert result.exit_code == 0, result.stdout + result.stderr
    mock_sdk.enrich_package_full.assert_awaited_once_with("PyPI", "django", version="4.0")


def test_enrich_package_json_roundtrip(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    payload = {"ecosystem": "npm", "package": "lodash", "vulnerability_count": 1, "advisories": [{"id": "GHSA-x"}]}
    mock_sdk.enrich_package_full.return_value = _stub_response(payload)

    result = runner.invoke(app, ["--json", "enrich", "package", "npm", "lodash"])

    assert result.exit_code == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == payload


def test_enrich_package_requires_both_args(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")

    result = runner.invoke(app, ["enrich", "package", "npm"])  # missing the package name

    assert result.exit_code != 0
    mock_sdk.enrich_package_full.assert_not_awaited()


def test_enrich_package_unauthorized_exits_3(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_package_full.side_effect = UnexpectedStatus(401, b'{"detail":"bad key"}', None)

    result = runner.invoke(app, ["enrich", "package", "npm", "lodash"])

    assert result.exit_code == int(ExitCode.API_ERROR)
    assert "401" in result.stderr


def test_enrich_package_osv_seeded_identifiers(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, clean_env: Path, mock_sdk
) -> None:
    """C5: ``ccc enrich package`` forwards ecosystem + package + version to the OSV advisor."""
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")
    mock_sdk.enrich_package_full.return_value = _stub_response(
        {"ecosystem": "npm", "package": "left-pad", "vulnerability_count": 0}
    )

    result = runner.invoke(app, ["enrich", "package", "npm", "left-pad", "--version", "1.0.0"])

    assert result.exit_code == 0, result.stdout + result.stderr
    mock_sdk.enrich_package_full.assert_awaited_once_with("npm", "left-pad", version="1.0.0")


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
    mock_sdk.enrich_cwe_full.assert_awaited_once_with("CWE-79", include=[*presets.CWE_FULL_WALK, "cves"])


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
    mock_sdk.enrich_cwe_full.assert_awaited_once_with("CWE-79", include=[*presets.CWE_FULL_WALK, "cves"])


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
