"""Tests for ``ccc ingest <format> <file>`` + the CLI's own ingest component (no network).

The CLI has its OWN ``crimson_crawler_cli.ingest`` file (one per client, identical logic), which calls the
SDK's public ``parse_scan`` + ``enrich_items`` and assembles the briefing. These tests mock those two SDK
building blocks and assert the rendered Markdown / JSON briefing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from crimson_crawler_cli import playbook
from crimson_crawler_cli.cli import app
from crimson_crawler_cli.exceptions import ExitCode
from crimson_crawler_client import UnexpectedStatus


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def authed(monkeypatch: pytest.MonkeyPatch, clean_env: Path) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")


_PARSE = {"format": "nmap", "items": [{"product": "Apache httpd"}], "count": 1}
_ENRICH = {
    "enrichment_id": "e" * 32,
    "report": {
        "summary": {"asset_count": 1, "total_cves": 3, "total_kev": 1, "max_weaponization": 98},
        "assets": [
            {
                "product": "Apache httpd",
                "vendor": "apache",
                "status": "ok",
                "cve_count": 3,
                "kev_count": 1,
                "max_weaponization": 98,
                "top_cves": [
                    {
                        "cve_id": "CVE-2021-44228",
                        "cvss_score": 10.0,
                        "epss": 0.97,
                        "kev": True,
                        "weaponization_score": 98,
                        "description": "D" * 600,
                    }
                ],
            },
            {"product": "openssl", "status": "error", "errors": ["upstream timeout"]},
        ],
    },
}


def _scan_file(tmp_path: Path) -> Path:
    p = tmp_path / "scan.xml"
    p.write_text("<nmaprun/>", encoding="utf-8")
    return p


def _wire(mock_sdk) -> None:
    mock_sdk.inventory_manager.parse_scan.return_value = _PARSE
    mock_sdk.inventory_manager.enrich_items.return_value = _ENRICH


class TestIngestMarkdown:
    def test_renders_briefing(self, runner, authed, mock_sdk, tmp_path) -> None:
        _wire(mock_sdk)
        result = runner.invoke(app, ["ingest", "nmap", str(_scan_file(tmp_path))])
        assert result.exit_code == ExitCode.OK
        assert "CVE\\-2021\\-44228" in result.output and "[KEV]" in result.output
        assert "Findings by asset" in result.output and "Apache httpd" in result.output
        assert "Errors" in result.output and "openssl" in result.output
        mock_sdk.inventory_manager.parse_scan.assert_awaited_once_with("<nmaprun/>", "nmap")

    def test_description_capped_without_expand(self, runner, authed, mock_sdk, tmp_path) -> None:
        _wire(mock_sdk)
        result = runner.invoke(app, ["ingest", "nmap", str(_scan_file(tmp_path))])
        assert "…" in result.output

    def test_expand_lifts_description_cap(self, runner, authed, mock_sdk, tmp_path) -> None:
        _wire(mock_sdk)
        result = runner.invoke(app, ["ingest", "nmap", str(_scan_file(tmp_path)), "--expand"])
        assert "D" * 600 in result.output

    @pytest.mark.parametrize(
        "untrusted",
        [
            "# injected heading",
            "[deceptive](https://example.invalid)",
            "![tracking pixel](https://example.invalid/pixel)",
            "<img src=x onerror=1>",
            "```danger```",
            "first | second",
            "first line\nsecond line\r\nthird line\x00",
        ],
    )
    def test_untrusted_scalars_are_escaped_everywhere(self, untrusted: str) -> None:
        briefing = {
            "format": untrusted,
            "parsed_count": untrusted,
            "recommended_actions": [
                {
                    "cve_id": untrusted,
                    "product": untrusted,
                    "weaponization_score": untrusted,
                    "reason": untrusted,
                }
            ],
            "report": {
                "summary": {
                    "total_cves": untrusted,
                    "total_kev": untrusted,
                    "max_weaponization": untrusted,
                },
                "assets": [
                    {
                        "product": untrusted,
                        "vendor": untrusted,
                        "status": "ok",
                        "cve_count": untrusted,
                        "kev_count": untrusted,
                        "max_weaponization": untrusted,
                        "top_cves": [
                            {
                                "cve_id": untrusted,
                                "cvss_score": untrusted,
                                "epss": untrusted,
                                "description": untrusted,
                            }
                        ],
                    },
                    {"product": untrusted, "status": "error", "errors": [untrusted]},
                ],
            },
        }

        rendered = playbook.render_briefing(briefing, scan_file=untrusted, expand=True)
        escaped = playbook.escape_markdown_scalar(untrusted)
        assert "\n" not in escaped and "\r" not in escaped and "\x00" not in escaped
        assert rendered.count(escaped) >= 18

    def test_xlsx_reads_file_as_bytes(self, runner, authed, mock_sdk, tmp_path) -> None:
        # The binary format: the CLI reads the file as BYTES (not text) and forwards them; the SDK
        # base64-encodes on the wire.
        _wire(mock_sdk)
        mock_sdk.inventory_manager.parse_scan.return_value = {"format": "xlsx", "items": [{"product": "x"}], "count": 1}
        raw = b"PK\x03\x04 xl/ workbook \x00\x01\x02"
        p = tmp_path / "assets.xlsx"
        p.write_bytes(raw)
        result = runner.invoke(app, ["ingest", "xlsx", str(p)])
        assert result.exit_code == ExitCode.OK
        mock_sdk.inventory_manager.parse_scan.assert_awaited_once_with(raw, "xlsx")

    def test_empty_scan(self, runner, authed, mock_sdk, tmp_path) -> None:
        mock_sdk.inventory_manager.parse_scan.return_value = {"format": "nmap", "items": [], "count": 0}
        result = runner.invoke(app, ["ingest", "nmap", str(_scan_file(tmp_path))])
        assert result.exit_code == ExitCode.OK
        assert "No enrichable assets" in result.output
        mock_sdk.inventory_manager.enrich_items.assert_not_awaited()


class TestIngestJsonAndOutput:
    def test_json_mode_round_trips(self, runner, authed, mock_sdk, tmp_path) -> None:
        _wire(mock_sdk)
        result = runner.invoke(app, ["ingest", "nmap", str(_scan_file(tmp_path)), "--json"])
        assert result.exit_code == ExitCode.OK
        doc = json.loads(result.output)
        assert doc["format"] == "nmap" and doc["parsed_count"] == 1
        assert doc["recommended_actions"][0]["cve_id"] == "CVE-2021-44228"

    def test_output_file(self, runner, authed, mock_sdk, tmp_path) -> None:
        _wire(mock_sdk)
        out = tmp_path / "briefing.md"
        result = runner.invoke(app, ["ingest", "nmap", str(_scan_file(tmp_path)), "--output", str(out)])
        assert result.exit_code == ExitCode.OK
        assert out.exists() and "Recommended actions" in out.read_text()


class TestIngestErrors:
    def test_unknown_format_exits_64(self, runner, authed, mock_sdk, tmp_path) -> None:
        result = runner.invoke(app, ["ingest", "bogus", str(_scan_file(tmp_path))])
        assert result.exit_code == ExitCode.BAD_INPUT
        mock_sdk.inventory_manager.parse_scan.assert_not_awaited()

    def test_missing_file_exits_64(self, runner, authed, mock_sdk) -> None:
        # Click rejects the unreadable path before the command body runs. Its
        # usage family is mapped to BAD_INPUT (see exceptions.py) so it cannot be
        # confused with exit 2, which means "no API key".
        result = runner.invoke(app, ["ingest", "nmap", "/no/such/scan.xml"])
        assert result.exit_code == int(ExitCode.BAD_INPUT)
        mock_sdk.inventory_manager.parse_scan.assert_not_awaited()

    def test_invalid_output_dir_fails_before_api(self, runner, authed, mock_sdk, tmp_path) -> None:
        """A bad ``--output`` dir exits 64 *before* any billable parse/enrich call (#199)."""
        result = runner.invoke(
            app, ["ingest", "nmap", str(_scan_file(tmp_path)), "--output", str(tmp_path / "nope" / "briefing.md")]
        )
        assert result.exit_code == ExitCode.BAD_INPUT
        assert "Output directory does not exist" in result.stderr
        mock_sdk.inventory_manager.parse_scan.assert_not_awaited()

    def test_api_error_exits_3(self, runner, authed, mock_sdk, tmp_path) -> None:
        mock_sdk.inventory_manager.parse_scan.side_effect = UnexpectedStatus(404, b"no")
        result = runner.invoke(app, ["ingest", "nmap", str(_scan_file(tmp_path))])
        assert result.exit_code == ExitCode.API_ERROR


class TestIngestFormatParity:
    """`ccc ingest <format> <file>` must accept every one of the 11 scan/inventory formats and pass it
    through to parse_scan — locks ingest.FORMATS against drift from the server's parser set."""

    @pytest.mark.parametrize(
        "fmt", ["json", "sbom", "csv", "nmap", "list", "grype", "trivy", "depcheck", "nessus", "gvm"]
    )
    def test_ingest_accepts_every_format(self, runner, authed, mock_sdk, tmp_path, fmt) -> None:
        _wire(mock_sdk)
        f = tmp_path / "scan.dat"
        f.write_text("x", encoding="utf-8")
        result = runner.invoke(app, ["--json", "ingest", fmt, str(f)])
        assert result.exit_code == ExitCode.OK
        assert mock_sdk.inventory_manager.parse_scan.await_args.args == ("x", fmt)

    def test_ingest_accepts_xlsx_bytes(self, runner, authed, mock_sdk, tmp_path) -> None:
        _wire(mock_sdk)
        mock_sdk.inventory_manager.parse_scan.return_value = {
            "format": "xlsx",
            "items": [{"product": "lib"}],
            "count": 1,
        }
        raw = b"PK\x03\x04 xl/ workbook"
        p = tmp_path / "scan.xlsx"
        p.write_bytes(raw)
        result = runner.invoke(app, ["--json", "ingest", "xlsx", str(p)])
        assert result.exit_code == ExitCode.OK
        assert mock_sdk.inventory_manager.parse_scan.await_args.args == (raw, "xlsx")
