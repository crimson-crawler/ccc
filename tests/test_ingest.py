"""Tests for ``ccc ingest <format> <file>`` + the SDK's shared ingest component (no network).

``ccc ingest`` is a thin shell over the SDK's :func:`crimson_crawler_client.ingest_scan`, which calls the
SDK's public ``parse_scan`` + ``enrich_items`` and assembles the briefing. These tests mock those two SDK
building blocks and assert the rendered Markdown / JSON briefing."""

from __future__ import annotations

import copy
import json
import unicodedata
from pathlib import Path

import pytest
from typer.testing import CliRunner

from crimson_crawler_cli import output, playbook
from crimson_crawler_cli.cli import app
from crimson_crawler_cli.exceptions import ExitCode
from crimson_crawler_client import UnexpectedStatus, assemble_briefing


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
                        "cvss_v3_score": 10.0,
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


# A briefing whose scalars carry an INLINE-escaped character (`_`) and an HTML-escapable one
# (`&`). Those are the only discriminators between the two destinations: after #329's mid-line
# trim, a CVE id renders identically in both modes, so it proves nothing about the mode.
_MODE_ENRICH = copy.deepcopy(_ENRICH)
_MODE_ENRICH["report"]["assets"][0]["product"] = "windows_server"
_MODE_ENRICH["report"]["assets"][0]["vendor"] = "AT&T"


def _scan_file(tmp_path: Path) -> Path:
    p = tmp_path / "scan.xml"
    p.write_text("<nmaprun/>", encoding="utf-8")
    return p


def _wire(mock_sdk, enrich: dict | None = None) -> None:
    mock_sdk.inventory_manager.parse_scan.return_value = _PARSE
    mock_sdk.inventory_manager.enrich_items.return_value = enrich or _ENRICH


# Adversarial scalars, shared by the escaped and plain-mode twins. Both tests derive their
# expected string from the renderer itself, so the corpus tracks the escape set automatically.
_ADVERSARIAL = [
    "# injected heading",
    "[deceptive](https://example.invalid)",
    "![tracking pixel](https://example.invalid/pixel)",
    "<img src=x onerror=1>",
    "```danger```",
    "first | second",
    "first line\nsecond line\r\nthird line\x00",
    # A value STARTING with a guard-set character — the case the mid-line trim makes
    # load-bearing: `- ` would open a nested list item inside the renderer's own bullet.
    "- injected bullet",
    "+ injected bullet too",
    # An ordered-list marker: `1. ` after the renderer's `- ` prefix nests an ordered list.
    "1. injected item",
    # Raw ANSI: the plain path has no escaping left, so control stripping is the only defense.
    "boom \x1b[31mRED\x1b[0m boom",
    # HTML-escapable characters, for the "no entities in plain mode" half.
    "AT&T <b> ops",
]


def _untrusted_briefing(untrusted: str) -> dict:
    """Plant one untrusted scalar in every interpolated slot of the briefing."""
    return {
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
                            "cvss_v3_score": untrusted,
                            "epss": untrusted,
                            "description": untrusted,
                        }
                    ],
                },
                {"product": untrusted, "status": "error", "errors": [untrusted]},
            ],
        },
    }


class TestIngestMarkdown:
    def test_renders_briefing(self, runner, authed, mock_sdk, tmp_path) -> None:
        _wire(mock_sdk)
        result = runner.invoke(app, ["ingest", "nmap", str(_scan_file(tmp_path))])
        assert result.exit_code == ExitCode.OK
        # Unescaped even here, under CliRunner's NON-TTY stdout: that is the #329 *trim*
        # (mid-line `-` is no longer in the escape set on ANY destination), not the TTY switch.
        # Don't read this as a plain-mode assertion — see TestIngestRenderDestination for that.
        assert "CVE-2021-44228" in result.output and "[KEV]" in result.output
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

    @pytest.mark.parametrize("untrusted", _ADVERSARIAL)
    def test_untrusted_scalars_are_escaped_everywhere(self, untrusted: str) -> None:
        rendered = playbook.render_briefing(_untrusted_briefing(untrusted), scan_file=untrusted, expand=True)
        escaped = playbook.escape_markdown_scalar(untrusted)
        assert "\n" not in escaped and "\r" not in escaped and "\x00" not in escaped
        assert rendered.count(escaped) >= 18

    @pytest.mark.parametrize("untrusted", _ADVERSARIAL)
    def test_untrusted_scalars_are_sanitized_in_plain_mode(self, untrusted: str) -> None:
        """The plain-mode twin: sanitization is unchanged, only the escaping is dropped.

        A terminal is a *more* hostile sink than a Markdown file, so NFC + control-char
        stripping + the single-line collapse all still run; what goes away is the structural
        translate (literal backslash noise) and `html.escape` (entities have no meaning here).
        None of the corpus inputs carry a literal backslash or a pre-formed entity, so the
        two absence assertions below are about what the renderer added, not about the input.
        """
        rendered = playbook.render_briefing(
            _untrusted_briefing(untrusted), scan_file=untrusted, expand=True, plain=True
        )
        plain = playbook.plain_scalar(untrusted)
        assert not any(control in plain for control in ("\n", "\r", "\x00", "\x1b"))
        assert "\\" not in plain  # no structural escapes leak to a terminal
        assert "&amp;" not in plain and "&lt;" not in plain and "&gt;" not in plain  # no entities either
        assert rendered.count(plain) >= 18

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

    def test_briefing_lists_unverified_assets(self, runner, authed, mock_sdk, tmp_path) -> None:
        """#348 — assets whose identity never resolved are surfaced in the briefing structure (product +
        installed version + why), so an empty CVE set on them reads as never-looked, not clean."""
        _wire(
            mock_sdk,
            {
                "enrichment_id": "e" * 32,
                "report": {
                    "summary": {"asset_count": 4, "total_cves": 0, "total_kev": 0, "max_weaponization": 0},
                    "assets": [
                        {
                            "product": "httpx",
                            "vendor": "encode",
                            "status": "ok",
                            "cve_count": 0,
                            "kev_count": 0,
                            "max_weaponization": None,
                            "top_cves": [],
                            "match": "cpe",
                            "match_detail": "encode:httpx",
                        },
                        {
                            "product": "rich",
                            "vendor": None,
                            "status": "ok",
                            "cve_count": 0,
                            "kev_count": 0,
                            "max_weaponization": None,
                            "versions": ["15.0.0"],
                            "top_cves": [],
                            "match": "cpe_fuzzy",
                            "match_detail": "no exact product among 57 CPEs",
                        },
                        {
                            "product": "typer",
                            "vendor": None,
                            "status": "ok",
                            "cve_count": 0,
                            "kev_count": 0,
                            "max_weaponization": None,
                            "versions": ["0.25.1"],
                            "top_cves": [],
                            "match": "none",
                            "match_detail": "no CPE candidates",
                        },
                        {"product": "broken", "status": "error", "errors": ["boom"]},
                    ],
                },
            },
        )
        result = runner.invoke(app, ["ingest", "nmap", str(_scan_file(tmp_path)), "--json"])
        assert result.exit_code == ExitCode.OK
        doc = json.loads(result.output)
        # The engine ranked no CVEs → no recommended actions, but the unverified list names the assets.
        assert doc["recommended_actions"] == []
        # A verified-clean asset (httpx) is not "unverified" — only none/cpe_fuzzy rows are.
        assert doc["unverified_assets"] == [
            {"product": "rich", "versions": ["15.0.0"], "match_detail": "no exact product among 57 CPEs"},
            {"product": "typer", "versions": ["0.25.1"], "match_detail": "no CPE candidates"},
        ]

    def test_briefing_omits_unverified_when_none(self, runner, authed, mock_sdk, tmp_path) -> None:
        """No none/cpe_fuzzy assets → an empty unverified_assets list (never a missing key — the renderer
        and JSON consumers can rely on the shape)."""
        _wire(mock_sdk)
        result = runner.invoke(app, ["ingest", "nmap", str(_scan_file(tmp_path)), "--json"])
        assert result.exit_code == ExitCode.OK
        doc = json.loads(result.output)
        assert doc["unverified_assets"] == []

    def test_markdown_lists_unverified_assets(self, runner, authed, mock_sdk, tmp_path) -> None:
        """#348 — the rendered playbook gains an 'Unverified assets' section naming product@version (why),
        so an empty per-asset finding list is not mistaken for a clean bill of health. A verified asset
        (httpx, match cpe) stays out of the section."""
        _wire(
            mock_sdk,
            {
                "enrichment_id": "e" * 32,
                "report": {
                    "summary": {"asset_count": 3, "total_cves": 0, "total_kev": 0, "max_weaponization": 0},
                    "assets": [
                        {
                            "product": "httpx",
                            "vendor": "encode",
                            "status": "ok",
                            "cve_count": 0,
                            "kev_count": 0,
                            "max_weaponization": None,
                            "top_cves": [],
                            "match": "cpe",
                            "match_detail": "encode:httpx",
                        },
                        {
                            "product": "rich",
                            "vendor": None,
                            "status": "ok",
                            "cve_count": 0,
                            "kev_count": 0,
                            "max_weaponization": None,
                            "versions": ["15.0.0"],
                            "top_cves": [],
                            "match": "cpe_fuzzy",
                            "match_detail": "no exact product among 57 CPEs",
                        },
                        {
                            "product": "typer",
                            "vendor": None,
                            "status": "ok",
                            "cve_count": 0,
                            "kev_count": 0,
                            "max_weaponization": None,
                            "versions": ["0.25.1"],
                            "top_cves": [],
                            "match": "none",
                            "match_detail": "no CPE candidates",
                        },
                    ],
                },
            },
        )
        result = runner.invoke(app, ["ingest", "nmap", str(_scan_file(tmp_path))])
        assert result.exit_code == ExitCode.OK
        section = result.output.split("## Unverified assets", 1)[1]
        assert "No CPE/OSV identity resolved" in section
        assert "- rich@15.0.0 — no exact product among 57 CPEs" in section
        assert "- typer@0.25.1 — no CPE candidates" in section
        assert "httpx" not in section  # verified assets are not unverified
        # The section sits between the per-asset findings and the errors block.
        assert result.output.index("Findings by asset") < result.output.index("## Unverified assets")

    def test_markdown_omits_unverified_heading_when_none(self, runner, authed, mock_sdk, tmp_path) -> None:
        """No none/cpe_fuzzy assets → the Markdown playbook carries no 'Unverified assets' section at all."""
        _wire(mock_sdk)
        result = runner.invoke(app, ["ingest", "nmap", str(_scan_file(tmp_path))])
        assert result.exit_code == ExitCode.OK
        assert "Unverified assets" not in result.output


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
    """`ccc ingest <format> <file>` must accept every one of the scan/inventory formats and pass it
    through to parse_scan — locks ingest.FORMATS against drift from the server's parser set."""

    @pytest.mark.parametrize(
        "fmt", ["json", "sbom", "csv", "nmap", "list", "grype", "trivy", "depcheck", "nessus", "gvm", "vex"]
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


class TestIngestRenderDestination:
    """#329 — one briefing, two destinations. Escape for files and pipes, plain for a TTY.

    The discriminators are `windows_server` (an ``_MARKDOWN_INLINE`` character) and `AT&T`
    (HTML-escapable). A CVE id is NOT usable here: the mid-line trim unescapes it on every
    destination, so it renders identically in both modes.
    """

    def test_non_tty_stdout_stays_markdown_escaped(self, runner, authed, mock_sdk, tmp_path) -> None:
        # CliRunner captures a non-TTY stdout — the redirect/pipe case.
        _wire(mock_sdk, _MODE_ENRICH)
        result = runner.invoke(app, ["ingest", "nmap", str(_scan_file(tmp_path))])
        assert result.exit_code == ExitCode.OK
        assert "windows\\_server" in result.output and "AT&amp;T" in result.output
        assert "CVE-2021-44228" in result.output  # unescaped on BOTH destinations (the trim)

    def test_tty_stdout_is_plain(self, runner, authed, mock_sdk, tmp_path, monkeypatch) -> None:
        _wire(mock_sdk, _MODE_ENRICH)
        monkeypatch.setattr(output, "stdout_is_tty", lambda: True)
        result = runner.invoke(app, ["ingest", "nmap", str(_scan_file(tmp_path))])
        assert result.exit_code == ExitCode.OK
        assert "windows_server" in result.output and "AT&T" in result.output
        assert "windows\\_server" not in result.output and "&amp;" not in result.output
        assert "CVE-2021-44228" in result.output

    def test_output_file_stays_escaped_even_under_a_tty(self, runner, authed, mock_sdk, tmp_path, monkeypatch) -> None:
        """`--output` is a FILE destination regardless of what stdout is.

        This is the regression Rich's `console.is_terminal` would have shipped: it reports a
        terminal whenever `FORCE_COLOR` is set, which would write plain text into a `.md`.
        """
        _wire(mock_sdk, _MODE_ENRICH)
        monkeypatch.setattr(output, "stdout_is_tty", lambda: True)
        out = tmp_path / "briefing.md"
        result = runner.invoke(app, ["ingest", "nmap", str(_scan_file(tmp_path)), "-o", str(out)])
        assert result.exit_code == ExitCode.OK
        written = out.read_text(encoding="utf-8")
        assert "windows\\_server" in written and "AT&amp;T" in written
        # …and the trim reaches the file too: no mid-line `-` escaping anywhere in it.
        assert "\\-" not in written

    def test_json_mode_is_untouched_under_a_tty(self, runner, authed, mock_sdk, tmp_path, monkeypatch) -> None:
        """`plain` is computed inside the non-JSON branch, so `--json` cannot see it."""
        _wire(mock_sdk, _MODE_ENRICH)
        monkeypatch.setattr(output, "stdout_is_tty", lambda: True)
        result = runner.invoke(app, ["ingest", "nmap", str(_scan_file(tmp_path)), "--json"])
        assert result.exit_code == ExitCode.OK
        doc = json.loads(result.output)
        assert doc["report"]["assets"][0]["product"] == "windows_server"


class TestScalarEscapeSets:
    """#329 — the leading guard, asserted directly on `escape_markdown_scalar`."""

    @pytest.mark.parametrize("char", ["-", "+", "#", "|"])
    def test_guard_set_is_escaped_at_position_zero(self, char: str) -> None:
        """A value STARTING with one of these would open a list item, heading, or table row
        inside the renderer's own `- ` / `  - ` / `### ` prefix."""
        assert playbook.escape_markdown_scalar(f"{char} value") == f"\\{char} value"

    @pytest.mark.parametrize("char", ["-", "+", "#", "|"])
    def test_guard_set_is_untouched_mid_string(self, char: str) -> None:
        """Mid-line these are not structural, so escaping them only corrupts real content.

        `>` is excluded — it is entity-escaped at any position; see the next test.
        """
        assert playbook.escape_markdown_scalar(f"value {char} tail") == f"value {char} tail"

    def test_gt_is_entity_escaped_never_backslashed(self) -> None:
        """`>` is in `_MARKDOWN_LEADING` for completeness only: `html.escape` runs FIRST, so the
        guard only ever sees `&gt;` and the blockquote is neutralized one step earlier. Pins both
        positions, and fails loudly if anyone reorders the guard ahead of `html.escape` (which
        would emit a double-guarded `\\&gt;`)."""
        assert playbook.escape_markdown_scalar("value > tail") == "value &gt; tail"
        assert playbook.escape_markdown_scalar("> quoted") == "&gt; quoted"

    def test_hyphenated_ids_are_no_longer_escaped(self) -> None:
        assert playbook.escape_markdown_scalar("CVE-2023-38408") == "CVE-2023-38408"
        assert playbook.escape_markdown_scalar("(1.2-2.0)") == "\\(1.2-2.0\\)"

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("1. injected", "1\\. injected"),  # the CommonMark marker: digits, `.`, space
            ("123456789.", "123456789\\."),  # 9 digits + `.` at end of line is still a marker
            ("1234567890. no", "1234567890. no"),  # 10 digits is NOT a marker (CommonMark caps at 9)
            ("1.2.3", "1.2.3"),  # version strings: `.` followed by a non-space is not a marker
            ("10.0.19045", "10.0.19045"),
            ("1) paren", "1\\) paren"),  # `)` form is covered by the inline set, unchanged here
            ("v1. tail", "v1. tail"),  # digit not at position 0 → not leading structure
        ],
    )
    def test_leading_ordered_list_marker_is_escaped(self, raw: str, expected: str) -> None:
        """Only the CommonMark ordered-list form `N.` + whitespace/EOL at position 0 gets its
        `.` escaped; ordinary version strings and mid-line digits are left alone."""
        assert playbook.escape_markdown_scalar(raw) == expected

    def test_inline_set_is_still_escaped(self) -> None:
        assert playbook.escape_markdown_scalar("windows_server") == "windows\\_server"
        assert playbook.escape_markdown_scalar("*bold*") == "\\*bold\\*"

    @pytest.mark.parametrize("empty", ["", "   ", "\x00", "\n\n"], ids=["empty", "spaces", "nul", "newlines"])
    def test_empty_scalar_renders_empty_not_a_stray_backslash(self, empty: str) -> None:
        """A scalar that sanitizes to nothing must render as nothing.

        The leading guard was first written `escaped[:1] in _MARKDOWN_LEADING`, which is
        substring containment — and `"" in "-+#>|"` is True, so EVERY empty scalar came back as
        a bare `\\`. Reachable in shipped output: `render_briefing` passes `a.get('reason', '')`,
        so a Recommended Action with no reason rendered `... (weaponization 0) — \\`.
        """
        assert playbook.escape_markdown_scalar(empty) == ""
        assert playbook.plain_scalar(empty) == ""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            # Tier 1 — `isprintable()`: nothing to neutralize, only the whitespace collapse runs.
            ("windows_server 2019", "windows_server 2019"),
            ("café ﬁ ｆｕｌｌ", "café ﬁ ｆｕｌｌ"),  # non-ASCII but printable; NFKC would mangle these
            # Tier 2 — ASCII carrying control characters: `Cc` -> space, then collapse.
            ("a\nb\r\nc\x00d", "a b c d"),
            ("boom \x1b[31mRED\x1b[0m", "boom [31mRED [0m"),
            # Tier 3 — non-ASCII AND control/format characters: the general category walk.
            ("café\x1b[31m x", "café [31m x"),
            ("a‮b\x00c", "ab c"),  # U+202E RIGHT-TO-LEFT OVERRIDE is `Cf` -> DROPPED; NUL is `Cc` -> space
            ("é﻿\tx", "é x"),  # U+FEFF is `Cf` -> DROPPED; TAB is `Cc` -> space
        ],
        ids=["t1-ascii", "t1-unicode", "t2-newlines", "t2-ansi", "t3-ansi", "t3-bidi", "t3-bom"],
    )
    def test_plain_scalar_tiers_all_sanitize(self, raw: str, expected: str) -> None:
        """`plain_scalar` dispatches through three tiers for speed; all must agree.

        The two fast paths exist because the general per-character `unicodedata.category` walk
        dominates a large briefing (~161k calls at the 200-asset x 200-CVE ceiling, over
        descriptions that now run to ~2.4 KB since the engine stopped truncating them). They are
        equivalences, not heuristics — `isprintable()` is False for exactly the categories the
        walk neutralizes — but a fast path that silently diverged would drop the ANSI-injection
        defense, so each tier is pinned by an input that can only reach it.
        """
        assert playbook.plain_scalar(raw) == expected
        # No control character survives ANY tier — the property that actually matters.
        assert not any(unicodedata.category(character).startswith("C") for character in playbook.plain_scalar(raw))

    def test_plain_scalar_tier_dispatch_matches_the_general_walk(self) -> None:
        """Differential check: every tier must equal the reference walk, byte for byte."""

        def reference(value: str) -> str:
            characters = []
            for character in unicodedata.normalize("NFC", value):
                category = unicodedata.category(character)
                if category == "Cc":
                    characters.append(" ")
                elif not category.startswith("C"):
                    characters.append(character)
            return " ".join("".join(characters).split())

        corpus = [
            "",
            "   ",
            "plain ascii",
            "café",
            "a\nb",
            "\x00\x1b",
            "é‮﻿\x1b[0m",
            "ｆｕｌｌ\twidth",
            "d" * 40 + "…",
            "\U0001f600 emoji\x07",
        ]
        for value in corpus:
            assert playbook.plain_scalar(value) == reference(value), value

    def test_plain_scalar_keeps_sanitization_and_drops_escaping(self) -> None:
        assert playbook.plain_scalar("windows_server") == "windows_server"
        assert playbook.plain_scalar("AT&T <b> > q") == "AT&T <b> > q"
        assert playbook.plain_scalar("a\nb\r\nc\x00") == "a b c"
        assert playbook.plain_scalar("x\x1b[31my") == "x [31my"


class TestDescriptionExpand:
    """#330 — `--expand` changes the rendered description for an over-cap input.

    Renderer-level: the description arrives as a fixture value, so these pin the CLI's own
    `_DESC_CAP` behaviour, NOT the engine's cap removal (`tests/v1_api_unit/test_routes.py`
    covers that). Built through the production `assemble_briefing` so the briefing shape cannot
    drift from what `ccc ingest` actually feeds `render_briefing`.
    """

    def _briefing(self, description: str) -> dict:
        report = copy.deepcopy(_ENRICH["report"])
        report["assets"][0]["top_cves"][0]["description"] = description
        return assemble_briefing(report, fmt="nmap", parsed_count=1, truncated=None, enrichment_id="e" * 32)

    def test_expand_changes_the_rendered_description(self) -> None:
        """The AC case: same briefing, two flag states, materially different output."""
        long_desc = "E" * 900
        briefing = self._briefing(long_desc)
        capped = playbook.render_briefing(briefing, scan_file="scan.xml", expand=False)
        full = playbook.render_briefing(briefing, scan_file="scan.xml", expand=True)
        assert capped != full
        assert "…" in capped and "…" not in full  # truncation is MARKED, never a silent mid-word cut
        assert long_desc in full
        assert long_desc not in capped
        # The cut lands AT the cap and is marked, not at some arbitrary point.
        assert "E" * playbook._DESC_CAP + "…" in capped

    def test_under_cap_descriptions_are_identical_either_way(self) -> None:
        """`--expand` only bites over the cap — a short description is never marked."""
        briefing = self._briefing("short and complete")
        capped = playbook.render_briefing(briefing, scan_file="scan.xml", expand=False)
        full = playbook.render_briefing(briefing, scan_file="scan.xml", expand=True)
        assert capped == full and "…" not in capped
