"""Tests for the ``ccc reports`` command group.

Every subcommand routes through the SDK's ``client.ai_reports`` namespace (mocked via
``mock_sdk.ai_reports``) — no network. Covers table + ``--json`` output, file export, validation /
API-error exit codes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from crimson_crawler_cli.cli import app
from crimson_crawler_cli.exceptions import ExitCode
from crimson_crawler_client import UnexpectedStatus


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def authed(monkeypatch: pytest.MonkeyPatch, clean_env: Path) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")


class TestTemplatesAndList:
    def test_lists_templates(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.list_templates.return_value = [
            {
                "id": "exec",
                "name": "Executive",
                "description": "C-suite brief",
                "ai_sections": [{"section_type": "bluf"}],
            },
        ]
        result = runner.invoke(app, ["reports", "templates"])
        assert result.exit_code == ExitCode.OK
        assert "Executive" in result.output
        mock_sdk.ai_reports.list_templates.assert_awaited_once_with()

    def test_templates_json(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.list_templates.return_value = [{"id": "exec"}]
        result = runner.invoke(app, ["--json", "reports", "templates"])
        assert json.loads(result.output) == {"templates": [{"id": "exec"}]}

    def test_templates_json_trailing_flag(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.list_templates.return_value = [{"id": "exec"}]
        result = runner.invoke(app, ["reports", "templates", "--json"])
        assert json.loads(result.output) == {"templates": [{"id": "exec"}]}

    def test_lists_reports(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.list_reports.return_value = [
            {"id": "r1", "name": "Q3 brief", "created_at": "2026-06-20"},
        ]
        result = runner.invoke(app, ["reports", "list"])
        assert result.exit_code == ExitCode.OK
        assert "Q3 brief" in result.output

    def test_empty_reports(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.list_reports.return_value = []
        result = runner.invoke(app, ["reports", "list"])
        assert result.exit_code == ExitCode.OK
        assert "No reports" in result.output

    def test_discovery_renders_doc(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.discovery.return_value = {"section": "ai-reports", "tier": "team"}
        result = runner.invoke(app, ["reports", "discovery"])
        assert result.exit_code == ExitCode.OK
        assert "ai-reports" in result.output
        mock_sdk.ai_reports.discovery.assert_awaited_once_with()

    def test_discovery_json(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.discovery.return_value = {"section": "ai-reports"}
        result = runner.invoke(app, ["--json", "reports", "discovery"])
        assert json.loads(result.output) == {"section": "ai-reports"}


class TestShow:
    def test_show_prints_html(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.get_report.return_value = {"id": "r1", "content": "<h1>Report</h1>"}
        result = runner.invoke(app, ["reports", "show", "r1"])
        assert result.exit_code == ExitCode.OK
        assert "<h1>Report</h1>" in result.output
        mock_sdk.ai_reports.get_report.assert_awaited_once_with("r1")

    def test_show_json(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.get_report.return_value = {"id": "r1", "content": "<h1/>"}
        result = runner.invoke(app, ["--json", "reports", "show", "r1"])
        assert json.loads(result.output) == {"id": "r1", "content": "<h1/>"}


class TestCreateAndGenerate:
    def test_create_draft(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.create_draft.return_value = {"id": "r9", "ai_sections": [{"section_type": "a"}]}
        result = runner.invoke(app, ["reports", "create", "exec", "-s", "s1", "-s", "s2", "--name", "Brief"])
        assert result.exit_code == ExitCode.OK
        assert "r9" in result.output
        mock_sdk.ai_reports.create_draft.assert_awaited_once_with("exec", source_ids=["s1", "s2"], name="Brief")

    def test_create_minimal(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.create_draft.return_value = {"id": "r9", "ai_sections": []}
        result = runner.invoke(app, ["reports", "create", "technical"])
        assert result.exit_code == ExitCode.OK
        mock_sdk.ai_reports.create_draft.assert_awaited_once_with("technical", source_ids=None, name=None)

    def test_generate(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.generate_report.return_value = {
            "report": {"id": "r9", "name": "Brief"},
            "sections": [{"section_type": "a"}, {"section_type": "b"}],
            "skipped": [],
        }
        result = runner.invoke(app, ["reports", "generate", "exec", "-s", "s1"])
        assert result.exit_code == ExitCode.OK
        assert "r9" in result.output
        assert "2 AI section" in result.output
        mock_sdk.ai_reports.generate_report.assert_awaited_once_with("exec", source_ids=["s1"], name=None)

    def test_generate_reports_skipped(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.generate_report.return_value = {
            "report": {"id": "r9"},
            "sections": [],
            "skipped": ["bad-id"],
        }
        result = runner.invoke(app, ["reports", "generate", "exec"])
        assert result.exit_code == ExitCode.OK
        assert "bad-id" in result.output

    def test_generate_json(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.generate_report.return_value = {"report": {"id": "r9"}, "sections": [], "skipped": []}
        result = runner.invoke(app, ["--json", "reports", "generate", "exec"])
        assert json.loads(result.output)["report"]["id"] == "r9"


class TestFill:
    def test_fill_happy_path(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.fill_section.return_value = {
            "section_type": "bluf",
            "filled": True,
            "truncated": False,
            "remaining": [{"section_type": "details"}],
            "complete": False,
        }
        result = runner.invoke(app, ["reports", "fill", "r1"])
        assert result.exit_code == ExitCode.OK
        assert "bluf" in result.output
        assert "1 remaining" in result.output
        mock_sdk.ai_reports.fill_section.assert_awaited_once_with("r1", section_type=None)

    def test_fill_complete(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.fill_section.return_value = {
            "section_type": "details",
            "remaining": [],
            "complete": True,
        }
        result = runner.invoke(app, ["reports", "fill", "r1"])
        assert result.exit_code == ExitCode.OK
        assert "complete" in result.output

    def test_fill_section_type_passthrough(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.fill_section.return_value = {"section_type": "bluf", "remaining": [], "complete": True}
        result = runner.invoke(app, ["reports", "fill", "r1", "--section", "bluf"])
        assert result.exit_code == ExitCode.OK
        mock_sdk.ai_reports.fill_section.assert_awaited_once_with("r1", section_type="bluf")

    def test_fill_json(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.fill_section.return_value = {
            "section_type": "bluf",
            "remaining": [],
            "complete": True,
        }
        result = runner.invoke(app, ["--json", "reports", "fill", "r1"])
        assert json.loads(result.output) == {"section_type": "bluf", "remaining": [], "complete": True}

    def test_fill_api_error(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.fill_section.side_effect = UnexpectedStatus(409, b"", "nothing left")
        result = runner.invoke(app, ["reports", "fill", "r1"])
        assert result.exit_code == ExitCode.API_ERROR


class TestSection:
    def test_section_happy_path(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.section.return_value = {
            "text": "## Findings\nGrounded prose.",
            "truncated": False,
            "grounded": True,
            "unsupported_ids": [],
        }
        result = runner.invoke(
            app,
            [
                "reports",
                "section",
                "-s",
                "s1",
                "-s",
                "s2",
                "--type",
                "details",
                "--verbosity",
                "detailed",
                "--instruction",
                "Focus on KEV",
            ],
        )
        assert result.exit_code == ExitCode.OK
        assert "Grounded prose." in result.output
        mock_sdk.ai_reports.section.assert_awaited_once_with(
            ["s1", "s2"],
            section_type="details",
            instruction="Focus on KEV",
            verbosity="detailed",
        )

    def test_section_minimal(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.section.return_value = {"text": "x", "truncated": False, "grounded": True}
        result = runner.invoke(app, ["reports", "section", "-s", "s1"])
        assert result.exit_code == ExitCode.OK
        mock_sdk.ai_reports.section.assert_awaited_once_with(
            ["s1"],
            section_type=None,
            instruction=None,
            verbosity=None,
        )

    def test_section_notes(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.section.return_value = {
            "text": "prose",
            "truncated": True,
            "grounded": False,
            "unsupported_ids": ["bad-id"],
        }
        result = runner.invoke(app, ["reports", "section", "-s", "s1"])
        assert result.exit_code == ExitCode.OK
        assert "truncated" in result.output
        assert "not fully grounded" in result.output
        assert "bad-id" in result.output

    def test_section_json(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.section.return_value = {"text": "x", "grounded": True}
        result = runner.invoke(app, ["--json", "reports", "section", "-s", "s1"])
        assert json.loads(result.output) == {"text": "x", "grounded": True}

    def test_section_requires_source(self, runner, authed, mock_sdk) -> None:
        result = runner.invoke(app, ["reports", "section"])
        assert result.exit_code == ExitCode.BAD_INPUT
        mock_sdk.ai_reports.section.assert_not_awaited()


class TestExport:
    def test_export_to_stdout(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.export_report.return_value = {
            "content": "# Report\n",
            "bytes": b"# Report\n",
            "filename": "r1.md",
            "content_type": "text/markdown",
        }
        result = runner.invoke(app, ["reports", "export", "r1", "--format", "md"])
        assert result.exit_code == ExitCode.OK
        assert "# Report" in result.output
        mock_sdk.ai_reports.export_report.assert_awaited_once_with("r1", "md")

    def test_export_default_html(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.export_report.return_value = {"content": "<h1/>", "filename": "r1.html"}
        runner.invoke(app, ["reports", "export", "r1"])
        mock_sdk.ai_reports.export_report.assert_awaited_once_with("r1", "html")

    def test_export_to_file(self, runner, authed, mock_sdk, tmp_path) -> None:
        mock_sdk.ai_reports.export_report.return_value = {"content": "# Report\n", "filename": "r1.md"}
        dest = tmp_path / "out.md"
        result = runner.invoke(app, ["reports", "export", "r1", "-f", "md", "-o", str(dest)])
        assert result.exit_code == ExitCode.OK
        assert dest.read_text() == "# Report\n"

    def test_export_to_file_json(self, runner, authed, mock_sdk, tmp_path) -> None:
        mock_sdk.ai_reports.export_report.return_value = {"content": "x", "filename": "r1.md"}
        dest = tmp_path / "out.md"
        result = runner.invoke(app, ["--json", "reports", "export", "r1", "-f", "md", "-o", str(dest)])
        assert json.loads(result.output)["written"] == str(dest)
        assert dest.read_text() == "x"


class TestRenameAndDelete:
    def test_rename(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.rename_report.return_value = {"id": "r1", "name": "New"}
        result = runner.invoke(app, ["reports", "rename", "r1", "New"])
        assert result.exit_code == ExitCode.OK
        assert "New" in result.output
        mock_sdk.ai_reports.rename_report.assert_awaited_once_with("r1", "New")

    def test_delete(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.delete_report.return_value = True
        result = runner.invoke(app, ["reports", "delete", "r1"])
        assert result.exit_code == ExitCode.OK
        assert "Deleted" in result.output
        mock_sdk.ai_reports.delete_report.assert_awaited_once_with("r1")


class TestExitCodes:
    def test_missing_creds(self, runner, clean_env, monkeypatch) -> None:
        monkeypatch.delenv("CRIMSON_CRAWLER_API_KEY", raising=False)
        result = runner.invoke(app, ["reports", "templates"])
        assert result.exit_code == ExitCode.MISSING_CREDENTIALS

    def test_api_error(self, runner, authed, mock_sdk) -> None:
        mock_sdk.ai_reports.list_reports.side_effect = UnexpectedStatus(500, b"", "boom")
        result = runner.invoke(app, ["reports", "list"])
        assert result.exit_code == ExitCode.API_ERROR


class TestGapC2AllSubcommands:
    """C2: every ``reports`` subcommand exists and routes to the SDK."""

    @pytest.mark.parametrize(
        "args,method,return_value",
        [
            (["templates"], "list_templates", []),
            (["discovery"], "discovery", {"section": "ai-reports"}),
            (["list"], "list_reports", []),
            (["show", "r1"], "get_report", {"id": "r1", "content": "<h1/>"}),
            (["create", "exec"], "create_draft", {"id": "r9", "ai_sections": []}),
            (["generate", "exec"], "generate_report", {"report": {"id": "r9"}, "sections": []}),
            (["fill", "r1"], "fill_section", {"section_type": "bluf", "complete": True}),
            (["section", "-s", "s1"], "section", {"text": "x", "grounded": True}),
            (["export", "r1", "-f", "md"], "export_report", {"content": "x", "filename": "r1.md"}),
            (["rename", "r1", "New"], "rename_report", {"id": "r1", "name": "New"}),
            (["delete", "r1"], "delete_report", True),
        ],
        ids=[
            "templates",
            "discovery",
            "list",
            "show r1",
            "create exec",
            "generate exec",
            "fill r1",
            "section -s s1",
            "export r1 -f md",
            "rename r1 New",
            "delete r1",
        ],
    )
    def test_subcommand_routes(self, runner, authed, mock_sdk, args, method, return_value) -> None:
        sdk_method = getattr(mock_sdk.ai_reports, method)
        sdk_method.return_value = return_value

        result = runner.invoke(app, ["reports", *args])

        assert result.exit_code == ExitCode.OK, result.output + result.stderr
        sdk_method.assert_awaited()


MARKUP = "[red]x[/red]"


class TestRichMarkupEscaping:
    """Server- and user-derived strings must not be interpreted as Rich markup.

    ``ccc reports`` renders report and template names straight into a markup-enabled
    ``Console``, and a report name is *user*-writable (``ccc reports rename``). Left
    unescaped, ``[link=…]`` becomes a real OSC-8 terminal hyperlink, style tags let a
    name forge output the CLI never said, and a malformed tag raises ``MarkupError``,
    turning a listing into "internal error"/exit 1.

    The assertion in each case is that the payload appears **verbatim** in the output:
    escaped markup renders back to its literal text, interpreted markup does not.
    Payloads stay short so table column wrapping can't break the match.

    Guarded in CI by ``crimson-crawler.rich-unescaped-untrusted-markup`` in
    ``.gitlab/security/project-rules.yml``, whose path scope covers this whole command
    package — these tests are what prove the rule's sanitizers are actually reached.
    """

    @pytest.mark.parametrize(
        ("method", "return_value", "args"),
        [
            ("list_reports", [{"id": "r1", "name": MARKUP, "created_at": "2026-01-01"}], ["list"]),
            ("discovery", {"tier": MARKUP}, ["discovery"]),
            (
                "generate_report",
                {"report": {"id": "r1", "name": MARKUP}, "sections": [], "skipped": []},
                ["generate", "exec"],
            ),
            ("rename_report", {"id": "r1", "name": MARKUP}, ["rename", "r1", MARKUP]),
            ("section", {"text": "body", "unsupported_ids": [MARKUP]}, ["section", "-s", "s1"]),
        ],
        ids=["list", "discovery", "generate", "rename", "section-unsupported-ids"],
    )
    def test_markup_renders_verbatim(self, runner, authed, mock_sdk, method, return_value, args) -> None:
        getattr(mock_sdk.ai_reports, method).return_value = return_value
        result = runner.invoke(app, ["reports", *args])
        assert result.exit_code == ExitCode.OK, result.output
        assert MARKUP in result.output

    def test_template_name_and_description_escaped(self, runner, authed, mock_sdk) -> None:
        """Separate: asserts BOTH cells escaped, so the count matters, not just presence."""
        mock_sdk.ai_reports.list_templates.return_value = [
            {"id": "t1", "name": MARKUP, "description": MARKUP, "ai_sections": []},
        ]
        result = runner.invoke(app, ["reports", "templates"])
        assert result.exit_code == ExitCode.OK, result.output
        assert result.output.count(MARKUP) == 2

    def test_malformed_markup_does_not_crash_the_listing(self, runner, authed, mock_sdk) -> None:
        """An unbalanced closing tag would raise MarkupError -> exit 1 if interpreted."""
        mock_sdk.ai_reports.list_reports.return_value = [
            {"id": "r1", "name": "[/]", "created_at": "2026-01-01"},
        ]
        result = runner.invoke(app, ["reports", "list"])
        assert result.exit_code == ExitCode.OK, result.output
        assert "[/]" in result.output
