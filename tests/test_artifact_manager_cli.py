"""Tests for the ``ccc artifact-manager`` command group.

Every subcommand routes through the SDK's ``client.artifact_manager`` namespace
(mocked via ``mock_sdk.artifact_manager``) — no network. Covers table + ``--json``
output, file I/O for ``get``/``export``/``upload``, input validation exit
codes, and the API-error path.
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


class TestList:
    def test_table_lists_artifacts(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.list_artifacts.return_value = [
            {
                "id": "a1",
                "kind": "artifact_enrichment",
                "name": "Scan · 5",
                "tlp": "AMBER+STRICT",
                "byte_size": 2048,
                "favorite": True,
                "created_at": "2026-06-10T01:02:03Z",
            },
        ]
        result = runner.invoke(app, ["artifact-manager", "list", "--kind", "artifact_enrichment"])
        assert result.exit_code == ExitCode.OK
        assert "Scan · 5" in result.output
        assert "AMBER+STRICT" in result.output  # the TLP column

    def test_json_mode_round_trips(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.list_artifacts.return_value = [{"id": "a1"}]
        result = runner.invoke(app, ["--json", "artifact-manager", "list"])
        assert json.loads(result.output) == {"artifacts": [{"id": "a1"}]}

    def test_api_error_exits_3(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.list_artifacts.side_effect = UnexpectedStatus(401, b"unauthorized")
        result = runner.invoke(app, ["artifact-manager", "list"])
        assert result.exit_code == ExitCode.API_ERROR


class TestUpload:
    def test_uploads_text_as_paste_and_binary_as_file(self, runner, authed, mock_sdk, tmp_path) -> None:
        text_file = tmp_path / "notes.txt"
        text_file.write_text("CVE-2024-3400 observed")
        bin_file = tmp_path / "dump.bin"
        bin_file.write_bytes(b"\x00\x01\xff")
        mock_sdk.artifact_manager.upload_artifacts.return_value = {"ids": ["n1", "n2"], "folderId": None}

        result = runner.invoke(app, ["artifact-manager", "upload", str(text_file), str(bin_file), "--folder", "case-1"])
        assert result.exit_code == ExitCode.OK
        assert "Uploaded 2" in result.output
        artifacts = mock_sdk.artifact_manager.upload_artifacts.await_args.args[0]
        assert artifacts[0]["format"] == "paste" and artifacts[0]["content"] == "CVE-2024-3400 observed"
        assert artifacts[1]["format"] == "file"  # binary → base64

    def test_missing_file_exits_64(self, runner, authed, mock_sdk, tmp_path) -> None:
        result = runner.invoke(app, ["artifact-manager", "upload", str(tmp_path / "nope.txt")])
        assert result.exit_code == ExitCode.BAD_INPUT
        mock_sdk.artifact_manager.upload_artifacts.assert_not_awaited()


class TestGet:
    _RAW = {
        "content": '{"report":1}',
        "id": "a1",
        "kind": "artifact_enrichment",
        "name": "Scan · 5",
        "format": "scan_report",
        "mime": "application/json",
        "tlp": "RED",
        "created_at": "2026-06-10",
    }

    def test_prints_raw_content_to_stdout(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.get_artifact_raw.return_value = self._RAW
        result = runner.invoke(app, ["artifact-manager", "get", "a1"])
        assert result.exit_code == ExitCode.OK
        assert '{"report":1}' in result.output

    def test_writes_to_output_file(self, runner, authed, mock_sdk, tmp_path) -> None:
        mock_sdk.artifact_manager.get_artifact_raw.return_value = self._RAW
        out = tmp_path / "report.json"
        result = runner.invoke(app, ["artifact-manager", "get", "a1", "-o", str(out)])
        assert result.exit_code == ExitCode.OK
        assert out.read_text() == '{"report":1}'
        assert "Saved" in result.output

    def test_invalid_output_dir_fails_before_api(self, runner, authed, mock_sdk, tmp_path) -> None:
        """A bad ``-o`` dir exits 64 before the (usage-exempt) API call — clean error, no traceback."""
        result = runner.invoke(app, ["artifact-manager", "get", "a1", "-o", str(tmp_path / "nope" / "f.json")])
        assert result.exit_code == ExitCode.BAD_INPUT
        mock_sdk.artifact_manager.get_artifact_raw.assert_not_awaited()


class TestExports:
    def test_lists_formats(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.list_exports.return_value = ["csv", "stix"]
        result = runner.invoke(app, ["artifact-manager", "exports", "s1"])
        assert "csv" in result.output and "stix" in result.output

    def test_export_writes_response_filename(self, runner, authed, mock_sdk, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        mock_sdk.artifact_manager.get_export.return_value = {
            "content": '{"type":"bundle"}',
            "bytes": b'{"type":"bundle"}',
            "filename": "stix.json",
            "content_type": "application/json; charset=utf-8",
        }
        result = runner.invoke(app, ["artifact-manager", "export", "s1", "stix"])
        assert result.exit_code == ExitCode.OK
        assert (tmp_path / "stix.json").read_text() == '{"type":"bundle"}'
        mock_sdk.artifact_manager.get_export.assert_awaited_once_with("s1", "stix", tlp=None)

    def test_export_traversal_filename_falls_back_to_local_default(
        self, runner, authed, mock_sdk, tmp_path, monkeypatch
    ) -> None:
        """A hostile ``../.env`` response filename must never escape the cwd — local default name instead."""
        workdir = tmp_path / "work"
        workdir.mkdir()
        monkeypatch.chdir(workdir)
        mock_sdk.artifact_manager.get_export.return_value = {
            "content": "SECRET=1",
            "bytes": b"SECRET=1",
            "filename": "../.env",
            "content_type": "text/plain",
        }
        result = runner.invoke(app, ["artifact-manager", "export", "s1", "stix"])
        assert result.exit_code == ExitCode.OK
        assert not (tmp_path / ".env").exists()  # nothing written outside the cwd
        assert not (workdir / ".env").exists()  # the server-picked basename is rejected wholesale
        assert (workdir / "s1.stix").read_bytes() == b"SECRET=1"

    def test_export_absolute_filename_falls_back_to_local_default(
        self, runner, authed, mock_sdk, tmp_path, monkeypatch
    ) -> None:
        """An absolute response filename is rejected — the write stays in the cwd under the local default."""
        workdir = tmp_path / "work"
        workdir.mkdir()
        monkeypatch.chdir(workdir)
        evil = tmp_path / "outside" / "evil.json"
        (tmp_path / "outside").mkdir()
        mock_sdk.artifact_manager.get_export.return_value = {
            "content": "x",
            "bytes": b"x",
            "filename": str(evil),
            "content_type": "application/json",
        }
        result = runner.invoke(app, ["artifact-manager", "export", "s1", "csaf"])
        assert result.exit_code == ExitCode.OK
        assert not evil.exists()
        assert (workdir / "s1.csaf").read_bytes() == b"x"

    @pytest.mark.parametrize(
        "unsafe_filename",
        ("NUL.json", "report.json:hidden", "bad?.json", "trailing.", "\x1f.json"),
    )
    def test_export_windows_unsafe_filename_falls_back_to_local_default(
        self, runner, authed, mock_sdk, tmp_path, monkeypatch, unsafe_filename
    ) -> None:
        monkeypatch.chdir(tmp_path)
        mock_sdk.artifact_manager.get_export.return_value = {
            "content": "x",
            "bytes": b"x",
            "filename": unsafe_filename,
            "content_type": "application/json",
        }

        result = runner.invoke(app, ["artifact-manager", "export", "s1", "stix"])

        assert result.exit_code == ExitCode.OK
        assert (tmp_path / "s1.stix").read_bytes() == b"x"
        assert not (tmp_path / unsafe_filename).exists()

    def test_export_explicit_output_overrides_response_filename(self, runner, authed, mock_sdk, tmp_path) -> None:
        """``--output`` is authoritative — the server filename (even a hostile one) is ignored."""
        out = tmp_path / "chosen.json"
        mock_sdk.artifact_manager.get_export.return_value = {
            "content": "x",
            "bytes": b"x",
            "filename": "../.env",
            "content_type": "application/json",
        }
        result = runner.invoke(app, ["artifact-manager", "export", "s1", "stix", "-o", str(out)])
        assert result.exit_code == ExitCode.OK
        assert out.read_bytes() == b"x"
        assert not (tmp_path / ".env").exists()

    def test_export_invalid_output_dir_fails_before_api(self, runner, authed, mock_sdk, tmp_path) -> None:
        """An explicit ``-o`` into a missing dir exits 64 before the API call."""
        result = runner.invoke(
            app, ["artifact-manager", "export", "s1", "stix", "-o", str(tmp_path / "nope" / "f.json")]
        )
        assert result.exit_code == ExitCode.BAD_INPUT
        mock_sdk.artifact_manager.get_export.assert_not_awaited()

    def test_export_writes_RAW_BYTES_for_binary_xlsx(self, runner, authed, mock_sdk, tmp_path, monkeypatch) -> None:
        # The emass/workbook XLSX exports are binary — the CLI must write the raw `bytes`, never the lossy
        # text `content` (which would corrupt the spreadsheet). The byte 0x80 is invalid UTF-8, so a
        # text-decode-then-encode round-trip mangles it; writing `bytes` preserves it exactly.
        monkeypatch.chdir(tmp_path)
        xlsx = b"PK\x03\x04\x80\x00\x01workbook-bytes\xff"
        mock_sdk.artifact_manager.get_export.return_value = {
            "content": xlsx.decode("utf-8", errors="replace"),
            "bytes": xlsx,
            "filename": "emass.xlsx",
            "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        }
        result = runner.invoke(app, ["artifact-manager", "export", "s1", "emass"])
        assert result.exit_code == ExitCode.OK
        assert (tmp_path / "emass.xlsx").read_bytes() == xlsx  # byte-exact, not corrupted

    def test_export_all_writes_zip_bytes(self, runner, authed, mock_sdk, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        mock_sdk.artifact_manager.download_all_exports.return_value = b"PK\x03\x04all-exports"
        result = runner.invoke(app, ["artifact-manager", "export-all", "s1"])
        assert result.exit_code == ExitCode.OK
        assert (tmp_path / "s1-exports.zip").read_bytes() == b"PK\x03\x04all-exports"
        mock_sdk.artifact_manager.download_all_exports.assert_awaited_once_with("s1", tlp=None)

    def test_export_all_default_refuses_existing_file_before_api(
        self, runner, authed, mock_sdk, tmp_path, monkeypatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        existing = tmp_path / "s1-exports.zip"
        existing.write_bytes(b"keep")

        result = runner.invoke(app, ["artifact-manager", "export-all", "s1"])

        assert result.exit_code == ExitCode.BAD_INPUT
        assert existing.read_bytes() == b"keep"
        mock_sdk.artifact_manager.download_all_exports.assert_not_awaited()

    def test_export_all_invalid_output_dir_fails_before_api(self, runner, authed, mock_sdk, tmp_path) -> None:
        """An explicit ``-o`` into a missing dir exits 64 before the API call."""
        result = runner.invoke(app, ["artifact-manager", "export-all", "s1", "-o", str(tmp_path / "nope" / "f.zip")])
        assert result.exit_code == ExitCode.BAD_INPUT
        mock_sdk.artifact_manager.download_all_exports.assert_not_awaited()


class TestCompare:
    def test_renders_counts_and_rows(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.compare_enrichments.return_value = {
            "counts": {"new": 1, "resolved": 2, "changed": 0, "persistent": 3},
            "columns": [{"name": "A"}, {"name": "B"}],
            "rows": [{"value": "CVE-2021-44228", "status": "persistent", "cells": [{"score": 92}, {"score": 95}]}],
        }
        result = runner.invoke(app, ["artifact-manager", "compare", "s1", "s2"])
        assert result.exit_code == ExitCode.OK
        assert "1 new" in result.output and "CVE-2021-44228" in result.output
        mock_sdk.artifact_manager.compare_enrichments.assert_awaited_once_with(["s1", "s2"])

    def test_requires_two_to_twelve_ids(self, runner, authed, mock_sdk) -> None:
        assert runner.invoke(app, ["artifact-manager", "compare", "only-one"]).exit_code == ExitCode.BAD_INPUT
        thirteen = [f"s{i}" for i in range(13)]
        assert runner.invoke(app, ["artifact-manager", "compare", *thirteen]).exit_code == ExitCode.BAD_INPUT
        mock_sdk.artifact_manager.compare_enrichments.assert_not_awaited()

    def test_accepts_seven_ids(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.compare_enrichments.return_value = {"counts": {}, "columns": [], "rows": []}
        seven = [f"s{i}" for i in range(7)]
        assert runner.invoke(app, ["artifact-manager", "compare", *seven]).exit_code == ExitCode.OK
        mock_sdk.artifact_manager.compare_enrichments.assert_awaited_once_with(seven)


class TestSaveEnrichment:
    def test_saves_and_reports_id(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.save_enrichment.return_value = {"enrichment_artifact_id": "art-1"}
        result = runner.invoke(app, ["artifact-manager", "save-enrichment", "abc123", "--new-folder", "Triage"])
        assert result.exit_code == ExitCode.OK
        assert "art-1" in result.output
        mock_sdk.artifact_manager.save_enrichment.assert_awaited_once_with(
            "abc123", folder_id=None, new_folder_name="Triage"
        )

    def test_already_saved_is_idempotent(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.save_enrichment.return_value = {"already_persisted": True}
        result = runner.invoke(app, ["artifact-manager", "save-enrichment", "abc123"])
        assert result.exit_code == ExitCode.OK
        assert "Already saved" in result.output


class TestDeleteAndFolders:
    def test_delete_single(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.bulk_delete.return_value = 1
        result = runner.invoke(app, ["artifact-manager", "delete", "a1"])
        assert result.exit_code == ExitCode.OK
        assert "Deleted" in result.output
        mock_sdk.artifact_manager.bulk_delete.assert_awaited_once_with(["a1"])

    def test_delete_many(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.bulk_delete.return_value = 3
        result = runner.invoke(app, ["artifact-manager", "delete", "a1", "a2", "a3"])
        assert result.exit_code == ExitCode.OK
        assert "Deleted 3" in result.output
        mock_sdk.artifact_manager.bulk_delete.assert_awaited_once_with(["a1", "a2", "a3"])

    def test_folders_table(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.list_folders.return_value = [
            {"id": "f1", "name": "evidence", "artifact_count": 3},
        ]
        result = runner.invoke(app, ["artifact-manager", "folders"])
        assert "evidence" in result.output and "3" in result.output

    def test_create_folder(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.create_folder.return_value = "f9"
        result = runner.invoke(app, ["artifact-manager", "create-folder", "evidence"])
        assert result.exit_code == ExitCode.OK and "Created" in result.output
        mock_sdk.artifact_manager.create_folder.assert_awaited_once_with("evidence")

    def test_rename_folder(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.rename_folder.return_value = {"id": "f1", "name": "renamed"}
        result = runner.invoke(app, ["artifact-manager", "rename-folder", "f1", "renamed"])
        assert result.exit_code == ExitCode.OK and "Renamed" in result.output
        mock_sdk.artifact_manager.rename_folder.assert_awaited_once_with("f1", "renamed")

    def test_delete_folder(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.delete_folder.return_value = True
        result = runner.invoke(app, ["artifact-manager", "delete-folder", "f1"])
        assert result.exit_code == ExitCode.OK and "Deleted" in result.output
        mock_sdk.artifact_manager.delete_folder.assert_awaited_once_with("f1")

    def test_delete_folder_api_error_exits_3(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.delete_folder.side_effect = UnexpectedStatus(404, b"no such folder")
        result = runner.invoke(app, ["artifact-manager", "delete-folder", "f1"])
        assert result.exit_code == ExitCode.API_ERROR


class TestSettings:
    def test_shows_both_defaults_without_writing(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.get_enricher_settings.return_value = {
            "artifact_tlp": "GREEN",
            "inventory_tlp": "AMBER",
        }
        result = runner.invoke(app, ["artifact-manager", "settings"])
        assert result.exit_code == ExitCode.OK
        assert "GREEN" in result.output and "AMBER" in result.output
        mock_sdk.artifact_manager.get_enricher_settings.assert_awaited_once_with()
        mock_sdk.artifact_manager.set_enricher_settings.assert_not_awaited()

    def test_sets_only_the_marking_it_was_given(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.set_enricher_settings.return_value = {
            "artifact_tlp": "RED",
            "inventory_tlp": "AMBER",
        }
        result = runner.invoke(app, ["artifact-manager", "settings", "--artifact-tlp", "red"])
        assert result.exit_code == ExitCode.OK and "RED" in result.output
        # lowercase input is matched case-insensitively and handed on canonical UPPERCASE
        mock_sdk.artifact_manager.set_enricher_settings.assert_awaited_once_with(artifact_tlp="RED")
        mock_sdk.artifact_manager.get_enricher_settings.assert_not_awaited()

    def test_invalid_marking_exits_64_before_any_call(self, runner, authed, mock_sdk) -> None:
        result = runner.invoke(app, ["artifact-manager", "settings", "--inventory-tlp", "PURPLE"])
        assert result.exit_code == ExitCode.BAD_INPUT
        mock_sdk.artifact_manager.set_enricher_settings.assert_not_awaited()

    def test_api_error_exits_3(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.get_enricher_settings.side_effect = UnexpectedStatus(503, b"nope")
        result = runner.invoke(app, ["artifact-manager", "settings"])
        assert result.exit_code == ExitCode.API_ERROR


class TestAuth:
    def test_missing_credentials_exits_2(self, runner, clean_env, mock_sdk) -> None:
        result = runner.invoke(app, ["artifact-manager", "list"])
        assert result.exit_code == ExitCode.MISSING_CREDENTIALS
        mock_sdk.artifact_manager.list_artifacts.assert_not_awaited()


class TestUpdate:
    def test_rename_and_star(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.update_artifact.return_value = {"id": "a1", "name": "Renamed"}
        result = runner.invoke(app, ["artifact-manager", "update", "a1", "--name", "Renamed", "--favorite"])
        assert result.exit_code == ExitCode.OK
        assert "Updated" in result.output
        mock_sdk.artifact_manager.update_artifact.assert_awaited_once_with("a1", name="Renamed", favorite=True)

    def test_move_to_root(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.update_artifact.return_value = {"id": "a1", "name": "x"}
        result = runner.invoke(app, ["artifact-manager", "update", "a1", "--root"])
        assert result.exit_code == ExitCode.OK
        mock_sdk.artifact_manager.update_artifact.assert_awaited_once_with("a1", folder_id=None)

    def test_folder_and_root_conflict_exits_64(self, runner, authed, mock_sdk) -> None:
        result = runner.invoke(app, ["artifact-manager", "update", "a1", "--folder", "f1", "--root"])
        assert result.exit_code == ExitCode.BAD_INPUT
        mock_sdk.artifact_manager.update_artifact.assert_not_awaited()

    def test_nothing_to_update_exits_64(self, runner, authed, mock_sdk) -> None:
        result = runner.invoke(app, ["artifact-manager", "update", "a1"])
        assert result.exit_code == ExitCode.BAD_INPUT
        mock_sdk.artifact_manager.update_artifact.assert_not_awaited()


class TestBulkMove:
    def test_move_to_folder(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.move_to_folder.return_value = 2
        result = runner.invoke(app, ["artifact-manager", "move", "a1", "a2", "--folder", "f1"])
        assert result.exit_code == ExitCode.OK
        assert "Moved 2" in result.output
        mock_sdk.artifact_manager.move_to_folder.assert_awaited_once_with(["a1", "a2"], "f1")

    def test_move_to_root(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.move_to_folder.return_value = 1
        result = runner.invoke(app, ["artifact-manager", "move", "a1", "--root"])
        assert result.exit_code == ExitCode.OK
        mock_sdk.artifact_manager.move_to_folder.assert_awaited_once_with(["a1"], None)

    def test_requires_exactly_one_destination(self, runner, authed, mock_sdk) -> None:
        # Neither --folder nor --root.
        assert runner.invoke(app, ["artifact-manager", "move", "a1"]).exit_code == ExitCode.BAD_INPUT
        # Both at once.
        assert (
            runner.invoke(app, ["artifact-manager", "move", "a1", "--folder", "f1", "--root"]).exit_code
            == ExitCode.BAD_INPUT
        )
        mock_sdk.artifact_manager.move_to_folder.assert_not_awaited()


class TestBulkFavorite:
    def test_favorite_on(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.bulk_set_favorite.return_value = 2
        result = runner.invoke(app, ["artifact-manager", "favorite", "a1", "a2", "--on"])
        assert result.exit_code == ExitCode.OK
        assert "Starred 2" in result.output
        mock_sdk.artifact_manager.bulk_set_favorite.assert_awaited_once_with(["a1", "a2"], True)

    def test_favorite_default_is_on(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.bulk_set_favorite.return_value = 1
        result = runner.invoke(app, ["artifact-manager", "favorite", "a1"])
        assert result.exit_code == ExitCode.OK
        mock_sdk.artifact_manager.bulk_set_favorite.assert_awaited_once_with(["a1"], True)

    def test_favorite_off(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.bulk_set_favorite.return_value = 1
        result = runner.invoke(app, ["artifact-manager", "favorite", "a1", "--off"])
        assert result.exit_code == ExitCode.OK
        assert "Unstarred 1" in result.output
        mock_sdk.artifact_manager.bulk_set_favorite.assert_awaited_once_with(["a1"], False)


class TestCopy:
    def test_copies(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.copy_artifact.return_value = "copy-1"
        result = runner.invoke(app, ["artifact-manager", "copy", "a1"])
        assert result.exit_code == ExitCode.OK
        assert "copy-1" in result.output
        mock_sdk.artifact_manager.copy_artifact.assert_awaited_once_with("a1")


class TestBundleDownloads:
    def test_download_folder_writes_zip(self, runner, authed, mock_sdk, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        mock_sdk.artifact_manager.download_folder.return_value = b"PK\x03\x04folder"
        result = runner.invoke(app, ["artifact-manager", "download-folder", "f1"])
        assert result.exit_code == ExitCode.OK
        assert (tmp_path / "f1-folder.zip").read_bytes() == b"PK\x03\x04folder"
        mock_sdk.artifact_manager.download_folder.assert_awaited_once_with("f1", tlp=None)

    def test_download_folder_invalid_output_dir_fails_before_api(self, runner, authed, mock_sdk, tmp_path) -> None:
        """An explicit ``-o`` into a missing dir exits 64 before the API call."""
        result = runner.invoke(
            app, ["artifact-manager", "download-folder", "f1", "-o", str(tmp_path / "nope" / "f.zip")]
        )
        assert result.exit_code == ExitCode.BAD_INPUT
        mock_sdk.artifact_manager.download_folder.assert_not_awaited()

    def test_download_bundle_writes_zip(self, runner, authed, mock_sdk, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        mock_sdk.artifact_manager.download_bundle.return_value = b"PK\x03\x04bundle"
        result = runner.invoke(app, ["artifact-manager", "download-bundle", "a1", "a2", "-o", "out.zip"])
        assert result.exit_code == ExitCode.OK
        assert (tmp_path / "out.zip").read_bytes() == b"PK\x03\x04bundle"
        mock_sdk.artifact_manager.download_bundle.assert_awaited_once_with(["a1", "a2"], tlp=None)

    def test_download_bundle_invalid_output_dir_fails_before_api(self, runner, authed, mock_sdk, tmp_path) -> None:
        """An explicit ``-o`` into a missing dir exits 64 before the API call."""
        result = runner.invoke(
            app, ["artifact-manager", "download-bundle", "a1", "a2", "-o", str(tmp_path / "nope" / "f.zip")]
        )
        assert result.exit_code == ExitCode.BAD_INPUT
        mock_sdk.artifact_manager.download_bundle.assert_not_awaited()


class TestRating:
    def test_get_rating(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.get_rating.return_value = {"rating": "up", "counts": {"up": 3, "down": 1}}
        result = runner.invoke(app, ["artifact-manager", "rating", "s1"])
        assert result.exit_code == ExitCode.OK
        assert "up" in result.output
        mock_sdk.artifact_manager.get_rating.assert_awaited_once_with("s1")
        mock_sdk.artifact_manager.set_rating.assert_not_awaited()

    def test_set_rating_down(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.set_rating.return_value = {"rating": "down", "counts": {"up": 0, "down": 1}}
        result = runner.invoke(app, ["artifact-manager", "rating", "s1", "--set", "down"])
        assert result.exit_code == ExitCode.OK
        mock_sdk.artifact_manager.set_rating.assert_awaited_once_with("s1", "down")

    def test_clear_rating_passes_none(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.set_rating.return_value = {"rating": None, "counts": {"up": 0, "down": 0}}
        result = runner.invoke(app, ["artifact-manager", "rating", "s1", "--set", "clear"])
        assert result.exit_code == ExitCode.OK
        mock_sdk.artifact_manager.set_rating.assert_awaited_once_with("s1", None)


MARKUP = "[red]x[/red]"


class TestRichMarkupEscaping:
    """``rating`` renders a server-supplied scalar into a markup-enabled ``Console``.

    ``_render_rating`` interpolates ``payload['rating']`` directly, so an unescaped
    value forges styled output and a malformed tag raises ``MarkupError`` inside a
    command that should have exited 0.

    The CI rule ``crimson-crawler.rich-unescaped-untrusted-markup`` covers this file's
    path, but ``rating`` is not in its field-name alternation, so these tests are the
    only guard on this site — see the rule's own note in
    ``.gitlab/security/project-rules.yml``.
    """

    def test_rating_renders_verbatim(self, runner, authed, mock_sdk) -> None:
        mock_sdk.artifact_manager.get_rating.return_value = {"rating": MARKUP, "counts": {"up": 1, "down": 0}}
        result = runner.invoke(app, ["artifact-manager", "rating", "s1"])
        assert result.exit_code == ExitCode.OK, result.output
        assert MARKUP in result.output

    def test_malformed_rating_does_not_crash(self, runner, authed, mock_sdk) -> None:
        """An unbalanced closing tag would raise MarkupError -> exit 1 if interpreted."""
        mock_sdk.artifact_manager.get_rating.return_value = {"rating": "[/]", "counts": {}}
        result = runner.invoke(app, ["artifact-manager", "rating", "s1"])
        assert result.exit_code == ExitCode.OK, result.output
        assert "[/]" in result.output


class TestTlpOption:
    """The #374 ``--tlp`` marking on every download command: case-insensitive input normalised to the
    canonical uppercase value, routed to the SDK, and an invalid value is a usage error (exit 64)
    before any API call."""

    _EXPORT = {"content": "{}", "bytes": b"{}", "filename": "stix.json", "content_type": "application/json"}

    def test_help_lists_the_five_canonical_uppercase_choices(self, runner) -> None:
        # A wide terminal: Rich folds the metavar mid-word at 80 columns, interleaving it with the help column.
        result = runner.invoke(app, ["artifact-manager", "export", "--help"], env={"COLUMNS": "200"})
        assert result.exit_code == ExitCode.OK
        assert "[CLEAR|GREEN|AMBER|AMBER+STRICT|RED]" in result.output

    def test_export_normalises_lowercase_to_canonical(self, runner, authed, mock_sdk, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        mock_sdk.artifact_manager.get_export.return_value = self._EXPORT
        result = runner.invoke(app, ["artifact-manager", "export", "s1", "stix", "--tlp", "amber+strict"])
        assert result.exit_code == ExitCode.OK
        mock_sdk.artifact_manager.get_export.assert_awaited_once_with("s1", "stix", tlp="AMBER+STRICT")

    @pytest.mark.parametrize(
        ("command", "args", "method", "expected_args", "expected_kwargs"),
        [
            ("export-all", ["s1"], "download_all_exports", ("s1",), {"tlp": "GREEN"}),
            ("download-folder", ["f1"], "download_folder", ("f1",), {"tlp": "CLEAR"}),
            ("download-bundle", ["a1", "a2"], "download_bundle", (["a1", "a2"],), {"tlp": "RED"}),
        ],
    )
    def test_each_download_command_forwards_tlp(
        self, runner, authed, mock_sdk, tmp_path, monkeypatch, command, args, method, expected_args, expected_kwargs
    ) -> None:
        monkeypatch.chdir(tmp_path)
        getattr(mock_sdk.artifact_manager, method).return_value = b"PK\x03\x04zip"
        tlp = expected_kwargs["tlp"]
        result = runner.invoke(app, ["artifact-manager", command, *args, "--tlp", tlp.lower()])
        assert result.exit_code == ExitCode.OK
        getattr(mock_sdk.artifact_manager, method).assert_awaited_once_with(*expected_args, **expected_kwargs)

    def test_invalid_tlp_is_a_usage_error_before_the_api(self, runner, authed, mock_sdk) -> None:
        result = runner.invoke(app, ["artifact-manager", "export", "s1", "stix", "--tlp", "WHITE"])
        # The CLI maps every Click usage error to BAD_INPUT (64), not Click's 2 — exit 2 is this
        # CLI's "missing credentials" (see exceptions.ExitCode + the README exit-code table).
        assert result.exit_code == ExitCode.BAD_INPUT
        # The usage error lists the canonical UPPERCASE spellings, not casefolded ones.
        # Flatten Rich's panel borders/line wrap before matching the list.
        assert "'CLEAR', 'GREEN', 'AMBER', 'AMBER+STRICT', 'RED'" in " ".join(result.output.replace("│", " ").split())
        mock_sdk.artifact_manager.get_export.assert_not_awaited()

    def test_omitted_tlp_passes_none(self, runner, authed, mock_sdk, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        mock_sdk.artifact_manager.get_export.return_value = self._EXPORT
        runner.invoke(app, ["artifact-manager", "export", "s1", "stix"])
        mock_sdk.artifact_manager.get_export.assert_awaited_once_with("s1", "stix", tlp=None)

    def test_list_rejects_invalid_tlp(self, runner, authed, mock_sdk) -> None:
        result = runner.invoke(app, ["artifact-manager", "list", "--tlp", "WHITE"])
        assert result.exit_code == ExitCode.BAD_INPUT
        mock_sdk.artifact_manager.list_artifacts.assert_not_awaited()

    def test_update_rejects_invalid_tlp(self, runner, authed, mock_sdk) -> None:
        result = runner.invoke(app, ["artifact-manager", "update", "a1", "--tlp", "WHITE"])
        assert result.exit_code == ExitCode.BAD_INPUT
        mock_sdk.artifact_manager.update_artifact.assert_not_awaited()
