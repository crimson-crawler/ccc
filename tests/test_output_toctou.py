"""Regression tests: every ``--output`` writer installs its file atomically.

``ensure_writable_output`` refuses a symlink destination, but it is only a
*preflight* — it runs before the work (usually a billable API call) that
produces the content. A destination that passes the check and is then replaced
by a symlink before the write is the TOCTOU window: ``Path.write_text`` follows
the link and truncates whatever it points at. ``paths.write_atomic`` closes the
window by staging in the destination directory and installing with
``os.replace``, which replaces the link itself.

Each test here monkeypatches ``paths.ensure_writable_output`` so it runs the
real validation and *then* plants the symlink — the exact interleaving an
attacker races for, made deterministic.

**All twelve writers are covered, in three groups, because they do not share one
outcome** — asserting "replaced, not followed" everywhere would have been wrong:

1. *Overwrite writers* (``write_atomic`` default) install over the link with
   ``os.replace``, so the link is replaced and its target survives untouched.
2. *New-only writers* (``write_atomic(overwrite=False)``) sit behind a caller-side
   ``exists()`` recheck (``artifact_manager._ensure_new_output`` and the inline
   check in ``inventory_manager.export``) that runs *after* the preflight. A link
   pointing at a real file therefore fails that recheck: clean ``BadInputError`` →
   exit 64, before any billable call. That is the behavior under race, so that is
   what these assert.
3. A *dangling* link defeats the recheck (``Path.exists()`` is False through a
   broken link) and does reach the write, where ``O_CREAT|O_EXCL|O_NOFOLLOW``
   refuses it. That path is asserted once here end-to-end and directly at the
   helper in ``test_paths.py``.

Treat a new writer as owing a case in the group matching its ``overwrite`` mode.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from crimson_crawler_cli import paths
from crimson_crawler_cli.cli import app
from crimson_crawler_cli.exceptions import ExitCode

SENTINEL_TEXT = "do not overwrite"


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def authed(monkeypatch: pytest.MonkeyPatch, clean_env: Path) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key-1234")


def _race_preflight(monkeypatch: pytest.MonkeyPatch, destination: Path, sentinel: Path) -> None:
    """Plant ``destination`` -> ``sentinel`` the instant the real preflight passes."""
    real_preflight = paths.ensure_writable_output

    def _preflight_then_plant(path: Path) -> None:
        real_preflight(path)
        # Idempotent: the new-only writers run the preflight twice (once before the
        # API call, once on the resolved target), and symlink_to would raise the
        # second time.
        if path == destination and not destination.is_symlink():
            destination.symlink_to(sentinel)

    monkeypatch.setattr(paths, "ensure_writable_output", _preflight_then_plant)


def _assert_link_replaced_not_followed(destination: Path, sentinel: Path) -> None:
    assert not destination.is_symlink(), "destination is still a symlink — the write followed it"
    assert sentinel.read_text(encoding="utf-8") == SENTINEL_TEXT, "the symlink target was truncated"


@pytest.fixture()
def sentinel(tmp_path: Path) -> Path:
    victim = tmp_path / "sentinel.txt"
    victim.write_text(SENTINEL_TEXT, encoding="utf-8")
    return victim


def test_crawl_project_output_replaces_planted_symlink(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, sentinel: Path
) -> None:
    """``ccc crawl project --output`` makes no API call, but still must not follow a link."""
    project = tmp_path / "project"
    project.mkdir()
    (project / ".python-version").write_text("3.12\n", encoding="utf-8")
    destination = tmp_path / "inventory.json"
    _race_preflight(monkeypatch, destination, sentinel)

    result = runner.invoke(app, ["crawl", "project", str(project), "-o", str(destination)])

    assert result.exit_code == ExitCode.OK, result.stdout + result.stderr
    _assert_link_replaced_not_followed(destination, sentinel)
    assert json.loads(destination.read_text(encoding="utf-8"))["bomFormat"] == "CycloneDX"


def test_reports_export_output_replaces_planted_symlink(
    runner: CliRunner, authed: None, mock_sdk, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, sentinel: Path
) -> None:
    mock_sdk.ai_reports.export_report.return_value = {"content": "# Report\n", "filename": "r1.md"}
    destination = tmp_path / "report.md"
    _race_preflight(monkeypatch, destination, sentinel)

    result = runner.invoke(app, ["reports", "export", "r1", "-f", "md", "-o", str(destination)])

    assert result.exit_code == ExitCode.OK, result.stdout + result.stderr
    _assert_link_replaced_not_followed(destination, sentinel)
    assert destination.read_text(encoding="utf-8") == "# Report\n"


def test_enrich_batch_output_replaces_planted_symlink(
    runner: CliRunner, authed: None, mock_sdk, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, sentinel: Path
) -> None:
    payload = {"results": [{"type": "cve", "cve_id": "CVE-2021-44228"}]}
    # The command calls ``response.to_dict()`` synchronously, so the awaited
    # result must be a MagicMock — an AsyncMock child would hand back a coroutine.
    response = MagicMock()
    response.to_dict.return_value = payload
    mock_sdk.enrich_batch.return_value = response
    destination = tmp_path / "batch.json"
    _race_preflight(monkeypatch, destination, sentinel)

    result = runner.invoke(
        app,
        ["enrich", "batch", "--item", '{"type":"cve","cve_id":"CVE-2021-44228"}', "-o", str(destination)],
    )

    assert result.exit_code == ExitCode.OK, result.stdout + result.stderr
    _assert_link_replaced_not_followed(destination, sentinel)
    assert json.loads(destination.read_text(encoding="utf-8")) == payload


def test_artifact_enrich_output_replaces_planted_symlink(
    runner: CliRunner, authed: None, mock_sdk, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, sentinel: Path
) -> None:
    payload = {"enrichment_id": "abc123", "report": {"summary": {}, "errors": []}}
    mock_sdk.enricher.enrich.return_value = payload
    destination = tmp_path / "report.json"
    _race_preflight(monkeypatch, destination, sentinel)

    result = runner.invoke(app, ["artifact-enrich", "--text", "hi", "--output", str(destination)])

    assert result.exit_code == ExitCode.OK, result.stdout + result.stderr
    _assert_link_replaced_not_followed(destination, sentinel)
    assert json.loads(destination.read_text(encoding="utf-8")) == payload


# -- group 1: overwrite writers (install over the link) --------------------- #

_PARSE = {"format": "nmap", "items": [{"product": "Apache httpd"}], "count": 1}
_ENRICH = {
    "enrichment_id": "e" * 32,
    "report": {
        "summary": {"asset_count": 1, "total_cves": 1, "total_kev": 0, "max_weaponization": 50},
        "assets": [{"product": "Apache httpd", "status": "ok", "cve_count": 1, "top_cves": []}],
    },
}


def test_ingest_output_replaces_planted_symlink(
    runner: CliRunner, authed: None, mock_sdk, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, sentinel: Path
) -> None:
    mock_sdk.inventory_manager.parse_scan.return_value = _PARSE
    mock_sdk.inventory_manager.enrich_items.return_value = _ENRICH
    scan = tmp_path / "scan.xml"
    scan.write_text("<nmaprun/>", encoding="utf-8")
    destination = tmp_path / "briefing.md"
    _race_preflight(monkeypatch, destination, sentinel)

    result = runner.invoke(app, ["ingest", "nmap", str(scan), "-o", str(destination)])

    assert result.exit_code == ExitCode.OK, result.stdout + result.stderr
    _assert_link_replaced_not_followed(destination, sentinel)
    assert "Apache httpd" in destination.read_text(encoding="utf-8")


def test_artifact_manager_get_output_replaces_planted_symlink(
    runner: CliRunner, authed: None, mock_sdk, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, sentinel: Path
) -> None:
    mock_sdk.artifact_manager.get_artifact_raw.return_value = {
        "id": "a1",
        "kind": "input",
        "name": "notes.txt",
        "format": "paste",
        "mime": "text/plain",
        "content": "artifact body\n",
    }
    destination = tmp_path / "artifact.txt"
    _race_preflight(monkeypatch, destination, sentinel)

    result = runner.invoke(app, ["artifact-manager", "get", "a1", "-o", str(destination)])

    assert result.exit_code == ExitCode.OK, result.stdout + result.stderr
    _assert_link_replaced_not_followed(destination, sentinel)
    assert destination.read_text(encoding="utf-8") == "artifact body\n"


# -- group 2: new-only writers (refused by the post-preflight exists() recheck) #

_ZIP = b"PK\x03\x04payload"
_EXPORT = {"filename": "stix.json", "content_type": "application/json", "bytes": b"{}", "content": "{}"}

_NEW_ONLY_WRITERS = [
    (["artifact-manager", "export", "e1", "stix"], "artifact_manager.get_export", _EXPORT),
    (["artifact-manager", "export-all", "e1"], "artifact_manager.download_all_exports", _ZIP),
    (["artifact-manager", "download-folder", "f1"], "artifact_manager.download_folder", _ZIP),
    (["artifact-manager", "download-bundle", "a1", "a2"], "artifact_manager.download_bundle", _ZIP),
    (["inventory-manager", "export", "p1", "--format", "workbook"], "inventory_manager.export_inventory", _ZIP),
    (
        ["inventory-manager", "export", "p1", "--format", "json"],
        "inventory_manager.export_inventory",
        '{"inventory": []}',
    ),
]


def _sdk_attr(mock_sdk, dotted: str):
    target = mock_sdk
    for part in dotted.split("."):
        target = getattr(target, part)
    return target


@pytest.mark.parametrize(
    ("args", "sdk_method", "return_value"),
    _NEW_ONLY_WRITERS,
    ids=[
        "am-export",
        "am-export-all",
        "am-download-folder",
        "am-download-bundle",
        "inv-export-xlsx",
        "inv-export-json",
    ],
)
def test_new_only_writer_refuses_planted_symlink(
    runner: CliRunner,
    authed: None,
    mock_sdk,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    sentinel: Path,
    args: list[str],
    sdk_method: str,
    return_value: object,
) -> None:
    """A link planted on the preflight fails the exists() recheck — before the API call."""
    method = _sdk_attr(mock_sdk, sdk_method)
    method.return_value = return_value
    destination = tmp_path / "out.bin"
    _race_preflight(monkeypatch, destination, sentinel)

    result = runner.invoke(app, [*args, "-o", str(destination)])

    assert result.exit_code == ExitCode.BAD_INPUT, result.stdout + result.stderr
    assert destination.is_symlink(), "the link was replaced — a new-only writer must refuse, not install"
    assert sentinel.read_text(encoding="utf-8") == SENTINEL_TEXT, "the symlink target was truncated"
    method.assert_not_awaited()


# -- group 3: a dangling link defeats the recheck and reaches the write ------ #


def test_new_only_writer_refuses_dangling_symlink_at_the_write(
    runner: CliRunner, authed: None, mock_sdk, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``Path.exists()`` is False through a broken link, so this one gets past the recheck.

    ``write_atomic(overwrite=False)`` is the backstop: ``O_CREAT|O_EXCL|O_NOFOLLOW``
    refuses the link rather than creating the file it points at. The victim path must
    never come into existence.

    The refusal surfaces as ``FileExistsError`` through ``@handle_errors``' top-level
    net, so the exit code is the generic 1 and the message reads "internal error"
    rather than a tidy 64. Secure, but blunter than the group-2 path.
    """
    mock_sdk.artifact_manager.download_all_exports.return_value = _ZIP
    victim = tmp_path / "not-yet-created.txt"
    destination = tmp_path / "out.zip"
    real_preflight = paths.ensure_writable_output

    def _preflight_then_plant_dangling(path: Path) -> None:
        real_preflight(path)
        if path == destination and not destination.is_symlink():
            destination.symlink_to(victim)  # target does not exist

    monkeypatch.setattr(paths, "ensure_writable_output", _preflight_then_plant_dangling)

    result = runner.invoke(app, ["artifact-manager", "export-all", "e1", "-o", str(destination)])

    assert result.exit_code == ExitCode.GENERIC_ERROR, result.stdout + result.stderr
    assert not victim.exists(), "the write followed the dangling link and created its target"
    assert destination.is_symlink(), "the link was replaced — overwrite=False must never install"
