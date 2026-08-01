"""Unit tests for the ``paths.ensure_writable_output`` pre-flight helper.

No SDK, no network — pure local path validation. Guards that a bad
``--output`` destination raises :class:`BadInputError` (exit 64) before any
command reaches its API call.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from crimson_crawler_cli.exceptions import BadInputError
from crimson_crawler_cli.paths import ensure_writable_output


def test_existing_writable_parent_passes(tmp_path: Path) -> None:
    """A file under an existing, writable directory validates cleanly."""
    ensure_writable_output(tmp_path / "playbook.md")


def test_bare_filename_passes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A bare filename resolves its parent to '.', which exists + is writable."""
    monkeypatch.chdir(tmp_path)
    ensure_writable_output(Path("playbook.md"))


def test_missing_parent_dir_raises(tmp_path: Path) -> None:
    target = tmp_path / "nope" / "playbook.md"
    with pytest.raises(BadInputError, match="Output directory does not exist"):
        ensure_writable_output(target)


def test_path_is_existing_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(BadInputError, match="is a directory, not a file"):
        ensure_writable_output(tmp_path)


def test_parent_is_a_file_raises(tmp_path: Path) -> None:
    """When the 'directory' on the path is actually a file, fail clearly."""
    a_file = tmp_path / "afile"
    a_file.write_text("x")
    with pytest.raises(BadInputError, match="is not a directory"):
        ensure_writable_output(a_file / "child.md")


def test_non_writable_parent_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    real_access = os.access

    def _fake_access(path: object, mode: int) -> bool:
        if mode == os.W_OK and Path(path) == tmp_path:
            return False
        return real_access(path, mode)

    monkeypatch.setattr(os, "access", _fake_access)
    with pytest.raises(BadInputError, match="is not writable"):
        ensure_writable_output(tmp_path / "playbook.md")


def test_symlink_target_raises(tmp_path: Path) -> None:
    """A symlink destination is refused rather than written through.

    ``Path.write_text`` follows the link and truncates its target, so this
    silently replaced the referenced file's contents and reported success.
    """
    victim = tmp_path / "victim.txt"
    victim.write_text("do not overwrite")
    link = tmp_path / "out.json"
    link.symlink_to(victim)

    with pytest.raises(BadInputError, match="is a symlink"):
        ensure_writable_output(link)
    assert victim.read_text() == "do not overwrite"


def test_broken_symlink_raises(tmp_path: Path) -> None:
    """A dangling link is still a link — refuse before creating its target."""
    link = tmp_path / "dangling.json"
    link.symlink_to(tmp_path / "does-not-exist")
    with pytest.raises(BadInputError, match="is a symlink"):
        ensure_writable_output(link)


def test_symlinked_parent_directory_is_allowed(tmp_path: Path) -> None:
    """Only the destination itself is checked.

    A symlinked *directory* is ordinary (``/tmp`` is one on macOS), and the file
    written inside it is newly created rather than an existing target being
    truncated, so refusing these would break normal use for no gain.
    """
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    linked_dir = tmp_path / "linked"
    linked_dir.symlink_to(real_dir, target_is_directory=True)
    ensure_writable_output(linked_dir / "report.md")
