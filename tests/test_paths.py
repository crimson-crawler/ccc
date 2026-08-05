"""Unit tests for safe ``--output`` preflight and writes.

No SDK, no network: these cover early path validation, atomic replacement,
exclusive creation, and restrictive output permissions.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from crimson_crawler_cli.exceptions import BadInputError
from crimson_crawler_cli.paths import ensure_writable_output, write_atomic


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


@pytest.mark.parametrize("data", ["safe text", b"safe bytes"])
def test_atomic_write_replaces_symlink_planted_after_preflight(tmp_path: Path, data: str | bytes) -> None:
    sentinel = tmp_path / "sentinel.txt"
    sentinel.write_text("unchanged", encoding="utf-8")
    destination = tmp_path / "output"

    ensure_writable_output(destination)
    destination.symlink_to(sentinel)
    write_atomic(destination, data)

    assert not destination.is_symlink()
    assert sentinel.read_text(encoding="utf-8") == "unchanged"
    if isinstance(data, str):
        assert destination.read_text(encoding="utf-8") == data
    else:
        assert destination.read_bytes() == data


def test_new_only_write_does_not_truncate_existing_file(tmp_path: Path) -> None:
    destination = tmp_path / "export.zip"
    destination.write_bytes(b"original")

    with pytest.raises(FileExistsError):
        write_atomic(destination, b"replacement", overwrite=False)

    assert destination.read_bytes() == b"original"


def test_new_only_write_uses_restrictive_permissions(tmp_path: Path) -> None:
    destination = tmp_path / "export.zip"
    write_atomic(destination, b"payload", overwrite=False)
    assert destination.stat().st_mode & 0o777 == 0o600
