"""Unit tests for :mod:`crimson_crawler_cli.auth`."""

from __future__ import annotations

from pathlib import Path

import pytest

from crimson_crawler_cli import auth, config
from crimson_crawler_cli.exceptions import MissingCredentialsError


def test_env_var_wins(monkeypatch: pytest.MonkeyPatch, clean_env: Path) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "env-key-12345678")

    resolved = auth.resolve_auth()

    assert resolved.source == "env"
    assert resolved.source_detail == "CRIMSON_CRAWLER_API_KEY"
    assert resolved.key == "env-key-12345678"
    assert resolved.key_tail == "5678"


def test_config_file_used_when_env_missing(secure_config_file: Path) -> None:
    secure_config_file.write_text('api_key = "cfg-key-abcdefgh"\n', encoding="utf-8")

    resolved = auth.resolve_auth()

    assert resolved.source == "config"
    assert resolved.source_detail == str(secure_config_file)
    assert resolved.key == "cfg-key-abcdefgh"
    assert resolved.key_tail == "efgh"


def test_env_overrides_config(monkeypatch: pytest.MonkeyPatch, secure_config_file: Path) -> None:
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "env-wins")
    secure_config_file.write_text('api_key = "cfg-loses"\n', encoding="utf-8")

    resolved = auth.resolve_auth()

    assert resolved.source == "env"
    assert resolved.key == "env-wins"


def test_missing_everywhere_raises(clean_env: Path) -> None:
    with pytest.raises(MissingCredentialsError) as exc_info:
        auth.resolve_auth()

    message = str(exc_info.value)
    assert "CRIMSON_CRAWLER_API_KEY" in message
    assert str(clean_env) in message


def test_config_file_without_api_key_field_raises(secure_config_file: Path) -> None:
    secure_config_file.write_text("other_field = 42\n", encoding="utf-8")

    with pytest.raises(MissingCredentialsError):
        auth.resolve_auth()


@pytest.mark.skipif(config.os.name != "posix", reason="POSIX ownership and mode checks")
@pytest.mark.parametrize("mode", [0o640, 0o604, 0o601])
def test_config_file_rejects_group_or_other_permissions(secure_config_file: Path, mode: int) -> None:
    secure_config_file.write_text('api_key = "cfg-key-abcdefgh"\n', encoding="utf-8")
    secure_config_file.chmod(mode)

    with pytest.raises(PermissionError) as exc_info:
        auth.resolve_auth()

    message = str(exc_info.value)
    assert str(secure_config_file) in message
    assert "chmod 600" in message


@pytest.mark.skipif(config.os.name != "posix", reason="POSIX ownership and mode checks")
def test_config_file_rejects_different_owner(monkeypatch: pytest.MonkeyPatch, secure_config_file: Path) -> None:
    secure_config_file.write_text('api_key = "cfg-key-abcdefgh"\n', encoding="utf-8")
    monkeypatch.setattr(config.os, "getuid", lambda: secure_config_file.stat().st_uid + 1)

    with pytest.raises(PermissionError) as exc_info:
        auth.resolve_auth()

    message = str(exc_info.value)
    assert str(secure_config_file) in message
    assert "Change its owner" in message


def test_masked_key_hides_body() -> None:
    resolved = auth.ResolvedAuth(
        source="env",
        key="abcdefghijklmnop",
        source_detail="CRIMSON_CRAWLER_API_KEY",
    )

    masked = resolved.masked_key

    assert masked.endswith("mnop")
    assert "abcdef" not in masked
    assert masked.count("•") == len("abcdefghijklmnop") - 4


def test_resolved_auth_repr_omits_key() -> None:
    resolved = auth.ResolvedAuth(
        source="env",
        key="secret-key-material",
        source_detail="CRIMSON_CRAWLER_API_KEY",
    )

    assert "secret-key-material" not in repr(resolved)
