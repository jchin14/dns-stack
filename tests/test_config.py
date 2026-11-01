from __future__ import annotations

from pathlib import Path

import pytest

from dnsstack.config import ConfigError, load_config


def write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(text)
    return p


def test_env_interpolation_and_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PH_PASS", "secret")
    monkeypatch.delenv("AG_USER", raising=False)
    cfg = load_config(
        write(
            tmp_path,
            """
pihole:
  url: http://172.20.1.41
  password: ${PH_PASS}
adguard:
  url: http://ag
  username: ${AG_USER:-admin}
  password: "x-${PH_PASS}-y"
""",
        )
    )
    assert cfg.pihole and cfg.pihole.password == "secret"
    assert cfg.pihole.name == "pihole"
    assert cfg.adguard and cfg.adguard.username == "admin"
    assert cfg.adguard.password == "x-secret-y"
    assert cfg.nextdns is None
    assert cfg.loki.url == "http://loki:3100"
    assert cfg.collector.poll_interval_s == 15
    assert [str(p) for p in cfg.lists.allowlist] == [
        "lists/allowlist.txt",
        "lists/cashback-allowlist.txt",
    ]
    assert cfg.lists.prune is False


def test_missing_env_is_config_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NOPE_NOT_SET", raising=False)
    with pytest.raises(ConfigError, match="NOPE_NOT_SET"):
        load_config(write(tmp_path, "nextdns:\n  profile_id: a\n  api_key: ${NOPE_NOT_SET}\n"))


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(tmp_path / "nope.yaml")


def test_invalid_schema(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, "pihole:\n  url: http://x\n"))  # missing password


def test_empty_file_gives_defaults(tmp_path: Path) -> None:
    cfg = load_config(write(tmp_path, ""))
    assert cfg.pihole is None and cfg.adguard is None and cfg.nextdns is None
