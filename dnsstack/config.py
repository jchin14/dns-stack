"""YAML configuration with ${ENV} / ${ENV:-default} interpolation."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


class ConfigError(Exception):
    """Raised when the configuration file is missing or invalid."""


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PiholeConfig(_Base):
    name: str = "pihole"
    url: str
    password: str
    verify_tls: bool = True
    ssh_host: str | None = None


class AdguardConfig(_Base):
    name: str = "adguard"
    url: str
    username: str
    password: str
    verify_tls: bool = True


class NextdnsConfig(_Base):
    name: str = "nextdns"
    profile_id: str
    api_key: str
    linked_ip_url: str | None = None


class ListsConfig(_Base):
    allowlist: list[Path] = Field(
        default_factory=lambda: [Path("lists/allowlist.txt"), Path("lists/cashback-allowlist.txt")]
    )
    denylist: list[Path] = Field(default_factory=lambda: [Path("lists/denylist.txt")])
    prune: bool = False


class LokiConfig(_Base):
    url: str = "http://loki:3100"
    tenant: str | None = None


class CollectorConfig(_Base):
    poll_interval_s: float = 15
    batch_size: int = 500
    state_path: str = "/data/state.json"
    health_port: int = 8080
    lookback_minutes: int = 10


class AppConfig(_Base):
    pihole: PiholeConfig | None = None
    adguard: AdguardConfig | None = None
    nextdns: NextdnsConfig | None = None
    lists: ListsConfig = Field(default_factory=ListsConfig)
    loki: LokiConfig = Field(default_factory=LokiConfig)
    collector: CollectorConfig = Field(default_factory=CollectorConfig)


def _interpolate_str(value: str) -> str:
    def repl(m: re.Match[str]) -> str:
        var, default = m.group(1), m.group(2)
        env = os.environ.get(var)
        if env is not None and (env != "" or default is None):
            return env
        if default is not None:
            return default
        raise ConfigError(f"environment variable {var} is not set")

    return _ENV_RE.sub(repl, value)


def interpolate(obj: Any) -> Any:
    """Recursively replace ${VAR} / ${VAR:-default} in all string values."""
    if isinstance(obj, str):
        return _interpolate_str(obj)
    if isinstance(obj, dict):
        return {k: interpolate(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [interpolate(v) for v in obj]
    return obj


def load_config(path: str | Path) -> AppConfig:
    """Load and validate the YAML config. Raises ConfigError on any problem.

    Relative list paths are resolved against the current working directory.
    """
    p = Path(path)
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise ConfigError(f"config file not found: {p}") from e
    except (OSError, yaml.YAMLError) as e:
        raise ConfigError(f"cannot read config {p}: {e}") from e
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError(f"config {p} must be a YAML mapping")
    try:
        return AppConfig.model_validate(interpolate(raw))
    except ValidationError as e:
        raise ConfigError(f"invalid config {p}:\n{e}") from e
