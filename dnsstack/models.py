"""Shared data models used across clients, sync, collector and Loki pusher."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class QueryRecord:
    """A single DNS query, normalised across all server types."""

    server: str  # configured server name, e.g. 'pihole' | 'adguard' | 'nextdns'
    ts: datetime  # timezone-aware UTC
    client: str  # ip or name
    domain: str
    qtype: str  # 'A', 'AAAA', ...
    status: str  # 'blocked' | 'allowed' | 'cached' | 'other'
    reason: str  # free text, e.g. list/rule name or upstream
    upstream: str | None
    response_ms: float | None
    id: str  # stable unique id within the server (used for dedupe)


@dataclass
class ServerHealth:
    server: str
    ok: bool
    detail: str
    version: str | None = None


@dataclass
class ListState:
    """Exact domains, lowercase, no trailing dot."""

    allow: set[str] = field(default_factory=set)
    deny: set[str] = field(default_factory=set)
