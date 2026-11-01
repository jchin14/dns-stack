"""DNS server client protocol and factory."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from dnsstack.models import ListState, QueryRecord, ServerHealth

if TYPE_CHECKING:
    from dnsstack.config import AppConfig


class ClientError(Exception):
    """Raised by clients on API/auth/transport failures."""


@runtime_checkable
class DnsServerClient(Protocol):
    name: str

    def health(self) -> ServerHealth: ...

    def fetch_queries(
        self, since: datetime, cursor: str | None
    ) -> tuple[list[QueryRecord], str | None]: ...

    def get_lists(self) -> ListState: ...

    def add_allow(self, domains: set[str]) -> None: ...

    def remove_allow(self, domains: set[str]) -> None: ...

    def add_deny(self, domains: set[str]) -> None: ...

    def remove_deny(self, domains: set[str]) -> None: ...

    def update(self, dry_run: bool) -> str: ...

    def close(self) -> None: ...


def build_clients(cfg: AppConfig) -> list[DnsServerClient]:
    """Instantiate a client for every configured (enabled) server."""
    from dnsstack.clients.adguard import AdguardClient
    from dnsstack.clients.nextdns import NextdnsClient
    from dnsstack.clients.pihole import PiholeClient

    clients: list[DnsServerClient] = []
    if cfg.pihole is not None:
        clients.append(PiholeClient(cfg.pihole))
    if cfg.adguard is not None:
        clients.append(AdguardClient(cfg.adguard))
    if cfg.nextdns is not None:
        clients.append(NextdnsClient(cfg.nextdns))
    return clients


__all__ = ["ClientError", "DnsServerClient", "build_clients"]
