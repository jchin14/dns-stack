"""Push QueryRecords and ServerHealth to Loki's HTTP push API."""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any

import httpx

from dnsstack.models import QueryRecord, ServerHealth

log = logging.getLogger(__name__)

PUSH_PATH = "/loki/api/v1/push"


class LokiPushError(RuntimeError):
    """Raised when Loki rejects a push or stays unreachable after retries."""


def _ns(ts: datetime) -> int:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    # integer math avoids float precision loss at ns scale
    delta = ts - datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000


def record_line(rec: QueryRecord) -> str:
    return json.dumps(
        {
            "client": rec.client,
            "domain": rec.domain,
            "qtype": rec.qtype,
            "status": rec.status,
            "reason": rec.reason,
            "upstream": rec.upstream,
            "response_ms": rec.response_ms,
            "id": rec.id,
        },
        separators=(",", ":"),
    )


def build_streams(records: Iterable[QueryRecord]) -> list[dict[str, Any]]:
    """Group records into Loki streams keyed by {job, server, status}."""
    groups: dict[tuple[str, str], list[tuple[int, str]]] = defaultdict(list)
    for rec in records:
        groups[(rec.server, rec.status)].append((_ns(rec.ts), record_line(rec)))
    streams = []
    for (server, status), values in sorted(groups.items()):
        values.sort(key=lambda v: v[0])
        streams.append(
            {
                "stream": {"job": "dns", "server": server, "status": status},
                "values": [[str(ts), line] for ts, line in values],
            }
        )
    return streams


def build_health_streams(
    healths: Iterable[ServerHealth], now: datetime | None = None
) -> list[dict[str, Any]]:
    ts = str(_ns(now or datetime.now(UTC)))
    streams = []
    for h in healths:
        line = json.dumps(
            {"ok": h.ok, "detail": h.detail, "version": h.version}, separators=(",", ":")
        )
        streams.append(
            {"stream": {"job": "dns-health", "server": h.server}, "values": [[ts, line]]}
        )
    return streams


class LokiPusher:
    def __init__(
        self,
        url: str,
        tenant: str | None = None,
        http: httpx.Client | None = None,
        *,
        max_tries: int = 5,
        backoff_base_s: float = 0.5,
        backoff_max_s: float = 8.0,
        batch_size: int = 500,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.url = url.rstrip("/") + PUSH_PATH
        self.tenant = tenant
        self._own_http = http is None
        self.http = http or httpx.Client(timeout=15.0)
        self.max_tries = max(1, max_tries)
        self.backoff_base_s = backoff_base_s
        self.backoff_max_s = backoff_max_s
        self.batch_size = max(1, batch_size)
        self._sleep = sleep

    def push(self, records: list[QueryRecord]) -> None:
        """Push records in batches of ``batch_size``. Raises LokiPushError on failure."""
        for i in range(0, len(records), self.batch_size):
            chunk = records[i : i + self.batch_size]
            self._post({"streams": build_streams(chunk)})

    def push_health(self, healths: list[ServerHealth]) -> None:
        if healths:
            self._post({"streams": build_health_streams(healths)})

    def _post(self, payload: dict[str, Any]) -> None:
        if not payload["streams"]:
            return
        headers = {"Content-Type": "application/json"}
        if self.tenant:
            headers["X-Scope-OrgID"] = self.tenant
        body = json.dumps(payload, separators=(",", ":"))
        last_err = ""
        for attempt in range(1, self.max_tries + 1):
            try:
                resp = self.http.post(self.url, content=body, headers=headers)
            except httpx.TransportError as exc:
                last_err = f"connection error: {exc}"
            else:
                if resp.status_code < 300:
                    return
                last_err = f"HTTP {resp.status_code}: {resp.text[:200]}"
                if resp.status_code < 500 and resp.status_code != 429:
                    raise LokiPushError(f"Loki rejected push: {last_err}")
            if attempt < self.max_tries:
                delay = min(self.backoff_max_s, self.backoff_base_s * 2 ** (attempt - 1))
                log.warning("Loki push failed (%s); retry %d in %.1fs", last_err, attempt, delay)
                self._sleep(delay)
        raise LokiPushError(f"Loki push failed after {self.max_tries} tries: {last_err}")

    def close(self) -> None:
        if self._own_http:
            self.http.close()
