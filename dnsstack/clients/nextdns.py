"""NextDNS API client (api.nextdns.io, X-Api-Key)."""

from __future__ import annotations

import contextlib
import hashlib
import logging
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx

from dnsstack.clients import ClientError
from dnsstack.config import NextdnsConfig
from dnsstack.models import ListState, QueryRecord, ServerHealth

log = logging.getLogger(__name__)

API = "https://api.nextdns.io"
PAGE_SIZE = 1000
MAX_PAGES = 20

_STATUS = {"blocked": "blocked", "allowed": "allowed", "default": "allowed"}


def parse_time(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


class NextdnsClient:
    def __init__(
        self, cfg: NextdnsConfig, http: httpx.Client | None = None, base_url: str = API
    ) -> None:
        self.cfg = cfg
        self.name = cfg.name
        self._owns_http = http is None
        self.http = http or httpx.Client(timeout=20.0)
        self.base = f"{base_url.rstrip('/')}/profiles/{cfg.profile_id}"
        self._headers = {"X-Api-Key": cfg.api_key}

    def _request(self, method: str, path: str, **kw: Any) -> httpx.Response:
        try:
            r = self.http.request(method, f"{self.base}{path}", headers=self._headers, **kw)
        except httpx.HTTPError as e:
            raise ClientError(f"{self.name}: {method} {path or '/'} failed: {e}") from e
        if r.status_code in (401, 403):
            raise ClientError(f"{self.name}: authentication failed (HTTP {r.status_code})")
        if r.status_code >= 400:
            raise ClientError(
                f"{self.name}: {method} {path or '/'} -> HTTP {r.status_code}: {r.text[:200]}"
            )
        return r

    def close(self) -> None:
        if self._owns_http:
            self.http.close()

    def health(self) -> ServerHealth:
        try:
            data = self._request("GET", "").json().get("data") or {}
        except ClientError as e:
            return ServerHealth(self.name, False, str(e), None)
        return ServerHealth(
            self.name, True, f"profile {data.get('name') or self.cfg.profile_id}", None
        )

    # --------------------------------------------------------------- queries
    def _to_record(self, e: dict[str, Any]) -> QueryRecord:
        ts = parse_time(e["timestamp"])
        device = e.get("device") or {}
        client = device.get("name") or e.get("clientIp") or ""
        domain = (e.get("domain") or "").rstrip(".").lower()
        qtype = e.get("type") or ""
        raw_status = (e.get("status") or "").lower()
        reasons = [r.get("name") or r.get("id") for r in (e.get("reasons") or [])]
        reason = ", ".join(r for r in reasons if r) or raw_status
        raw_id = f"{e['timestamp']}|{e.get('clientIp', '')}|{domain}|{qtype}|{device.get('id', '')}"
        return QueryRecord(
            server=self.name,
            ts=ts,
            client=client,
            domain=domain,
            qtype=qtype,
            status=_STATUS.get(raw_status, "other"),
            reason=reason,
            upstream=None,
            response_ms=None,
            id=hashlib.sha1(raw_id.encode()).hexdigest()[:16],
        )

    def fetch_queries(
        self, since: datetime, cursor: str | None
    ) -> tuple[list[QueryRecord], str | None]:
        """Fetch logs ascending from max(since, cursor-time).

        Our cursor is the ISO timestamp of the newest record returned (NextDNS
        pagination cursors are only used internally within one call).
        """
        start = since
        if cursor:
            with contextlib.suppress(ValueError):
                start = max(since, parse_time(cursor))
        params: dict[str, Any] = {
            "from": start.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "sort": "asc",
            "limit": PAGE_SIZE,
            "raw": 1,
        }
        out: dict[str, QueryRecord] = {}
        for _ in range(MAX_PAGES):
            body = self._request("GET", "/logs", params=params).json()
            for e in body.get("data") or []:
                try:
                    rec = self._to_record(e)
                except (KeyError, ValueError) as err:
                    log.debug("%s: skipping malformed log: %s", self.name, err)
                    continue
                if rec.ts >= start:
                    out[rec.id] = rec
            nxt = ((body.get("meta") or {}).get("pagination") or {}).get("cursor")
            if not nxt or nxt == params.get("cursor"):
                break
            params["cursor"] = nxt
        records = sorted(out.values(), key=lambda r: r.ts)
        return records, (records[-1].ts.isoformat() if records else cursor)

    # ----------------------------------------------------------------- lists
    def _get(self, kind: str) -> set[str]:
        data = self._request("GET", f"/{kind}").json().get("data") or []
        return {d["id"].rstrip(".").lower() for d in data if d.get("id")}

    def get_lists(self) -> ListState:
        return ListState(allow=self._get("allowlist"), deny=self._get("denylist"))

    def _add(self, kind: str, domains: set[str]) -> None:
        for d in sorted(domains):
            self._request("POST", f"/{kind}", json={"id": d, "active": True})

    def _remove(self, kind: str, domains: set[str]) -> None:
        for d in sorted(domains):
            self._request("DELETE", f"/{kind}/{quote(d, safe='')}")

    def add_allow(self, domains: set[str]) -> None:
        self._add("allowlist", domains)

    def remove_allow(self, domains: set[str]) -> None:
        self._remove("allowlist", domains)

    def add_deny(self, domains: set[str]) -> None:
        self._add("denylist", domains)

    def remove_deny(self, domains: set[str]) -> None:
        self._remove("denylist", domains)

    def update(self, dry_run: bool) -> str:
        return "cloud service, nothing to update"
