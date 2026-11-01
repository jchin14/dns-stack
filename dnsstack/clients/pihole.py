"""Pi-hole v6 REST API client (session auth via /api/auth, X-FTL-SID header)."""

from __future__ import annotations

import logging
import subprocess
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx

from dnsstack.clients import ClientError
from dnsstack.config import PiholeConfig
from dnsstack.models import ListState, QueryRecord, ServerHealth

log = logging.getLogger(__name__)

PAGE_SIZE = 1000
MAX_PAGES = 50
COMMENT = "managed by dns-stack"

BLOCKED = {
    "GRAVITY",
    "REGEX",
    "DENYLIST",
    "EXTERNAL_BLOCKED_IP",
    "EXTERNAL_BLOCKED_NULL",
    "EXTERNAL_BLOCKED_NXRA",
    "EXTERNAL_BLOCKED_EDE15",
    "GRAVITY_CNAME",
    "REGEX_CNAME",
    "DENYLIST_CNAME",
    "SPECIAL_DOMAIN",
}
CACHED = {"CACHE", "CACHE_STALE"}
ALLOWED = {"FORWARDED", "RETRIED", "RETRIED_DNSSEC"}


def map_status(status: str | None) -> str:
    s = (status or "").upper()
    if s in BLOCKED:
        return "blocked"
    if s in CACHED:
        return "cached"
    if s in ALLOWED:
        return "allowed"
    return "other"


class PiholeClient:
    def __init__(self, cfg: PiholeConfig, http: httpx.Client | None = None) -> None:
        self.cfg = cfg
        self.name = cfg.name
        self._owns_http = http is None
        self.http = http or httpx.Client(timeout=20.0, verify=cfg.verify_tls)
        self.base = cfg.url.rstrip("/")
        self._sid: str | None = None
        self._authed = False

    # ------------------------------------------------------------------ auth
    def _login(self) -> None:
        try:
            r = self.http.post(f"{self.base}/api/auth", json={"password": self.cfg.password})
        except httpx.HTTPError as e:
            raise ClientError(f"{self.name}: cannot reach {self.base}: {e}") from e
        if r.status_code != 200:
            raise ClientError(f"{self.name}: authentication failed (HTTP {r.status_code})")
        session = r.json().get("session", {})
        if not session.get("valid"):
            raise ClientError(f"{self.name}: authentication failed: {session.get('message')}")
        self._sid = session.get("sid")  # None when Pi-hole has no password
        self._authed = True

    def _request(self, method: str, path: str, **kw: Any) -> httpx.Response:
        for attempt in range(2):
            if not self._authed:
                self._login()
            headers = {"X-FTL-SID": self._sid} if self._sid else {}
            try:
                r = self.http.request(method, f"{self.base}{path}", headers=headers, **kw)
            except httpx.HTTPError as e:
                raise ClientError(f"{self.name}: {method} {path} failed: {e}") from e
            if r.status_code == 401 and attempt == 0:
                self._authed = False  # session expired; re-login once
                continue
            if r.status_code >= 400:
                raise ClientError(
                    f"{self.name}: {method} {path} -> HTTP {r.status_code}: {r.text[:200]}"
                )
            return r
        raise ClientError(f"{self.name}: unauthorized")

    def close(self) -> None:
        try:
            if self._authed and self._sid:
                self.http.delete(f"{self.base}/api/auth", headers={"X-FTL-SID": self._sid})
        except httpx.HTTPError:
            pass
        finally:
            self._sid = None
            self._authed = False
            if self._owns_http:
                self.http.close()

    # ---------------------------------------------------------------- health
    def _versions(self) -> dict[str, Any]:
        return self._request("GET", "/api/info/version").json().get("version", {})

    def health(self) -> ServerHealth:
        try:
            versions = self._versions()
            blocking = self._request("GET", "/api/dns/blocking").json().get("blocking")
        except ClientError as e:
            return ServerHealth(self.name, False, str(e), None)
        core = (versions.get("core") or {}).get("local", {}).get("version")
        ftl = (versions.get("ftl") or {}).get("local", {}).get("version")
        version = " ".join(f"{k} {v}" for k, v in (("core", core), ("ftl", ftl)) if v) or None
        ok = blocking == "enabled"
        return ServerHealth(self.name, ok, f"blocking {blocking}", version)

    # --------------------------------------------------------------- queries
    def _to_record(self, q: dict[str, Any]) -> QueryRecord:
        client = q.get("client") or {}
        if isinstance(client, dict):
            client_s = client.get("name") or client.get("ip") or ""
        else:
            client_s = str(client)
        reply = q.get("reply") or {}
        rt = reply.get("time")
        response_ms = (
            round(float(rt) * 1000, 3) if isinstance(rt, (int, float)) and rt >= 0 else None
        )  # API reports seconds
        status_raw = q.get("status") or "UNKNOWN"
        reason = status_raw
        if q.get("list_id") is not None:
            reason = f"{status_raw} (list {q['list_id']})"
        return QueryRecord(
            server=self.name,
            ts=datetime.fromtimestamp(float(q["time"]), tz=UTC),
            client=client_s,
            domain=(q.get("domain") or "").rstrip(".").lower(),
            qtype=q.get("type") or "",
            status=map_status(status_raw),
            reason=reason,
            upstream=q.get("upstream") or None,
            response_ms=response_ms,
            id=str(q["id"]),
        )

    def fetch_queries(
        self, since: datetime, cursor: str | None
    ) -> tuple[list[QueryRecord], str | None]:
        """Return queries with ts >= since (oldest first).

        Cursor is the highest query id already returned; ids <= cursor are skipped.
        Pi-hole returns newest first, so we page backwards from now to `since`.
        """
        last_id = int(cursor) if cursor and cursor.isdigit() else -1
        since_ts = since.timestamp()
        until = int(datetime.now(UTC).timestamp()) + 1
        out: dict[str, QueryRecord] = {}
        db_cursor: Any = None
        start = 0
        for _ in range(MAX_PAGES):
            params: dict[str, Any] = {
                "from": int(since_ts),
                "until": until,
                "length": PAGE_SIZE,
                "start": start,
            }
            if db_cursor is not None:
                # FTL pins the result set to this cursor so paging with `start` is stable
                params["cursor"] = db_cursor
            data = self._request("GET", "/api/queries", params=params).json()
            queries = data.get("queries") or []
            stop = False
            for q in queries:
                if float(q.get("time", 0)) < since_ts or int(q.get("id", -1)) <= last_id:
                    stop = True
                    continue
                rec = self._to_record(q)
                out[rec.id] = rec
            if stop or len(queries) < PAGE_SIZE:
                break
            if db_cursor is None:
                db_cursor = data.get("cursor")
            start += len(queries)
        records = sorted(out.values(), key=lambda r: (r.ts, int(r.id)))
        new_last = max([last_id, *(int(r.id) for r in records)])
        return records, (str(new_last) if new_last >= 0 else cursor)

    # ----------------------------------------------------------------- lists
    def _get_domains(self, kind: str) -> set[str]:
        data = self._request("GET", f"/api/domains/{kind}/exact").json()
        return {d["domain"].rstrip(".").lower() for d in data.get("domains", []) if d.get("domain")}

    def get_lists(self) -> ListState:
        return ListState(allow=self._get_domains("allow"), deny=self._get_domains("deny"))

    def _add(self, kind: str, domains: set[str]) -> None:
        if not domains:
            return
        self._request(
            "POST",
            f"/api/domains/{kind}/exact",
            json={"domain": sorted(domains), "comment": COMMENT, "groups": [0], "enabled": True},
        )

    def _remove(self, kind: str, domains: set[str]) -> None:
        for d in sorted(domains):
            self._request("DELETE", f"/api/domains/{kind}/exact/{quote(d, safe='')}")

    def add_allow(self, domains: set[str]) -> None:
        self._add("allow", domains)

    def remove_allow(self, domains: set[str]) -> None:
        self._remove("allow", domains)

    def add_deny(self, domains: set[str]) -> None:
        self._add("deny", domains)

    def remove_deny(self, domains: set[str]) -> None:
        self._remove("deny", domains)

    # ---------------------------------------------------------------- update
    def _update_summary(self) -> tuple[bool, str]:
        versions = self._versions()
        parts, available = [], False
        for comp in ("core", "web", "ftl"):
            info = versions.get(comp) or {}
            local = (info.get("local") or {}).get("version")
            remote = (info.get("remote") or {}).get("version")
            if local and remote and local != remote:
                available = True
                parts.append(f"{comp} {local} -> {remote}")
            elif local:
                parts.append(f"{comp} {local}")
        return available, ", ".join(parts)

    def update(self, dry_run: bool) -> str:
        try:
            available, summary = self._update_summary()
        except ClientError as e:
            available, summary = True, f"version check failed ({e})"
        if not available:
            return f"up to date ({summary})"
        if not self.cfg.ssh_host:
            return (
                f"update available ({summary}); no ssh_host configured, run 'pihole -up' manually"
            )
        cmd = ["ssh", "-o", "BatchMode=yes", self.cfg.ssh_host, "sudo pihole -up"]
        if dry_run:
            return f"update available ({summary}); would run: {' '.join(cmd)}"
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, check=False)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise ClientError(f"{self.name}: ssh update failed: {e}") from e
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout).strip().splitlines()[-5:]
            raise ClientError(f"{self.name}: 'pihole -up' failed: {' | '.join(tail)}")
        return f"updated ({summary})"
