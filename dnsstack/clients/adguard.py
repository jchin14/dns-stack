"""AdGuard Home client (/control/* API with HTTP basic auth)."""

from __future__ import annotations

import contextlib
import hashlib
import logging
import re
from datetime import UTC, datetime
from typing import Any

import httpx

from dnsstack.clients import ClientError
from dnsstack.config import AdguardConfig
from dnsstack.models import ListState, QueryRecord, ServerHealth

log = logging.getLogger(__name__)

PAGE_SIZE = 500
MAX_PAGES = 40

_ALLOW_RE = re.compile(r"^@@\|\|([a-z0-9.\-_]+)\^$")
_DENY_RE = re.compile(r"^\|\|([a-z0-9.\-_]+)\^$")
_FRAC_RE = re.compile(r"(\.\d{6})\d+")


def parse_time(value: str) -> datetime:
    """Parse AdGuard RFC3339 timestamps (may carry nanoseconds) to aware UTC."""
    s = _FRAC_RE.sub(r"\1", value.strip()).replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def map_status(entry: dict[str, Any]) -> str:
    reason = entry.get("reason") or ""
    if reason.startswith("Filtered"):
        return "blocked"
    if entry.get("cached"):
        return "cached"
    if reason.startswith("NotFiltered") or reason in ("Rewrite", "RewriteEtcHosts", "RewriteRule"):
        return "allowed"
    return "other"


class AdguardClient:
    def __init__(self, cfg: AdguardConfig, http: httpx.Client | None = None) -> None:
        self.cfg = cfg
        self.name = cfg.name
        self._owns_http = http is None
        self.http = http or httpx.Client(timeout=20.0, verify=cfg.verify_tls)
        self.base = cfg.url.rstrip("/")
        self._auth = httpx.BasicAuth(cfg.username, cfg.password)

    def _request(self, method: str, path: str, **kw: Any) -> httpx.Response:
        try:
            r = self.http.request(method, f"{self.base}{path}", auth=self._auth, **kw)
        except httpx.HTTPError as e:
            raise ClientError(f"{self.name}: {method} {path} failed: {e}") from e
        if r.status_code in (401, 403):
            raise ClientError(f"{self.name}: authentication failed (HTTP {r.status_code})")
        if r.status_code >= 400:
            raise ClientError(
                f"{self.name}: {method} {path} -> HTTP {r.status_code}: {r.text[:200]}"
            )
        return r

    def close(self) -> None:
        if self._owns_http:
            self.http.close()

    # ---------------------------------------------------------------- health
    def health(self) -> ServerHealth:
        try:
            st = self._request("GET", "/control/status").json()
        except ClientError as e:
            return ServerHealth(self.name, False, str(e), None)
        running = bool(st.get("running", True))
        protection = bool(st.get("protection_enabled"))
        ok = running and protection
        detail = f"running={running} protection={'enabled' if protection else 'disabled'}"
        return ServerHealth(self.name, ok, detail, st.get("version"))

    # --------------------------------------------------------------- queries
    def _to_record(self, e: dict[str, Any]) -> QueryRecord:
        q = e.get("question") or {}
        ts = parse_time(e["time"])
        client_info = e.get("client_info") or {}
        client = client_info.get("name") or e.get("client") or ""
        domain = (q.get("unicode_name") or q.get("name") or "").rstrip(".").lower()
        qtype = q.get("type") or ""
        elapsed = e.get("elapsedMs")
        try:
            response_ms: float | None = float(elapsed) if elapsed is not None else None
        except (TypeError, ValueError):
            response_ms = None
        reason = e.get("reason") or ""
        rules = [r.get("text") for r in (e.get("rules") or []) if r.get("text")]
        if rules:
            reason = f"{reason}: {rules[0]}"
        elif e.get("service_name"):
            reason = f"{reason}: {e['service_name']}"
        raw_id = f"{e['time']}|{e.get('client', '')}|{domain}|{qtype}"
        return QueryRecord(
            server=self.name,
            ts=ts,
            client=client,
            domain=domain,
            qtype=qtype,
            status=map_status(e),
            reason=reason,
            upstream=e.get("upstream") or None,
            response_ms=response_ms,
            id=hashlib.sha1(raw_id.encode()).hexdigest()[:16],
        )

    def fetch_queries(
        self, since: datetime, cursor: str | None
    ) -> tuple[list[QueryRecord], str | None]:
        """Page backwards via older_than from now until `since` is reached.

        Cursor is the ISO time of the newest record returned; records strictly older
        than it are skipped (equal times are kept and left to id dedupe).
        """
        floor = since
        if cursor:
            with contextlib.suppress(ValueError):
                floor = max(since, parse_time(cursor))
        out: dict[str, QueryRecord] = {}
        older_than: str | None = None
        for _ in range(MAX_PAGES):
            params: dict[str, Any] = {"limit": PAGE_SIZE}
            if older_than:
                params["older_than"] = older_than
            data = self._request("GET", "/control/querylog", params=params).json()
            entries = data.get("data") or []
            reached = False
            for e in entries:
                try:
                    rec = self._to_record(e)
                except (KeyError, ValueError) as err:
                    log.debug("%s: skipping malformed entry: %s", self.name, err)
                    continue
                if rec.ts < floor:
                    reached = True
                    continue
                out[rec.id] = rec
            oldest = data.get("oldest")
            if reached or not entries or not oldest or oldest == older_than:
                break
            older_than = oldest
        records = sorted(out.values(), key=lambda r: r.ts)
        new_cursor = records[-1].ts.isoformat() if records else cursor
        return records, new_cursor

    # ----------------------------------------------------------------- lists
    def _user_rules(self) -> list[str]:
        st = self._request("GET", "/control/filtering/status").json()
        return list(st.get("user_rules") or [])

    @staticmethod
    def _parse_rules(rules: list[str]) -> ListState:
        state = ListState()
        for rule in rules:
            r = rule.strip().lower()
            if m := _ALLOW_RE.match(r):
                state.allow.add(m.group(1).rstrip("."))
            elif m := _DENY_RE.match(r):
                state.deny.add(m.group(1).rstrip("."))
        return state

    def get_lists(self) -> ListState:
        return self._parse_rules(self._user_rules())

    def _set_rules(self, rules: list[str]) -> None:
        self._request("POST", "/control/filtering/set_rules", json={"rules": rules})

    def _modify(self, add: set[str], remove: set[str], allow: bool) -> None:
        if not add and not remove:
            return
        pattern = _ALLOW_RE if allow else _DENY_RE
        fmt = "@@||{}^" if allow else "||{}^"
        rules = self._user_rules()
        kept: list[str] = []
        present: set[str] = set()
        for rule in rules:
            m = pattern.match(rule.strip().lower())
            if m:
                d = m.group(1).rstrip(".")
                if d in remove:
                    continue
                present.add(d)
            kept.append(rule)
        kept.extend(fmt.format(d) for d in sorted(add - present))
        self._set_rules(kept)

    def add_allow(self, domains: set[str]) -> None:
        self._modify(set(domains), set(), allow=True)

    def remove_allow(self, domains: set[str]) -> None:
        self._modify(set(), set(domains), allow=True)

    def add_deny(self, domains: set[str]) -> None:
        self._modify(set(domains), set(), allow=False)

    def remove_deny(self, domains: set[str]) -> None:
        self._modify(set(), set(domains), allow=False)

    # ---------------------------------------------------------------- update
    def update(self, dry_run: bool) -> str:
        current = None
        with contextlib.suppress(ClientError):
            current = self._request("GET", "/control/status").json().get("version")
        r = self._request("POST", "/control/version.json", json={"recheck_now": False})
        info = r.json() if r.content else {}
        if info.get("disabled"):
            return f"update checks disabled on server (current {current})"
        new = info.get("new_version")
        if not new or new == current:
            return f"up to date ({current})"
        if not info.get("can_autoupdate", True):
            return f"update available ({current} -> {new}) but server cannot auto-update"
        if dry_run:
            return f"update available ({current} -> {new}); would POST /control/update"
        self._request("POST", "/control/update")
        return f"update to {new} started (was {current})"
