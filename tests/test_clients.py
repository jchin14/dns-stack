from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import respx

from dnsstack.clients import DnsServerClient, build_clients
from dnsstack.clients.adguard import AdguardClient
from dnsstack.clients.nextdns import NextdnsClient
from dnsstack.clients.pihole import PiholeClient
from dnsstack.config import AppConfig

PH = "http://pihole.test"
AG = "http://adguard.test"
ND = "https://api.nextdns.io/profiles/abc123"


def _ph_auth(mock: respx.MockRouter) -> respx.Route:
    return mock.post(f"{PH}/api/auth").respond(
        200, json={"session": {"valid": True, "sid": "SID1", "validity": 1800}}
    )


# ------------------------------------------------------------------ pihole
def test_pihole_auth_header_and_logout(mock, http, pihole_cfg):
    auth = _ph_auth(mock)
    blocking = mock.get(f"{PH}/api/dns/blocking").respond(200, json={"blocking": "enabled"})
    mock.get(f"{PH}/api/info/version").respond(
        200,
        json={
            "version": {
                "core": {"local": {"version": "v6.1"}},
                "ftl": {"local": {"version": "v6.2"}},
            }
        },
    )
    logout = mock.delete(f"{PH}/api/auth").respond(204)
    c = PiholeClient(pihole_cfg, http=http)
    h = c.health()
    assert h.ok and h.version == "core v6.1 ftl v6.2"
    assert auth.call_count == 1
    assert json.loads(auth.calls[0].request.content) == {"password": "pw"}
    assert blocking.calls[0].request.headers["X-FTL-SID"] == "SID1"
    c.close()
    assert logout.called and logout.calls[0].request.headers["X-FTL-SID"] == "SID1"


def test_pihole_relogin_on_401(mock, http, pihole_cfg):
    auth = _ph_auth(mock)
    mock.get(f"{PH}/api/domains/allow/exact").mock(
        side_effect=[
            httpx.Response(401),
            httpx.Response(200, json={"domains": [{"domain": "A.com."}]}),
        ]
    )
    mock.get(f"{PH}/api/domains/deny/exact").respond(200, json={"domains": []})
    c = PiholeClient(pihole_cfg, http=http)
    assert c.get_lists().allow == {"a.com"}
    assert auth.call_count == 2


def test_pihole_auth_failure_health(mock, http, pihole_cfg):
    mock.post(f"{PH}/api/auth").respond(401, json={"session": {"valid": False}})
    h = PiholeClient(pihole_cfg, http=http).health()
    assert not h.ok and "authentication failed" in h.detail


def test_pihole_fetch_queries(mock, http, pihole_cfg):
    _ph_auth(mock)
    now = datetime.now(UTC).timestamp()
    queries = [
        {
            "id": 12,
            "time": now - 1,
            "type": "A",
            "status": "GRAVITY",
            "domain": "ads.example",
            "upstream": None,
            "reply": {"type": "IP", "time": 0.2},
            "client": {"ip": "10.0.0.2", "name": "laptop"},
            "list_id": 3,
        },
        {
            "id": 11,
            "time": now - 2,
            "type": "AAAA",
            "status": "FORWARDED",
            "domain": "ok.example",
            "upstream": "1.1.1.1#53",
            "reply": {"type": "IP", "time": 0.0125},
            "client": {"ip": "10.0.0.3", "name": None},
        },
        {
            "id": 10,
            "time": now - 3,
            "type": "A",
            "status": "CACHE",
            "domain": "old.example",
            "reply": {"time": -1},
            "client": {"ip": "10.0.0.3"},
        },
    ]
    route = mock.get(f"{PH}/api/queries").respond(
        200, json={"queries": queries, "cursor": 12, "recordsTotal": 3, "recordsFiltered": 3}
    )
    c = PiholeClient(pihole_cfg, http=http)
    recs, cur = c.fetch_queries(datetime.now(UTC) - timedelta(minutes=5), "10")
    assert [r.id for r in recs] == ["11", "12"]  # oldest first, id<=cursor dropped
    assert cur == "12"
    assert recs[0].status == "allowed" and recs[0].upstream == "1.1.1.1#53"
    assert recs[0].response_ms == 12.5 and recs[0].client == "10.0.0.3"
    assert recs[1].status == "blocked" and recs[1].client == "laptop"
    assert recs[1].ts.tzinfo is not None
    assert route.calls[0].request.url.params["length"] == "1000"


def test_pihole_add_remove(mock, http, pihole_cfg):
    _ph_auth(mock)
    add = mock.post(f"{PH}/api/domains/deny/exact").respond(201, json={})
    rm = mock.delete(f"{PH}/api/domains/allow/exact/b.com").respond(204)
    c = PiholeClient(pihole_cfg, http=http)
    c.add_deny({"x.com", "a.com"})
    c.remove_allow({"b.com"})
    body = json.loads(add.calls[0].request.content)
    assert body["domain"] == ["a.com", "x.com"]
    assert rm.called


def test_pihole_update_without_ssh(mock, http, pihole_cfg):
    _ph_auth(mock)
    mock.get(f"{PH}/api/info/version").respond(
        200,
        json={"version": {"core": {"local": {"version": "v6.0"}, "remote": {"version": "v6.1"}}}},
    )
    msg = PiholeClient(pihole_cfg, http=http).update(dry_run=False)
    assert "manually" in msg and "v6.0 -> v6.1" in msg


# ----------------------------------------------------------------- adguard
def test_adguard_health_basic_auth(mock, http, adguard_cfg):
    r = mock.get(f"{AG}/control/status").respond(
        200, json={"running": True, "protection_enabled": True, "version": "v0.107.55"}
    )
    h = AdguardClient(adguard_cfg, http=http).health()
    assert h.ok and h.version == "v0.107.55"
    assert r.calls[0].request.headers["Authorization"].startswith("Basic ")


def test_adguard_fetch_queries_paginates(mock, http, adguard_cfg):
    now = datetime.now(UTC)
    t = lambda s: (now - timedelta(seconds=s)).strftime("%Y-%m-%dT%H:%M:%S.%f") + "123Z"  # noqa: E731
    page1 = {
        "data": [
            {
                "time": t(1),
                "client": "10.0.0.5",
                "client_info": {"name": "tv"},
                "question": {"name": "ads.tv.", "type": "A", "class": "IN"},
                "reason": "FilteredBlackList",
                "rules": [{"text": "||ads.tv^", "filter_list_id": 1}],
                "elapsedMs": "0.5",
                "upstream": "",
                "cached": False,
            },
        ],
        "oldest": t(1),
    }
    page2 = {
        "data": [
            {
                "time": t(2),
                "client": "10.0.0.6",
                "question": {"name": "ok.com", "type": "AAAA"},
                "reason": "NotFilteredNotFound",
                "elapsedMs": "20.1",
                "upstream": "https://dns.quad9.net/dns-query",
                "cached": True,
            },
            {
                "time": t(3600),
                "client": "10.0.0.6",
                "question": {"name": "old.com", "type": "A"},
                "reason": "NotFilteredNotFound",
            },
        ],
        "oldest": t(3600),
    }
    route = mock.get(f"{AG}/control/querylog").mock(
        side_effect=[httpx.Response(200, json=page1), httpx.Response(200, json=page2)]
    )
    c = AdguardClient(adguard_cfg, http=http)
    recs, cur = c.fetch_queries(now - timedelta(minutes=10), None)
    assert [r.domain for r in recs] == ["ok.com", "ads.tv"]
    assert recs[0].status == "cached" and recs[0].response_ms == 20.1
    assert recs[1].status == "blocked" and recs[1].client == "tv" and "||ads.tv^" in recs[1].reason
    assert recs[1].upstream is None
    assert cur == recs[-1].ts.isoformat()
    assert "older_than" in route.calls[1].request.url.params
    # second call with cursor: same data -> ids stable
    route.side_effect = [httpx.Response(200, json=page1), httpx.Response(200, json=page2)]
    recs2, _ = c.fetch_queries(now - timedelta(minutes=10), None)
    assert {r.id for r in recs2} == {r.id for r in recs}


def test_adguard_lists_preserve_other_rules(mock, http, adguard_cfg):
    rules = ["! comment", "@@||keep.com^", "||bad.com^", "||regex.*^$important", "/re/"]
    mock.get(f"{AG}/control/filtering/status").respond(200, json={"user_rules": rules})
    setr = mock.post(f"{AG}/control/filtering/set_rules").respond(200)
    c = AdguardClient(adguard_cfg, http=http)
    st = c.get_lists()
    assert st.allow == {"keep.com"} and st.deny == {"bad.com"}
    c.add_allow({"new.com", "keep.com"})
    sent = json.loads(setr.calls[0].request.content)["rules"]
    assert sent == rules + ["@@||new.com^"]
    c.remove_deny({"bad.com"})
    sent = json.loads(setr.calls[1].request.content)["rules"]
    assert "||bad.com^" not in sent and "||regex.*^$important" in sent and "/re/" in sent


def test_adguard_update(mock, http, adguard_cfg):
    mock.get(f"{AG}/control/status").respond(200, json={"version": "v0.107.50"})
    ver = mock.post(f"{AG}/control/version.json").respond(
        200, json={"new_version": "v0.107.55", "can_autoupdate": True}
    )
    upd = mock.post(f"{AG}/control/update").respond(200)
    c = AdguardClient(adguard_cfg, http=http)
    assert "would" in c.update(dry_run=True) and not upd.called
    assert json.loads(ver.calls[0].request.content) == {"recheck_now": False}
    assert "started" in c.update(dry_run=False) and upd.called


# ----------------------------------------------------------------- nextdns
def test_nextdns_logs_cursor_paging(mock, http, nextdns_cfg):
    since = datetime(2026, 1, 1, tzinfo=UTC)
    p1 = {
        "data": [
            {
                "timestamp": "2026-01-01T00:00:01.000Z",
                "domain": "ads.x",
                "type": "A",
                "status": "blocked",
                "reasons": [{"id": "oisd", "name": "OISD"}],
                "clientIp": "1.2.3.4",
                "device": {"id": "D1", "name": "phone"},
            }
        ],
        "meta": {"pagination": {"cursor": "C2"}},
    }
    p2 = {
        "data": [
            {
                "timestamp": "2026-01-01T00:00:02.000Z",
                "domain": "ok.x.",
                "type": "AAAA",
                "status": "default",
                "reasons": [],
                "clientIp": "1.2.3.5",
            }
        ],
        "meta": {"pagination": {"cursor": None}},
    }
    route = mock.get(f"{ND}/logs").mock(
        side_effect=[httpx.Response(200, json=p1), httpx.Response(200, json=p2)]
    )
    recs, cur = NextdnsClient(nextdns_cfg, http=http).fetch_queries(since, None)
    assert [r.domain for r in recs] == ["ads.x", "ok.x"]
    assert recs[0].status == "blocked" and recs[0].reason == "OISD" and recs[0].client == "phone"
    assert recs[1].status == "allowed" and recs[1].client == "1.2.3.5"
    assert cur == recs[-1].ts.isoformat()
    req0 = route.calls[0].request
    assert req0.headers["X-Api-Key"] == "key"
    assert req0.url.params["sort"] == "asc" and "cursor" not in req0.url.params
    assert route.calls[1].request.url.params["cursor"] == "C2"


def test_nextdns_lists(mock, http, nextdns_cfg):
    mock.get(f"{ND}/allowlist").respond(200, json={"data": [{"id": "a.com", "active": True}]})
    mock.get(f"{ND}/denylist").respond(200, json={"data": [{"id": "B.com", "active": True}]})
    add = mock.post(f"{ND}/denylist").respond(200, json={})
    rm = mock.delete(f"{ND}/allowlist/a.com").respond(204)
    c = NextdnsClient(nextdns_cfg, http=http)
    st = c.get_lists()
    assert st.allow == {"a.com"} and st.deny == {"b.com"}
    c.add_deny({"c.com"})
    c.remove_allow({"a.com"})
    assert json.loads(add.calls[0].request.content) == {"id": "c.com", "active": True}
    assert rm.called
    assert c.update(dry_run=False) == "cloud service, nothing to update"


def test_nextdns_health_failure(mock, http, nextdns_cfg):
    mock.get(ND).respond(403)
    h = NextdnsClient(nextdns_cfg, http=http).health()
    assert not h.ok


# ----------------------------------------------------------------- factory
def test_build_clients(pihole_cfg, nextdns_cfg):
    clients = build_clients(AppConfig(pihole=pihole_cfg, nextdns=nextdns_cfg))
    assert [c.name for c in clients] == ["pihole", "nextdns"]
    assert all(isinstance(c, DnsServerClient) for c in clients)
    for c in clients:
        c.close()
