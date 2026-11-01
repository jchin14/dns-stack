from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest
import respx

from dnsstack.loki import LokiPusher, LokiPushError, build_streams
from dnsstack.models import QueryRecord, ServerHealth

URL = "http://loki:3100"
PUSH = URL + "/loki/api/v1/push"


def rec(i: int, server: str = "pihole", status: str = "allowed", sec: int = 0) -> QueryRecord:
    return QueryRecord(
        server=server,
        ts=datetime(2026, 1, 1, 0, 0, sec, i, tzinfo=UTC),
        client="10.0.0.2",
        domain=f"d{i}.example",
        qtype="A",
        status=status,
        reason="gravity",
        upstream=None,
        response_ms=1.5,
        id=str(i),
    )


def test_build_streams_groups_and_sorts() -> None:
    records = [rec(3, sec=5), rec(1, sec=1), rec(2, status="blocked"), rec(4, server="adguard")]
    streams = build_streams(records)
    labels = [s["stream"] for s in streams]
    assert {"job": "dns", "server": "pihole", "status": "allowed"} in labels
    assert {"job": "dns", "server": "pihole", "status": "blocked"} in labels
    assert {"job": "dns", "server": "adguard", "status": "allowed"} in labels
    assert all(set(lab) == {"job", "server", "status"} for lab in labels)
    allowed = next(
        s
        for s in streams
        if s["stream"]
        == labels[labels.index({"job": "dns", "server": "pihole", "status": "allowed"})]
    )
    ts = [int(v[0]) for v in allowed["values"]]
    assert ts == sorted(ts)
    assert all(isinstance(v[0], str) for v in allowed["values"])
    line = json.loads(allowed["values"][0][1])
    assert set(line) == {
        "client",
        "domain",
        "qtype",
        "status",
        "reason",
        "upstream",
        "response_ms",
        "id",
    }
    assert line["id"] == "1"


def test_ns_precision() -> None:
    (s,) = build_streams([rec(123456, sec=0)])
    assert s["values"][0][0] == "1767225600123456000"


@respx.mock
def test_push_with_tenant_and_batches() -> None:
    route = respx.post(PUSH).mock(return_value=httpx.Response(204))
    with httpx.Client() as http:
        p = LokiPusher(URL, tenant="t1", http=http, batch_size=2, sleep=lambda s: None)
        p.push([rec(i) for i in range(5)])
    assert route.call_count == 3
    assert route.calls[0].request.headers["X-Scope-OrgID"] == "t1"


@respx.mock
def test_push_empty_noop() -> None:
    route = respx.post(PUSH).mock(return_value=httpx.Response(204))
    LokiPusher(URL, http=httpx.Client()).push([])
    assert route.call_count == 0


@respx.mock
def test_retry_on_5xx_then_success() -> None:
    sleeps: list[float] = []
    route = respx.post(PUSH).mock(
        side_effect=[httpx.Response(503), httpx.ConnectError("boom"), httpx.Response(204)]
    )
    LokiPusher(URL, http=httpx.Client(), sleep=sleeps.append).push([rec(1)])
    assert route.call_count == 3
    assert sleeps == [0.5, 1.0]


@respx.mock
def test_retry_gives_up() -> None:
    route = respx.post(PUSH).mock(return_value=httpx.Response(500))
    p = LokiPusher(URL, http=httpx.Client(), max_tries=5, sleep=lambda s: None)
    with pytest.raises(LokiPushError):
        p.push([rec(1)])
    assert route.call_count == 5


@respx.mock
def test_4xx_not_retried() -> None:
    route = respx.post(PUSH).mock(return_value=httpx.Response(400, text="bad"))
    with pytest.raises(LokiPushError):
        LokiPusher(URL, http=httpx.Client(), sleep=lambda s: None).push([rec(1)])
    assert route.call_count == 1


@respx.mock
def test_push_health() -> None:
    route = respx.post(PUSH).mock(return_value=httpx.Response(204))
    LokiPusher(URL, http=httpx.Client()).push_health(
        [ServerHealth("pihole", True, "ok", "6.0"), ServerHealth("nextdns", False, "down", None)]
    )
    body = json.loads(route.calls[0].request.content)
    labels = [s["stream"] for s in body["streams"]]
    assert labels == [
        {"job": "dns-health", "server": "pihole"},
        {"job": "dns-health", "server": "nextdns"},
    ]
    assert json.loads(body["streams"][1]["values"][0][1]) == {
        "ok": False,
        "detail": "down",
        "version": None,
    }
