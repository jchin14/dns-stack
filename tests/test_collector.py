from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from dnsstack.collector import Collector
from dnsstack.models import QueryRecord, ServerHealth
from dnsstack.state import CollectorState

NOW = datetime.now(UTC)


@dataclass
class Cfg:
    poll_interval_s: int = 15
    batch_size: int = 500
    state_path: str = ""
    health_port: int = 0
    lookback_minutes: int = 10


def rec(server: str, i: int, ts: datetime) -> QueryRecord:
    return QueryRecord(server, ts, "1.2.3.4", f"d{i}.com", "A", "allowed", "", None, None, str(i))


@dataclass
class FakeClient:
    name: str
    batches: list[list[QueryRecord]] = field(default_factory=list)
    fail: bool = False
    calls: list[tuple[datetime, str | None]] = field(default_factory=list)

    def health(self) -> ServerHealth:
        if self.fail:
            raise RuntimeError("unreachable")
        return ServerHealth(self.name, True, "ok", "1")

    def fetch_queries(self, since, cursor):
        self.calls.append((since, cursor))
        if self.fail:
            raise RuntimeError("fetch failed")
        recs = self.batches.pop(0) if self.batches else []
        return [r for r in recs if r.ts >= since], f"c{len(self.calls)}"


class FakePusher:
    def __init__(self, fail_times: int = 0) -> None:
        self.pushed: list[QueryRecord] = []
        self.health: list[list[ServerHealth]] = []
        self.fail_times = fail_times

    def push(self, records):
        if self.fail_times:
            self.fail_times -= 1
            raise RuntimeError("loki down")
        self.pushed.extend(records)

    def push_health(self, healths):
        self.health.append(list(healths))


def make(tmp_path: Path, clients, pusher=None, **cfg):
    state = CollectorState(tmp_path / "state.json")
    return Collector(clients, pusher or FakePusher(), state, Cfg(**cfg)), state


def test_run_once_pushes_and_persists(tmp_path: Path) -> None:
    t = NOW - timedelta(minutes=1)
    c = FakeClient("pihole", [[rec("pihole", 1, t), rec("pihole", 2, t + timedelta(seconds=1))]])
    col, state = make(tmp_path, [c])
    assert col.run_once() == {"pihole": 2}
    saved = json.loads((tmp_path / "state.json").read_text())["servers"]["pihole"]
    assert saved["cursor"] == "c1"
    assert saved["recent_ids"] == ["1", "2"]
    assert datetime.fromisoformat(saved["last_ts"]) == t + timedelta(seconds=1)
    # first-run lookback
    since, cursor = c.calls[0]
    assert cursor is None and NOW - since >= timedelta(minutes=9)


def test_dedupe_across_cycles_and_restart(tmp_path: Path) -> None:
    t = NOW - timedelta(minutes=1)
    r1, r2, r3 = (rec("pihole", i, t + timedelta(seconds=i)) for i in (1, 2, 3))
    c = FakeClient("pihole", [[r1, r2], [r2, r3]])
    pusher = FakePusher()
    col, _ = make(tmp_path, [c], pusher)
    col.run_once()
    # simulate restart: new collector reloading state
    col2, _ = make(tmp_path, [c], pusher)
    assert col2.run_once() == {"pihole": 1}
    assert [r.id for r in pusher.pushed] == ["1", "2", "3"]
    since, cursor = c.calls[1]
    assert cursor == "c1" and since == r2.ts


def test_failing_server_does_not_stop_others(tmp_path: Path) -> None:
    good = FakeClient("adguard", [[rec("adguard", 1, NOW)]])
    bad = FakeClient("pihole", fail=True)
    pusher = FakePusher()
    col, _ = make(tmp_path, [bad, good], pusher)
    assert col.run_once() == {"pihole": 0, "adguard": 1}
    health = {h.server: h for h in pusher.health[0]}
    assert health["pihole"].ok is False and health["adguard"].ok is True
    assert "adguard" in col.last_success and "pihole" not in col.last_success


def test_push_failure_does_not_advance_state(tmp_path: Path) -> None:
    r = rec("pihole", 1, NOW)
    c = FakeClient("pihole", [[r], [r]])
    pusher = FakePusher(fail_times=1)
    col, state = make(tmp_path, [c], pusher)
    assert col.run_once() == {"pihole": 0}
    assert state.cursor("pihole") is None and state.recent_ids("pihole") == []
    assert col.run_once() == {"pihole": 1}
    assert [x.id for x in pusher.pushed] == ["1"]


def test_batching(tmp_path: Path) -> None:
    recs = [rec("p", i, NOW + timedelta(milliseconds=i)) for i in range(7)]
    calls: list[int] = []

    class P(FakePusher):
        def push(self, records):
            calls.append(len(records))
            super().push(records)

    col, _ = make(tmp_path, [FakeClient("p", [recs])], P(), batch_size=3)
    col.run_once()
    assert calls == [3, 3, 1]


def test_state_bounded_and_corrupt(tmp_path: Path) -> None:
    s = CollectorState(tmp_path / "s.json", max_recent=3)
    s.record_pushed("x", NOW, [str(i) for i in range(10)])
    s.record_pushed("x", NOW - timedelta(hours=1), [])
    s.save()
    s2 = CollectorState(tmp_path / "s.json", max_recent=3)
    s2.load()
    assert s2.recent_ids("x") == ["7", "8", "9"]
    assert s2.last_ts("x") == NOW  # never goes backwards
    (tmp_path / "s.json").write_text("{not json")
    s2.load()
    assert s2.servers() == []


def _get(port: int) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_healthz(tmp_path: Path) -> None:
    col, _ = make(tmp_path, [FakeClient("pihole", [[rec("pihole", 1, NOW)]])])
    port = col.start_health_server("127.0.0.1", 0)
    try:
        code, body = _get(port)
        assert code == 503 and body["servers"]["pihole"]["last_success"] is None
        col.run_once()
        code, body = _get(port)
        assert code == 200 and body["servers"]["pihole"]["last_success"]
        col.last_success["pihole"] = NOW - timedelta(seconds=76)
        assert _get(port)[0] == 503
    finally:
        col.stop_health_server()


def test_run_forever_stops(tmp_path: Path) -> None:
    c = FakeClient("pihole")
    col, _ = make(tmp_path, [c], poll_interval_s=1)
    col.cfg.health_port = 0
    stop = threading.Event()
    t = threading.Thread(target=col.run_forever, args=(stop,))
    t.start()
    for _ in range(500):
        if c.calls:
            break
        threading.Event().wait(0.01)
    stop.set()
    t.join(timeout=5)
    assert not t.is_alive()
    assert len(c.calls) >= 1
