from __future__ import annotations

from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from dnsstack import cli
from dnsstack.linkedip import update_linked_ip
from dnsstack.models import ListState, QueryRecord, ServerHealth
from dnsstack.sync import Plan, apply, plan


class FakeClient:
    def __init__(
        self,
        name: str,
        allow: set[str] | None = None,
        deny: set[str] | None = None,
        fail: bool = False,
    ) -> None:
        self.name = name
        self.allow = set(allow or ())
        self.deny = set(deny or ())
        self.fail = fail
        self.calls: list[tuple[str, set[str]]] = []
        self.update_calls: list[bool] = []
        self.closed = False

    def health(self) -> ServerHealth:
        if self.fail:
            raise RuntimeError("down")
        return ServerHealth(self.name, True, "ok", "1.0")

    def fetch_queries(
        self, since: datetime, cursor: str | None
    ) -> tuple[list[QueryRecord], str | None]:
        return [], cursor

    def get_lists(self) -> ListState:
        if self.fail:
            raise RuntimeError("boom")
        return ListState(allow=set(self.allow), deny=set(self.deny))

    def add_allow(self, domains: set[str]) -> None:
        self.calls.append(("add_allow", domains))
        self.allow |= domains

    def remove_allow(self, domains: set[str]) -> None:
        self.calls.append(("remove_allow", domains))
        self.allow -= domains

    def add_deny(self, domains: set[str]) -> None:
        self.calls.append(("add_deny", domains))
        self.deny |= domains

    def remove_deny(self, domains: set[str]) -> None:
        self.calls.append(("remove_deny", domains))
        self.deny -= domains

    def update(self, dry_run: bool) -> str:
        self.update_calls.append(dry_run)
        return "would update" if dry_run else "updated"

    def close(self) -> None:
        self.closed = True


DESIRED = ListState(allow={"a.com", "b.com"}, deny={"x.com"})


def test_plan_add_only() -> None:
    c = FakeClient("pihole", allow={"a.com", "extra.com"}, deny={"old.com"})
    p = plan(c, DESIRED, prune=False)
    assert p.server == "pihole"
    assert p.add_allow == {"b.com"}
    assert p.add_deny == {"x.com"}
    assert p.remove_allow == set()
    assert p.remove_deny == set()


def test_plan_prune() -> None:
    c = FakeClient("adguard", allow={"a.com", "extra.com"}, deny={"old.com", "x.com"})
    p = plan(c, DESIRED, prune=True)
    assert p.add_allow == {"b.com"}
    assert p.remove_allow == {"extra.com"}
    assert p.add_deny == set()
    assert p.remove_deny == {"old.com"}


def test_plan_without_prune_moves_conflicting_entries() -> None:
    # Server denies a domain we want allowed, and allows one we want denied.
    c = FakeClient("nextdns", allow={"x.com"}, deny={"a.com", "keep.com"})
    p = plan(c, DESIRED, prune=False)
    assert p.remove_deny == {"a.com"}
    assert p.remove_allow == {"x.com"}
    assert "keep.com" not in p.remove_deny


def test_plan_in_sync() -> None:
    c = FakeClient("pihole", allow={"a.com", "b.com"}, deny={"x.com"})
    p = plan(c, DESIRED, prune=True)
    assert p.is_empty
    assert "in sync" in p.describe()


def test_apply_converges_and_removes_first() -> None:
    c = FakeClient("pihole", allow={"x.com", "stale.com"}, deny={"a.com"})
    p = plan(c, DESIRED, prune=True)
    apply(c, p)
    assert c.allow == DESIRED.allow
    assert c.deny == DESIRED.deny
    ops = [op for op, _ in c.calls]
    assert ops.index("remove_allow") < ops.index("add_deny")
    assert ops.index("remove_deny") < ops.index("add_allow")
    assert plan(c, DESIRED, prune=True).is_empty


def test_apply_empty_plan_no_calls() -> None:
    c = FakeClient("pihole")
    apply(c, Plan(server="pihole"))
    assert c.calls == []


def test_describe_lists_changes() -> None:
    p = Plan(server="adguard", add_allow={"b.com"}, remove_deny={"z.com"})
    text = p.describe()
    assert "[adguard] allow +1 -0, deny +0 -1" in text
    assert "+ allow b.com" in text
    assert "- deny  z.com" in text
    assert "\n" not in p.describe(verbose=False)


# --------------------------------------------------------------------------- CLI


def _cfg(
    tmp_path: Path,
    allow: str = "a.com\n",
    deny: str = "x.com\n",
    prune: bool = False,
    linked_ip_url: str | None = None,
) -> Any:
    (tmp_path / "allow.txt").write_text(allow)
    (tmp_path / "deny.txt").write_text(deny)
    return SimpleNamespace(
        lists=SimpleNamespace(
            allowlist=[tmp_path / "allow.txt"], denylist=[tmp_path / "deny.txt"], prune=prune
        ),
        nextdns=SimpleNamespace(linked_ip_url=linked_ip_url) if linked_ip_url else None,
    )


@pytest.fixture
def wire(monkeypatch: pytest.MonkeyPatch):
    def _wire(cfg: Any, clients: list[FakeClient]) -> None:
        monkeypatch.setattr(cli, "_load_config", lambda path: cfg)
        monkeypatch.setattr(cli, "_build_clients", lambda c: clients)

    return _wire


def test_cli_sync_dry_run_does_not_write(tmp_path, wire, capsys) -> None:
    c = FakeClient("pihole")
    wire(_cfg(tmp_path), [c])
    assert cli.main(["sync"]) == 0
    out = capsys.readouterr().out
    assert "+ allow a.com" in out
    assert "dry run" in out
    assert c.calls == []
    assert c.closed


def test_cli_sync_apply_writes(tmp_path, wire) -> None:
    c = FakeClient("pihole")
    wire(_cfg(tmp_path), [c])
    assert cli.main(["sync", "--apply"]) == 0
    assert c.allow == {"a.com"}
    assert c.deny == {"x.com"}


def test_cli_sync_one_failure_does_not_block_others(tmp_path, wire, capsys) -> None:
    bad = FakeClient("adguard", fail=True)
    good = FakeClient("nextdns")
    wire(_cfg(tmp_path), [bad, good])
    assert cli.main(["sync", "--apply"]) == 1
    assert good.allow == {"a.com"}
    assert "[adguard] ERROR" in capsys.readouterr().err


def test_cli_sync_conflict_is_config_error_and_touches_nothing(tmp_path, wire, capsys) -> None:
    c = FakeClient("pihole")
    wire(_cfg(tmp_path, allow="dup.com\n", deny="dup.com\n"), [c])
    assert cli.main(["sync", "--apply"]) == 2
    assert "dup.com" in capsys.readouterr().err
    assert c.calls == []


def test_cli_update_dry_run_default(tmp_path, wire, capsys) -> None:
    c = FakeClient("pihole")
    wire(_cfg(tmp_path), [c])
    assert cli.main(["update"]) == 0
    assert c.update_calls == [True]
    assert cli.main(["update", "--apply"]) == 0
    assert c.update_calls == [True, False]


def test_cli_status(tmp_path, wire, capsys) -> None:
    wire(_cfg(tmp_path), [FakeClient("pihole"), FakeClient("adguard", fail=True)])
    assert cli.main(["status"]) == 1
    out = capsys.readouterr().out
    assert "pihole" in out and "OK" in out
    assert "FAIL" in out


def test_cli_config_error_exit_2(tmp_path, monkeypatch, capsys) -> None:
    def boom(path: str) -> Any:
        raise cli.ConfigError("nope")

    monkeypatch.setattr(cli, "_load_config", boom)
    assert cli.main(["status"]) == 2
    assert "config error" in capsys.readouterr().err


def test_cli_linked_ip_requires_url(tmp_path, wire) -> None:
    wire(_cfg(tmp_path), [])
    assert cli.main(["linked-ip"]) == 2


def test_cli_linked_ip(tmp_path, wire, monkeypatch, capsys) -> None:
    wire(_cfg(tmp_path, linked_ip_url="https://link-ip.nextdns.io/abc/def"), [])
    import dnsstack.linkedip as linkedip

    monkeypatch.setattr(linkedip, "update_linked_ip", lambda url, http=None: "1.2.3.4")
    assert cli.main(["linked-ip"]) == 0
    assert "1.2.3.4" in capsys.readouterr().out


def test_update_linked_ip_http() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/abc/def"
        return httpx.Response(200, text="203.0.113.7\n")

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        assert update_linked_ip("https://link-ip.nextdns.io/abc/def", http=http) == "203.0.113.7"


def test_update_linked_ip_error() -> None:
    transport = httpx.MockTransport(lambda r: httpx.Response(403))
    with httpx.Client(transport=transport) as http, pytest.raises(httpx.HTTPStatusError):
        update_linked_ip("https://link-ip.nextdns.io/abc/def", http=http)
