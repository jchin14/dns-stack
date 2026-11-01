from pathlib import Path

import pytest

from dnsstack.sync import (
    ListConflictError,
    ListFileError,
    desired_state,
    load_list_files,
    parse_list_lines,
)

REPO = Path(__file__).resolve().parent.parent


def test_parse_basic_comments_and_case() -> None:
    lines = [
        "# header comment",
        "",
        "   ",
        "Example.COM",
        "foo.example.org.   # inline comment",
        "\tbar.net\t",
    ]
    assert parse_list_lines(lines) == {"example.com", "foo.example.org", "bar.net"}


def test_parse_hosts_style() -> None:
    lines = [
        "0.0.0.0 ads.example.com",
        "127.0.0.1 localhost",
        "::1 ip6-localhost ip6-loopback",
        "0.0.0.0 0.0.0.0",
        "0.0.0.0 a.com b.com  # two on one line",
    ]
    assert parse_list_lines(lines) == {"ads.example.com", "a.com", "b.com"}


def test_parse_underscore_and_single_label() -> None:
    assert parse_list_lines(["_dmarc.example.com", "intranet"]) == {
        "_dmarc.example.com",
        "intranet",
    }


@pytest.mark.parametrize(
    "bad",
    [
        "exa mple.com",
        "bad!domain.com",
        "-lead.com",
        "trail-.com",
        "a..b",
        "||adblock^",
        "x" * 64 + ".com",
    ],
)
def test_parse_rejects_invalid(bad: str) -> None:
    with pytest.raises(ListFileError):
        parse_list_lines([bad], source="f.txt")


def test_invalid_error_mentions_location() -> None:
    with pytest.raises(ListFileError, match=r"f\.txt:2"):
        parse_list_lines(["ok.com", "not valid!"], source="f.txt")


def test_load_list_files_merges(tmp_path: Path) -> None:
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("one.com\ntwo.com\n")
    b.write_text("TWO.com.\nthree.com\n")
    assert load_list_files([a, str(b)]) == {"one.com", "two.com", "three.com"}


def test_load_list_files_missing(tmp_path: Path) -> None:
    with pytest.raises(ListFileError, match="not found"):
        load_list_files([tmp_path / "nope.txt"])


def test_desired_state_conflict(tmp_path: Path) -> None:
    allow = tmp_path / "allow.txt"
    deny = tmp_path / "deny.txt"
    allow.write_text("both.com\nok.com\n")
    deny.write_text("Both.com\nbad.com\n")
    with pytest.raises(ListConflictError, match="both.com"):
        desired_state([allow], [deny])


def test_desired_state_ok(tmp_path: Path) -> None:
    allow = tmp_path / "allow.txt"
    deny = tmp_path / "deny.txt"
    allow.write_text("ok.com\n")
    deny.write_text("bad.com\n")
    state = desired_state([allow], [deny])
    assert state.allow == {"ok.com"}
    assert state.deny == {"bad.com"}


def test_shipped_lists_parse() -> None:
    lists = REPO / "lists"
    state = desired_state(
        [lists / "allowlist.txt", lists / "cashback-allowlist.txt"], [lists / "denylist.txt"]
    )
    assert "prf.hn" in state.allow
    assert "redirect.viglink.com" in state.allow
    assert len(state.allow) >= 16
