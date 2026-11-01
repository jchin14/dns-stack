"""Allow/deny list reconciliation across DNS servers.

Desired state comes from plain-text list files; each server's current state is
read through its client, diffed, and (optionally) written back.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from dnsstack.models import ListState

if TYPE_CHECKING:
    from dnsstack.clients import DnsServerClient

log = logging.getLogger(__name__)

# One DNS label: 1-63 chars of [a-z0-9_-], not starting/ending with '-'.
# Underscore is allowed because real-world service names (e.g. _dmarc) use it.
_LABEL = r"(?!-)[a-z0-9_-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)*{_LABEL}$")

# Hostnames that appear in hosts files but must never be synced.
_HOSTS_IGNORE = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "local",
        "broadcasthost",
        "ip6-localhost",
        "ip6-loopback",
        "ip6-localnet",
        "ip6-mcastprefix",
        "ip6-allnodes",
        "ip6-allrouters",
        "ip6-allhosts",
        "0.0.0.0",
    }
)


class ListFileError(ValueError):
    """A list file is missing or contains an invalid entry."""


class ListConflictError(ValueError):
    """The same domain appears in both the allow and deny lists."""


def normalize_domain(raw: str) -> str:
    """Lowercase, strip whitespace and a trailing dot."""
    return raw.strip().lower().rstrip(".")


def is_valid_domain(domain: str) -> bool:
    return 0 < len(domain) <= 253 and bool(_DOMAIN_RE.match(domain))


def _is_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
    except ValueError:
        return False
    return True


def parse_list_lines(lines: Iterable[str], source: str = "<input>") -> set[str]:
    """Parse list-file lines into a set of normalised domains.

    Accepted forms per line:
      * ``example.com``
      * ``example.com  # inline comment``
      * ``0.0.0.0 example.com [other.com ...]`` (hosts-file style)
    Blank lines and ``#`` comments are ignored.  Raises ListFileError on an
    invalid domain so typos are caught instead of silently dropped.
    """
    domains: set[str] = set()
    for lineno, line in enumerate(lines, start=1):
        content = line.split("#", 1)[0].strip()
        if not content:
            continue
        tokens = content.split()
        if _is_ip(tokens[0]):
            candidates = [t for t in tokens[1:] if normalize_domain(t) not in _HOSTS_IGNORE]
        else:
            if len(tokens) > 1:
                raise ListFileError(
                    f"{source}:{lineno}: expected one domain per line, got {content!r}"
                )
            candidates = tokens
        for token in candidates:
            domain = normalize_domain(token)
            if not is_valid_domain(domain):
                raise ListFileError(f"{source}:{lineno}: invalid domain {token!r}")
            domains.add(domain)
    return domains


def load_list_files(paths: Iterable[str | Path]) -> set[str]:
    """Load and merge several list files.  Missing files raise ListFileError."""
    domains: set[str] = set()
    for p in paths:
        path = Path(p)
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise ListFileError(f"list file not found: {path}") from exc
        except OSError as exc:
            raise ListFileError(f"cannot read list file {path}: {exc}") from exc
        domains |= parse_list_lines(text.splitlines(), source=str(path))
    return domains


def desired_state(allow_paths: Iterable[str | Path], deny_paths: Iterable[str | Path]) -> ListState:
    """Build the desired ListState from files, rejecting allow/deny overlaps."""
    allow = load_list_files(allow_paths)
    deny = load_list_files(deny_paths)
    overlap = allow & deny
    if overlap:
        raise ListConflictError(
            "domains present in both allow and deny lists: " + ", ".join(sorted(overlap))
        )
    return ListState(allow=allow, deny=deny)


@dataclass
class Plan:
    server: str
    add_allow: set[str] = field(default_factory=set)
    remove_allow: set[str] = field(default_factory=set)
    add_deny: set[str] = field(default_factory=set)
    remove_deny: set[str] = field(default_factory=set)

    @property
    def is_empty(self) -> bool:
        return not (self.add_allow or self.remove_allow or self.add_deny or self.remove_deny)

    def counts(self) -> dict[str, int]:
        return {
            "add_allow": len(self.add_allow),
            "remove_allow": len(self.remove_allow),
            "add_deny": len(self.add_deny),
            "remove_deny": len(self.remove_deny),
        }

    def describe(self, verbose: bool = True) -> str:
        """Human-readable summary, one change per line when verbose."""
        if self.is_empty:
            return f"[{self.server}] in sync, no changes"
        c = self.counts()
        header = (
            f"[{self.server}] allow +{c['add_allow']} -{c['remove_allow']}, "
            f"deny +{c['add_deny']} -{c['remove_deny']}"
        )
        if not verbose:
            return header
        lines = [header]
        for label, sign, items in (
            ("allow", "+", self.add_allow),
            ("allow", "-", self.remove_allow),
            ("deny", "+", self.add_deny),
            ("deny", "-", self.remove_deny),
        ):
            lines.extend(f"  {sign} {label:5} {d}" for d in sorted(items))
        return "\n".join(lines)


def plan(client: DnsServerClient, desired: ListState, prune: bool) -> Plan:
    """Diff a server's current lists against the desired state.

    Without ``prune`` entries are only added, never removed, with one
    exception: a desired allow domain that the server currently denies (or
    vice versa) is removed from the opposite list, because leaving it in both
    would make the server's behaviour depend on its precedence rules.
    """
    current = client.get_lists()
    add_allow = desired.allow - current.allow
    add_deny = desired.deny - current.deny
    if prune:
        remove_allow = current.allow - desired.allow
        remove_deny = current.deny - desired.deny
    else:
        remove_allow = current.allow & desired.deny
        remove_deny = current.deny & desired.allow
    return Plan(
        server=client.name,
        add_allow=add_allow,
        remove_allow=remove_allow,
        add_deny=add_deny,
        remove_deny=remove_deny,
    )


def apply(client: DnsServerClient, plan: Plan) -> None:
    """Write a plan to the server.  Removals go first so a domain moving
    between lists is never in both at once."""
    if plan.remove_allow:
        log.info("[%s] removing %d allow entries", plan.server, len(plan.remove_allow))
        client.remove_allow(set(plan.remove_allow))
    if plan.remove_deny:
        log.info("[%s] removing %d deny entries", plan.server, len(plan.remove_deny))
        client.remove_deny(set(plan.remove_deny))
    if plan.add_allow:
        log.info("[%s] adding %d allow entries", plan.server, len(plan.add_allow))
        client.add_allow(set(plan.add_allow))
    if plan.add_deny:
        log.info("[%s] adding %d deny entries", plan.server, len(plan.add_deny))
        client.add_deny(set(plan.add_deny))
