"""Persistent collector state: per-server cursors and recent ids for dedupe."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DEFAULT_MAX_RECENT = 5000


def _to_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=UTC)
    return ts.astimezone(UTC)


class CollectorState:
    """JSON-backed state file.

    Layout::

        {"servers": {"<name>": {"cursor": str|None,
                                "last_ts": iso str|None,
                                "recent_ids": [str, ...]}}}
    """

    def __init__(self, path: str | Path, max_recent: int = DEFAULT_MAX_RECENT) -> None:
        self.path = Path(path)
        self.max_recent = max_recent
        self._servers: dict[str, dict[str, Any]] = {}

    # ---- persistence -------------------------------------------------
    def load(self) -> None:
        """Load state from disk. A missing or corrupt file yields empty state."""
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            self._servers = {}
            return
        except (OSError, ValueError) as exc:
            log.warning("state file %s unreadable (%s); starting fresh", self.path, exc)
            self._servers = {}
            return
        servers = raw.get("servers", {}) if isinstance(raw, dict) else {}
        self._servers = {}
        for name, entry in servers.items():
            if not isinstance(entry, dict):
                continue
            ids = entry.get("recent_ids") or []
            self._servers[str(name)] = {
                "cursor": entry.get("cursor"),
                "last_ts": entry.get("last_ts"),
                "recent_ids": [str(i) for i in ids][-self.max_recent :],
            }

    def save(self) -> None:
        """Atomically write state (tmp file in same dir + os.replace)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps({"servers": self._servers}, separators=(",", ":"))
        fd, tmp = tempfile.mkstemp(prefix=".state-", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise

    # ---- accessors ---------------------------------------------------
    def _entry(self, server: str) -> dict[str, Any]:
        return self._servers.setdefault(server, {"cursor": None, "last_ts": None, "recent_ids": []})

    def cursor(self, server: str) -> str | None:
        return self._servers.get(server, {}).get("cursor")

    def last_ts(self, server: str) -> datetime | None:
        value = self._servers.get(server, {}).get("last_ts")
        if not value:
            return None
        try:
            return _to_utc(datetime.fromisoformat(value))
        except ValueError:
            return None

    def recent_ids(self, server: str) -> list[str]:
        return list(self._servers.get(server, {}).get("recent_ids", []))

    def set_cursor(self, server: str, cursor: str | None) -> None:
        self._entry(server)["cursor"] = cursor

    def record_pushed(self, server: str, last_ts: datetime | None, ids: Iterable[str]) -> None:
        """Advance last_ts (never backwards) and append ids to the bounded window."""
        entry = self._entry(server)
        if last_ts is not None:
            current = self.last_ts(server)
            new = _to_utc(last_ts)
            if current is None or new > current:
                entry["last_ts"] = new.isoformat()
        recent: list[str] = entry["recent_ids"]
        recent.extend(ids)
        if len(recent) > self.max_recent:
            del recent[: len(recent) - self.max_recent]

    def servers(self) -> list[str]:
        return list(self._servers)
