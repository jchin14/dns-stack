"""Poll each DNS server for query logs and push them to Loki."""

from __future__ import annotations

import json
import logging
import signal
import threading
import time
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any

from dnsstack.models import QueryRecord, ServerHealth

if TYPE_CHECKING:
    from dnsstack.clients import DnsServerClient
    from dnsstack.config import CollectorConfig
    from dnsstack.loki import LokiPusher
    from dnsstack.state import CollectorState

log = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Collector:
    def __init__(
        self,
        clients: Sequence[DnsServerClient],
        pusher: LokiPusher,
        state: CollectorState,
        cfg: CollectorConfig,
    ) -> None:
        self.clients = list(clients)
        self.pusher = pusher
        self.state = state
        self.cfg = cfg
        self._lock = threading.Lock()
        self.last_success: dict[str, datetime] = {}
        self.last_error: dict[str, str] = {}
        self.started_at = _utcnow()
        self._httpd: ThreadingHTTPServer | None = None
        self.state.load()

    # ---- one cycle ---------------------------------------------------
    def run_once(self) -> dict[str, int]:
        results: dict[str, int] = {}
        healths: list[ServerHealth] = []
        for client in self.clients:
            name = client.name
            try:
                healths.append(client.health())
            except Exception as exc:  # noqa: BLE001 - one server must not stop others
                healths.append(ServerHealth(server=name, ok=False, detail=str(exc), version=None))
            try:
                results[name] = self._collect_one(client)
                with self._lock:
                    self.last_success[name] = _utcnow()
                    self.last_error.pop(name, None)
            except Exception as exc:  # noqa: BLE001
                log.error(
                    "collect from %s failed: %s",
                    name,
                    exc,
                    exc_info=log.isEnabledFor(logging.DEBUG),
                )
                with self._lock:
                    self.last_error[name] = str(exc)
                results[name] = 0
        try:
            self.pusher.push_health(healths)
        except Exception as exc:  # noqa: BLE001
            log.error("health push failed: %s", exc)
        return results

    def _collect_one(self, client: DnsServerClient) -> int:
        name = client.name
        last_ts = self.state.last_ts(name)
        since = last_ts or (_utcnow() - timedelta(minutes=self.cfg.lookback_minutes))
        cursor = self.state.cursor(name)
        records, new_cursor = client.fetch_queries(since, cursor)

        seen = set(self.state.recent_ids(name))
        fresh: list[QueryRecord] = []
        for rec in records:
            if rec.id in seen:
                continue
            if last_ts is not None and rec.ts < last_ts:
                continue  # older than what we already pushed and not in id window
            seen.add(rec.id)
            fresh.append(rec)
        fresh.sort(key=lambda r: r.ts)

        batch = max(1, self.cfg.batch_size)
        for i in range(0, len(fresh), batch):
            chunk = fresh[i : i + batch]
            self.pusher.push(chunk)  # raises on failure; state only advances for pushed chunks
            self.state.record_pushed(name, chunk[-1].ts, (r.id for r in chunk))
            self.state.save()
        self.state.set_cursor(name, new_cursor)
        self.state.save()
        log.info("%s: %d fetched, %d pushed", name, len(records), len(fresh))
        return len(fresh)

    # ---- loop --------------------------------------------------------
    def run_forever(self, stop_event: threading.Event | None = None) -> None:
        stop = stop_event or threading.Event()
        self._install_signal_handlers(stop)
        self.start_health_server()
        try:
            while not stop.is_set():
                started = time.monotonic()
                self.run_once()
                elapsed = time.monotonic() - started
                stop.wait(max(0.0, self.cfg.poll_interval_s - elapsed))
        finally:
            self.stop_health_server()
            log.info("collector stopped")

    @staticmethod
    def _install_signal_handlers(stop: threading.Event) -> None:
        if threading.current_thread() is not threading.main_thread():
            return

        def handler(signum: int, _frame: Any) -> None:
            log.info("received signal %d, shutting down", signum)
            stop.set()

        signal.signal(signal.SIGTERM, handler)
        signal.signal(signal.SIGINT, handler)

    # ---- health ------------------------------------------------------
    def health_status(self) -> tuple[int, dict[str, Any]]:
        now = _utcnow()
        window = timedelta(seconds=5 * self.cfg.poll_interval_s)
        with self._lock:
            servers = {
                c.name: {
                    "last_success": self.last_success[c.name].isoformat()
                    if c.name in self.last_success
                    else None,
                    "error": self.last_error.get(c.name),
                }
                for c in self.clients
            }
            latest = max(self.last_success.values(), default=None)
        healthy = latest is not None and now - latest <= window
        body = {"ok": healthy, "now": now.isoformat(), "servers": servers}
        return (200 if healthy else 503), body

    def start_health_server(self, host: str = "0.0.0.0", port: int | None = None) -> int:
        """Start /healthz in a daemon thread; returns the bound port."""
        collector = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path.split("?", 1)[0] != "/healthz":
                    self.send_error(404)
                    return
                code, body = collector.health_status()
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, fmt: str, *args: Any) -> None:
                log.debug("healthz: " + fmt, *args)

        self._httpd = ThreadingHTTPServer(
            (host, self.cfg.health_port if port is None else port), Handler
        )
        self._httpd.daemon_threads = True
        threading.Thread(target=self._httpd.serve_forever, name="healthz", daemon=True).start()
        return self._httpd.server_address[1]

    def stop_health_server(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
