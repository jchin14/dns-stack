"""dnsstack command-line interface."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dnsstack.clients import DnsServerClient
    from dnsstack.config import AppConfig

log = logging.getLogger("dnsstack")

EXIT_OK = 0
EXIT_RUNTIME = 1
EXIT_CONFIG = 2

DEFAULT_CONFIG = "./config/config.yaml"


class ConfigError(Exception):
    """Configuration could not be loaded or is incomplete."""


# --------------------------------------------------------------------------- helpers


def _load_config(path: str) -> AppConfig:
    from pydantic import ValidationError

    from dnsstack.config import ConfigError as LoaderConfigError
    from dnsstack.config import load_config

    try:
        return load_config(path)
    except LoaderConfigError as exc:
        raise ConfigError(str(exc)) from exc
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {path}") from exc
    except ValidationError as exc:
        raise ConfigError(f"invalid config {path}:\n{exc}") from exc
    except (ValueError, KeyError, OSError) as exc:
        # yaml.YAMLError subclasses Exception only; caught below in main().
        raise ConfigError(f"cannot load config {path}: {exc}") from exc


def _build_clients(cfg: AppConfig) -> list[DnsServerClient]:
    from dnsstack.clients import build_clients

    clients = build_clients(cfg)
    if not clients:
        raise ConfigError("no DNS servers configured (add a pihole, adguard or nextdns section)")
    return clients


def _close_all(clients: Sequence[DnsServerClient]) -> None:
    for c in clients:
        try:
            c.close()
        except Exception:  # noqa: BLE001 - best effort cleanup
            log.debug("error closing %s", getattr(c, "name", c), exc_info=True)


def _stop_event() -> threading.Event:
    """Event set on SIGINT/SIGTERM so loops exit cleanly (docker stop)."""
    stop = threading.Event()

    def _handler(signum: int, _frame: object) -> None:
        log.info("received signal %d, stopping", signum)
        stop.set()

    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, _handler)
        signal.signal(signal.SIGINT, _handler)
    return stop


def _print_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> None:
    widths = [len(h) for h in headers]
    for row in rows:
        widths = [max(w, len(cell)) for w, cell in zip(widths, row, strict=True)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*("-" * w for w in widths)))
    for row in rows:
        print(fmt.format(*row))


# --------------------------------------------------------------------------- commands


def cmd_status(args: argparse.Namespace, cfg: AppConfig) -> int:
    clients = _build_clients(cfg)
    try:
        rows: list[list[str]] = []
        all_ok = True
        for c in clients:
            try:
                h = c.health()
                ok, detail, version = h.ok, h.detail, h.version or "-"
            except Exception as exc:  # noqa: BLE001 - report, don't crash
                log.debug("health check failed for %s", c.name, exc_info=True)
                ok, detail, version = False, f"{type(exc).__name__}: {exc}", "-"
            all_ok &= ok
            rows.append([c.name, "OK" if ok else "FAIL", version, detail])
        _print_table(["SERVER", "STATUS", "VERSION", "DETAIL"], rows)
        return EXIT_OK if all_ok else EXIT_RUNTIME
    finally:
        _close_all(clients)


def run_sync(cfg: AppConfig, apply_changes: bool, verbose: bool = True) -> int:
    """Plan (and optionally apply) list sync on every server.

    Returns EXIT_OK if every server succeeded, EXIT_RUNTIME otherwise.  List
    file errors / allow-deny conflicts raise before any server is contacted.
    """
    from dnsstack import sync

    desired = sync.desired_state(cfg.lists.allowlist, cfg.lists.denylist)
    log.info("desired state: %d allow, %d deny", len(desired.allow), len(desired.deny))
    clients = _build_clients(cfg)
    failed = 0
    try:
        for c in clients:
            try:
                p = sync.plan(c, desired, prune=cfg.lists.prune)
                print(p.describe(verbose=verbose))
                if apply_changes and not p.is_empty:
                    sync.apply(c, p)
                    print(f"[{c.name}] applied")
            except Exception as exc:  # noqa: BLE001 - one server must not block others
                failed += 1
                log.debug("sync failed for %s", c.name, exc_info=True)
                print(f"[{c.name}] ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        if not apply_changes:
            print("\n(dry run - re-run with --apply to write changes)")
    finally:
        _close_all(clients)
    return EXIT_RUNTIME if failed else EXIT_OK


def cmd_sync(args: argparse.Namespace, cfg: AppConfig) -> int:
    return run_sync(cfg, apply_changes=args.apply)


def cmd_watch_sync(args: argparse.Namespace, cfg: AppConfig) -> int:
    from dnsstack import sync

    stop = _stop_event()
    while not stop.is_set():
        try:
            # Re-load list files each round so edits are picked up without restart.
            run_sync(cfg, apply_changes=True, verbose=False)
        except (sync.ListFileError, sync.ListConflictError) as exc:
            print(f"sync skipped: {exc}", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001 - keep the loop alive
            log.debug("sync round failed", exc_info=True)
            print(f"sync round failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.stdout.flush()
        stop.wait(args.interval)
    return EXIT_OK


def cmd_update(args: argparse.Namespace, cfg: AppConfig) -> int:
    clients = _build_clients(cfg)
    failed = 0
    try:
        for c in clients:
            try:
                msg = c.update(dry_run=not args.apply)
                print(f"[{c.name}] {msg}")
            except Exception as exc:  # noqa: BLE001
                failed += 1
                log.debug("update failed for %s", c.name, exc_info=True)
                print(f"[{c.name}] ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        if not args.apply:
            print("\n(dry run - re-run with --apply to install updates)")
    finally:
        _close_all(clients)
    return EXIT_RUNTIME if failed else EXIT_OK


def cmd_collect(args: argparse.Namespace, cfg: AppConfig) -> int:
    from dnsstack.collector import Collector
    from dnsstack.loki import LokiPusher
    from dnsstack.state import CollectorState

    clients = _build_clients(cfg)
    pusher = LokiPusher(cfg.loki.url, tenant=cfg.loki.tenant)
    state = CollectorState(cfg.collector.state_path)
    collector = Collector(clients, pusher, state, cfg.collector)
    try:
        if args.once:
            counts = collector.run_once()
            for server, n in counts.items():
                print(f"[{server}] pushed {n} records")
            return EXIT_OK
        collector.run_forever(_stop_event())
        return EXIT_OK
    finally:
        close = getattr(pusher, "close", None)
        if callable(close):
            close()
        _close_all(clients)


def cmd_linked_ip(args: argparse.Namespace, cfg: AppConfig) -> int:
    from dnsstack.linkedip import update_linked_ip

    url = cfg.nextdns.linked_ip_url if cfg.nextdns else None
    if not url:
        raise ConfigError("nextdns.linked_ip_url is not configured")

    if not args.interval:
        print(update_linked_ip(url))
        return EXIT_OK

    stop = _stop_event()
    while not stop.is_set():
        try:
            print(update_linked_ip(url), flush=True)
        except Exception as exc:  # noqa: BLE001 - keep looping
            log.debug("linked-ip update failed", exc_info=True)
            # Don't print the exception text verbatim: httpx includes the URL,
            # which embeds the secret link-ip token.
            print(f"linked-ip update failed: {type(exc).__name__}", file=sys.stderr, flush=True)
        stop.wait(args.interval)
    return EXIT_OK


# --------------------------------------------------------------------------- parser


def _positive_int(value: str) -> int:
    n = int(value)
    if n <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return n


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dnsstack",
        description=(
            "Keep Pi-hole, AdGuard Home and NextDNS in sync and ship their query logs to Loki."
        ),
    )
    parser.add_argument(
        "--config",
        default=os.environ.get("DNSSTACK_CONFIG", DEFAULT_CONFIG),
        help="path to config.yaml (default: $DNSSTACK_CONFIG or %(default)s)",
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("DNSSTACK_LOG_LEVEL", "INFO"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        type=str.upper,
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p = sub.add_parser("status", help="show health of each server")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("sync", help="reconcile allow/deny lists (dry run unless --apply)")
    p.add_argument("--apply", action="store_true", help="write changes to servers")
    p.set_defaults(func=cmd_sync)

    p = sub.add_parser("update", help="update server software (dry run unless --apply)")
    p.add_argument("--apply", action="store_true", help="actually perform updates")
    p.set_defaults(func=cmd_update)

    p = sub.add_parser("collect", help="ship query logs to Loki")
    p.add_argument("--once", action="store_true", help="run a single collection cycle and exit")
    p.set_defaults(func=cmd_collect)

    p = sub.add_parser("linked-ip", help="update the NextDNS linked IP")
    p.add_argument("--interval", type=_positive_int, default=None, help="repeat every N seconds")
    p.set_defaults(func=cmd_linked_ip)

    p = sub.add_parser("watch-sync", help="run 'sync --apply' in a loop")
    p.add_argument(
        "--interval", type=_positive_int, default=3600, help="seconds between runs (default 3600)"
    )
    p.set_defaults(func=cmd_watch_sync)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    debug = args.log_level == "DEBUG"
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    # httpx logs every request URL at INFO; NextDNS link-ip URLs are secrets.
    if not debug:
        logging.getLogger("httpx").setLevel(logging.WARNING)

    func: Callable[[argparse.Namespace, AppConfig], int] = args.func
    try:
        cfg = _load_config(args.config)
        return func(args, cfg)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except KeyboardInterrupt:
        return EXIT_RUNTIME
    except Exception as exc:  # noqa: BLE001
        from dnsstack import sync

        if debug:
            log.exception("command failed")
        if isinstance(exc, sync.ListFileError | sync.ListConflictError):
            print(f"list error: {exc}", file=sys.stderr)
            return EXIT_CONFIG
        if type(exc).__name__ == "YAMLError" or type(exc).__module__.startswith("yaml"):
            print(f"config error: {exc}", file=sys.stderr)
            return EXIT_CONFIG
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_RUNTIME


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
