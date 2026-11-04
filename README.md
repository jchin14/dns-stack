# dns-stack

Keep **Pi-hole v6** (Raspberry Pi), **AdGuard Home** (VM) and **NextDNS** (cloud)
in sync as redundant DNS resolvers, and pull all of their query logs into a
single **Loki + Grafana** dashboard.

- **Lists:** one set of allow/deny files in git, pushed to all three servers.
- **Logs:** a collector polls each server's query log and ships it to Loki.
- **Dashboard:** queries/min, blocked %, top domains and clients, client ->
  server matrix, server health and a searchable query log.
- **Updates:** Pi-hole and AdGuard software updates from one command.

## Architecture

```
                        LAN clients
          (DHCP hands out all three resolvers as DNS 1/2/3)
               |                 |                  |
               v                 v                  v
        +-------------+   +-------------+   +---------------+
        |  Pi-hole v6 |   | AdGuard Home|   |    NextDNS    |
        | (Rasp. Pi)  |   |    (VM)     |   |    (cloud)    |
        +------+------+   +------+------+   +-------+-------+
               ^  |              ^  |               ^  |
   lists (sync)|  |query log      |  |               |  |
               |  v              |  v               |  v
        +------+-----------------+------------------+------+
        |                 dns-stack (docker compose)       |
        |                                                  |
        |  sync ------- lists/*.txt  (allow / deny)        |
        |  linked-ip -- keeps NextDNS linked IP current    |
        |  collector -- polls logs -> Loki  (:8080/healthz)|
        |                     |                            |
        |                     v                            |
        |                   Loki  (30d retention, :3100)   |
        |                     |                            |
        |                     v                            |
        |                  Grafana  (:3000)                |
        +--------------------------------------------------+
```

Loki labels are kept deliberately low-cardinality: `job` (`dns` or
`dns-health`), `server` and `status` (`blocked`, `allowed`, `cached`,
`other`). Everything else (`client`, `domain`, `qtype`, `reason`, `upstream`,
`response_ms`, `id`) lives in the JSON log line and is extracted with `| json`.

## Caveats - read these first

1. **Client failover is not load balancing.** Handing out three DNS servers
   via DHCP gives redundancy, but clients choose for themselves: most stick to
   the first one that answers, some (Android, Windows) race or rotate. Expect
   uneven traffic. The *client -> server matrix* panel shows who uses what. A
   blocklist only protects clients while they use a resolver that has it,
   which is why keeping the lists in sync matters.
2. **Don't chain the resolvers.** Do not point Pi-hole's upstream at AdGuard,
   or AdGuard's at NextDNS, etc. Chaining turns three independent backups into
   one serial point of failure, double-counts every query in the dashboard and
   hides the real client IP from the downstream server. Give each server its
   own independent upstreams.
3. **NextDNS linked IP / single client.** Plain DNS (port 53) to NextDNS
   identifies your profile only by your public IP, so the *Linked IP* must be
   kept current; the `linked-ip` service calls the profile's link-ip URL every
   5 minutes. Because all LAN traffic arrives from one NAT address, NextDNS
   sees your whole network as **a single client** - per-device stats there are
   not available unless devices use DoH/DoT with a device ID. Only one public
   IP can be linked per profile.
4. **Cashback allowlist.** Cashback / affiliate sites (e.g. ShopBack, Cashrewards,
   TopCashback) rely on tracking and redirect domains that common blocklists
   block, so purchases silently fail to track. `lists/cashback-allowlist.txt`
   holds those domains and is synced as an allowlist. Allowing them also
   allows their tracking for every client on the network - that trade-off is
   yours to make.

## Quickstart

Requirements: Docker with Compose v2, network access from the Docker host to
Pi-hole and AdGuard, and a NextDNS API key (Account page).

```sh
git clone https://github.com/jchin14/dns-stack.git
cd dns-stack
cp .env.example .env                              # fill in URLs and secrets
cp config/config.example.yaml config/config.yaml  # usually no edits needed
mkdir -p lists && touch lists/allowlist.txt lists/cashback-allowlist.txt lists/denylist.txt

docker compose build
docker compose run --rm collector status          # check connectivity
docker compose run --rm sync sync                 # dry-run: see what would change
docker compose up -d
```

Open Grafana at <http://localhost:3000> (user `admin`, password
`GF_ADMIN_PASSWORD`). The **DNS Overview** dashboard is provisioned
automatically.

The `sync` service applies list changes every `SYNC_INTERVAL` seconds
(default 3600). It only **adds** entries unless `lists.prune: true`.

### Running without Docker

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
set -a; . ./.env; set +a
dnsstack --config config/config.yaml status
```

## List files

Plain text, one domain per line. Blank lines and `#` comments (whole-line or
inline) are ignored, domains are lowercased and a trailing dot is stripped.
Hosts-file lines like `0.0.0.0 ads.example.com` are accepted. Only **exact**
domains are synced (Pi-hole exact allow/deny, AdGuard `@@||domain^` /
`||domain^` user rules, NextDNS allowlist/denylist). Other AdGuard custom
rules you've written by hand are preserved. A domain present in both an allow
and a deny file is an error and nothing is changed.

```
# lists/denylist.txt
telemetry.example.com
0.0.0.0 ads.example.net   # hosts style is fine
```

## Configuration reference

`config/config.yaml` (see `config/config.example.yaml`). Any string may be
`${ENV_VAR}` or `${ENV_VAR:-default}`. Omit a server section to disable it.

| Key | Default | Description |
| --- | --- | --- |
| `pihole.name` | `pihole` | Name used in the `server` label |
| `pihole.url` | - | e.g. `http://172.20.1.41` |
| `pihole.password` | - | Pi-hole web/app password |
| `pihole.verify_tls` | `true` | Verify HTTPS certificates |
| `pihole.ssh_host` | `null` | ssh host/alias for `update --apply` (`sudo pihole -up`) |
| `adguard.name` | `adguard` | Name used in the `server` label |
| `adguard.url` | - | e.g. `http://172.20.1.42:3000` |
| `adguard.username` / `password` | - | AdGuard Home admin credentials |
| `adguard.verify_tls` | `true` | Verify HTTPS certificates |
| `nextdns.name` | `nextdns` | Name used in the `server` label |
| `nextdns.profile_id` | - | Profile ID (e.g. `abc123`) |
| `nextdns.api_key` | - | API key from the NextDNS account page |
| `nextdns.linked_ip_url` | `null` | Link-IP URL from the profile's Setup page |
| `lists.allowlist` | `[lists/allowlist.txt, lists/cashback-allowlist.txt]` | Allow files (relative to CWD, `/app` in the container) |
| `lists.denylist` | `[lists/denylist.txt]` | Deny files |
| `lists.prune` | `false` | Also remove server entries not in the files |
| `loki.url` | `http://loki:3100` | Loki base URL |
| `loki.tenant` | `null` | `X-Scope-OrgID` for multi-tenant Loki |
| `collector.poll_interval_s` | `15` | Seconds between polls |
| `collector.batch_size` | `500` | Records per Loki push |
| `collector.state_path` | `/data/state.json` | Cursor / dedupe state |
| `collector.health_port` | `8080` | Port for `GET /healthz` |
| `collector.lookback_minutes` | `10` | History fetched on first run |

Environment variables (`.env`): see `.env.example`. `GF_ADMIN_PASSWORD` is
required by Compose; `SYNC_INTERVAL` controls the sync loop.

### Pi-hole updates over ssh

`dnsstack update --apply` runs `ssh <ssh_host> 'sudo pihole -up'`. To use it
from the container, mount an ssh key and known_hosts read-only, e.g. add to a
compose override:

```yaml
services:
  sync:
    volumes:
      - ~/.ssh/dnsstack_ed25519:/home/dnsstack/.ssh/id_ed25519:ro
      - ~/.ssh/known_hosts:/home/dnsstack/.ssh/known_hosts:ro
```

The remote user needs passwordless sudo for `pihole`.

## CLI

```
dnsstack [--config PATH] [--log-level LEVEL] <command>
```

`--config` defaults to `$DNSSTACK_CONFIG`, else `./config/config.yaml`.

| Command | What it does |
| --- | --- |
| `status` | Health/version table for each configured server |
| `sync [--apply]` | Show per-server add/remove plan; writes only with `--apply` |
| `update [--apply]` | Software updates (AdGuard via API, Pi-hole via ssh, NextDNS n/a); dry-run by default |
| `collect [--once]` | Run the log collector (forever, or one cycle) |
| `linked-ip [--interval N]` | Update the NextDNS linked IP once, or every N seconds |
| `watch-sync --interval N` | Loop `sync --apply` every N seconds |

Exit codes: `0` ok, `1` runtime/server error, `2` config error. Add
`--log-level DEBUG` for tracebacks.

Also runnable as `python -m dnsstack`.

## Dashboard

`deploy/grafana/dashboards/dns-overview.json`, provisioned into the *DNS*
folder. Template variables: `server`, `status` (Loki labels) and `client` (a
regex matched against the JSON field). Panels:

- Queries / min per server
- Blocked % per server
- Server health (from `job="dns-health"`, with `absent_over_time` to flag a dead collector)
- Top blocked domains, top clients
- Client -> server matrix
- Query log

## License

This project is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE).

You're free to use, modify, and share it for personal, hobby, educational, research, and other **noncommercial** purposes. **Commercial use requires prior written permission** — contact Jonathan Chin via [GitHub](https://github.com/jchin14) to arrange a commercial license.

Copies obtained before this change were released under the MIT License and remain MIT-licensed.
