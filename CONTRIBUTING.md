# Contributing

Thanks for helping out. Bug reports, fixes and new DNS server backends are all welcome.

## Development setup

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
```

## Checks (same as CI)

```sh
ruff check .
ruff format --check .
pytest
docker compose config -q   # needs a .env (cp .env.example .env)
```

## Guidelines

- Python 3.12+, type hints everywhere, synchronous `httpx`.
- Tests must not hit real servers: mock HTTP with `respx`.
- Never commit secrets. Config values that are secret belong in `.env` and are
  referenced from `config/config.yaml` as `${VAR}`.
- Keep Loki labels low-cardinality: only `job`, `server` and `status`. Put
  everything else (client, domain, qtype, ...) in the JSON log line.
- Adding a backend: implement the `DnsServerClient` protocol in
  `dnsstack/clients/`, register it in `build_clients`, add a config model and tests.
- One logical change per commit, with a focused message.
