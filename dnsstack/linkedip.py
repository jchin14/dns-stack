"""NextDNS linked-IP updater."""

from __future__ import annotations

import httpx


def update_linked_ip(url: str, http: httpx.Client | None = None) -> str:
    """GET the NextDNS per-profile link-ip URL and return the response text.

    The URL itself is the credential, so it is never logged by this function.
    Raises httpx.HTTPError on network failure or a non-2xx response.
    """
    owns_client = http is None
    client = http or httpx.Client(timeout=15.0, follow_redirects=True)
    try:
        resp = client.get(url)
        resp.raise_for_status()
        return resp.text.strip()
    finally:
        if owns_client:
            client.close()
