from __future__ import annotations

import httpx
import pytest
import respx

from dnsstack.config import AdguardConfig, NextdnsConfig, PiholeConfig


@pytest.fixture
def pihole_cfg() -> PiholeConfig:
    return PiholeConfig(url="http://pihole.test", password="pw")


@pytest.fixture
def adguard_cfg() -> AdguardConfig:
    return AdguardConfig(url="http://adguard.test", username="admin", password="pw")


@pytest.fixture
def nextdns_cfg() -> NextdnsConfig:
    return NextdnsConfig(profile_id="abc123", api_key="key")


@pytest.fixture
def mock() -> respx.MockRouter:
    with respx.mock(assert_all_called=False) as router:
        yield router


@pytest.fixture
def http(mock: respx.MockRouter) -> httpx.Client:
    with httpx.Client() as c:
        yield c
