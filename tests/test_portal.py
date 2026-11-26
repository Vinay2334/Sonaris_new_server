"""Customer portal endpoint tests (no network, no Supabase).

Covers POST /api/v1/me/subscription/portal with fakes for the Supabase
linkage read and the Dodo portal-session call:
- Authenticated user with a linkage row gets a one-click portal URL.
- No linkage row (or row without a customer id) is a 404, so the site
  can render its static-portal/support fallback.
- Supabase/Dodo failures are retryable 502s; a missing API key is a 503.
- Service-level payload shapes for the linkage GET and the Dodo POST
  (merge upsert is covered in test_billing.py).
"""

import pytest
from fastapi.testclient import TestClient

import app.api.subscription as subscription_api
from app.core.config import Settings
from app.main import create_app
from app.services.billing import (
    SubscriptionLinkage,
    create_portal_session,
    get_subscription_linkage,
)
from tests.test_auth_quota import make_token

USER_ID = "33333333-4444-5555-6666-777777777777"
PORTAL_LINK = "https://customer.dodopayments.com/session/abc123"


def make_settings(**overrides):
    base = {
        "OPENAI_API_KEY": "test-key",
        "SUBTITLE_PROVIDER": "none",
        "SUPABASE_URL": "https://example.supabase.co",
        "SUPABASE_SERVICE_ROLE_KEY": "test-service-role-key",
        "SUPABASE_JWT_SECRET": "test-jwt-secret-for-sonaris-quota-tests",
        "DODO_API_KEY": "test-dodo-api-key",
        "DODO_API_BASE": "https://test.dodopayments.com",
    }
    base.update(overrides)
    return Settings(**base)


def make_client(monkeypatch, **overrides):
    settings = make_settings(**overrides)
    app = create_app(settings)
    calls: dict = {}

    async def fake_linkage(user_id, _settings, **kwargs):
        calls["linkage_user"] = user_id
        if "linkage_error" in calls:
            raise calls["linkage_error"]
        return calls.get("linkage")

    async def fake_portal(customer_id, _settings, **kwargs):
        calls["portal_customer"] = customer_id
        calls["portal_kwargs"] = kwargs
        return calls.get("portal_url")

    monkeypatch.setattr(
        subscription_api, "get_subscription_linkage", fake_linkage
    )
    monkeypatch.setattr(
        subscription_api, "create_portal_session", fake_portal
    )
    return TestClient(app), calls


def post_portal(client, body=None, token=True):
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + make_token(user_id=USER_ID)
    return client.post(
        "/api/v1/me/subscription/portal",
        json=body or {},
        headers=headers,
    )


def paid_linkage():
    return SubscriptionLinkage(
        provider="dodo",
        provider_customer_id="cus_456",
        provider_subscription_id="sub_123",
        current_period_end="2026-12-26T00:00:00Z",
    )


# --- endpoint ---------------------------------------------------------------


def test_portal_returns_url_for_linked_user(monkeypatch):
    client, calls = make_client(monkeypatch)
    calls["linkage"] = paid_linkage()
    calls["portal_url"] = PORTAL_LINK
    resp = post_portal(
        client, {"return_url": "http://localhost:8080/account.html"}
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "url": PORTAL_LINK}
    assert calls["linkage_user"] == USER_ID
    assert calls["portal_customer"] == "cus_456"
    assert calls["portal_kwargs"].get("return_url") == (
        "http://localhost:8080/account.html"
    )


def test_portal_without_linkage_is_404(monkeypatch):
    client, calls = make_client(monkeypatch)
    calls["linkage"] = None
    resp = post_portal(client)
    assert resp.status_code == 404
    assert resp.json() == {"ok": False, "reason": "no_subscription"}
    assert "portal_customer" not in calls


def test_portal_without_customer_id_is_404(monkeypatch):
    client, calls = make_client(monkeypatch)
    calls["linkage"] = SubscriptionLinkage(provider="dodo")
    resp = post_portal(client)
    assert resp.status_code == 404
    assert resp.json()["reason"] == "no_subscription"


def test_portal_rejects_foreign_provider(monkeypatch):
    client, calls = make_client(monkeypatch)
    calls["linkage"] = SubscriptionLinkage(
        provider="stripe", provider_customer_id="cus_s"
    )
    resp = post_portal(client)
    assert resp.status_code == 404
    assert resp.json()["reason"] == "no_subscription"
    assert "portal_customer" not in calls


def test_portal_lookup_failure_retries(monkeypatch):
    client, calls = make_client(monkeypatch)
    calls["linkage_error"] = RuntimeError("linkage lookup failed")
    resp = post_portal(client)
    assert resp.status_code == 502
    assert resp.json()["reason"] == "lookup_failed"


def test_portal_dodo_failure_retries(monkeypatch):
    client, calls = make_client(monkeypatch)
    calls["linkage"] = paid_linkage()
    calls["portal_url"] = None
    resp = post_portal(client)
    assert resp.status_code == 502
    assert resp.json()["reason"] == "portal_failed"


def test_portal_disabled_without_api_key(monkeypatch):
    client, _ = make_client(monkeypatch, DODO_API_KEY="")
    resp = post_portal(client)
    assert resp.status_code == 503
    assert resp.json()["reason"] == "portal_unavailable"


def test_portal_rejects_anonymous(monkeypatch):
    client, _ = make_client(monkeypatch)
    resp = post_portal(client, token=False)
    assert resp.status_code == 401


# --- service payloads --------------------------------------------------------


class FakeResponse:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = body if body is not None else {}

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class FakeClient:
    """Injectable httpx stand-in capturing GET/POST calls (no network)."""

    def __init__(self, status=200, body=None):
        self.gets = []
        self.posts = []
        self._status = status
        self._body = body

    async def get(self, url, params=None, headers=None):
        self.gets.append(
            {"url": url, "params": params, "headers": headers}
        )
        return FakeResponse(self._status, self._body)

    async def post(self, url, json=None, headers=None, params=None):
        self.posts.append(
            {"url": url, "json": json, "headers": headers, "params": params}
        )
        return FakeResponse(self._status, self._body)


async def test_linkage_read_parses_first_row():
    settings = make_settings()
    client = FakeClient(body=[{
        "provider": "dodo",
        "provider_customer_id": "cus_456",
        "provider_subscription_id": "sub_123",
        "current_period_end": "2026-12-26T00:00:00Z",
    }])
    linkage = await get_subscription_linkage("u1", settings, client=client)
    assert linkage == SubscriptionLinkage(
        provider="dodo",
        provider_customer_id="cus_456",
        provider_subscription_id="sub_123",
        current_period_end="2026-12-26T00:00:00Z",
    )
    assert client.gets[0]["url"].endswith("/rest/v1/billing_subscriptions")
    assert client.gets[0]["params"]["user_id"] == "eq.u1"


async def test_linkage_read_empty_is_none():
    settings = make_settings()
    client = FakeClient(body=[])
    assert await get_subscription_linkage("u1", settings, client=client) is None


async def test_linkage_read_failure_raises():
    settings = make_settings()
    client = FakeClient(status=500)
    with pytest.raises(RuntimeError):
        await get_subscription_linkage("u1", settings, client=client)


async def test_portal_session_returns_link():
    settings = make_settings()
    client = FakeClient(body={"link": PORTAL_LINK})
    url = await create_portal_session(
        "cus_456", settings, client=client,
        return_url="http://localhost:8080/account.html",
    )
    assert url == PORTAL_LINK
    post = client.posts[0]
    assert post["url"].startswith(
        "https://test.dodopayments.com/customers/cus_456/"
        "customer-portal/session"
    )
    assert "return_url=http" in post["url"]
    assert post["headers"]["Authorization"] == "Bearer test-dodo-api-key"
    # The Supabase service key must never ride along to Dodo.
    assert "test-service-role-key" not in list(post["headers"].values())


async def test_portal_session_missing_link_is_none():
    settings = make_settings()
    client = FakeClient(body={})
    assert await create_portal_session("cus_456", settings, client=client) is None


async def test_portal_session_failure_is_none():
    settings = make_settings()
    client = FakeClient(status=422)
    assert await create_portal_session("cus_456", settings, client=client) is None
