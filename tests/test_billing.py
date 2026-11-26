"""Dodo Payments webhook tests (no network, no Supabase).

Covers the billing contract with fakes for the Supabase REST calls:
- Standard Webhooks signature check (valid / wrong secret / tampered /
  stale / missing headers / whsec_ prefix).
- Event normalization (activate / deactivate / ignore), including the
  paid-period fields (`next_billing_date`, `cancel_at_next_billing_date`,
  subscription/customer ids).
- Cancel semantics: cancel-at-period-end only records the period
  (`cancel_scheduled`, plan untouched); an immediate cancel clears the
  period and drops to free.
- Endpoint status contract: 401 bad signature, 503 billing disabled,
  200 applied-or-ignored, 502 transient Supabase failure.
- Plan changes apply to the metadata user id, or to the email-resolved
  user when the link carried no user id.
"""

import base64
import hashlib
import hmac
import json
import time

import pytest
from fastapi.testclient import TestClient

import app.api.billing as billing_api
from app.core.config import Settings
from app.main import create_app
from app.services.billing import (
    BillingEvent,
    parse_dodo_event,
    set_user_plan,
    upsert_subscription_linkage,
    verify_dodo_signature,
)

TEST_SECRET = "test-dodo-webhook-secret"
PLAN_MAP = {"prod_pro": "pro", "prod_studio": "studio"}
USER_ID = "22222222-3333-4444-5555-666666666666"


def make_settings(**overrides):
    base = {
        "OPENAI_API_KEY": "test-key",
        "SUBTITLE_PROVIDER": "none",
        "SUPABASE_URL": "https://example.supabase.co",
        "SUPABASE_SERVICE_ROLE_KEY": "test-service-role-key",
        "SUPABASE_JWT_SECRET": "test-jwt-secret",
        "DODO_WEBHOOK_SECRET": TEST_SECRET,
        "DODO_PLAN_MAP": "prod_pro=pro,prod_studio=studio",
    }
    base.update(overrides)
    return Settings(**base)


def sign(body: bytes, secret: str = TEST_SECRET, msg_id="msg_test_1", ts=None):
    ts = str(int(time.time())) if ts is None else str(ts)
    key = base64.b64decode(secret) if _looks_b64(secret) else secret.encode()
    mac = hmac.new(
        key, f"{msg_id}.{ts}.".encode() + body, hashlib.sha256
    ).digest()
    sig = base64.b64encode(mac).decode()
    return (
        {"webhook-id": msg_id, "webhook-timestamp": ts,
         "webhook-signature": f"v1,{sig}"},
        body,
    )


def _looks_b64(secret: str) -> bool:
    try:
        base64.b64decode(secret)
        return True
    except Exception:
        return False


def signed_request(payload: dict, **overrides):
    body = json.dumps(payload).encode()
    headers, raw = sign(body, **overrides)
    return headers, raw


# --- signature verification -------------------------------------------------


def test_valid_signature_verifies():
    payload = {"type": "payment.succeeded", "data": {}}
    headers, raw = signed_request(payload)
    assert verify_dodo_signature(
        raw, headers["webhook-id"], headers["webhook-timestamp"],
        headers["webhook-signature"], TEST_SECRET,
    )


def test_whsec_prefix_secret_verifies():
    raw_secret = base64.b64encode(b"another-secret").decode()
    body = b'{"type":"payment.succeeded"}'
    headers, raw = sign(body, secret=raw_secret)
    assert verify_dodo_signature(
        raw, headers["webhook-id"], headers["webhook-timestamp"],
        headers["webhook-signature"], f"whsec_{raw_secret}",
    )


def test_wrong_secret_rejected():
    headers, raw = signed_request({"type": "payment.succeeded"})
    assert not verify_dodo_signature(
        raw, headers["webhook-id"], headers["webhook-timestamp"],
        headers["webhook-signature"], "wrong-secret",
    )


def test_tampered_body_rejected():
    headers, raw = signed_request({"type": "payment.succeeded"})
    assert not verify_dodo_signature(
        raw + b" ", headers["webhook-id"], headers["webhook-timestamp"],
        headers["webhook-signature"], TEST_SECRET,
    )


def test_stale_timestamp_rejected():
    headers, raw = signed_request(
        {"type": "payment.succeeded"}, ts=int(time.time()) - 3600
    )
    assert not verify_dodo_signature(
        raw, headers["webhook-id"], headers["webhook-timestamp"],
        headers["webhook-signature"], TEST_SECRET,
    )


def test_missing_headers_rejected():
    assert not verify_dodo_signature(b"{}", None, None, None, TEST_SECRET)
    assert not verify_dodo_signature(b"{}", "id", "123", None, TEST_SECRET)


def test_empty_secret_never_verifies():
    headers, raw = signed_request({"type": "payment.succeeded"})
    assert not verify_dodo_signature(
        raw, headers["webhook-id"], headers["webhook-timestamp"],
        headers["webhook-signature"], "",
    )


# --- event normalization ----------------------------------------------------


def test_payment_succeeded_activates_mapped_plan():
    event = parse_dodo_event(
        {
            "id": "evt_1",
            "type": "payment.succeeded",
            "data": {
                "product_id": "prod_pro",
                "customer": {"email": "buyer@sonaris.local"},
                "metadata": {"user_id": USER_ID},
            },
        },
        PLAN_MAP,
    )
    assert event == BillingEvent(
        action="activate", product_id="prod_pro", plan_id="pro",
        user_id=USER_ID, email="buyer@sonaris.local", event_id="evt_1",
    )


def test_subscription_cancelled_deactivates():
    event = parse_dodo_event(
        {
            "type": "subscription.cancelled",
            "data": {"metadata": {"user_id": USER_ID}},
        },
        PLAN_MAP,
    )
    assert event.action == "deactivate"
    assert event.user_id == USER_ID


def test_payment_succeeded_reads_product_cart():
    # Real Dodo Payment payloads nest the product in product_cart[0];
    # there is no top-level product_id on the data object.
    event = parse_dodo_event(
        {
            "id": "evt_real",
            "type": "payment.succeeded",
            "data": {
                "product_cart": [{"product_id": "prod_studio", "quantity": 1}],
                "customer": {"email": "buyer@sonaris.local"},
                "metadata": {"user_id": USER_ID, "plan_id": "studio"},
            },
        },
        PLAN_MAP,
    )
    assert event == BillingEvent(
        action="activate", product_id="prod_studio", plan_id="studio",
        user_id=USER_ID, email="buyer@sonaris.local", event_id="evt_real",
    )


def test_unmapped_product_ignored():
    event = parse_dodo_event(
        {"type": "payment.succeeded",
         "data": {"product_id": "prod_unknown"}},
        PLAN_MAP,
    )
    assert event.action == "ignore"


def test_unknown_event_type_ignored():
    event = parse_dodo_event(
        {"type": "refund.succeeded", "data": {"product_id": "prod_pro"}},
        PLAN_MAP,
    )
    assert event.action == "ignore"


def test_malformed_envelope_ignored():
    assert parse_dodo_event({}, PLAN_MAP).action == "ignore"
    assert parse_dodo_event({"type": 42}, PLAN_MAP).action == "ignore"


# --- config -----------------------------------------------------------------


def test_plan_map_parsing_skips_malformed():
    settings = make_settings(DODO_PLAN_MAP="prod_a=pro, broken ,=x,prod_b= studio ")
    assert settings.dodo_plans() == {"prod_a": "pro", "prod_b": "studio"}
    assert settings.billing_enabled() is True


def test_billing_disabled_without_secret():
    assert make_settings(DODO_WEBHOOK_SECRET="").billing_enabled() is False


def test_billing_disabled_without_supabase_key():
    settings = make_settings(SUPABASE_SERVICE_ROLE_KEY="")
    assert settings.billing_enabled() is False


# --- endpoint ----------------------------------------------------------------


def make_client(monkeypatch, **overrides):
    settings = make_settings(**overrides)
    app = create_app(settings)
    calls: dict = {}

    async def fake_set_plan(user_id, plan_id, _settings, **kwargs):
        calls["set_plan"] = (user_id, plan_id)
        return calls.get("plan_ok", True)

    async def fake_upsert(user_id, _settings, **kwargs):
        calls["upsert"] = (user_id, kwargs)
        return calls.get("plan_ok", True)

    async def fake_find(email, _settings, **kwargs):
        calls["find_email"] = email
        return calls.get("found_user")

    monkeypatch.setattr(billing_api, "set_user_plan", fake_set_plan)
    monkeypatch.setattr(
        billing_api, "upsert_subscription_linkage", fake_upsert
    )
    monkeypatch.setattr(billing_api, "find_user_id_by_email", fake_find)
    return TestClient(app), calls


def post_webhook(client, payload, **sign_kwargs):
    headers, raw = signed_request(payload, **sign_kwargs)
    return client.post(
        "/api/v1/billing/dodo/webhook",
        content=raw,
        headers={**headers, "Content-Type": "application/json"},
    )


def test_webhook_upgrades_metadata_user(monkeypatch):
    client, calls = make_client(monkeypatch)
    resp = post_webhook(client, {
        "id": "evt_up",
        "type": "payment.succeeded",
        "data": {"product_id": "prod_pro",
                  "metadata": {"user_id": USER_ID}},
    })
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "action": "activate", "plan_id": "pro"}
    assert calls["set_plan"] == (USER_ID, "pro")


def test_webhook_cancellation_downgrades_to_free(monkeypatch):
    client, calls = make_client(monkeypatch)
    resp = post_webhook(client, {
        "type": "subscription.cancelled",
        "data": {"metadata": {"user_id": USER_ID}},
    })
    assert resp.status_code == 200
    assert resp.json()["action"] == "deactivate"
    assert calls["set_plan"] == (USER_ID, "free")
    # Immediate downgrade clears the period end but keeps the ids.
    user_id, kwargs = calls["upsert"]
    assert user_id == USER_ID
    assert kwargs.get("current_period_end") is None


def test_webhook_resolves_user_by_email(monkeypatch):
    client, calls = make_client(monkeypatch)
    calls["found_user"] = USER_ID
    resp = post_webhook(client, {
        "type": "subscription.active",
        "data": {"product_id": "prod_studio",
                  "customer": {"email": "buyer@sonaris.local"}},
    })
    assert resp.status_code == 200
    assert calls["find_email"] == "buyer@sonaris.local"
    assert calls["set_plan"] == (USER_ID, "studio")


def test_webhook_unknown_user_ignored(monkeypatch):
    client, calls = make_client(monkeypatch)
    calls["found_user"] = None
    resp = post_webhook(client, {
        "type": "payment.succeeded",
        "data": {"product_id": "prod_pro",
                  "customer": {"email": "ghost@sonaris.local"}},
    })
    assert resp.status_code == 200
    assert resp.json()["reason"] == "unknown_user"
    assert "set_plan" not in calls


def test_webhook_upgrades_product_cart_payment(monkeypatch):
    client, calls = make_client(monkeypatch)
    resp = post_webhook(client, {
        "id": "evt_cart",
        "type": "payment.succeeded",
        "data": {"product_cart": [{"product_id": "prod_studio", "quantity": 1}],
                  "customer": {"email": "buyer@sonaris.local"},
                  "metadata": {"user_id": USER_ID, "plan_id": "studio"}},
    })
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "action": "activate", "plan_id": "studio"}
    assert calls["set_plan"] == (USER_ID, "studio")


def test_webhook_unmapped_product_ignored(monkeypatch):
    client, calls = make_client(monkeypatch)
    resp = post_webhook(client, {
        "type": "payment.succeeded",
        "data": {"product_id": "prod_nope",
                  "metadata": {"user_id": USER_ID}},
    })
    assert resp.status_code == 200
    assert resp.json()["action"] == "ignored"
    assert "set_plan" not in calls


def test_webhook_plan_failure_retries(monkeypatch):
    client, calls = make_client(monkeypatch)
    calls["plan_ok"] = False
    resp = post_webhook(client, {
        "type": "payment.succeeded",
        "data": {"product_id": "prod_pro",
                  "metadata": {"user_id": USER_ID}},
    })
    assert resp.status_code == 502
    assert resp.json()["reason"] == "plan_update_failed"


def test_webhook_bad_signature_rejected(monkeypatch):
    client, _ = make_client(monkeypatch)
    headers, raw = signed_request({"type": "payment.succeeded"})
    headers["webhook-signature"] = "v1,bm90LXJlYWxseS1hLXNpZ25hdHVyZQ=="
    resp = client.post(
        "/api/v1/billing/dodo/webhook", content=raw, headers=headers
    )
    assert resp.status_code == 401


def test_webhook_disabled_without_secret(monkeypatch):
    client, _ = make_client(monkeypatch, DODO_WEBHOOK_SECRET="")
    resp = post_webhook(client, {"type": "payment.succeeded", "data": {}})
    assert resp.status_code == 503


# --- paid-period extraction --------------------------------------------------


def test_subscription_active_extracts_period():
    event = parse_dodo_event(
        {
            "id": "evt_period",
            "type": "subscription.active",
            "data": {
                "product_id": "prod_pro",
                "subscription_id": "sub_123",
                "customer": {"customer_id": "cus_456",
                             "email": "buyer@sonaris.local"},
                "next_billing_date": "2026-12-26T00:00:00Z",
                "cancel_at_next_billing_date": False,
                "metadata": {"user_id": USER_ID},
            },
        },
        PLAN_MAP,
    )
    assert event == BillingEvent(
        action="activate", product_id="prod_pro", plan_id="pro",
        user_id=USER_ID, email="buyer@sonaris.local", event_id="evt_period",
        next_billing_date="2026-12-26T00:00:00Z",
        cancel_at_next_billing_date=False,
        subscription_id="sub_123", customer_id="cus_456",
    )


def test_cancelled_at_period_end_marks_scheduled():
    event = parse_dodo_event(
        {
            "type": "subscription.cancelled",
            "data": {
                "subscription_id": "sub_123",
                "customer": {"customer_id": "cus_456"},
                "cancel_at_next_billing_date": True,
                "next_billing_date": "2026-12-26T00:00:00Z",
                "metadata": {"user_id": USER_ID},
            },
        },
        PLAN_MAP,
    )
    assert event.action == "deactivate"
    assert event.cancel_at_next_billing_date is True
    assert event.next_billing_date == "2026-12-26T00:00:00Z"
    assert event.subscription_id == "sub_123"
    assert event.customer_id == "cus_456"


def test_string_customer_id_accepted():
    event = parse_dodo_event(
        {
            "type": "subscription.renewed",
            "data": {
                "product_id": "prod_studio",
                "subscription_id": "sub_9",
                "customer": "cus_bare",
                "next_billing_date": "2026-12-26T00:00:00Z",
            },
        },
        PLAN_MAP,
    )
    assert event.action == "activate"
    assert event.customer_id == "cus_bare"


# --- scheduled vs immediate cancel (endpoint) --------------------------------


def test_webhook_scheduled_cancel_keeps_plan(monkeypatch):
    client, calls = make_client(monkeypatch)
    resp = post_webhook(client, {
        "type": "subscription.cancelled",
        "data": {
                    "subscription_id": "sub_123",
                    "customer": {"customer_id": "cus_456"},
                    "cancel_at_next_billing_date": True,
                    "next_billing_date": "2026-12-26T00:00:00Z",
                    "metadata": {"user_id": USER_ID}},
    })
    assert resp.status_code == 200
    assert resp.json() == {
        "ok": True, "action": "cancel_scheduled",
        "current_period_end": "2026-12-26T00:00:00Z",
    }
    assert "set_plan" not in calls
    user_id, kwargs = calls["upsert"]
    assert user_id == USER_ID
    assert kwargs.get("current_period_end") == "2026-12-26T00:00:00Z"
    assert kwargs.get("subscription_id") == "sub_123"
    assert kwargs.get("customer_id") == "cus_456"


def test_webhook_scheduled_cancel_without_date_downgrades(monkeypatch):
    # Flag but no date: nothing to schedule against, so downgrade now.
    client, calls = make_client(monkeypatch)
    resp = post_webhook(client, {
        "type": "subscription.cancelled",
        "data": {"cancel_at_next_billing_date": True,
                  "metadata": {"user_id": USER_ID}},
    })
    assert resp.status_code == 200
    assert resp.json()["action"] == "deactivate"
    assert calls["set_plan"] == (USER_ID, "free")
    user_id, kwargs = calls["upsert"]
    assert user_id == USER_ID
    assert kwargs.get("current_period_end") is None


def test_webhook_activate_stores_period(monkeypatch):
    client, calls = make_client(monkeypatch)
    resp = post_webhook(client, {
        "id": "evt_store",
        "type": "subscription.renewed",
        "data": {"product_id": "prod_pro",
                  "subscription_id": "sub_123",
                  "customer": {"customer_id": "cus_456"},
                  "next_billing_date": "2026-12-26T00:00:00Z",
                  "metadata": {"user_id": USER_ID}},
    })
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "action": "activate", "plan_id": "pro"}
    assert calls["set_plan"] == (USER_ID, "pro")
    user_id, kwargs = calls["upsert"]
    assert user_id == USER_ID
    assert kwargs.get("current_period_end") == "2026-12-26T00:00:00Z"
    assert kwargs.get("subscription_id") == "sub_123"
    assert kwargs.get("customer_id") == "cus_456"


# --- plan + linkage writer payloads ------------------------------------------


class FakeResponse:
    def __init__(self, status_code=200):
        self.status_code = status_code


class FakeClient:
    """Injectable httpx stand-in capturing PATCH/POST calls (no network)."""

    def __init__(self, status=200):
        self.patches = []
        self.posts = []
        self._status = status

    async def patch(self, url, json=None, headers=None):
        self.patches.append({"url": url, "json": json})
        return FakeResponse(self._status)

    async def post(self, url, json=None, headers=None, params=None):
        self.posts.append(
            {"url": url, "json": json, "headers": headers, "params": params}
        )
        return FakeResponse(self._status)


async def test_set_user_plan_writes_plan_only():
    settings = make_settings()
    client = FakeClient()
    assert await set_user_plan("u1", "pro", settings, client=client)
    body = client.patches[0]["json"]
    assert body["plan_id"] == "pro"
    assert "current_period_end" not in body
    assert "provider_subscription_id" not in body


async def test_linkage_upsert_writes_full_row():
    settings = make_settings()
    client = FakeClient()
    assert await upsert_subscription_linkage(
        "u1", settings, client=client,
        current_period_end="2026-12-26T00:00:00Z",
        subscription_id="sub_1", customer_id="cus_1",
    )
    post = client.posts[0]
    assert post["url"].endswith(
        "/rest/v1/billing_subscriptions?on_conflict=user_id"
    )
    assert post["headers"]["Prefer"] == "resolution=merge-duplicates"
    body = post["json"]
    assert body["user_id"] == "u1"
    assert body["provider"] == "dodo"
    assert body["current_period_end"] == "2026-12-26T00:00:00Z"
    assert body["provider_subscription_id"] == "sub_1"
    assert body["provider_customer_id"] == "cus_1"


async def test_linkage_upsert_leaves_period_when_omitted():
    settings = make_settings()
    client = FakeClient()
    assert await upsert_subscription_linkage(
        "u1", settings, client=client, subscription_id="sub_1"
    )
    body = client.posts[0]["json"]
    assert "current_period_end" not in body
    assert body["provider_subscription_id"] == "sub_1"


async def test_linkage_upsert_clear_period_keeps_ids():
    settings = make_settings()
    client = FakeClient()
    assert await upsert_subscription_linkage(
        "u1", settings, client=client, current_period_end=None
    )
    body = client.posts[0]["json"]
    assert body["current_period_end"] is None
    assert "provider_subscription_id" not in body
    assert "provider_customer_id" not in body


async def test_writer_failure_returns_false():
    settings = make_settings()
    client = FakeClient(status=500)
    assert not await set_user_plan("u1", "pro", settings, client=client)
    assert not await upsert_subscription_linkage(
        "u1", settings, client=client, current_period_end=None
    )
