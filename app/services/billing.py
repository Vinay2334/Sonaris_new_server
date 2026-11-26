"""Dodo Payments webhook handling: verify, normalize, apply plan changes.

The pricing site links out to Dodo's hosted checkout (no card data ever
touches us). Dodo then tells this backend about money movement via
``POST /api/v1/billing/dodo/webhook``; this module holds everything that
endpoint needs except the FastAPI shell:

- ``verify_dodo_signature``: Standard Webhooks (Svix-compatible) HMAC
  check over the raw body, stdlib only — no new dependency.
- ``parse_dodo_event``: normalize Dodo's envelope into one BillingEvent
  (activate / deactivate / ignore) that only ever names a plan.
- ``find_user_id_by_email`` / ``set_user_plan`` /
  ``upsert_subscription_linkage``: service_role Supabase REST calls (the
  only writer of plan/quota, per the migration's RLS).
- Paid access is time-boxed by ``billing_subscriptions.current_period_end``
  (Dodo's ``next_billing_date``): every activate upserts it, a
  cancel-at-period-end only refreshes it, and the quota RPCs lazily
  downgrade past-due rows to ``free`` — so ``cancelled`` vs ``expired``
  needs no branching beyond "keep the date or clear it". Provider ids
  live in that table (not ``profiles``) so a future provider switch only
  writes a new ``provider`` value.

Idempotency is structural: applying the same event twice writes the same
``plan_id``, so Dodo retries can never double-apply. Unknown event types
and unmapped products resolve to ``ignore`` — retrying those would never
succeed, so the endpoint answers 200 for them.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import time
from dataclasses import dataclass

import httpx

from app.core.config import Settings
from app.core.logging import get_logger

log = get_logger(__name__)

# Dodo signs with the Standard Webhooks scheme and timestamps are
# time-checked with a 5 minute tolerance (per Dodo's docs).
WEBHOOK_TOLERANCE_SECONDS = 5 * 60

# Events that grant the mapped paid plan. `payment.succeeded` covers the
# first charge (and one-off products); subscription events cover renewals.
ACTIVATE_EVENTS = frozenset(
    {
        "payment.succeeded",
        "subscription.active",
        "subscription.renewed",
    }
)

# Events that drop the account back to the free plan.
DEACTIVATE_EVENTS = frozenset(
    {
        "subscription.cancelled",
        "subscription.expired",
    }
)

# Upper bound when resolving an email through the paginated Auth Admin API
# (50 users/page). Past this we stop and log instead of paging forever.
_MAX_ADMIN_PAGES = 20
_ADMIN_PAGE_SIZE = 50


@dataclass(frozen=True)
class BillingEvent:
    """Normalized webhook: what to do, for whom, on which plan."""

    action: str  # "activate" | "deactivate" | "ignore"
    product_id: str | None = None
    plan_id: str | None = None
    user_id: str | None = None
    email: str | None = None
    event_id: str | None = None
    # Paid-period bounds (Dodo subscription payloads only; None when the
    # event carries no subscription object). ``cancel_at_next_billing_date``
    # marks a cancel that keeps paid access until ``next_billing_date``.
    next_billing_date: str | None = None
    cancel_at_next_billing_date: bool = False
    subscription_id: str | None = None
    customer_id: str | None = None


def _webhook_key(secret: str) -> bytes:
    """Decode a Standard Webhooks secret (optional `whsec_` prefix)."""
    raw = secret.strip()
    if raw.lower().startswith("whsec_"):
        raw = raw[len("whsec_"):]
    try:
        return base64.b64decode(raw)
    except (binascii.Error, ValueError):
        # Not base64: fall back to the raw bytes (test secrets, odd setups).
        return raw.encode("utf-8")


def verify_dodo_signature(
    raw_body: bytes,
    webhook_id: str | None,
    webhook_timestamp: str | None,
    webhook_signature: str | None,
    secret: str,
    *,
    now: float | None = None,
) -> bool:
    """Check the Standard Webhooks signature of a Dodo delivery.

    Signed content is ``{webhook-id}.{webhook-timestamp}.{raw_body}`` and
    the header holds one or more space-separated ``v1,<base64>`` values.
    Returns False (never raises) when anything is missing, malformed,
    stale, or mismatched.
    """
    if not secret or not secret.strip():
        return False
    if not webhook_id or not webhook_timestamp or not webhook_signature:
        return False
    try:
        issued_at = int(webhook_timestamp)
    except (TypeError, ValueError):
        return False
    current = time.time() if now is None else now
    if abs(current - issued_at) > WEBHOOK_TOLERANCE_SECONDS:
        return False
    try:
        payload = raw_body.decode("utf-8")
    except UnicodeDecodeError:
        return False
    signed = f"{webhook_id}.{webhook_timestamp}.{payload}".encode("utf-8")
    expected = base64.b64encode(
        hmac.new(_webhook_key(secret), signed, hashlib.sha256).digest()
    ).decode("ascii")
    for candidate in webhook_signature.split():
        _version, _, signature = candidate.partition(",")
        if signature and hmac.compare_digest(signature, expected):
            return True
    return False


def _first_str(*values: object) -> str | None:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _dig(data: object, *paths: str) -> str | None:
    """Fetch the first present dotted path (``a.b.c``) from nested dicts."""
    if not isinstance(data, dict):
        return None
    for path in paths:
        node: object = data
        for part in path.split("."):
            if not isinstance(node, dict):
                node = None
                break
            node = node.get(part)
        if isinstance(node, str) and node.strip():
            return node.strip()
    return None


def _first_cart_product(data: object) -> str | None:
    """Product id of the first cart line, or None.

    Real Dodo Payment payloads carry the product inside
    ``product_cart`` (a list of ``{product_id, quantity}``) with no
    top-level ``product_id`` on the data object. Single-product
    checkouts — everything this endpoint activates — have exactly one
    line; multi-product carts resolve to their first line. This is a
    fallback: the dotted-path shapes (subscriptions, older envelopes)
    keep priority via ``_dig``.
    """
    if not isinstance(data, dict):
        return None
    items = data.get("product_cart")
    if not isinstance(items, list) or not items:
        return None
    first = items[0]
    if not isinstance(first, dict):
        return None
    product_id = first.get("product_id")
    if isinstance(product_id, str) and product_id.strip():
        return product_id.strip()
    return None


def _dig_bool(data: object, *paths: str) -> bool:
    """Fetch the first present dotted path that holds a real boolean."""
    if not isinstance(data, dict):
        return False
    for path in paths:
        node: object = data
        for part in path.split("."):
            if not isinstance(node, dict):
                node = None
                break
            node = node.get(part)
        if isinstance(node, bool):
            return node
    return False


def _customer_id(data: dict) -> str | None:
    """Dodo customer id: dict (``customer_id``) or a bare id string."""
    customer = data.get("customer")
    if isinstance(customer, dict):
        return _first_str(customer.get("customer_id"), customer.get("id"))
    if isinstance(customer, str) and customer.strip():
        return customer.strip()
    return _first_str(data.get("customer_id"))


def parse_dodo_event(payload: dict, plan_map: dict[str, str]) -> BillingEvent:
    """Normalize a Dodo webhook envelope into an actionable event.

    ``plan_map`` is Dodo product id -> Supabase plans.id. The product id
    and customer identity are read defensively from several likely spots
    (top-level and nested subscription/payment objects) because Dodo's
    per-event shapes differ; anything unrecognized becomes ``ignore``.
    """
    event_type = payload.get("type") if isinstance(payload, dict) else None
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(event_type, str) or not isinstance(data, dict):
        return BillingEvent(action="ignore")

    event_id = _first_str(payload.get("id"), data.get("webhook_id"))
    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}

    event = BillingEvent(
        action="ignore",
        product_id=_dig(
            data,
            "product_id",
            "product.product_id",
            "subscription.product_id",
            "payment.product_id",
            "cart.product_id",
        )
        or _first_cart_product(data),
        user_id=_first_str(metadata.get("user_id"), metadata.get("userId")),
        email=_dig(
            data,
            "customer.email",
            "customer_email",
            "email",
            "subscription.customer.email",
            "payment.customer.email",
        ),
        event_id=event_id,
        next_billing_date=_dig(
            data,
            "next_billing_date",
            "subscription.next_billing_date",
            "payment.next_billing_date",
        ),
        cancel_at_next_billing_date=_dig_bool(
            data,
            "cancel_at_next_billing_date",
            "subscription.cancel_at_next_billing_date",
        ),
        subscription_id=_dig(
            data,
            "subscription_id",
            "subscription.subscription_id",
            "payment.subscription_id",
        ),
        customer_id=_customer_id(data),
    )

    if event_type in DEACTIVATE_EVENTS:
        return BillingEvent(
            action="deactivate",
            product_id=event.product_id,
            user_id=event.user_id,
            email=event.email,
            event_id=event.event_id,
            next_billing_date=event.next_billing_date,
            cancel_at_next_billing_date=event.cancel_at_next_billing_date,
            subscription_id=event.subscription_id,
            customer_id=event.customer_id,
        )
    if event_type in ACTIVATE_EVENTS:
        plan_id = plan_map.get(event.product_id or "")
        if not plan_id:
            log.warning(
                "dodo event for unmapped product type=%s product=%s",
                event_type,
                event.product_id,
            )
            return BillingEvent(
                action="ignore",
                product_id=event.product_id,
                user_id=event.user_id,
                email=event.email,
                event_id=event.event_id,
            )
        return BillingEvent(
            action="activate",
            product_id=event.product_id,
            plan_id=plan_id,
            user_id=event.user_id,
            email=event.email,
            event_id=event.event_id,
            next_billing_date=event.next_billing_date,
            cancel_at_next_billing_date=event.cancel_at_next_billing_date,
            subscription_id=event.subscription_id,
            customer_id=event.customer_id,
        )
    return event


def _supabase_headers(settings: Settings) -> dict[str, str]:
    key = settings.supabase_service_role_key.strip()
    return {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }


async def find_user_id_by_email(
    email: str, settings: Settings, *, client: httpx.AsyncClient | None = None
) -> str | None:
    """Resolve a Supabase user id from an email via the Auth Admin API.

    ``client`` is a test seam: production passes None (a real client is
    built); tests inject a fake transport so no network is touched.
    """
    base = settings.supabase_url.rstrip("/")
    headers = _supabase_headers(settings)
    wanted = email.strip().lower()
    owned = client is not None
    http = client or httpx.AsyncClient(
        base_url=base, headers=headers, timeout=10.0
    )
    try:
        for page in range(1, _MAX_ADMIN_PAGES + 1):
            if owned:
                response = await http.get(
                    f"{base}/auth/v1/admin/users",
                    params={"page": page, "per_page": _ADMIN_PAGE_SIZE},
                    headers=headers,
                )
            else:
                response = await http.get(
                    "/auth/v1/admin/users",
                    params={"page": page, "per_page": _ADMIN_PAGE_SIZE},
                )
            if response.status_code >= 400:
                log.warning(
                    "dodo user lookup failed status=%s", response.status_code
                )
                return None
            try:
                body = response.json()
            except ValueError:
                return None
            users = body.get("users", []) if isinstance(body, dict) else []
            for user in users:
                if (
                    isinstance(user, dict)
                    and str(user.get("email", "")).strip().lower() == wanted
                    and user.get("id")
                ):
                    return str(user["id"])
            if len(users) < _ADMIN_PAGE_SIZE:
                return None
        log.warning("dodo user lookup hit page cap email=%s", email)
        return None
    except httpx.HTTPError as exc:
        log.warning("dodo user lookup transport failed type=%s", type(exc).__name__)
        return None
    finally:
        if not owned:
            await http.aclose()


async def _patch_profile(
    user_id: str, payload: dict, settings: Settings, *, client=None
) -> bool:
    """PATCH one profile row (service_role bypasses RLS by design)."""
    base = settings.supabase_url.rstrip("/")
    headers = _supabase_headers(settings)
    owned = client is not None
    http = client or httpx.AsyncClient(
        base_url=base, headers=headers, timeout=10.0
    )
    try:
        if owned:
            response = await http.patch(
                f"{base}/rest/v1/profiles?user_id=eq.{user_id}",
                json=payload,
                headers=headers,
            )
        else:
            response = await http.patch(
                f"/rest/v1/profiles?user_id=eq.{user_id}",
                json=payload,
            )
        if response.status_code >= 400:
            log.warning(
                "dodo profile update failed user=%s status=%s",
                user_id,
                response.status_code,
            )
            return False
        return True
    except httpx.HTTPError as exc:
        log.warning(
            "dodo profile update transport failed type=%s",
            type(exc).__name__,
        )
        return False
    finally:
        if not owned:
            await http.aclose()


async def set_user_plan(
    user_id: str, plan_id: str, settings: Settings, *, client=None
) -> bool:
    """Move a profile to ``plan_id`` (service_role bypasses RLS by design).

    Plan only: the paid period lives in ``billing_subscriptions`` (see
    ``upsert_subscription_linkage``). Returns True on success. A missing
    ``plans`` row fails closed (False) via the foreign key instead of
    inventing a plan.
    """
    from datetime import datetime, timezone

    ok = await _patch_profile(
        user_id,
        {
            "plan_id": plan_id,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
        settings,
        client=client,
    )
    if not ok:
        log.warning(
            "dodo plan update failed user=%s plan=%s", user_id, plan_id
        )
    return ok


# Sentinel: "leave the stored period end untouched" (vs None = clear it).
_KEEP_PERIOD_END: object = object()


async def upsert_subscription_linkage(
    user_id: str,
    settings: Settings,
    *,
    client=None,
    provider: str = "dodo",
    current_period_end: str | None | object = _KEEP_PERIOD_END,
    subscription_id: str | None = None,
    customer_id: str | None = None,
) -> bool:
    """Upsert the user's row in ``billing_subscriptions`` (keyed on user).

    Only provided fields are written (PostgREST merge-duplicates):
    ``current_period_end`` left at the default leaves the stored date
    untouched, an explicit ``None`` clears it (immediate downgrade keeps
    the ids for the portal button). ``provider`` scopes the row so a
    future provider switch writes a new value instead of touching
    ``profiles``. Returns True on success.
    """
    from datetime import datetime, timezone

    base = settings.supabase_url.rstrip("/")
    headers = {
        **_supabase_headers(settings),
        "Prefer": "resolution=merge-duplicates",
    }
    row: dict = {
        "user_id": user_id,
        "provider": provider,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    if current_period_end is not _KEEP_PERIOD_END:
        row["current_period_end"] = current_period_end
    if subscription_id is not None:
        row["provider_subscription_id"] = subscription_id
    if customer_id is not None:
        row["provider_customer_id"] = customer_id
    owned = client is not None
    http = client or httpx.AsyncClient(
        base_url=base, headers=headers, timeout=10.0
    )
    try:
        if owned:
            response = await http.post(
                f"{base}/rest/v1/billing_subscriptions?on_conflict=user_id",
                json=row,
                headers=headers,
            )
        else:
            response = await http.post(
                "/rest/v1/billing_subscriptions",
                params={"on_conflict": "user_id"},
                json=row,
            )
        if response.status_code >= 400:
            log.warning(
                "dodo linkage upsert failed user=%s status=%s",
                user_id,
                response.status_code,
            )
            return False
        return True
    except httpx.HTTPError as exc:
        log.warning(
            "dodo linkage upsert transport failed type=%s",
            type(exc).__name__,
        )
        return False
    finally:
        if not owned:
            await http.aclose()


@dataclass(frozen=True)
class SubscriptionLinkage:
    """One user's row in ``billing_subscriptions`` (provider-agnostic)."""

    provider: str
    provider_customer_id: str | None = None
    provider_subscription_id: str | None = None
    current_period_end: str | None = None


_LINKAGE_COLUMNS = (
    "provider,provider_customer_id,"
    "provider_subscription_id,current_period_end"
)


async def get_subscription_linkage(
    user_id: str, settings: Settings, *, client=None
) -> SubscriptionLinkage | None:
    """Read the user's billing linkage row (None when never subscribed).

    Raises RuntimeError when Supabase cannot be reached: the portal
    endpoint maps that to a retryable 502 instead of "no subscription".
    ``client`` is a test seam (see ``find_user_id_by_email``).
    """
    base = settings.supabase_url.rstrip("/")
    headers = _supabase_headers(settings)
    owned = client is not None
    http = client or httpx.AsyncClient(
        base_url=base, headers=headers, timeout=10.0
    )
    try:
        if owned:
            response = await http.get(
                f"{base}/rest/v1/billing_subscriptions",
                params={
                    "user_id": f"eq.{user_id}",
                    "select": _LINKAGE_COLUMNS,
                },
                headers=headers,
            )
        else:
            response = await http.get(
                "/rest/v1/billing_subscriptions",
                params={
                    "user_id": f"eq.{user_id}",
                    "select": _LINKAGE_COLUMNS,
                },
            )
        if response.status_code >= 400:
            log.warning(
                "dodo linkage read failed status=%s", response.status_code
            )
            raise RuntimeError("linkage lookup failed")
        try:
            rows = response.json()
        except ValueError:
            raise RuntimeError("linkage lookup failed")
        if not isinstance(rows, list) or not rows:
            return None
        row = rows[0] if isinstance(rows[0], dict) else {}
        return SubscriptionLinkage(
            provider=str(row.get("provider") or ""),
            provider_customer_id=_first_str(row.get("provider_customer_id")),
            provider_subscription_id=_first_str(
                row.get("provider_subscription_id")
            ),
            current_period_end=_first_str(row.get("current_period_end")),
        )
    except httpx.HTTPError as exc:
        log.warning(
            "dodo linkage read transport failed type=%s", type(exc).__name__
        )
        raise RuntimeError("linkage lookup failed")
    finally:
        if not owned:
            await http.aclose()


async def create_portal_session(
    customer_id: str,
    settings: Settings,
    *,
    client=None,
    return_url: str | None = None,
) -> str | None:
    """Mint a Dodo customer-portal sign-in link (valid 24 hours).

    Returns the ``link`` to redirect the user to, or None when Dodo
    cannot be reached or rejects the request. The link itself is never
    logged: it signs the customer in. ``client`` is a test seam.
    """
    from urllib.parse import urlencode

    base = settings.dodo_api_base.rstrip("/")
    headers = {
        "Authorization": f"Bearer {settings.dodo_api_key.strip()}",
        "Content-Type": "application/json",
    }
    owned = client is not None
    http = client or httpx.AsyncClient(
        base_url=base, headers=headers, timeout=10.0
    )
    try:
        if owned:
            url = f"{base}/customers/{customer_id}/customer-portal/session"
            if return_url:
                url += "?" + urlencode({"return_url": return_url})
            response = await http.post(url, headers=headers)
        else:
            response = await http.post(
                f"/customers/{customer_id}/customer-portal/session",
                params={"return_url": return_url} if return_url else None,
            )
        if response.status_code >= 400:
            log.warning(
                "dodo portal session failed status=%s", response.status_code
            )
            return None
        try:
            body = response.json()
        except ValueError:
            return None
        link = body.get("link") if isinstance(body, dict) else None
        if isinstance(link, str) and link.strip():
            return link.strip()
        log.warning("dodo portal session missing link")
        return None
    except httpx.HTTPError as exc:
        log.warning(
            "dodo portal session transport failed type=%s", type(exc).__name__
        )
        return None
    finally:
        if not owned:
            await http.aclose()
