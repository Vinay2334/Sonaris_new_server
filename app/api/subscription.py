"""Authenticated subscription self-service (Dodo customer portal).

``POST /api/v1/me/subscription/portal`` mints a one-click portal
sign-in link for the signed-in user (valid 24 hours) and returns it as
``{"ok": true, "url": ...}``; the site redirects the browser there, so
the user manages (or cancels) their subscription inside Dodo instead of
filing a support ticket. The link itself is never logged: it signs the
customer in.

Status contract:
- 401 no/invalid Supabase token (via ``require_user``).
- 503 portal not configured (no Dodo API key) — the site renders its
  support fallback instead.
- 404 the user has no billing linkage (never subscribed, or a legacy
  paid row from before linkage existed) — the site falls back to the
  static portal link / support email.
- 502 Supabase or Dodo failed — transient, worth a retry.
"""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from app.core.logging import get_logger
from app.core.supabase_auth import AuthUser, require_user
from app.services.billing import (
    create_portal_session,
    get_subscription_linkage,
)

log = get_logger(__name__)

router = APIRouter()


@router.post("/api/v1/me/subscription/portal")
async def subscription_portal(
    request: Request, user: AuthUser = Depends(require_user)
) -> JSONResponse:
    settings = request.app.state.settings
    if not settings.portal_available():
        return JSONResponse(
            status_code=503, content={"ok": False, "reason": "portal_unavailable"}
        )
    try:
        body = await request.json()
        return_url = body.get("return_url") if isinstance(body, dict) else None
    except Exception:
        return_url = None
    if not isinstance(return_url, str) or not return_url.strip():
        return_url = None
    else:
        return_url = return_url.strip()
    try:
        linkage = await get_subscription_linkage(user.id, settings)
    except Exception as exc:
        log.warning("portal linkage lookup failed type=%s", type(exc).__name__)
        return JSONResponse(
            status_code=502, content={"ok": False, "reason": "lookup_failed"}
        )
    if linkage is None or not linkage.provider_customer_id:
        return JSONResponse(
            status_code=404, content={"ok": False, "reason": "no_subscription"}
        )
    if linkage.provider and linkage.provider != "dodo":
        log.warning("portal for unsupported provider user=%s", user.id)
        return JSONResponse(
            status_code=404, content={"ok": False, "reason": "no_subscription"}
        )
    url = await create_portal_session(
        linkage.provider_customer_id, settings, return_url=return_url
    )
    if not url:
        return JSONResponse(
            status_code=502, content={"ok": False, "reason": "portal_failed"}
        )
    return JSONResponse(status_code=200, content={"ok": True, "url": url})
