"""Authentication + quota management tests (no network, no Supabase).

Covers the task contract with the in-process MemoryQuotaStore:
- Supabase JWT verification (valid / expired / wrong-secret).
- Protected endpoints reject anonymous callers only when auth is on.
- Quota check before start, billing in seconds, remaining = limit - used.
- Concurrent sessions never over-bill; retries never double-bill.
- Failed/unprocessed sessions bill 0.
- Exhausted quota refuses new sessions (402 offer / WS close).
"""

import asyncio
import json
import time

import jwt
import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.supabase_auth import AuthError, verify_supabase_token
from app.main import create_app
from app.services.quota import (
    MemoryQuotaStore,
    QuotaDenied,
    SessionQuotaTracker,
    begin_tracked_session,
    billed_seconds_for_bytes,
)

TEST_SECRET = "test-jwt-secret-for-sonaris-quota-tests"
USER_ID = "11111111-2222-3333-4444-555555555555"


def make_token(
    user_id: str = USER_ID,
    secret: str = TEST_SECRET,
    exp_in: int = 3600,
    anonymous: bool = False,
) -> str:
    now = int(time.time())
    claims: dict = {"sub": user_id, "iat": now, "exp": now + exp_in}
    if anonymous:
        claims["is_anonymous"] = True
    else:
        claims["email"] = "user@sonaris.local"
    return jwt.encode(claims, secret, algorithm="HS256")


def make_settings(**overrides):
    base = {
        "OPENAI_API_KEY": "test-key",
        "SUBTITLE_PROVIDER": "none",
        "SUPABASE_URL": "https://example.supabase.co",
        "SUPABASE_JWT_SECRET": TEST_SECRET,
    }
    base.update(overrides)
    return Settings(**base)


def make_client(**overrides):
    connect_error = overrides.pop("_connect_error", None)
    settings = make_settings(**overrides)
    app = create_app(settings)

    from tests.test_websocket import FakeUpstream  # reuse the fake socket

    fakes: list[FakeUpstream] = []

    def factory() -> FakeUpstream:
        fake = FakeUpstream(connect_error=connect_error)
        fakes.append(fake)
        return fake

    app.state.upstream_factory = factory
    return TestClient(app), fakes, app


# --- token verification ----------------------------------------------------


def test_valid_hs256_token_verifies():
    user = verify_supabase_token(make_token(), make_settings())
    assert user.id == USER_ID
    assert user.email == "user@sonaris.local"


def test_wrong_secret_rejected():
    with pytest.raises(AuthError):
        verify_supabase_token(make_token(secret="wrong"), make_settings())


def test_expired_token_rejected():
    with pytest.raises(AuthError):
        verify_supabase_token(make_token(exp_in=-120), make_settings())


def test_missing_token_rejected():
    with pytest.raises(AuthError):
        verify_supabase_token("", make_settings())


def test_anonymous_token_rejected():
    with pytest.raises(AuthError) as exc_info:
        verify_supabase_token(make_token(anonymous=True), make_settings())
    assert exc_info.value.code == "anonymous_disabled"


# --- anonymous access is impossible in production -------------------------------


def test_production_refuses_to_boot_without_supabase():
    settings = make_settings(ENVIRONMENT="production", SUPABASE_URL="")
    with pytest.raises(RuntimeError):
        create_app(settings)


def test_production_boots_with_supabase_configured():
    settings = make_settings(ENVIRONMENT="production")
    assert create_app(settings) is not None


def test_development_keeps_local_open_mode_without_supabase():
    settings = make_settings(SUPABASE_URL="", SUPABASE_JWT_SECRET="")
    assert create_app(settings) is not None
    assert not settings.auth_enabled()


# --- billing math ------------------------------------------------------------


def test_billed_seconds_rounds_up_partial_chunks():
    # One 200 ms extension chunk (9600 bytes) bills 1 second.
    assert billed_seconds_for_bytes(9600) == 1
    assert billed_seconds_for_bytes(48_000) == 1
    assert billed_seconds_for_bytes(48_001) == 2
    assert billed_seconds_for_bytes(0) == 0


def test_billed_seconds_scales_pro_audio_by_multiplier():
    # Pro-tier audio bills QUOTA_PRO_MULTIPLIER quota seconds per audio
    # second; rounding happens once on the scaled total.
    assert billed_seconds_for_bytes(48_000, 3.0) == 3
    assert billed_seconds_for_bytes(9600, 3.0) == 1  # 0.2 s * 3 = 0.6 s
    assert billed_seconds_for_bytes(48_001, 3.0) == 4
    assert billed_seconds_for_bytes(0, 3.0) == 0
    assert billed_seconds_for_bytes(48_000, 2.0) == 2


@pytest.mark.asyncio
async def test_pro_session_bills_scaled_seconds():
    store = MemoryQuotaStore()
    tracker = await begin_tracked_session(
        store, USER_ID, "sess-pro", model_tier="pro", pro_multiplier=3.0
    )
    tracker.add_audio_bytes(48_000)  # 1 s of pro audio -> 3 quota seconds
    tracker.note_transcript()
    assert tracker.billed_seconds == 3
    final = await tracker.finish("closed")
    assert final is not None
    assert final.used_seconds == 3
    assert final.remaining_seconds == 2397


@pytest.mark.asyncio
async def test_base_session_bills_one_to_one():
    store = MemoryQuotaStore()
    tracker = await begin_tracked_session(
        store, USER_ID, "sess-base", model_tier="base"
    )
    tracker.add_audio_bytes(48_000)
    tracker.note_transcript()
    assert tracker.billed_seconds == 1
    final = await tracker.finish("closed")
    assert final is not None
    assert final.used_seconds == 1


@pytest.mark.asyncio
async def test_mid_session_tier_switch_splits_billing():
    store = MemoryQuotaStore()
    tracker = await begin_tracked_session(
        store, USER_ID, "sess-switch", model_tier="base"
    )
    tracker.add_audio_bytes(48_000)  # 1 s base -> 1 quota second
    tracker.set_model_tier("pro")
    tracker.add_audio_bytes(48_000)  # 1 s pro -> 3 quota seconds
    tracker.note_transcript()
    assert tracker.billed_seconds == 4
    final = await tracker.finish("closed")
    assert final is not None
    assert final.used_seconds == 4


@pytest.mark.asyncio
async def test_custom_pro_multiplier_scales_billing():
    store = MemoryQuotaStore()
    tracker = await begin_tracked_session(
        store, USER_ID, "sess-mult", model_tier="pro", pro_multiplier=2.0
    )
    tracker.add_audio_bytes(48_000)
    tracker.note_transcript()
    assert tracker.billed_seconds == 2
    final = await tracker.finish("closed")
    assert final is not None
    assert final.used_seconds == 2


def test_quota_pro_multiplier_config_defaults_and_validates():
    from pydantic import ValidationError

    from app.core.config import Settings

    assert Settings(QUOTA_PRO_MULTIPLIER="3").quota_pro_multiplier == 3.0
    assert Settings(QUOTA_PRO_MULTIPLIER="2.5").quota_pro_multiplier == 2.5
    with pytest.raises(ValidationError):
        Settings(QUOTA_PRO_MULTIPLIER="0")
    with pytest.raises(ValidationError):
        Settings(QUOTA_PRO_MULTIPLIER="-1")


@pytest.mark.asyncio
async def test_daily_reset_clears_yesterday_usage():
    from datetime import datetime, timedelta, timezone

    store = MemoryQuotaStore()
    tracker = await begin_tracked_session(store, USER_ID, "sess-day1")
    tracker.add_audio_bytes(48_000 * 10)
    tracker.note_transcript()
    await tracker.finish("closed")
    assert (await store.get_quota(USER_ID)).used_seconds == 10
    # Simulate UTC midnight passing: the stored period goes stale.
    yesterday = (
        datetime.now(timezone.utc).date() - timedelta(days=1)
    ).isoformat()
    store._profiles[USER_ID]["period"] = yesterday
    snapshot = await store.get_quota(USER_ID)
    assert snapshot.used_seconds == 0
    assert snapshot.remaining_seconds == snapshot.limit_seconds
    # A new session starts against the fresh day, not yesterday's usage.
    tracker2 = await begin_tracked_session(store, USER_ID, "sess-day2")
    assert tracker2.remaining_seconds == tracker2.snapshot.limit_seconds
    assert tracker2.snapshot.period_start != yesterday


# --- authorize / commit semantics ---------------------------------------------


@pytest.mark.asyncio
async def test_authorize_commit_updates_remaining():
    store = MemoryQuotaStore()
    tracker = await begin_tracked_session(store, USER_ID, "sess-1")
    assert tracker.remaining_seconds == 2400
    tracker.add_audio_bytes(96_000)  # 2 s of audio
    tracker.note_transcript()
    final = await tracker.finish("closed")
    assert final is not None
    assert final.used_seconds == 2
    assert final.remaining_seconds == 2398
    assert final.limit_seconds - final.used_seconds == final.remaining_seconds


@pytest.mark.asyncio
async def test_failed_session_bills_zero():
    store = MemoryQuotaStore()
    tracker = await begin_tracked_session(store, USER_ID, "sess-fail")
    tracker.add_audio_bytes(480_000)  # 10 s streamed, then upstream died
    final = await tracker.finish("upstream_error:rate_limited")
    assert final is not None
    assert final.used_seconds == 0


@pytest.mark.asyncio
async def test_unprocessed_session_bills_zero():
    store = MemoryQuotaStore()
    tracker = await begin_tracked_session(store, USER_ID, "sess-silent")
    tracker.add_audio_bytes(480_000)  # audio flowed, but no subtitles came out
    final = await tracker.finish("closed")
    assert final is not None
    assert final.used_seconds == 0


@pytest.mark.asyncio
async def test_retry_same_key_never_double_bills():
    store = MemoryQuotaStore()
    tracker = await begin_tracked_session(store, USER_ID, "sess-retry")
    tracker.add_audio_bytes(48_000)
    tracker.note_transcript()
    first = await tracker.finish("closed")
    # A retried commit for the same logical session is a no-op.
    second = await store.commit("sess-retry", 1, "completed")
    assert first is not None and second is not None
    assert first.used_seconds == 1
    assert second.used_seconds == 1


@pytest.mark.asyncio
async def test_concurrent_sessions_bill_exactly_once_each():
    store = MemoryQuotaStore()
    trackers = await asyncio.gather(
        *(begin_tracked_session(store, USER_ID, f"sess-{i}") for i in range(5))
    )
    for tracker in trackers:
        tracker.add_audio_bytes(48_000)
        tracker.note_transcript()
    finals = await asyncio.gather(*(t.finish("closed") for t in trackers))
    assert all(f is not None for f in finals)
    snapshot = await store.get_quota(USER_ID)
    assert snapshot.used_seconds == 5


@pytest.mark.asyncio
async def test_checkpoint_commits_mid_session_and_finish_does_not_double_bill():
    store = MemoryQuotaStore()
    tracker = await begin_tracked_session(store, USER_ID, "sess-checkpoint")
    tracker.add_audio_bytes(96_000)  # 2 s of audio, session still running
    tracker.note_transcript()
    snapshot = await tracker.maybe_checkpoint(force=True)
    # Usage is in the DB while the session is still open.
    assert snapshot.used_seconds == 2
    assert (await store.get_quota(USER_ID)).used_seconds == 2
    # A retried checkpoint for the same audio is a no-op.
    snapshot = await tracker.maybe_checkpoint(force=True)
    assert snapshot.used_seconds == 2
    # Finish bills only the seconds streamed after the checkpoint.
    tracker.add_audio_bytes(48_000)  # +1 s
    final = await tracker.finish("closed")
    assert final is not None
    assert final.used_seconds == 3
    assert final.remaining_seconds == 2397


@pytest.mark.asyncio
async def test_checkpoint_makes_usage_visible_to_another_session():
    # Another tab's session must see this session's committed usage on its
    # next refresh instead of both overshooting the same remainder.
    store = MemoryQuotaStore()
    store.set_plan(USER_ID, "Free", 10)
    first = await begin_tracked_session(store, USER_ID, "sess-tab-a")
    second = await begin_tracked_session(store, USER_ID, "sess-tab-b")
    first.add_audio_bytes(48_000 * 8)  # 8 of the 10 remaining seconds
    first.note_transcript()
    await first.maybe_checkpoint(force=True)
    snapshot = await second.maybe_refresh(force=True)
    assert snapshot.remaining_seconds == 2
    assert second.effective_remaining_seconds == 2


@pytest.mark.asyncio
async def test_effective_remaining_counts_uncommitted_audio():
    # Between checkpoints the DB still shows the old remainder, but this
    # session's own streamed audio already counts against it.
    store = MemoryQuotaStore()
    store.set_plan(USER_ID, "Free", 10)
    tracker = await begin_tracked_session(store, USER_ID, "sess-live")
    tracker.add_audio_bytes(48_000 * 10)  # whole remainder, not yet committed
    tracker.note_transcript()
    assert tracker.snapshot.remaining_seconds == 10
    assert tracker.uncommitted_seconds == 10
    assert tracker.effective_remaining_seconds == 0
    assert tracker.quota_event()["remaining_seconds"] == 0


@pytest.mark.asyncio
async def test_failed_session_refunds_checkpointed_seconds():
    store = MemoryQuotaStore()
    tracker = await begin_tracked_session(store, USER_ID, "sess-fail-ckpt")
    tracker.add_audio_bytes(96_000)
    tracker.note_transcript()
    await tracker.maybe_checkpoint(force=True)
    assert (await store.get_quota(USER_ID)).used_seconds == 2
    final = await tracker.finish("upstream_error:rate_limited")
    assert final is not None
    assert final.used_seconds == 0


@pytest.mark.asyncio
async def test_checkpoint_commits_before_first_transcript_and_silent_finish_refunds():
    # The 15s worker commits on cadence, even before any transcript. A
    # session that ends with no output still bills 0 overall, so finish
    # refunds what the checkpoint committed.
    store = MemoryQuotaStore()
    tracker = await begin_tracked_session(store, USER_ID, "sess-silent-ckpt")
    tracker.add_audio_bytes(96_000)
    await tracker.checkpoint()
    assert (await store.get_quota(USER_ID)).used_seconds == 2
    final = await tracker.finish("closed")
    assert final is not None
    assert final.used_seconds == 0


@pytest.mark.asyncio
async def test_checkpoint_commits_to_db_on_every_call():
    # The background worker commits every 15s tick: each call reaches the
    # store even when no new whole second has been billed since the last.
    class CountingStore(MemoryQuotaStore):
        def __init__(self):
            super().__init__()
            self.checkpoint_calls = 0

        async def checkpoint(self, client_session_id, billed_seconds):
            self.checkpoint_calls += 1
            return await super().checkpoint(client_session_id, billed_seconds)

    store = CountingStore()
    tracker = await begin_tracked_session(store, USER_ID, "sess-worker")
    await tracker.checkpoint()
    await tracker.checkpoint()
    await tracker.checkpoint()
    assert store.checkpoint_calls == 3
    # No audio was billed, so repeated commits change nothing in the DB.
    assert (await store.get_quota(USER_ID)).used_seconds == 0


@pytest.mark.asyncio
async def test_exhausted_quota_refuses_new_session():
    store = MemoryQuotaStore()
    store.set_plan(USER_ID, "Free", 0)
    with pytest.raises(QuotaDenied) as exc_info:
        await begin_tracked_session(store, USER_ID, "sess-denied")
    assert exc_info.value.snapshot.remaining_seconds == 0


# --- protected endpoints -------------------------------------------------------


def test_webrtc_offer_without_token_rejected_when_auth_on():
    client, _, _ = make_client()
    response = client.post(
        "/api/v1/transcription/webrtc/offer",
        json={"sdp": "v=0", "type": "offer", "client_session_id": "x"},
    )
    assert response.status_code == 401
    assert response.json()["code"] == "auth_expired"


def test_webrtc_offer_quota_exhausted_returns_402_with_quota():
    client, _, app = make_client()
    app.state.quota_store.set_plan(USER_ID, "Free", 0)
    response = client.post(
        "/api/v1/transcription/webrtc/offer",
        headers={"Authorization": f"Bearer {make_token()}"},
        json={"sdp": "v=0", "type": "offer", "client_session_id": "spent"},
    )
    assert response.status_code == 402
    body = response.json()
    assert body["code"] == "quota_exceeded"
    assert body["quota"]["remaining_seconds"] == 0


def test_me_quota_requires_auth_when_enabled():
    client, _, _ = make_client()
    assert client.get("/api/v1/me/quota").status_code in (401, 403)


def test_me_quota_returns_own_plan_and_usage():
    client, _, _ = make_client()
    response = client.get(
        "/api/v1/me/quota", headers={"Authorization": f"Bearer {make_token()}"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["user_id"] == USER_ID
    assert body["limit_seconds"] == 2400
    assert body["used_seconds"] == 0
    assert body["remaining_seconds"] == 2400


def test_webrtc_offer_anonymous_token_rejected():
    client, _, _ = make_client()
    response = client.post(
        "/api/v1/transcription/webrtc/offer",
        headers={"Authorization": f"Bearer {make_token(anonymous=True)}"},
        json={"sdp": "v=0", "type": "offer", "client_session_id": "anon"},
    )
    assert response.status_code == 401
    assert response.json()["code"] == "anonymous_disabled"


def test_websocket_anonymous_token_closed():
    client, _, _ = make_client()
    with client.websocket_connect(
        f"/api/v1/transcription/ws?token={make_token(anonymous=True)}"
    ) as ws:
        msg = json.loads(ws.receive_text())
        assert msg["type"] == "error"
        assert msg["code"] == "anonymous_disabled"


def test_websocket_without_token_closed_when_auth_on():
    client, _, _ = make_client()
    with client.websocket_connect("/api/v1/transcription/ws") as ws:
        msg = json.loads(ws.receive_text())
        assert msg["type"] == "error"
        assert msg["code"] == "auth_expired"


# --- end-to-end over the WebSocket transport ------------------------------------

import contextlib as _contextlib


@_contextlib.contextmanager
def _tolerant_websocket(client, url):
    """websocket_connect that tolerates the portal teardown race.

    starlette's WebSocketTestSession teardown can raise
    concurrent.futures.CancelledError when the server already closed the
    connection (the relay closes both sockets once the client goes away).
    The server commits quota before that close, so the billing assertions
    after the block stay the ground truth; body AssertionErrors propagate
    normally.
    """
    from concurrent.futures import CancelledError

    try:
        with client.websocket_connect(url) as ws:
            yield ws
    except CancelledError:
        pass


def test_websocket_tracked_session_bills_audio_seconds():
    from tests.test_websocket import wait_for

    # Explicit base tier + pinned Soniox key: billing must not depend on
    # the deployment's STT_PROVIDER default.
    client, fakes, app = make_client(SONIOX_API_KEY="test-soniox-key")
    token = make_token()
    with _tolerant_websocket(
        client, f"/api/v1/transcription/ws?token={token}&model_tier=base"
    ) as ws:
        ready = json.loads(ws.receive_text())
        assert ready["type"] == "session.ready"
        opening = json.loads(ws.receive_text())
        assert opening["type"] == "quota.update"
        assert opening["remaining_seconds"] == 2400
        # 36_000 decoded bytes (~0.75 s of audio) bills a full second.
        ws.send_text(json.dumps({"type": "audio.append", "audio": "AQID" * 12000}))
        assert wait_for(lambda: len(fakes[0].sent) >= 1)
        fakes[0].inject(
            {
                "tokens": [
                    {
                        "text": "hello",
                        "is_final": True,
                        "translation_status": "original",
                    }
                ],
                "finished": False,
            }
        )
        deadline = time.time() + 5
        while time.time() < deadline:
            msg = json.loads(ws.receive_text())
            if msg.get("type") == "transcript.delta":
                assert msg["delta"] == "hello"
                break
    store = app.state.quota_store
    import asyncio as _asyncio

    used = _asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
        store.get_quota(USER_ID)
    )
    assert used.used_seconds == 1
    assert used.remaining_seconds == 2399


def test_websocket_tiered_billing_end_to_end():
    # One session, two engines: base audio bills 1:1, audio after a
    # mid-session switch to pro bills QUOTA_PRO_MULTIPLIER (3x). A single
    # connection covers both stretches because the test harness only
    # supports one full relay session per process (a second
    # websocket_connect fails at the portal with CancelledError).
    from tests.test_websocket import FakeUpstream, wait_for

    client, fakes, app = make_client(SONIOX_API_KEY="test-soniox-key")
    # Tier-aware factory: the base -> pro swap connects a fresh fake.
    def tier_factory(tier=None):
        fake = FakeUpstream()
        fakes.append(fake)
        return fake

    app.state.upstream_factory = tier_factory
    token = make_token()
    with _tolerant_websocket(
        client, f"/api/v1/transcription/ws?token={token}&model_tier=base"
    ) as ws:
        def next_of(*types, timeout=5.0):
            deadline = time.time() + timeout
            while time.time() < deadline:
                msg = json.loads(ws.receive_text())
                if msg.get("type") in types:
                    return msg
            raise AssertionError(f"timed out waiting for {types}")

        assert next_of("session.ready")["type"] == "session.ready"
        opening = next_of("quota.update")
        assert opening["remaining_seconds"] == 2400
        # Base stretch: 48_000 decoded bytes (1 s of audio) bills 1 second.
        ws.send_text(json.dumps({"type": "audio.append", "audio": "AQID" * 16000}))
        assert wait_for(lambda: len(fakes) > 0 and len(fakes[0].sent) >= 1)
        fakes[0].inject(
            {
                "tokens": [
                    {
                        "text": "hello",
                        "is_final": True,
                        "translation_status": "original",
                    }
                ],
                "finished": False,
            }
        )
        assert next_of("transcript.delta")["delta"] == "hello"
        # Switch to pro mid-session: later audio bills 3x.
        ws.send_text(
            json.dumps(
                {
                    "type": "language-config",
                    "mode": "transcription",
                    "model_tier": "pro",
                }
            )
        )
        swapped = next_of("session.ready", "error")
        assert swapped["type"] == "session.ready", swapped
        # Pro stretch: 1 s of audio bills 3 quota seconds.
        ws.send_text(json.dumps({"type": "audio.append", "audio": "AQID" * 16000}))
        assert wait_for(lambda: len(fakes) > 1 and len(fakes[1].sent) >= 1)
        fakes[1].inject(
            {
                "type": "conversation.item.input_audio_transcription.completed",
                "transcript": "hello",
            }
        )
        assert next_of("transcript.completed")["transcript"] == "hello"
    store = app.state.quota_store
    import asyncio as _asyncio

    used = _asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
        store.get_quota(USER_ID)
    )
    # 1 s base + 1 s pro bills 1 + 3 = 4 quota seconds.
    assert used.used_seconds == 4
    assert used.remaining_seconds == 2396


def test_webrtc_offer_auth_checked_before_api_key_config():
    # Auth runs first: no token -> 401 even when the API key is missing
    # (previously this returned 503 and leaked server config state).
    client, _, _ = make_client(OPENAI_API_KEY="")
    response = client.post(
        "/api/v1/transcription/webrtc/offer",
        json={"sdp": "v=0", "type": "offer", "client_session_id": "x"},
    )
    assert response.status_code == 401
    assert response.json()["code"] == "auth_expired"


def test_webrtc_offer_auth_checked_before_origin():
    # Auth runs first: no token -> 401 even from a disallowed origin
    # (previously 403).
    client, _, _ = make_client(
        ALLOWED_WEBSOCKET_ORIGINS="https://example.com"
    )
    response = client.post(
        "/api/v1/transcription/webrtc/offer",
        json={"sdp": "v=0", "type": "offer", "client_session_id": "x"},
        headers={"origin": "https://evil.test"},
    )
    assert response.status_code == 401
    assert response.json()["code"] == "auth_expired"


def test_webrtc_offer_valid_token_passes_auth_gate():
    # A valid token passes the auth gate: with no API key configured the
    # request fails at the config check (503), not at auth.
    client, _, _ = make_client(OPENAI_API_KEY="")
    response = client.post(
        "/api/v1/transcription/webrtc/offer",
        headers={"Authorization": f"Bearer {make_token()}"},
        json={"sdp": "v=0", "type": "offer", "client_session_id": "ok"},
    )
    assert response.status_code == 503
    assert response.json()["code"] == "not_configured"
