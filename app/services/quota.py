"""User quota tracking billed in whole subtitle seconds.

Billing rule (server-side only, never trusts client-supplied numbers):
every validated inbound audio byte counts ``1 / PCM_BYTES_PER_SECOND`` of
a second at the session's model tier; the commit rounds up to whole
seconds. Base-tier audio (Soniox) bills 1:1; pro-tier audio (OpenAI)
bills ``QUOTA_PRO_MULTIPLIER`` (default 3) quota seconds per audio
second. Paused/muted stretches send no audio, so they bill nothing; an
idle-but-open session with no audio bills nothing.

Quotas are daily: ``used`` counts this UTC day only and resets to 0 at
UTC midnight (profiles carry ``quota_period_start``; every read/write
path resets a stale period before enforcing).

Safety properties:
- ``authorize`` runs before a session starts and refuses when no quota
  remains (``Remaining = limit - used``).
- ``commit`` is idempotent on ``client_session_id``: reconnects/retries
  that reuse the key can never double-bill, and concurrent sessions are
  serialized (row lock in Postgres, asyncio lock in memory).
- Sessions that produced no transcript (upstream failure before any
  output, pure silence, rejected audio) commit 0 seconds and are marked
  ``failed``/unprocessed instead of ``completed``.
- A running session re-reads remaining quota every few seconds; at zero
  it is cut off with ``quota_exceeded`` so it cannot consume past its
  allocation.
- Every ``QUOTA_COMMIT_SECONDS`` (default 15) a running session also
  checkpoints: it commits the seconds billed so far to the DB (session
  stays ``active``) and then re-reads quota, so another tab/session sees
  this usage within one interval instead of only at session end. Between
  checkpoints the session's own uncommitted audio already counts against
  its effective remainder, so a single session cannot overshoot either.
  Checkpoints carry the cumulative billed total, so retries apply only
  the delta since the last checkpoint and never double-bill; a session
  that ultimately bills 0 (no transcript / upstream failure) refunds any
  checkpointed seconds at ``finish``.
"""

from __future__ import annotations

import asyncio
import math
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

from app.core.config import Settings
from app.core.logging import get_logger

log = get_logger(__name__)

# Extension audio is mono PCM16 @ 24 kHz: 24_000 samples/s * 2 bytes.
PCM_BYTES_PER_SECOND = 48_000

# Quota for users when the backend has no Supabase project configured
# (local dev / tests). Matches the SQL `free` plan (40 daily minutes).
MEMORY_DEFAULT_PLAN = "Free"
MEMORY_DEFAULT_LIMIT_SECONDS = 2400

# Quota multiplier applied to pro-tier audio when no explicit value is
# passed (mirrors Settings.quota_pro_multiplier's default).
DEFAULT_PRO_MULTIPLIER = 3.0


def utc_today_iso() -> str:
    """Current UTC calendar day (``YYYY-MM-DD``): the daily quota period."""
    return datetime.now(timezone.utc).date().isoformat()


def billed_seconds_for_bytes(num_bytes: float, multiplier: float = 1.0) -> int:
    """Whole seconds billed for validated audio bytes (rounds up).

    ``multiplier`` scales the audio time before rounding: base-tier audio
    bills 1:1, pro-tier audio bills ``QUOTA_PRO_MULTIPLIER`` quota seconds
    per audio second. Rounding happens once on the scaled total, so a
    short pro burst bills ``ceil(bytes * multiplier / 48_000)``.
    """
    if num_bytes <= 0:
        return 0
    return int(math.ceil(num_bytes * max(multiplier, 0.0) / PCM_BYTES_PER_SECOND))


@dataclass(frozen=True)
class QuotaSnapshot:
    user_id: str
    plan: str
    used_seconds: int
    limit_seconds: int
    period_start: str = ""

    @property
    def remaining_seconds(self) -> int:
        return max(self.limit_seconds - self.used_seconds, 0)

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "plan": self.plan,
            "used_seconds": self.used_seconds,
            "limit_seconds": self.limit_seconds,
            "remaining_seconds": self.remaining_seconds,
            "period_start": self.period_start,
        }


class QuotaDenied(Exception):
    """Raised when a session may not start (no quota left)."""

    def __init__(self, snapshot: QuotaSnapshot, reason: str = "quota_exceeded") -> None:
        super().__init__(reason)
        self.snapshot = snapshot
        self.reason = reason


class QuotaStore:
    """Persistence behind quota checks/commits (Supabase or memory)."""

    async def get_quota(self, user_id: str) -> QuotaSnapshot:
        raise NotImplementedError

    async def authorize(
        self, user_id: str, client_session_id: str, min_start_seconds: int = 1
    ) -> QuotaSnapshot:
        """Reserve a session slot. Raises QuotaDenied when not allowed."""
        raise NotImplementedError

    async def commit(
        self, client_session_id: str, billed_seconds: int, status: str
    ) -> QuotaSnapshot | None:
        """Idempotent finalize. Returns the fresh snapshot (None if unknown)."""
        raise NotImplementedError

    async def checkpoint(
        self, client_session_id: str, billed_seconds: int
    ) -> QuotaSnapshot | None:
        """Commit cumulative billed seconds mid-session (stays active).

        ``billed_seconds`` is the session total so far, not a delta: only
        the increase since the last checkpoint/finalize is applied, so a
        retried checkpoint never double-bills. Returns the fresh snapshot
        (None if the session is unknown or already finalized).
        """
        raise NotImplementedError


class MemoryQuotaStore(QuotaStore):
    """In-process store: local dev fallback and hermetic tests.

    Daily quotas: each profile carries the UTC day its ``used`` counts
    for. Any access in a new day resets ``used`` to 0 first, so usage
    never leaks across the UTC-midnight boundary.
    """

    def __init__(self, default_limit_seconds: int = MEMORY_DEFAULT_LIMIT_SECONDS) -> None:
        self._lock = asyncio.Lock()
        self._profiles: dict[str, dict] = {}
        self._sessions: dict[str, dict] = {}
        self._default_limit = default_limit_seconds

    def set_plan(self, user_id: str, plan: str, limit_seconds: int) -> None:
        """Dashboard equivalent for tests: change a user's plan + limit."""
        profile = self._profiles.setdefault(
            user_id,
            {
                "plan": MEMORY_DEFAULT_PLAN,
                "limit": self._default_limit,
                "used": 0,
                "period": utc_today_iso(),
            },
        )
        profile["plan"] = plan
        profile["limit"] = limit_seconds

    def _profile(self, user_id: str) -> dict:
        """Profile row, resetting a stale daily period to zero usage."""
        profile = self._profiles.setdefault(
            user_id,
            {
                "plan": MEMORY_DEFAULT_PLAN,
                "limit": self._default_limit,
                "used": 0,
                "period": utc_today_iso(),
            },
        )
        today = utc_today_iso()
        if profile.get("period") != today:
            profile["used"] = 0
            profile["period"] = today
        return profile

    def _snapshot(self, user_id: str) -> QuotaSnapshot:
        profile = self._profile(user_id)
        return QuotaSnapshot(
            user_id=user_id,
            plan=profile["plan"],
            used_seconds=profile["used"],
            limit_seconds=profile["limit"],
            period_start=profile.get("period", ""),
        )

    async def get_quota(self, user_id: str) -> QuotaSnapshot:
        async with self._lock:
            return self._snapshot(user_id)

    async def authorize(
        self, user_id: str, client_session_id: str, min_start_seconds: int = 1
    ) -> QuotaSnapshot:
        async with self._lock:
            existing = self._sessions.get(client_session_id)
            if existing is not None and existing["status"] == "active":
                # Reconnect reuses the key: resume without double-reserving.
                return self._snapshot(user_id)
            snapshot = self._snapshot(user_id)
            if snapshot.remaining_seconds < max(min_start_seconds, 1):
                raise QuotaDenied(snapshot)
            self._sessions[client_session_id] = {
                "user_id": user_id,
                "status": "active",
                "billed": 0,
            }
            return snapshot

    async def checkpoint(
        self, client_session_id: str, billed_seconds: int
    ) -> QuotaSnapshot | None:
        async with self._lock:
            session = self._sessions.get(client_session_id)
            if session is None or session["status"] in ("completed", "failed"):
                return None
            billed = max(int(billed_seconds or 0), 0)
            delta = max(billed - session["billed"], 0)
            if delta:
                session["billed"] = billed
                profile = self._profile(session["user_id"])
                profile["used"] += delta
            return self._snapshot(session["user_id"])

    async def commit(
        self, client_session_id: str, billed_seconds: int, status: str
    ) -> QuotaSnapshot | None:
        async with self._lock:
            session = self._sessions.get(client_session_id)
            if session is None:
                return None
            if session["status"] in ("completed", "failed"):
                return self._snapshot(session["user_id"])
            # Delta against checkpointed seconds: a session billed at
            # checkpoints only pays the remainder here, and one that
            # ultimately bills 0 refunds what it checkpointed.
            final_billed = max(int(billed_seconds or 0), 0)
            delta = final_billed - session["billed"]
            session["status"] = status
            session["billed"] = final_billed
            profile = self._profile(session["user_id"])
            profile["used"] = max(profile["used"] + delta, 0)
            return self._snapshot(session["user_id"])


class SupabaseQuotaStore(QuotaStore):
    """Postgres-backed store via Supabase REST (service role key).

    All quota reads/writes go through the atomic daily-quota RPCs
    (``authorize_session`` / ``get_quota_snapshot`` /
    ``checkpoint_session_usage`` / ``commit_session_usage``); a missing
    or failing RPC raises instead of silently serving stale numbers.
    """

    def __init__(self, settings: Settings) -> None:
        base = settings.supabase_url.rstrip("/")
        key = settings.supabase_service_role_key.strip()
        self._base = base
        self._headers = {
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        }

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._base, headers=self._headers, timeout=10.0
        )

    async def _rpc(self, name: str, params: dict) -> dict | None:
        try:
            async with self._client() as client:
                response = await client.post(f"/rest/v1/rpc/{name}", json=params)
        except httpx.HTTPError as exc:
            log.warning("quota RPC %s transport failed type=%s", name, type(exc).__name__)
            return None
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            log.warning("quota RPC %s failed status=%s", name, response.status_code)
            return None
        try:
            return response.json()
        except ValueError:
            return None

    @staticmethod
    def _snapshot_from_rpc(user_id: str, data: dict) -> QuotaSnapshot:
        return QuotaSnapshot(
            user_id=user_id,
            plan=str(data.get("plan", "Free")),
            used_seconds=int(data.get("used_seconds", 0) or 0),
            limit_seconds=int(data.get("limit_seconds", 0) or 0),
            period_start=str(data.get("period_start", "") or ""),
        )

    async def get_quota(self, user_id: str) -> QuotaSnapshot:
        data = await self._rpc("get_quota_snapshot", {"p_user_id": user_id})
        if data is None or data.get("used_seconds") is None:
            raise RuntimeError("quota snapshot RPC unavailable")
        return self._snapshot_from_rpc(user_id, data)

    async def authorize(
        self, user_id: str, client_session_id: str, min_start_seconds: int = 1
    ) -> QuotaSnapshot:
        data = await self._rpc(
            "authorize_session",
            {"p_user_id": user_id, "p_client_session_id": client_session_id},
        )
        if data is None:
            raise RuntimeError("quota authorize RPC unavailable")
        snapshot = self._snapshot_from_rpc(user_id, data)
        if not data.get("allowed", False):
            raise QuotaDenied(snapshot)
        return snapshot

    async def checkpoint(
        self, client_session_id: str, billed_seconds: int
    ) -> QuotaSnapshot | None:
        data = await self._rpc(
            "checkpoint_session_usage",
            {
                "p_client_session_id": client_session_id,
                "p_billed_seconds": max(int(billed_seconds or 0), 0),
            },
        )
        if data is None:
            raise RuntimeError("quota checkpoint RPC unavailable")
        used = data.get("used_seconds")
        if used is None:
            return None
        return QuotaSnapshot(
            user_id="",
            plan=str(data.get("plan", "Free")),
            used_seconds=int(used or 0),
            limit_seconds=int(data.get("limit_seconds", 0) or 0),
        )

    async def commit(
        self, client_session_id: str, billed_seconds: int, status: str
    ) -> QuotaSnapshot | None:
        data = await self._rpc(
            "commit_session_usage",
            {
                "p_client_session_id": client_session_id,
                "p_billed_seconds": max(int(billed_seconds or 0), 0),
                "p_status": status if status in ("completed", "failed") else "completed",
            },
        )
        if data is None:
            raise RuntimeError("quota commit RPC unavailable")
        used = data.get("used_seconds")
        if used is None:
            return None
        return QuotaSnapshot(
            user_id="",
            plan=str(data.get("plan", "Free")),
            used_seconds=int(used or 0),
            limit_seconds=int(data.get("limit_seconds", 0) or 0),
        )


def build_quota_store(settings: Settings) -> QuotaStore:
    if settings.quota_enforced():
        return SupabaseQuotaStore(settings)
    return MemoryQuotaStore()


@dataclass
class SessionQuotaTracker:
    """Per-session billing accumulator owned by one relay session.

    Only audio bytes the relay actually kept (post-validation,
    post-rate-limit) are added. ``finish`` converts to whole seconds and
    commits exactly once; unknown sessions commit nothing.

    Tier-weighted billing: bytes are bucketed by the tier in effect when
    they arrived. Base-tier audio bills 1:1; pro-tier audio bills
    ``pro_multiplier`` quota seconds per audio second. A mid-session tier
    swap (``set_model_tier``) routes later bytes to the other bucket, so
    each stretch bills at the engine that actually transcribed it.
    """

    store: QuotaStore
    user_id: str
    client_session_id: str
    snapshot: QuotaSnapshot
    model_tier: str | None = None
    pro_multiplier: float = DEFAULT_PRO_MULTIPLIER
    audio_bytes: int = 0
    base_audio_bytes: int = 0
    pro_audio_bytes: int = 0
    transcripts_emitted: int = 0
    refresh_interval: float = 5.0
    checkpoint_interval: float = 15.0
    _finished: bool = field(default=False, init=False)
    _last_refresh: float = field(default_factory=time.monotonic, init=False)
    _committed_seconds: int = field(default=0, init=False)
    _last_checkpoint: float = field(default_factory=time.monotonic, init=False)

    @property
    def billed_seconds(self) -> int:
        weighted = self.base_audio_bytes + self.pro_audio_bytes * max(
            self.pro_multiplier, 0.0
        )
        return billed_seconds_for_bytes(weighted)

    @property
    def remaining_seconds(self) -> int:
        return self.snapshot.remaining_seconds

    @property
    def committed_seconds(self) -> int:
        """Seconds already checkpointed/committed to the DB."""
        return self._committed_seconds

    @property
    def uncommitted_seconds(self) -> int:
        """Billed seconds not yet in the DB snapshot."""
        return max(self.billed_seconds - self._committed_seconds, 0)

    @property
    def effective_remaining_seconds(self) -> int:
        """DB remainder minus this session's uncommitted audio.

        The DB snapshot alone never shrinks while this session runs, so
        the cutoff must use this value to fire mid-session.
        """
        return max(self.snapshot.remaining_seconds - self.uncommitted_seconds, 0)

    def set_model_tier(self, model_tier: str | None) -> None:
        """Route subsequently added audio to a tier's billing bucket."""
        tier = (model_tier or "").strip().lower()
        self.model_tier = tier if tier in ("base", "pro") else None

    def set_pro_multiplier(self, multiplier: float) -> None:
        """Update the pro-tier scaling for subsequently billed audio."""
        if multiplier > 0:
            self.pro_multiplier = multiplier

    def add_audio_bytes(self, num_bytes: int) -> None:
        if num_bytes <= 0:
            return
        self.audio_bytes += num_bytes
        if (self.model_tier or "").strip().lower() == "pro":
            self.pro_audio_bytes += num_bytes
        else:
            self.base_audio_bytes += num_bytes

    def note_transcript(self) -> None:
        self.transcripts_emitted += 1

    def quota_event(self) -> dict:
        event = self.snapshot.to_dict()
        event["used_seconds"] = self.snapshot.used_seconds + self.uncommitted_seconds
        event["remaining_seconds"] = self.effective_remaining_seconds
        return {"type": "quota.update", **event}

    async def checkpoint(self) -> QuotaSnapshot:
        """Commit the billed-so-far total to the DB now (stays active).

        Unconditional: the 15s background worker calls this every tick,
        even with no new whole second or no transcript yet, so usage
        reaches the DB on cadence rather than only when convenient. The
        store applies only the delta since the last checkpoint, so
        repeat commits never double-bill; if the session later bills 0
        at finish (no transcript / upstream failure), ``finish`` refunds
        whatever was committed here.
        """
        if self._finished:
            return self.snapshot
        self._last_checkpoint = time.monotonic()
        billed = self.billed_seconds
        try:
            fresh = await self.store.checkpoint(self.client_session_id, billed)
        except Exception as exc:
            log.warning("quota checkpoint failed type=%s", type(exc).__name__)
            return self.snapshot
        if fresh is None:
            # Unknown session or checkpoint RPC not deployed yet: keep
            # the seconds uncommitted and retry on the next tick.
            log.warning("quota checkpoint unavailable for session")
            return self.snapshot
        if not fresh.user_id:
            fresh = QuotaSnapshot(
                user_id=self.user_id,
                plan=fresh.plan,
                used_seconds=fresh.used_seconds,
                limit_seconds=fresh.limit_seconds,
            )
        self.snapshot = fresh
        self._committed_seconds = billed
        return self.snapshot

    async def maybe_checkpoint(
        self, *, force: bool = False, interval: float | None = None
    ) -> QuotaSnapshot:
        """Checkpoint if the interval has elapsed (or ``force``).

        Kept for interval-driven callers; the transports instead run a
        dedicated 15s worker that calls :meth:`checkpoint` directly.
        """
        if self._finished:
            return self.snapshot
        now = time.monotonic()
        due = self.checkpoint_interval if interval is None else interval
        if not force and now - self._last_checkpoint < max(due, 0.0):
            return self.snapshot
        return await self.checkpoint()

    async def maybe_refresh(self, *, force: bool = False) -> QuotaSnapshot:
        now = time.monotonic()
        if not force and now - self._last_refresh < self.refresh_interval:
            return self.snapshot
        self._last_refresh = now
        try:
            self.snapshot = await self.store.get_quota(self.user_id)
        except Exception as exc:
            log.warning("quota refresh failed type=%s", type(exc).__name__)
        return self.snapshot

    async def finish(self, reason: str) -> QuotaSnapshot | None:
        """Commit usage exactly once. Failed/unprocessed sessions bill 0."""
        if self._finished:
            return None
        self._finished = True
        failed = reason.startswith(
            ("upstream_error", "relay_error", "internal_error", "upstream_send_failed")
        )
        if failed or self.transcripts_emitted == 0:
            billed, status = 0, "failed"
        else:
            billed, status = self.billed_seconds, "completed"
        try:
            final = await self.store.commit(self.client_session_id, billed, status)
        except Exception as exc:
            log.warning("quota commit failed type=%s", type(exc).__name__)
            return None
        if final is not None and not final.user_id:
            final = QuotaSnapshot(
                user_id=self.user_id,
                plan=final.plan,
                used_seconds=final.used_seconds,
                limit_seconds=final.limit_seconds,
            )
        if final is not None:
            self._committed_seconds = billed
            self.snapshot = final
        log.info(
            "quota session billed user=%s billed=%ds transcripts=%d status=%s reason=%s tier=%s",
            self.user_id,
            billed,
            self.transcripts_emitted,
            status,
            reason,
            self.model_tier or "base",
        )
        return final


async def begin_tracked_session(
    store: QuotaStore,
    user_id: str,
    client_session_id: str,
    *,
    min_start_seconds: int = 1,
    model_tier: str | None = None,
    pro_multiplier: float = DEFAULT_PRO_MULTIPLIER,
) -> SessionQuotaTracker:
    """Authorize + build a tracker. Raises QuotaDenied when not allowed.

    ``model_tier`` selects the billing bucket from the first byte
    (``"pro"`` scales by ``pro_multiplier``, anything else bills 1:1).
    """
    snapshot = await store.authorize(
        user_id, client_session_id, min_start_seconds=min_start_seconds
    )
    tracker = SessionQuotaTracker(
        store=store, user_id=user_id, client_session_id=client_session_id, snapshot=snapshot
    )
    tracker.set_model_tier(model_tier)
    tracker.set_pro_multiplier(pro_multiplier)
    return tracker
