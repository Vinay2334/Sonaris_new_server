-- Captify daily quota reset.
--
-- SOURCE OF TRUTH for `supabase db push` (apply after
-- 20261119000000_quota_checkpoint.sql). Additive only.
--
-- Quotas are daily: profiles.quota_used_seconds counts the current UTC
-- day only (profiles.quota_period_start). Every RPC below resets a stale
-- period to zero usage before enforcing, so usage never leaks across the
-- UTC-midnight boundary and no cron job is needed. get_quota_snapshot
-- gives reads the same atomic reset (used by GET /api/v1/me/quota).

alter table public.profiles
  add column if not exists quota_period_start date not null default CURRENT_DATE;

-- ------------------------------------------- atomic daily quota RPCs ---
-- Each function below locks the profile row, resets a stale daily
-- period to zero usage first (same transaction, so the reset and the
-- charge that follows are atomic), then enforces as before.

-- authorize_session: called BEFORE a subtitle session starts. Locks the
-- profile row, resets a stale daily period, reuses the idempotency key
-- on reconnect, and refuses when no quota remains. One transaction =>
-- concurrent starts cannot overbook.
create or replace function public.authorize_session(
  p_user_id uuid,
  p_client_session_id text
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_plan_id text;
  v_used integer;
  v_limit integer;
  v_plan_name text;
  v_period date;
  v_existing_id uuid;
  v_existing_status text;
  v_existing_billed integer;
begin
  -- Ensure a profile exists (covers users created before this migration).
  insert into public.profiles (user_id, plan_id, quota_used_seconds)
  values (p_user_id, 'free', 0)
  on conflict (user_id) do nothing;

  select plan_id, quota_used_seconds, quota_period_start
    into v_plan_id, v_used, v_period
    from public.profiles
   where user_id = p_user_id
   for update;

  -- Daily reset: yesterday's usage reads as zero from today on.
  if v_period is distinct from CURRENT_DATE then
    v_used := 0;
    v_period := CURRENT_DATE;
    update public.profiles
       set quota_used_seconds = 0,
           quota_period_start = CURRENT_DATE,
           updated_at = now()
     where user_id = p_user_id;
  end if;

  select quota_limit_seconds, name
    into v_limit, v_plan_name
    from public.plans
   where id = v_plan_id;
  if v_limit is null then
    v_limit := 0;
    v_plan_name := v_plan_id;
  end if;

  -- Reconnect with the same idempotency key: resume, never double-reserve.
  select id, status, billed_seconds
    into v_existing_id, v_existing_status, v_existing_billed
    from public.subtitle_sessions
   where client_session_id = p_client_session_id;

  if v_existing_id is not null then
    return jsonb_build_object(
      'allowed', (v_limit - v_used) > 0 or v_existing_status = 'active',
      'resumed', true,
      'session_id', v_existing_id,
      'status', v_existing_status,
      'billed_seconds', v_existing_billed,
      'used_seconds', v_used,
      'limit_seconds', v_limit,
      'remaining_seconds', greatest(v_limit - v_used, 0),
      'plan', v_plan_name,
      'period_start', v_period
    );
  end if;

  if (v_limit - v_used) <= 0 then
    return jsonb_build_object(
      'allowed', false,
      'resumed', false,
      'used_seconds', v_used,
      'limit_seconds', v_limit,
      'remaining_seconds', 0,
      'plan', v_plan_name,
      'period_start', v_period
    );
  end if;

  insert into public.subtitle_sessions (user_id, client_session_id, status)
  values (p_user_id, p_client_session_id, 'active')
  returning id into v_existing_id;

  return jsonb_build_object(
    'allowed', true,
    'resumed', false,
    'session_id', v_existing_id,
    'used_seconds', v_used,
    'limit_seconds', v_limit,
    'remaining_seconds', v_limit - v_used,
    'plan', v_plan_name,
    'period_start', v_period
  );
end;
$$;

-- get_quota_snapshot: atomic read for GET /api/v1/me/quota. Resets a
-- stale daily period (persisting the reset) so the dashboard converges
-- without waiting for the next session start.
create or replace function public.get_quota_snapshot(
  p_user_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_plan_id text;
  v_used integer;
  v_limit integer;
  v_plan_name text;
  v_period date;
begin
  insert into public.profiles (user_id, plan_id, quota_used_seconds)
  values (p_user_id, 'free', 0)
  on conflict (user_id) do nothing;

  select plan_id, quota_used_seconds, quota_period_start
    into v_plan_id, v_used, v_period
    from public.profiles
   where user_id = p_user_id
   for update;

  if v_period is distinct from CURRENT_DATE then
    v_used := 0;
    v_period := CURRENT_DATE;
    update public.profiles
       set quota_used_seconds = 0,
           quota_period_start = CURRENT_DATE,
           updated_at = now()
     where user_id = p_user_id;
  end if;

  select quota_limit_seconds, name
    into v_limit, v_plan_name
    from public.plans
   where id = v_plan_id;
  if v_limit is null then
    v_limit := 0;
    v_plan_name := v_plan_id;
  end if;

  return jsonb_build_object(
    'used_seconds', v_used,
    'limit_seconds', coalesce(v_limit, 0),
    'remaining_seconds', greatest(coalesce(v_limit, 0) - v_used, 0),
    'plan', v_plan_name,
    'period_start', v_period
  );
end;
$$;

-- ------------------------------------------- checkpoint_session_usage ---
create or replace function public.checkpoint_session_usage(
  p_client_session_id text,
  p_billed_seconds integer
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_session_id uuid;
  v_user_id uuid;
  v_old_status text;
  v_old_billed integer;
  v_delta integer;
  v_used integer;
  v_limit integer;
  v_plan_name text;
  v_plan_id text;
  v_period date;
begin
  if p_billed_seconds is null or p_billed_seconds < 0 then
    p_billed_seconds := 0;
  end if;

  select id, user_id, status, billed_seconds
    into v_session_id, v_user_id, v_old_status, v_old_billed
    from public.subtitle_sessions
   where client_session_id = p_client_session_id
   for update;

  if v_session_id is null then
    return jsonb_build_object(
      'committed', false,
      'reason', 'unknown_session',
      'billed_seconds', 0
    );
  end if;

  select quota_used_seconds, plan_id, quota_period_start
    into v_used, v_plan_id, v_period
    from public.profiles
   where user_id = v_user_id
   for update;

  -- Daily reset before applying the delta: yesterday's usage must not
  -- eat today's quota, and a date change mid-session starts counting
  -- from zero (the tracker's cumulative total is today's audio only
  -- when the session started today; a session spanning UTC midnight
  -- keeps the pre-midnight checkpointed seconds billed, which errs
  -- toward the user by at most one session).
  if v_period is distinct from CURRENT_DATE then
    v_used := 0;
    v_period := CURRENT_DATE;
    update public.profiles
       set quota_used_seconds = 0,
           quota_period_start = CURRENT_DATE,
           updated_at = now()
     where user_id = v_user_id;
  end if;

  select quota_limit_seconds, name
    into v_limit, v_plan_name
    from public.plans
   where id = v_plan_id;

  if v_old_status in ('completed', 'failed') then
    return jsonb_build_object(
      'committed', false,
      'reason', 'already_finalized',
      'billed_seconds', v_old_billed,
      'used_seconds', coalesce(v_used, 0),
      'limit_seconds', coalesce(v_limit, 0),
      'remaining_seconds', greatest(coalesce(v_limit, 0) - coalesce(v_used, 0), 0),
      'plan', v_plan_name,
      'period_start', v_period
    );
  end if;

  v_delta := greatest(p_billed_seconds - v_old_billed, 0);

  if v_delta > 0 then
    update public.subtitle_sessions
       set billed_seconds = p_billed_seconds
     where id = v_session_id;

    update public.profiles
       set quota_used_seconds = quota_used_seconds + v_delta,
           updated_at = now()
     where user_id = v_user_id
    returning quota_used_seconds into v_used;
  end if;

  return jsonb_build_object(
    'committed', v_delta > 0,
    'billed_seconds', greatest(v_old_billed, p_billed_seconds),
    'used_seconds', coalesce(v_used, 0),
    'limit_seconds', coalesce(v_limit, 0),
    'remaining_seconds', greatest(coalesce(v_limit, 0) - coalesce(v_used, 0), 0),
    'plan', v_plan_name,
    'period_start', v_period
  );
end;
$$;

-- ------------------------------ commit_session_usage (delta-aware) ---
create or replace function public.commit_session_usage(
  p_client_session_id text,
  p_billed_seconds integer,
  p_status text
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_session_id uuid;
  v_user_id uuid;
  v_old_status text;
  v_old_billed integer;
  v_delta integer;
  v_used integer;
  v_limit integer;
  v_plan_name text;
  v_plan_id text;
  v_period date;
begin
  if p_billed_seconds is null or p_billed_seconds < 0 then
    p_billed_seconds := 0;
  end if;
  if p_status not in ('completed', 'failed') then
    p_status := 'completed';
  end if;

  select id, user_id, status, billed_seconds
    into v_session_id, v_user_id, v_old_status, v_old_billed
    from public.subtitle_sessions
   where client_session_id = p_client_session_id
   for update;

  if v_session_id is null then
    return jsonb_build_object(
      'committed', false,
      'reason', 'unknown_session',
      'billed_seconds', 0
    );
  end if;

  if v_old_status in ('completed', 'failed') then
    select quota_used_seconds, plan_id, quota_period_start
      into v_used, v_plan_id, v_period
      from public.profiles
     where user_id = v_user_id;
    -- A stale period on an already-finalized session reads reset.
    if v_period is distinct from CURRENT_DATE then
      v_used := 0;
      v_period := CURRENT_DATE;
    end if;
    select quota_limit_seconds into v_limit from public.plans where id = v_plan_id;
    return jsonb_build_object(
      'committed', false,
      'reason', 'already_finalized',
      'billed_seconds', v_old_billed,
      'used_seconds', coalesce(v_used, 0),
      'limit_seconds', coalesce(v_limit, 0),
      'remaining_seconds', greatest(coalesce(v_limit, 0) - coalesce(v_used, 0), 0),
      'period_start', v_period
    );
  end if;

  -- Daily reset before applying the delta (see checkpoint above).
  select quota_used_seconds, quota_period_start
    into v_used, v_period
    from public.profiles
   where user_id = v_user_id
   for update;
  if v_period is distinct from CURRENT_DATE then
    v_used := 0;
    v_period := CURRENT_DATE;
    update public.profiles
       set quota_used_seconds = 0,
           quota_period_start = CURRENT_DATE,
           updated_at = now()
     where user_id = v_user_id;
  end if;

  -- Delta against checkpointed seconds (0 when never checkpointed):
  -- negative when the final total is 0 and checkpoints must be refunded.
  v_delta := p_billed_seconds - v_old_billed;

  update public.subtitle_sessions
     set status = p_status,
         billed_seconds = p_billed_seconds,
         ended_at = now()
   where id = v_session_id;

  update public.profiles
     set quota_used_seconds = greatest(quota_used_seconds + v_delta, 0),
         updated_at = now()
   where user_id = v_user_id
  returning quota_used_seconds, plan_id into v_used, v_plan_id;

  select quota_limit_seconds, name
    into v_limit, v_plan_name
    from public.plans
   where id = v_plan_id;

  return jsonb_build_object(
    'committed', true,
    'billed_seconds', p_billed_seconds,
    'used_seconds', v_used,
    'limit_seconds', coalesce(v_limit, 0),
    'remaining_seconds', greatest(coalesce(v_limit, 0) - v_used, 0),
    'plan', v_plan_name,
    'period_start', v_period
  );
end;
$$;
