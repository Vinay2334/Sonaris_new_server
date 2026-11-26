-- Sonaris paid-period expiry: cancel-anytime keeps quota until next billing.
--
-- SOURCE OF TRUTH for `supabase db push` (apply after
-- 20261125000000_quota_resume.sql). Additive only.
--
-- Provider linkage lives in `billing_subscriptions` (one row per user),
-- NOT in `profiles`: swapping payment providers later means writing a
-- new `provider` value, not migrating profile columns. The Dodo webhook
-- upserts the row on every activate and refreshes `current_period_end`
-- on cancel-at-period-end (see app/services/billing.py). The date is the
-- downgrade trigger: every quota RPC below lapses a past-due paid row
-- back to `free` before enforcing, in the same transaction as the read
-- that observes it. Consequences:
-- - No cancelled-vs-expired branching anywhere: time does the downgrade.
-- - A missed Expired webhook self-heals on the next authorize/snapshot.
-- - Quota already used is never touched: only the plan (limit) changes;
--   `quota_used_seconds` keeps counting the day and resets at midnight.
-- - No linkage row (or a NULL `current_period_end`) means no paid
--   period: never auto-downgraded.
-- - Expired rows are kept (ids + past end) for the customer-portal
--   button and reconciliation; a resubscribe upserts over them.

create table if not exists public.billing_subscriptions (
  user_id uuid primary key references auth.users (id) on delete cascade,
  -- Payment provider that owns this linkage ('dodo'; 'stripe', ... later).
  -- Enforcement only reads `current_period_end`, never this value.
  provider text not null default 'dodo',
  provider_customer_id text,
  provider_subscription_id text,
  -- End of the paid period (Dodo's `next_billing_date`). NULL = no bound.
  current_period_end timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.billing_subscriptions enable row level security;

-- Users read only their own linkage. No write policies for authenticated
-- users: the linkage is backend-only (service_role bypasses RLS).
drop policy if exists "billing_subscriptions_read_own"
  on public.billing_subscriptions;
create policy "billing_subscriptions_read_own"
  on public.billing_subscriptions for select
  to authenticated
  using (auth.uid() = user_id);

-- Lapse one past-due paid row to free. Called by every quota RPC below
-- before its locked read; a no-op for free rows and for users with no
-- (or unbounded) linkage row. Reads only `current_period_end`, so it is
-- provider-agnostic: switching providers never touches enforcement.
-- The linkage row itself is kept for the portal button + reconciliation.
create or replace function public.expire_subscription_if_due(
  p_user_id uuid
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if exists (
    select 1
      from public.billing_subscriptions s
     where s.user_id = p_user_id
       and s.current_period_end is not null
       and s.current_period_end <= now()
  ) then
    update public.profiles
       set plan_id = 'free',
           updated_at = now()
     where user_id = p_user_id
       and plan_id <> 'free';
  end if;
end;
$$;

-- authorize_session: as 20261125000000_quota_resume.sql, plus the
-- paid-period expiry before the locked profile read.
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

  -- Paid-period expiry: a past subscription_ends_at lapses the paid plan
  -- back to free here, atomically with the authorize that observes it.
  perform public.expire_subscription_if_due(p_user_id);

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
    if v_existing_status in ('completed', 'failed')
       and (v_limit - v_used) <= 0 then
      return jsonb_build_object(
        'allowed', false,
        'resumed', true,
        'session_id', v_existing_id,
        'status', v_existing_status,
        'billed_seconds', v_existing_billed,
        'used_seconds', v_used,
        'limit_seconds', v_limit,
        'remaining_seconds', 0,
        'plan', v_plan_name,
        'period_start', v_period
      );
    end if;
    if v_existing_status in ('completed', 'failed') then
      -- The previous transport finalized this row (pause / restart /
      -- reconnect race). Reopen it with the billed total preserved so
      -- the resumed stretch bills on top instead of being dropped as
      -- already-finalized.
      update public.subtitle_sessions
         set status = 'active'
       where id = v_existing_id;
      v_existing_status := 'active';
    end if;
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

-- get_quota_snapshot: as 20261120000000_daily_quota.sql, plus the
-- paid-period expiry before the locked profile read, so the dashboard
-- (GET /api/v1/me/quota) converges without waiting for a session start.
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

  -- Paid-period expiry (see authorize_session above).
  perform public.expire_subscription_if_due(p_user_id);

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

-- checkpoint_session_usage: as 20261120000000_daily_quota.sql, plus the
-- paid-period expiry before the locked profile read, so usage past the
-- billing date bills against the free plan.
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

  -- Paid-period expiry (see authorize_session above).
  perform public.expire_subscription_if_due(v_user_id);

  select quota_used_seconds, plan_id, quota_period_start
    into v_used, v_plan_id, v_period
    from public.profiles
   where user_id = v_user_id
   for update;

  -- Daily reset before applying the delta: yesterday's usage must not
  -- eat today's quota, and a date change mid-session starts counting
  -- from zero (see 20261120000000_daily_quota.sql for the full note).
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

-- commit_session_usage (delta-aware): as
-- 20261120000000_daily_quota.sql, plus the paid-period expiry on both
-- branches, so the final charge lands on the correct plan.
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
    -- Paid-period expiry (see authorize_session above).
    perform public.expire_subscription_if_due(v_user_id);
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

  -- Paid-period expiry (see authorize_session above).
  perform public.expire_subscription_if_due(v_user_id);

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
