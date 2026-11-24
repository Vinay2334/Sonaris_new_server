-- Sonaris resume-after-restart quota fix.
--
-- SOURCE OF TRUTH for `supabase db push` (apply after
-- 20261121000000_daily_plans.sql). Additive only.
--
-- Bug: when a transport dropped (pause -> idle timeout, extension
-- restart, reconnect race) the old relay task finalized the
-- subtitle_sessions row, and the reconnect reusing the same
-- client_session_id resumed against that finalized row. Every later
-- checkpoint/commit then fell into the `already_finalized` branch and
-- billed nothing, so quota stopped increasing after the first pause
-- or restart -- for base and pro sessions alike.
--
-- Fix: authorize_session reopens a finalized row back to `active`,
-- keeping its billed total. The backend seeds the new tracker with
-- that total as an offset (see app/services/quota.py), so the resumed
-- stretch bills exactly the new audio on top: no drops, no refunds of
-- already-consumed usage, no double-bills. A finalized row with no
-- quota left stays denied.
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
