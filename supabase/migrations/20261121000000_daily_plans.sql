-- Captify daily plan catalog: Free / Starter / Pro / Studio.
--
-- SOURCE OF TRUTH for `supabase db push` (apply after
-- 20261120000000_daily_quota.sql). Enforces the daily plans: each row is
-- upserted unconditionally (unlike the catalog seeds before it), so
-- re-running repairs limits/labels/features edited by hand and every
-- project converges on the same quotas:
--
--   free     2,400 s  (40 min / day)   $0  / month
--   starter 10,800 s  (3 h   / day)    $10 / month
--   pro     32,400 s  (9 h   / day)    $27 / month  (featured)
--   studio  43,200 s  (12 h  / day)    $50 / month
--
-- Quotas reset every 24 hours (see 20261120000000_daily_quota.sql).
-- Paid plans check out through Dodo: link each product to its plan id in
-- the backend's DODO_PLAN_MAP (e.g. "prod_abc=starter,prod_def=pro").
-- The free plan needs no product.

insert into public.plans (
  id, name, quota_limit_seconds, price_label, tagline,
  price_monthly_usd, features, display_order, is_featured
)
values
  (
    'free', 'Free', 2400, '$0 / month', 'For trying Captify',
    0,
    '[
      {"text": "40 mins daily live transcription", "dim": false},
      {"text": "Real-time browser tab captions", "dim": false},
      {"text": "11+ languages, auto-detected", "dim": false},
      {"text": "Quota resets every 24 hours", "dim": false},
      {"text": "High-Accuracy transcription mode", "dim": true},
      {"text": "Early access to upcoming releases", "dim": true}
    ]'::jsonb,
    0, false
  ),
  (
    'starter', 'Starter', 10800, '$10 / month', 'For casual viewing and study',
    10,
    '[
      {"text": "3 hours daily live transcription", "dim": false},
      {"text": "Real-time browser tab captions", "dim": false},
      {"text": "11+ languages, auto-detected", "dim": false},
      {"text": "Quota resets every 24 hours", "dim": false},
      {"text": "High-Accuracy transcription mode", "dim": true},
      {"text": "Early access to upcoming releases", "dim": true}
    ]'::jsonb,
    1, false
  ),
  (
    'pro', 'Pro', 32400, '$27 / month', 'For daily meetings, streams & learners',
    27,
    '[
      {"text": "9 hours daily live transcription", "dim": false},
      {"text": "Real-time browser tab captions", "dim": false},
      {"text": "11+ languages, auto-detected", "dim": false},
      {"text": "Quota resets every 24 hours", "dim": false},
      {"text": "High-Accuracy transcription mode", "dim": false},
      {"text": "Early access to upcoming releases", "dim": true}
    ]'::jsonb,
    2, true
  ),
  (
    'studio', 'Studio', 43200, '$50 / month', 'For all-day power users',
    50,
    '[
      {"text": "12 hours daily live transcription", "dim": false},
      {"text": "Real-time browser tab captions", "dim": false},
      {"text": "11+ languages, auto-detected", "dim": false},
      {"text": "Quota resets every 24 hours", "dim": false},
      {"text": "High-Accuracy transcription mode", "dim": false},
      {"text": "Early access to upcoming releases & priority support", "dim": false}
    ]'::jsonb,
    3, false
  )
on conflict (id) do update set
  name = excluded.name,
  quota_limit_seconds = excluded.quota_limit_seconds,
  price_label = excluded.price_label,
  tagline = excluded.tagline,
  price_monthly_usd = excluded.price_monthly_usd,
  features = excluded.features,
  display_order = excluded.display_order,
  is_featured = excluded.is_featured;
