-- Close the direct-write hole on public.leaderboard.
--
-- Background: Supabase grants the `anon` and `authenticated` roles full CRUD
-- privileges on every table in the `public` schema by default. The earlier
-- hardening migrations enabled RLS and revoked SELECT from those roles, but
-- they never revoked the default INSERT/UPDATE/DELETE *grants*. With the write
-- grant still in place, an unauthenticated client holding the public anon key
-- can POST straight to PostgREST (`/rest/v1/leaderboard`) and create rows,
-- completely bypassing /api/submit-score (run-token check, deterministic replay,
-- plausibility caps) and the submit_run RPC. A directly-inserted row with any
-- run_id then shows up on leaderboard_public immediately.
--
-- This migration removes the write grants (the fix that actually stops PostgREST
-- from accepting the insert) and adds a restrictive RLS deny policy as a belt.
-- All legitimate writes continue to flow through submit_run, which is SECURITY
-- DEFINER and runs as service_role (which bypasses both grants and RLS).

-- 1) Remove the default write grants. This is what makes PostgREST reject the
--    anon/authenticated write at the privilege layer (HTTP 401/403) before RLS
--    is even consulted.
revoke insert, update, delete, truncate on public.leaderboard from anon, authenticated;
revoke insert, update, delete, truncate on public.leaderboard from public;

-- 2) Defense in depth: ensure RLS is on and add an explicit RESTRICTIVE deny
--    policy for the public roles. Restrictive + USING(false)/WITH CHECK(false)
--    means writes stay blocked even if some future permissive policy is added.
--    service_role bypasses RLS, so submit_run is unaffected.
alter table public.leaderboard enable row level security;

drop policy if exists no_anon_writes on public.leaderboard;
create policy no_anon_writes on public.leaderboard
    as restrictive
    for all
    to anon, authenticated
    using (false)
    with check (false);

-- 3) Same treatment for run_tokens, which has the identical default-grant
--    exposure. Only service_role (via the submit_run / start-run paths) should
--    ever touch it.
revoke select, insert, update, delete, truncate on public.run_tokens from anon, authenticated;
revoke select, insert, update, delete, truncate on public.run_tokens from public;

-- 4) Purge the three rows inserted during the vulnerability disclosure testing.
--    Scoped tightly to the @test.com throwaway emails within the documented
--    insertion window (2026-06-17 19:20–19:22 UTC) so no real entry is touched.
delete from public.leaderboard
where email ilike '%@test.com'
  and created_at >= timestamptz '2026-06-17 19:20:00+00'
  and created_at <  timestamptz '2026-06-17 19:23:00+00';
