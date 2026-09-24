-- Keep the authenticated RPC names stable while moving privileged implementations out of public.
alter function public.prstk_load_manager_state() set schema prstk_private;
alter function public.prstk_save_manager_state(bigint, jsonb) set schema prstk_private;

-- The private functions validate auth.uid() against the manager allowlist.
-- Grant only schema/function access; authenticated clients still cannot query private tables directly.
revoke all on schema prstk_private from public, anon, authenticated;
grant usage on schema prstk_private to authenticated;
revoke all on table prstk_private.manager_allowlist from public, anon, authenticated;
revoke all on table prstk_private.manager_state from public, anon, authenticated;
revoke all on table prstk_private.pin_attempt_state from public, anon, authenticated;

revoke all on function prstk_private.prstk_load_manager_state() from public, anon, authenticated;
revoke all on function prstk_private.prstk_save_manager_state(bigint, jsonb) from public, anon, authenticated;
grant execute on function prstk_private.prstk_load_manager_state() to authenticated;
grant execute on function prstk_private.prstk_save_manager_state(bigint, jsonb) to authenticated;

create or replace function public.prstk_load_manager_state()
returns jsonb
language sql
security invoker
set search_path = ''
as $function$
  select prstk_private.prstk_load_manager_state();
$function$;

create or replace function public.prstk_save_manager_state(p_expected_revision bigint, p_payload jsonb)
returns bigint
language sql
security invoker
set search_path = ''
as $function$
  select prstk_private.prstk_save_manager_state(p_expected_revision, p_payload);
$function$;

revoke all on function public.prstk_load_manager_state() from public, anon, authenticated;
revoke all on function public.prstk_save_manager_state(bigint, jsonb) from public, anon, authenticated;
grant execute on function public.prstk_load_manager_state() to authenticated;
grant execute on function public.prstk_save_manager_state(bigint, jsonb) to authenticated;