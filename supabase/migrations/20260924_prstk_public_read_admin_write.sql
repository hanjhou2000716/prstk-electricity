-- PRStK: anonymous read access to a sanitized settlement projection and
-- authenticated manager-only access to the full workspace.

create schema if not exists prstk_private;
revoke all on schema prstk_private from public, anon, authenticated;

create table if not exists prstk_private.manager_allowlist (
  user_id uuid primary key references auth.users(id) on delete cascade
);

create table if not exists prstk_private.manager_state (
  singleton boolean primary key default true check (singleton),
  revision bigint not null default 0,
  payload jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);
alter table prstk_private.manager_state enable row level security;

create table if not exists public.prstk_public_snapshot (
  singleton boolean primary key default true check (singleton),
  revision bigint not null default 0,
  payload jsonb not null default '{"schemaVersion":1,"rooms":["1 號房","2 號房","3 號房","4 號房"],"records":[]}'::jsonb,
  updated_at timestamptz not null default now()
);
alter table public.prstk_public_snapshot enable row level security;
revoke all on table public.prstk_public_snapshot from public, anon, authenticated;
grant select on table public.prstk_public_snapshot to anon, authenticated;
drop policy if exists "prstk settlement snapshot is public" on public.prstk_public_snapshot;
create policy "prstk settlement snapshot is public"
  on public.prstk_public_snapshot for select to anon, authenticated using (true);

insert into public.prstk_public_snapshot(singleton) values (true)
on conflict (singleton) do nothing;

create table if not exists prstk_private.pin_attempt_state (
  singleton boolean primary key default true check (singleton),
  attempts integer not null default 0,
  window_started_at timestamptz not null default now(),
  blocked_until timestamptz
);
insert into prstk_private.pin_attempt_state(singleton) values (true)
on conflict (singleton) do nothing;

create or replace function public.prstk_reserve_pin_attempt()
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_state prstk_private.pin_attempt_state%rowtype;
  v_now timestamptz := pg_catalog.now();
begin
  select * into v_state from prstk_private.pin_attempt_state where singleton = true for update;
  if v_state.blocked_until is not null and v_state.blocked_until > v_now then
    return false;
  end if;
  if v_state.window_started_at + interval '30 minutes' <= v_now then
    update prstk_private.pin_attempt_state
       set attempts = 0, window_started_at = v_now, blocked_until = null
     where singleton = true;
    v_state.attempts := 0;
  end if;
  if v_state.attempts >= 5 then
    update prstk_private.pin_attempt_state set blocked_until = v_now + interval '30 minutes' where singleton = true;
    return false;
  end if;
  update prstk_private.pin_attempt_state set attempts = attempts + 1 where singleton = true;
  return true;
end;
$$;

create or replace function public.prstk_record_pin_login(p_success boolean)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_state prstk_private.pin_attempt_state%rowtype;
  v_now timestamptz := pg_catalog.now();
begin
  select * into v_state from prstk_private.pin_attempt_state where singleton = true for update;
  if p_success then
    update prstk_private.pin_attempt_state set attempts = 0, window_started_at = v_now, blocked_until = null where singleton = true;
  elsif v_state.attempts >= 5 then
    update prstk_private.pin_attempt_state set blocked_until = v_now + interval '30 minutes' where singleton = true;
  end if;
end;
$$;
revoke all on function public.prstk_reserve_pin_attempt() from public, anon, authenticated;
revoke all on function public.prstk_record_pin_login(boolean) from public, anon, authenticated;
grant execute on function public.prstk_reserve_pin_attempt() to service_role;
grant execute on function public.prstk_record_pin_login(boolean) to service_role;

create or replace function public.prstk_bootstrap_manager(p_user_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into prstk_private.manager_allowlist(user_id) values (p_user_id)
  on conflict (user_id) do nothing;
end;
$$;
revoke all on function public.prstk_bootstrap_manager(uuid) from public, anon, authenticated;
grant execute on function public.prstk_bootstrap_manager(uuid) to service_role;

create or replace function public.prstk_load_manager_state()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_state prstk_private.manager_state%rowtype;
begin
  if auth.uid() is null or not exists (
    select 1 from prstk_private.manager_allowlist where user_id = auth.uid()
  ) then
    raise exception using errcode = '42501', message = 'manager access required';
  end if;
  select * into v_state from prstk_private.manager_state where singleton = true;
  if not found then
    return null;
  end if;
  return pg_catalog.jsonb_build_object('revision', v_state.revision, 'payload', v_state.payload);
end;
$$;

create or replace function public.prstk_save_manager_state(p_expected_revision bigint, p_payload jsonb)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_state prstk_private.manager_state%rowtype;
  v_workspace jsonb;
  v_public_records jsonb;
  v_public_payload jsonb;
  v_next bigint;
begin
  if auth.uid() is null or not exists (
    select 1 from prstk_private.manager_allowlist where user_id = auth.uid()
  ) then
    raise exception using errcode = '42501', message = 'manager access required';
  end if;
  if pg_catalog.jsonb_typeof(p_payload) is distinct from 'object'
     or pg_catalog.jsonb_typeof(p_payload->'workspace') is distinct from 'object'
     or pg_catalog.jsonb_typeof(p_payload->'workspace'->'records') is distinct from 'array' then
    raise exception using errcode = '22023', message = 'workspace format or size is not supported';
  end if;
  if pg_catalog.jsonb_array_length(p_payload->'workspace'->'records') > 600
     or pg_catalog.octet_length(p_payload::text) > 5000000 then
    raise exception using errcode = '22023', message = 'workspace format or size is not supported';
  end if;

  select * into v_state from prstk_private.manager_state where singleton = true for update;
  if not found then
    if p_expected_revision <> 0 then
      raise exception using errcode = '40001', message = 'workspace changed on another device';
    end if;
    v_next := 1;
  else
    if v_state.revision <> p_expected_revision then
      raise exception using errcode = '40001', message = 'workspace changed on another device';
    end if;
    v_next := v_state.revision + 1;
  end if;

  v_workspace := p_payload->'workspace';
  select coalesce(
    pg_catalog.jsonb_agg(
      pg_catalog.jsonb_build_object(
        'id', r.value->>'id',
        'month', r.value->'data'->>'month',
        'start', r.value->'data'->>'start',
        'end', r.value->'data'->>'end',
        'rooms', (
          select pg_catalog.jsonb_agg(
            pg_catalog.jsonb_build_object(
              'name', ((room.ordinality)::integer)::text || ' 號房',
              'usage', (room.value->>'usage')::numeric,
              'payable', (room.value->>'payable')::numeric
            ) order by room.ordinality
          )
          from pg_catalog.jsonb_array_elements(r.value->'result'->'rooms') with ordinality as room(value, ordinality)
          where room.ordinality <= 4
        )
      ) order by r.value->'data'->>'start' desc
    ), '[]'::jsonb
  ) into v_public_records
  from pg_catalog.jsonb_array_elements(v_workspace->'records') as r(value)
  where r.value->>'status' = 'final';

  v_public_payload := pg_catalog.jsonb_build_object(
    'schemaVersion', 1,
    'rooms', pg_catalog.jsonb_build_array('1 號房','2 號房','3 號房','4 號房'),
    'records', v_public_records
  );

  insert into prstk_private.manager_state(singleton, revision, payload, updated_at)
  values (true, v_next, p_payload, pg_catalog.now())
  on conflict (singleton) do update
    set revision = excluded.revision, payload = excluded.payload, updated_at = excluded.updated_at;

  insert into public.prstk_public_snapshot(singleton, revision, payload, updated_at)
  values (true, v_next, v_public_payload, pg_catalog.now())
  on conflict (singleton) do update
    set revision = excluded.revision, payload = excluded.payload, updated_at = excluded.updated_at;

  return v_next;
end;
$$;
revoke all on function public.prstk_load_manager_state() from public, anon, authenticated;
revoke all on function public.prstk_save_manager_state(bigint, jsonb) from public, anon, authenticated;
grant execute on function public.prstk_load_manager_state() to authenticated;
grant execute on function public.prstk_save_manager_state(bigint, jsonb) to authenticated;

comment on table public.prstk_public_snapshot is 'Sanitized final-settlement projection: dates, room numbers, room usage, and payable amounts only.';
comment on table prstk_private.manager_state is 'Full manager-only workspace and working draft. Never expose via GitHub or public API.';

