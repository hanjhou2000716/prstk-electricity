-- Keep final demo/sample records out of the public settlement projection.
create or replace function prstk_private.prstk_save_manager_state(p_expected_revision bigint, p_payload jsonb)
returns bigint
language plpgsql
security definer
set search_path = ''
as $function$
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
  where r.value->>'status' = 'final'
    and (r.value->'data'->>'demo') is distinct from 'true';

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
$function$;
