-- Incremental claim for in-progress business actions.
-- Do not edit or rerun 20261028220000_makex_tx_coordinator.sql.
-- Apply this file once on project yalewhpzptgtfzwpzhjm before deploying the matching code.

alter table public.makex_operations
  add column if not exists claim_owner text,
  add column if not exists claim_expires_at timestamptz;

alter table public.makex_operations drop constraint if exists makex_operations_state_chk;

alter table public.makex_operations
  add constraint makex_operations_state_chk check (
    state in (
      'RECEIVED', 'FEE_PREPARED', 'FEE_SUBMITTED', 'FEE_CONFIRMED',
      'OPERATION_PREPARED', 'OPERATION_SUBMITTED', 'OPERATION_CONFIRMED',
      'OPERATION_FAILED', 'OPERATION_PENDING', 'OPERATION_IN_PROGRESS',
      'FAILED', 'INCONCLUSIVE', 'NEEDS_RECONCILIATION'
    )
  );

create or replace function public.makex_tx_claim_business(
  p_id uuid,
  p_owner text,
  p_ttl_ms integer
)
returns jsonb
language plpgsql
set search_path = public
as $$
declare
  existing public.makex_operations%rowtype;
begin
  perform set_config('statement_timeout', '5000', true);
  select * into existing
  from public.makex_operations
  where id = p_id
  for update;

  if not found then
    return jsonb_build_object('ok', false, 'reason', 'not_found');
  end if;

  if existing.state = 'OPERATION_CONFIRMED' then
    return jsonb_build_object(
      'ok', true,
      'claimed', false,
      'reason', 'confirmed',
      'operation', public.makex_tx_operation_json(existing)
    );
  end if;

  if existing.state = 'OPERATION_IN_PROGRESS'
     and existing.claim_owner is not null
     and existing.claim_owner is distinct from p_owner
     and existing.claim_expires_at > now() then
    return jsonb_build_object(
      'ok', true,
      'claimed', false,
      'reason', 'in_progress',
      'retryAfterMs', greatest(1, floor(extract(epoch from (existing.claim_expires_at - now())) * 1000)),
      'operation', public.makex_tx_operation_json(existing)
    );
  end if;

  update public.makex_operations
  set state = 'OPERATION_IN_PROGRESS',
      claim_owner = p_owner,
      claim_expires_at = now() + make_interval(secs => greatest(p_ttl_ms, 1) / 1000.0),
      updated_at = now()
  where id = p_id
  returning * into existing;

  return jsonb_build_object(
    'ok', true,
    'claimed', true,
    'operation', public.makex_tx_operation_json(existing)
  );
end;
$$;

revoke all on function public.makex_tx_claim_business(uuid, text, integer) from public, anon, authenticated;
grant execute on function public.makex_tx_claim_business(uuid, text, integer) to service_role;
