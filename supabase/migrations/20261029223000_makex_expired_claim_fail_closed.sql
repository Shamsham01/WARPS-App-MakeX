-- Fail closed when an in-progress business claim has expired.
-- Do not edit or rerun 20261028220000_makex_tx_coordinator.sql or 20261028233000_makex_operation_claim.sql.
-- A new worker must not reclaim an expired OPERATION_IN_PROGRESS row: the external action may already have succeeded.
-- The same owner can still renew an unexpired claim, and can extend its own claim after expiry.
-- The row stays OPERATION_IN_PROGRESS so the deployed Transfers service does not treat it as a fee resume.

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

  if existing.state = 'OPERATION_IN_PROGRESS'
     and existing.claim_owner is not null
     and existing.claim_owner is distinct from p_owner
     and (existing.claim_expires_at is null or existing.claim_expires_at <= now()) then
    update public.makex_operations
    set error_class = 'business_claim_expired',
        error_detail = left('The business claim expired before its result was stored. Reconcile this operation before running it again.', 500),
        updated_at = now()
    where id = p_id
    returning * into existing;

    return jsonb_build_object(
      'ok', true,
      'claimed', false,
      'reason', 'needs_reconciliation',
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
