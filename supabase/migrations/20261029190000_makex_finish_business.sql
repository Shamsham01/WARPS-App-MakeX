-- Fenced completion for an in-progress business claim.
-- Do not edit or rerun 20261028220000_makex_tx_coordinator.sql or 20261028233000_makex_operation_claim.sql.
-- Apply this file once before deploying the matching application revision.

create or replace function public.makex_tx_finish_business(
  p_id uuid,
  p_owner text,
  p_patch jsonb
)
returns jsonb
language plpgsql
set search_path = public
as $$
declare
  existing public.makex_operations%rowtype;
  updated public.makex_operations%rowtype;
begin
  perform set_config('statement_timeout', '5000', true);
  select * into existing
  from public.makex_operations
  where id = p_id
  for update;

  if not found then
    return jsonb_build_object('ok', false, 'reason', 'not_found');
  end if;

  if existing.state is distinct from 'OPERATION_IN_PROGRESS'
     or existing.claim_owner is distinct from p_owner
     or existing.claim_expires_at is null
     or existing.claim_expires_at <= now() then
    return jsonb_build_object(
      'ok', false,
      'reason', case
        when existing.claim_owner is distinct from p_owner then 'stale_claim'
        else 'claim_expired'
      end,
      'operation', public.makex_tx_operation_json(existing)
    );
  end if;

  update public.makex_operations
  set state = case when p_patch ? 'state' then p_patch->>'state' else state end,
      fee_reservation_id = case when p_patch ? 'fee_reservation_id' then nullif(p_patch->>'fee_reservation_id', '')::uuid else fee_reservation_id end,
      primary_reservation_id = case when p_patch ? 'primary_reservation_id' then nullif(p_patch->>'primary_reservation_id', '')::uuid else primary_reservation_id end,
      fee_tx_hash = case when p_patch ? 'fee_tx_hash' then p_patch->>'fee_tx_hash' else fee_tx_hash end,
      primary_tx_hash = case when p_patch ? 'primary_tx_hash' then p_patch->>'primary_tx_hash' else primary_tx_hash end,
      fee_amount_wei = case when p_patch ? 'fee_amount_wei' then p_patch->>'fee_amount_wei' else fee_amount_wei end,
      fee_token = case when p_patch ? 'fee_token' then p_patch->>'fee_token' else fee_token end,
      fee_token_identifier = case when p_patch ? 'fee_token_identifier' then p_patch->>'fee_token_identifier' else fee_token_identifier end,
      usd_amount = case when p_patch ? 'usd_amount' then (p_patch->>'usd_amount')::numeric else usd_amount end,
      skipped_whitelist = case when p_patch ? 'skipped_whitelist' then (p_patch->>'skipped_whitelist')::boolean else skipped_whitelist end,
      whitelist_reason = case when p_patch ? 'whitelist_reason' then p_patch->>'whitelist_reason' else whitelist_reason end,
      error_class = case when p_patch ? 'error_class' then p_patch->>'error_class' else error_class end,
      error_detail = case when p_patch ? 'error_detail' then left(p_patch->>'error_detail', 500) else error_detail end,
      result_json = case when p_patch ? 'result_json' then p_patch->'result_json' else result_json end,
      http_status = case when p_patch ? 'http_status' then (p_patch->>'http_status')::integer else http_status end,
      progress_json = case when p_patch ? 'progress_json' then p_patch->'progress_json' else progress_json end,
      updated_at = now()
  where id = p_id
  returning * into updated;

  return jsonb_build_object('ok', true, 'operation', public.makex_tx_operation_json(updated));
end;
$$;

revoke all on function public.makex_tx_finish_business(uuid, text, jsonb) from public, anon, authenticated;
grant execute on function public.makex_tx_finish_business(uuid, text, jsonb) to service_role;
