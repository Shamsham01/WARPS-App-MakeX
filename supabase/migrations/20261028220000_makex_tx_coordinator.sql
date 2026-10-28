-- Durable nonce authority shared by every MakeX service.
-- Short transactions only: callers must not hold these locks across gateway I/O.
-- Semantics match tx/memoryStore.mjs.

create table if not exists public.makex_wallet_tx_authority (
  network text not null,
  sender_address text not null,
  lease_owner text,
  fencing_token bigint not null default 0,
  lease_expires_at timestamptz,
  next_nonce bigint,
  unresolved_reservation_id uuid,
  updated_at timestamptz not null default now(),
  primary key (network, sender_address)
);

create table if not exists public.makex_tx_reservations (
  id uuid primary key default gen_random_uuid(),
  operation_id uuid,
  app_id text,
  network text not null,
  sender_address text not null,
  purpose text not null,
  nonce bigint not null,
  fencing_token bigint not null,
  tx_hash text,
  signed_tx jsonb,
  state text not null,
  payload_fingerprint text,
  error_class text,
  error_detail text,
  attempt integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint makex_tx_reservations_state_chk check (
    state in (
      'RESERVED', 'SIGNED', 'SUBMITTED', 'PENDING', 'CONFIRMED',
      'FAILED', 'REJECTED', 'UNKNOWN', 'NEEDS_RECONCILIATION'
    )
  )
);

create unique index if not exists makex_tx_reservations_live_nonce_idx
  on public.makex_tx_reservations (network, sender_address, nonce)
  where state <> 'REJECTED';

create unique index if not exists makex_tx_one_unresolved_idx
  on public.makex_tx_reservations (network, sender_address)
  where state in ('RESERVED', 'SIGNED', 'SUBMITTED', 'PENDING', 'UNKNOWN', 'NEEDS_RECONCILIATION');

create index if not exists makex_tx_reservations_operation_idx
  on public.makex_tx_reservations (operation_id, purpose, created_at desc);

create table if not exists public.makex_operations (
  id uuid primary key default gen_random_uuid(),
  idempotency_key text not null,
  request_fingerprint text not null,
  app_id text not null,
  network text not null,
  wallet_address text not null,
  state text not null,
  fee_reservation_id uuid,
  primary_reservation_id uuid,
  fee_tx_hash text,
  primary_tx_hash text,
  fee_amount_wei text,
  fee_token text,
  fee_token_identifier text,
  usd_amount numeric,
  skipped_whitelist boolean not null default false,
  whitelist_reason text,
  error_class text,
  error_detail text,
  result_json jsonb,
  http_status integer,
  progress_json jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint makex_operations_state_chk check (
    state in (
      'RECEIVED', 'FEE_PREPARED', 'FEE_SUBMITTED', 'FEE_CONFIRMED',
      'OPERATION_PREPARED', 'OPERATION_SUBMITTED', 'OPERATION_CONFIRMED',
      'OPERATION_FAILED', 'FAILED', 'INCONCLUSIVE', 'NEEDS_RECONCILIATION'
    )
  ),
  constraint makex_operations_idempotency_key unique (app_id, network, wallet_address, idempotency_key)
);

create index if not exists makex_operations_state_idx on public.makex_operations (state);

alter table public.makex_wallet_tx_authority enable row level security;
alter table public.makex_tx_reservations enable row level security;
alter table public.makex_operations enable row level security;

revoke all on table public.makex_wallet_tx_authority from public, anon, authenticated;
revoke all on table public.makex_tx_reservations from public, anon, authenticated;
revoke all on table public.makex_operations from public, anon, authenticated;
grant select, insert, update, delete on table public.makex_wallet_tx_authority to service_role;
grant select, insert, update, delete on table public.makex_tx_reservations to service_role;
grant select, insert, update, delete on table public.makex_operations to service_role;

create or replace function public.makex_tx_reservation_json(r public.makex_tx_reservations)
returns jsonb
language sql
stable
set search_path = public
as $$
  select jsonb_build_object(
    'id', r.id,
    'operation_id', r.operation_id,
    'app_id', r.app_id,
    'network', r.network,
    'sender_address', r.sender_address,
    'purpose', r.purpose,
    'nonce', r.nonce,
    'fencing_token', r.fencing_token,
    'tx_hash', r.tx_hash,
    'signed_tx', r.signed_tx,
    'state', r.state,
    'payload_fingerprint', r.payload_fingerprint,
    'error_class', r.error_class,
    'error_detail', r.error_detail,
    'attempt', r.attempt,
    'created_at', r.created_at,
    'updated_at', r.updated_at
  );
$$;

create or replace function public.makex_tx_health()
returns jsonb
language sql
stable
set search_path = public
as $$
  select jsonb_build_object('ok', true, 'version', 1, 'store', 'supabase');
$$;

create or replace function public.makex_tx_acquire_lease(
  p_network text,
  p_sender text,
  p_owner text,
  p_ttl_ms integer
)
returns jsonb
language plpgsql
set search_path = public
as $$
declare
  row public.makex_wallet_tx_authority%rowtype;
  unresolved jsonb;
begin
  perform set_config('statement_timeout', '5000', true);
  insert into public.makex_wallet_tx_authority (network, sender_address)
  values (p_network, p_sender)
  on conflict (network, sender_address) do nothing;

  select * into row
  from public.makex_wallet_tx_authority
  where network = p_network and sender_address = p_sender
  for update;

  if row.lease_owner is not null
     and row.lease_owner <> p_owner
     and row.lease_expires_at > now() then
    return jsonb_build_object(
      'acquired', false,
      'retryAfterMs', greatest(1, floor(extract(epoch from (row.lease_expires_at - now())) * 1000))
    );
  end if;

  update public.makex_wallet_tx_authority
  set lease_owner = p_owner,
      fencing_token = fencing_token + 1,
      lease_expires_at = now() + make_interval(secs => p_ttl_ms / 1000.0),
      updated_at = now()
  where network = p_network and sender_address = p_sender
  returning * into row;

  unresolved := null;
  if row.unresolved_reservation_id is not null then
    select public.makex_tx_reservation_json(r) into unresolved
    from public.makex_tx_reservations r
    where r.id = row.unresolved_reservation_id;
  end if;

  return jsonb_build_object(
    'acquired', true,
    'fencingToken', row.fencing_token,
    'nextNonce', row.next_nonce,
    'unresolved', unresolved
  );
end;
$$;

create or replace function public.makex_tx_refresh_lease(
  p_network text,
  p_sender text,
  p_owner text,
  p_fencing_token bigint,
  p_ttl_ms integer
)
returns jsonb
language plpgsql
set search_path = public
as $$
declare
  updated_count integer;
begin
  perform set_config('statement_timeout', '5000', true);
  update public.makex_wallet_tx_authority
  set lease_expires_at = now() + make_interval(secs => p_ttl_ms / 1000.0),
      updated_at = now()
  where network = p_network
    and sender_address = p_sender
    and lease_owner = p_owner
    and fencing_token = p_fencing_token;
  get diagnostics updated_count = row_count;
  if updated_count = 0 then
    return jsonb_build_object('ok', false, 'reason', 'fencing');
  end if;
  return jsonb_build_object('ok', true, 'fencingToken', p_fencing_token);
end;
$$;

create or replace function public.makex_tx_release_lease(
  p_network text,
  p_sender text,
  p_owner text,
  p_fencing_token bigint
)
returns jsonb
language plpgsql
set search_path = public
as $$
declare
  updated_count integer;
begin
  perform set_config('statement_timeout', '5000', true);
  update public.makex_wallet_tx_authority
  set lease_owner = null,
      lease_expires_at = null,
      updated_at = now()
  where network = p_network
    and sender_address = p_sender
    and lease_owner = p_owner
    and fencing_token = p_fencing_token;
  get diagnostics updated_count = row_count;
  if updated_count = 0 then
    return jsonb_build_object('ok', false, 'reason', 'fencing');
  end if;
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.makex_tx_reserve_nonce(
  p_network text,
  p_sender text,
  p_owner text,
  p_fencing_token bigint,
  p_chain_nonce bigint,
  p_operation_id uuid,
  p_app_id text,
  p_purpose text,
  p_payload_fingerprint text
)
returns jsonb
language plpgsql
set search_path = public
as $$
declare
  row public.makex_wallet_tx_authority%rowtype;
  chosen bigint;
  existing public.makex_tx_reservations%rowtype;
  created public.makex_tx_reservations%rowtype;
begin
  perform set_config('statement_timeout', '5000', true);
  select * into row
  from public.makex_wallet_tx_authority
  where network = p_network and sender_address = p_sender
  for update;

  if row.lease_owner is distinct from p_owner or row.fencing_token is distinct from p_fencing_token then
    return jsonb_build_object('ok', false, 'reason', 'fencing');
  end if;
  if row.unresolved_reservation_id is not null then
    select * into existing from public.makex_tx_reservations where id = row.unresolved_reservation_id;
    return jsonb_build_object('ok', false, 'reason', 'unresolved', 'reservation', public.makex_tx_reservation_json(existing));
  end if;
  if p_chain_nonce is null or p_chain_nonce < 0 then
    return jsonb_build_object('ok', false, 'reason', 'bad_chain_nonce');
  end if;

  if row.next_nonce is null then
    chosen := p_chain_nonce;
  elsif p_chain_nonce > row.next_nonce then
    chosen := p_chain_nonce;
  else
    chosen := row.next_nonce;
  end if;

  select * into existing
  from public.makex_tx_reservations
  where network = p_network
    and sender_address = p_sender
    and nonce = chosen
    and state <> 'REJECTED'
  limit 1;
  if found then
    return jsonb_build_object('ok', false, 'reason', 'nonce_already_used', 'reservation', public.makex_tx_reservation_json(existing));
  end if;

  insert into public.makex_tx_reservations (
    operation_id, app_id, network, sender_address, purpose, nonce, fencing_token, state, payload_fingerprint
  ) values (
    p_operation_id, p_app_id, p_network, p_sender, p_purpose, chosen, p_fencing_token, 'RESERVED', p_payload_fingerprint
  ) returning * into created;

  update public.makex_wallet_tx_authority
  set next_nonce = chosen + 1,
      unresolved_reservation_id = created.id,
      updated_at = now()
  where network = p_network and sender_address = p_sender;

  return jsonb_build_object('ok', true, 'reservation', public.makex_tx_reservation_json(created));
end;
$$;

create or replace function public.makex_tx_save_signed(
  p_reservation_id uuid,
  p_owner text,
  p_fencing_token bigint,
  p_tx_hash text,
  p_signed_tx jsonb
)
returns jsonb
language plpgsql
set search_path = public
as $$
declare
  reservation public.makex_tx_reservations%rowtype;
  row public.makex_wallet_tx_authority%rowtype;
begin
  perform set_config('statement_timeout', '5000', true);
  select * into reservation from public.makex_tx_reservations where id = p_reservation_id for update;
  if not found then
    return jsonb_build_object('ok', false, 'reason', 'not_found');
  end if;
  select * into row
  from public.makex_wallet_tx_authority
  where network = reservation.network and sender_address = reservation.sender_address
  for update;
  if row.lease_owner is distinct from p_owner or row.fencing_token is distinct from p_fencing_token then
    return jsonb_build_object('ok', false, 'reason', 'fencing');
  end if;
  if reservation.state <> 'RESERVED' then
    return jsonb_build_object('ok', false, 'reason', 'illegal_transition', 'reservation', public.makex_tx_reservation_json(reservation));
  end if;

  update public.makex_tx_reservations
  set state = 'SIGNED',
      tx_hash = p_tx_hash,
      signed_tx = p_signed_tx,
      updated_at = now()
  where id = p_reservation_id
  returning * into reservation;

  return jsonb_build_object('ok', true, 'reservation', public.makex_tx_reservation_json(reservation));
end;
$$;

create or replace function public.makex_tx_transition_reservation(
  p_reservation_id uuid,
  p_owner text,
  p_fencing_token bigint,
  p_next_state text,
  p_chain_nonce bigint,
  p_error_class text,
  p_error_detail text,
  p_tx_hash text,
  p_attempt integer
)
returns jsonb
language plpgsql
set search_path = public
as $$
declare
  reservation public.makex_tx_reservations%rowtype;
  row public.makex_wallet_tx_authority%rowtype;
  allowed boolean;
begin
  perform set_config('statement_timeout', '5000', true);
  select * into reservation from public.makex_tx_reservations where id = p_reservation_id for update;
  if not found then
    return jsonb_build_object('ok', false, 'reason', 'not_found');
  end if;
  select * into row
  from public.makex_wallet_tx_authority
  where network = reservation.network and sender_address = reservation.sender_address
  for update;
  if p_owner is not null or p_fencing_token is not null then
    if row.lease_owner is distinct from p_owner or row.fencing_token is distinct from p_fencing_token then
      return jsonb_build_object('ok', false, 'reason', 'fencing');
    end if;
  end if;

  allowed := (reservation.state = p_next_state and reservation.state not in ('CONFIRMED', 'FAILED', 'REJECTED'))
    or (reservation.state = 'RESERVED' and p_next_state in ('SIGNED', 'REJECTED', 'NEEDS_RECONCILIATION'))
    or (reservation.state = 'SIGNED' and p_next_state in ('SUBMITTED', 'UNKNOWN', 'REJECTED', 'NEEDS_RECONCILIATION', 'PENDING', 'CONFIRMED', 'FAILED'))
    or (reservation.state = 'SUBMITTED' and p_next_state in ('PENDING', 'CONFIRMED', 'FAILED', 'UNKNOWN', 'NEEDS_RECONCILIATION'))
    or (reservation.state = 'PENDING' and p_next_state in ('CONFIRMED', 'FAILED', 'UNKNOWN', 'NEEDS_RECONCILIATION', 'PENDING'))
    or (reservation.state = 'UNKNOWN' and p_next_state in ('SUBMITTED', 'PENDING', 'CONFIRMED', 'FAILED', 'REJECTED', 'NEEDS_RECONCILIATION', 'UNKNOWN'))
    or (reservation.state = 'NEEDS_RECONCILIATION' and p_next_state in ('CONFIRMED', 'FAILED', 'REJECTED', 'PENDING', 'SUBMITTED', 'UNKNOWN', 'NEEDS_RECONCILIATION'));
  if not allowed then
    return jsonb_build_object('ok', false, 'reason', 'illegal_transition', 'reservation', public.makex_tx_reservation_json(reservation));
  end if;

  update public.makex_tx_reservations
  set state = p_next_state,
      tx_hash = coalesce(p_tx_hash, tx_hash),
      error_class = coalesce(p_error_class, error_class),
      error_detail = coalesce(left(p_error_detail, 500), error_detail),
      attempt = coalesce(p_attempt, attempt),
      updated_at = now()
  where id = p_reservation_id
  returning * into reservation;

  if p_next_state in ('CONFIRMED', 'FAILED', 'REJECTED') and row.unresolved_reservation_id = reservation.id then
    row.unresolved_reservation_id := null;
  end if;
  if p_next_state in ('CONFIRMED', 'FAILED') then
    row.next_nonce := greatest(coalesce(row.next_nonce, reservation.nonce + 1), reservation.nonce + 1);
  end if;
  if p_next_state = 'REJECTED' then
    if p_chain_nonce is not null and p_chain_nonce > reservation.nonce then
      row.next_nonce := greatest(coalesce(row.next_nonce, p_chain_nonce), p_chain_nonce);
    elsif row.next_nonce = reservation.nonce + 1 then
      row.next_nonce := reservation.nonce;
    end if;
  end if;

  update public.makex_wallet_tx_authority
  set next_nonce = row.next_nonce,
      unresolved_reservation_id = row.unresolved_reservation_id,
      updated_at = now()
  where network = row.network and sender_address = row.sender_address;

  return jsonb_build_object('ok', true, 'reservation', public.makex_tx_reservation_json(reservation));
end;
$$;

create or replace function public.makex_tx_operation_json(o public.makex_operations)
returns jsonb
language sql
stable
set search_path = public
as $$
  select jsonb_build_object(
    'id', o.id,
    'idempotency_key', o.idempotency_key,
    'request_fingerprint', o.request_fingerprint,
    'app_id', o.app_id,
    'network', o.network,
    'wallet_address', o.wallet_address,
    'state', o.state,
    'fee_reservation_id', o.fee_reservation_id,
    'primary_reservation_id', o.primary_reservation_id,
    'fee_tx_hash', o.fee_tx_hash,
    'primary_tx_hash', o.primary_tx_hash,
    'fee_amount_wei', o.fee_amount_wei,
    'fee_token', o.fee_token,
    'fee_token_identifier', o.fee_token_identifier,
    'usd_amount', o.usd_amount,
    'skipped_whitelist', o.skipped_whitelist,
    'whitelist_reason', o.whitelist_reason,
    'error_class', o.error_class,
    'error_detail', o.error_detail,
    'result_json', o.result_json,
    'http_status', o.http_status,
    'progress_json', o.progress_json,
    'created_at', o.created_at,
    'updated_at', o.updated_at
  );
$$;

create or replace function public.makex_tx_begin_operation(
  p_idempotency_key text,
  p_request_fingerprint text,
  p_app_id text,
  p_network text,
  p_wallet_address text
)
returns jsonb
language plpgsql
set search_path = public
as $$
declare
  created public.makex_operations%rowtype;
  existing public.makex_operations%rowtype;
begin
  perform set_config('statement_timeout', '5000', true);
  insert into public.makex_operations (
    idempotency_key, request_fingerprint, app_id, network, wallet_address, state
  ) values (
    p_idempotency_key, p_request_fingerprint, p_app_id, p_network, p_wallet_address, 'RECEIVED'
  )
  on conflict (app_id, network, wallet_address, idempotency_key) do nothing
  returning * into created;

  if created.id is not null then
    return jsonb_build_object('ok', true, 'created', true, 'operation', public.makex_tx_operation_json(created));
  end if;

  select * into existing
  from public.makex_operations
  where app_id = p_app_id
    and network = p_network
    and wallet_address = p_wallet_address
    and idempotency_key = p_idempotency_key
  for update;

  if existing.request_fingerprint is distinct from p_request_fingerprint then
    return jsonb_build_object('ok', false, 'reason', 'fingerprint_mismatch', 'operation', public.makex_tx_operation_json(existing));
  end if;
  return jsonb_build_object('ok', true, 'created', false, 'operation', public.makex_tx_operation_json(existing));
end;
$$;

create or replace function public.makex_tx_update_operation(
  p_id uuid,
  p_patch jsonb,
  p_expected_state text
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
  select * into existing from public.makex_operations where id = p_id for update;
  if not found then
    return jsonb_build_object('ok', false, 'reason', 'not_found');
  end if;
  if p_expected_state is not null and existing.state is distinct from p_expected_state then
    return jsonb_build_object('ok', false, 'reason', 'state_conflict', 'operation', public.makex_tx_operation_json(existing));
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

revoke all on function public.makex_tx_reservation_json(public.makex_tx_reservations) from public, anon, authenticated;
revoke all on function public.makex_tx_operation_json(public.makex_operations) from public, anon, authenticated;
revoke all on function public.makex_tx_health() from public, anon, authenticated;
revoke all on function public.makex_tx_acquire_lease(text, text, text, integer) from public, anon, authenticated;
revoke all on function public.makex_tx_refresh_lease(text, text, text, bigint, integer) from public, anon, authenticated;
revoke all on function public.makex_tx_release_lease(text, text, text, bigint) from public, anon, authenticated;
revoke all on function public.makex_tx_reserve_nonce(text, text, text, bigint, bigint, uuid, text, text, text) from public, anon, authenticated;
revoke all on function public.makex_tx_save_signed(uuid, text, bigint, text, jsonb) from public, anon, authenticated;
revoke all on function public.makex_tx_transition_reservation(uuid, text, bigint, text, bigint, text, text, text, integer) from public, anon, authenticated;
revoke all on function public.makex_tx_begin_operation(text, text, text, text, text) from public, anon, authenticated;
revoke all on function public.makex_tx_update_operation(uuid, jsonb, text) from public, anon, authenticated;

grant execute on function public.makex_tx_health() to service_role;
grant execute on function public.makex_tx_acquire_lease(text, text, text, integer) to service_role;
grant execute on function public.makex_tx_refresh_lease(text, text, text, bigint, integer) to service_role;
grant execute on function public.makex_tx_release_lease(text, text, text, bigint) to service_role;
grant execute on function public.makex_tx_reserve_nonce(text, text, text, bigint, bigint, uuid, text, text, text) to service_role;
grant execute on function public.makex_tx_save_signed(uuid, text, bigint, text, jsonb) to service_role;
grant execute on function public.makex_tx_transition_reservation(uuid, text, bigint, text, bigint, text, text, text, integer) to service_role;
grant execute on function public.makex_tx_begin_operation(text, text, text, text, text) to service_role;
grant execute on function public.makex_tx_update_operation(uuid, jsonb, text) to service_role;
grant execute on function public.makex_tx_reservation_json(public.makex_tx_reservations) to service_role;
grant execute on function public.makex_tx_operation_json(public.makex_operations) to service_role;
