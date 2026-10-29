import { TxCoordinationError } from './errors.mjs';

function asDbError(error, label) {
  const message = error?.message || 'unknown database error';
  const missing =
    error?.code === 'PGRST202' ||
    /could not find the function|does not exist|schema cache/i.test(message);
  if (missing) {
    return new TxCoordinationError(
      'COORDINATOR_SCHEMA_MISSING',
      'Transaction coordinator schema is not installed. Apply supabase/migrations in filename order. Do not rerun 20261028220000_makex_tx_coordinator.sql or 20261028233000_makex_operation_claim.sql if they are already applied. Apply 20261029190000_makex_finish_business.sql before serving this revision.',
      { retryable: false, httpStatus: 503, errorClass: 'schema_missing' },
    );
  }
  return new TxCoordinationError(
    'COORDINATOR_DB_ERROR',
    `Transaction coordinator database error during ${label}: ${message}`,
    { retryable: true, httpStatus: 503, errorClass: 'database' },
  );
}

async function call(supabase, fn, args, label) {
  const result = await supabase.rpc(fn, args);
  if (result.error) throw asDbError(result.error, label);
  return result.data;
}

export function createSupabaseStore(supabase) {
  if (!supabase) {
    throw new TxCoordinationError(
      'COORDINATOR_SCHEMA_MISSING',
      'Supabase is not configured. Refusing to allocate wallet nonces from process memory.',
      { retryable: false, httpStatus: 503 },
    );
  }

  return {
    ping() {
      return call(supabase, 'makex_tx_health', {}, 'health');
    },

    acquireLease({ network, sender, owner, ttlMs }) {
      return call(
        supabase,
        'makex_tx_acquire_lease',
        { p_network: network, p_sender: sender, p_owner: owner, p_ttl_ms: ttlMs },
        'acquire lease',
      );
    },

    refreshLease({ network, sender, owner, fencingToken, ttlMs }) {
      return call(
        supabase,
        'makex_tx_refresh_lease',
        {
          p_network: network,
          p_sender: sender,
          p_owner: owner,
          p_fencing_token: fencingToken,
          p_ttl_ms: ttlMs,
        },
        'refresh lease',
      );
    },

    releaseLease({ network, sender, owner, fencingToken }) {
      return call(
        supabase,
        'makex_tx_release_lease',
        { p_network: network, p_sender: sender, p_owner: owner, p_fencing_token: fencingToken },
        'release lease',
      );
    },

    async getReservation(id) {
      const result = await supabase.from('makex_tx_reservations').select('*').eq('id', id).maybeSingle();
      if (result.error) throw asDbError(result.error, 'load reservation');
      return result.data;
    },

    async listReservationsForOperation(operationId) {
      const result = await supabase
        .from('makex_tx_reservations')
        .select('*')
        .eq('operation_id', operationId)
        .order('created_at', { ascending: true });
      if (result.error) throw asDbError(result.error, 'list reservations');
      return result.data || [];
    },

    async getLatestReservation({ operationId, purpose }) {
      const result = await supabase
        .from('makex_tx_reservations')
        .select('*')
        .eq('operation_id', operationId)
        .eq('purpose', purpose)
        .order('created_at', { ascending: false })
        .limit(1)
        .maybeSingle();
      if (result.error) throw asDbError(result.error, 'load latest reservation');
      return result.data;
    },

    reserveNonce(args) {
      return call(
        supabase,
        'makex_tx_reserve_nonce',
        {
          p_network: args.network,
          p_sender: args.sender,
          p_owner: args.owner,
          p_fencing_token: args.fencingToken,
          p_chain_nonce: args.chainNonce,
          p_operation_id: args.operationId,
          p_app_id: args.appId,
          p_purpose: args.purpose,
          p_payload_fingerprint: args.payloadFingerprint,
        },
        'reserve nonce',
      );
    },

    saveSigned(args) {
      return call(
        supabase,
        'makex_tx_save_signed',
        {
          p_reservation_id: args.reservationId,
          p_owner: args.owner,
          p_fencing_token: args.fencingToken,
          p_tx_hash: args.txHash,
          p_signed_tx: args.signedTx,
        },
        'save signed transaction',
      );
    },

    transitionReservation(args) {
      return call(
        supabase,
        'makex_tx_transition_reservation',
        {
          p_reservation_id: args.reservationId,
          p_owner: args.owner,
          p_fencing_token: args.fencingToken,
          p_next_state: args.nextState,
          p_chain_nonce: args.chainNonce ?? null,
          p_error_class: args.errorClass ?? null,
          p_error_detail: args.errorDetail ?? null,
          p_tx_hash: args.txHash ?? null,
          p_attempt: args.attempt ?? null,
        },
        'transition reservation',
      );
    },

    beginOperation(args) {
      return call(
        supabase,
        'makex_tx_begin_operation',
        {
          p_idempotency_key: args.idempotencyKey,
          p_request_fingerprint: args.requestFingerprint,
          p_app_id: args.appId,
          p_network: args.network,
          p_wallet_address: args.walletAddress,
        },
        'begin operation',
      );
    },

    updateOperation({ id, patch, expectedState = null }) {
      return call(
        supabase,
        'makex_tx_update_operation',
        { p_id: id, p_patch: patch, p_expected_state: expectedState },
        'update operation',
      );
    },

    claimBusiness({ id, owner, ttlMs = 120000 }) {
      return call(
        supabase,
        'makex_tx_claim_business',
        { p_id: id, p_owner: owner, p_ttl_ms: ttlMs },
        'claim business operation',
      );
    },

    finishBusiness({ id, owner, patch }) {
      return call(
        supabase,
        'makex_tx_finish_business',
        { p_id: id, p_owner: owner, p_patch: patch },
        'finish business operation',
      );
    },

    async getOperation(id) {
      const result = await supabase.from('makex_operations').select('*').eq('id', id).maybeSingle();
      if (result.error) throw asDbError(result.error, 'load operation');
      return result.data;
    },
  };
}
