import { randomUUID } from 'node:crypto';

/**
 * In-process stand-in for the PostgreSQL RPCs in supabase/migrations.
 * A single mutex makes each operation atomic, matching row locks.
 * Production uses Supabase so separate Node processes share one authority.
 */

function clone(value) {
  return value == null ? value : JSON.parse(JSON.stringify(value));
}

const TERMINAL = new Set(['CONFIRMED', 'FAILED', 'REJECTED']);

const ALLOWED = {
  RESERVED: ['SIGNED', 'REJECTED', 'NEEDS_RECONCILIATION'],
  SIGNED: ['SUBMITTED', 'UNKNOWN', 'REJECTED', 'NEEDS_RECONCILIATION', 'PENDING', 'CONFIRMED', 'FAILED'],
  SUBMITTED: ['PENDING', 'CONFIRMED', 'FAILED', 'UNKNOWN', 'NEEDS_RECONCILIATION'],
  PENDING: ['CONFIRMED', 'FAILED', 'UNKNOWN', 'NEEDS_RECONCILIATION', 'PENDING'],
  UNKNOWN: ['SUBMITTED', 'PENDING', 'CONFIRMED', 'FAILED', 'REJECTED', 'NEEDS_RECONCILIATION', 'UNKNOWN'],
  NEEDS_RECONCILIATION: ['CONFIRMED', 'FAILED', 'REJECTED', 'PENDING', 'SUBMITTED', 'UNKNOWN', 'NEEDS_RECONCILIATION'],
  CONFIRMED: [],
  FAILED: [],
  REJECTED: [],
};

export function createMemoryStore() {
  const authorities = new Map();
  const reservations = new Map();
  const operations = new Map();
  let queue = Promise.resolve();

  const lock = (fn) => {
    const run = queue.then(fn, fn);
    queue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  };

  const authorityKey = (network, sender) => `${network}|${sender}`;
  const operationKey = (appId, network, wallet, idempotencyKey) =>
    `${appId}|${network}|${wallet}|${idempotencyKey}`;

  const ensureAuthority = (network, sender) => {
    const key = authorityKey(network, sender);
    if (!authorities.has(key)) {
      authorities.set(key, {
        network,
        sender_address: sender,
        lease_owner: null,
        fencing_token: 0,
        lease_expires_at: 0,
        next_nonce: null,
        unresolved_reservation_id: null,
      });
    }
    return authorities.get(key);
  };

  return {
    async ping() {
      return { ok: true, version: 1, store: 'memory' };
    },

    acquireLease({ network, sender, owner, ttlMs }) {
      return lock(() => {
        const row = ensureAuthority(network, sender);
        const now = Date.now();
        if (row.lease_owner && row.lease_owner !== owner && row.lease_expires_at > now) {
          return {
            acquired: false,
            retryAfterMs: Math.max(1, row.lease_expires_at - now),
          };
        }
        row.lease_owner = owner;
        row.fencing_token += 1;
        row.lease_expires_at = now + ttlMs;
        const unresolved = row.unresolved_reservation_id
          ? clone(reservations.get(row.unresolved_reservation_id))
          : null;
        return {
          acquired: true,
          fencingToken: row.fencing_token,
          nextNonce: row.next_nonce,
          unresolved,
        };
      });
    },

    refreshLease({ network, sender, owner, fencingToken, ttlMs }) {
      return lock(() => {
        const row = ensureAuthority(network, sender);
        if (row.lease_owner !== owner || row.fencing_token !== fencingToken) {
          return { ok: false, reason: 'fencing' };
        }
        row.lease_expires_at = Date.now() + ttlMs;
        return { ok: true, fencingToken: row.fencing_token };
      });
    },

    releaseLease({ network, sender, owner, fencingToken }) {
      return lock(() => {
        const row = ensureAuthority(network, sender);
        if (row.lease_owner !== owner || row.fencing_token !== fencingToken) {
          return { ok: false, reason: 'fencing' };
        }
        row.lease_owner = null;
        row.lease_expires_at = 0;
        return { ok: true };
      });
    },

    getReservation(id) {
      return lock(() => clone(reservations.get(id) || null));
    },

    listReservationsForOperation(operationId) {
      return lock(() => {
        return [...reservations.values()]
          .filter((row) => row.operation_id === operationId)
          .sort((a, b) => a.created_at.localeCompare(b.created_at))
          .map((row) => clone(row));
      });
    },

    getLatestReservation({ operationId, purpose }) {
      return lock(() => {
        const rows = [...reservations.values()].filter(
          (row) => row.operation_id === operationId && row.purpose === purpose,
        );
        rows.sort((a, b) => a.created_at.localeCompare(b.created_at));
        return clone(rows.at(-1) || null);
      });
    },

    reserveNonce({
      network,
      sender,
      owner,
      fencingToken,
      chainNonce,
      operationId,
      appId,
      purpose,
      payloadFingerprint,
    }) {
      return lock(() => {
        const row = ensureAuthority(network, sender);
        if (row.lease_owner !== owner || row.fencing_token !== fencingToken) {
          return { ok: false, reason: 'fencing' };
        }
        if (row.unresolved_reservation_id) {
          return {
            ok: false,
            reason: 'unresolved',
            reservation: clone(reservations.get(row.unresolved_reservation_id)),
          };
        }
        if (!Number.isInteger(chainNonce) || chainNonce < 0) {
          return { ok: false, reason: 'bad_chain_nonce' };
        }

        let chosen;
        if (row.next_nonce == null) chosen = chainNonce;
        else if (chainNonce > row.next_nonce) chosen = chainNonce;
        else chosen = row.next_nonce;

        const activeNonce = [...reservations.values()].find(
          (item) =>
            item.network === network &&
            item.sender_address === sender &&
            item.nonce === chosen &&
            item.state !== 'REJECTED',
        );
        if (activeNonce) {
          return { ok: false, reason: 'nonce_already_used', reservation: clone(activeNonce) };
        }

        const now = new Date().toISOString();
        const reservation = {
          id: randomUUID(),
          operation_id: operationId,
          app_id: appId,
          network,
          sender_address: sender,
          purpose,
          nonce: chosen,
          fencing_token: fencingToken,
          tx_hash: null,
          signed_tx: null,
          state: 'RESERVED',
          payload_fingerprint: payloadFingerprint || null,
          error_class: null,
          error_detail: null,
          attempt: 0,
          created_at: now,
          updated_at: now,
        };
        reservations.set(reservation.id, reservation);
        row.next_nonce = chosen + 1;
        row.unresolved_reservation_id = reservation.id;
        return { ok: true, reservation: clone(reservation) };
      });
    },

    saveSigned({ reservationId, owner, fencingToken, txHash, signedTx }) {
      return lock(() => {
        const reservation = reservations.get(reservationId);
        if (!reservation) return { ok: false, reason: 'not_found' };
        const row = ensureAuthority(reservation.network, reservation.sender_address);
        if (row.lease_owner !== owner || row.fencing_token !== fencingToken) {
          return { ok: false, reason: 'fencing' };
        }
        if (reservation.state !== 'RESERVED') {
          return { ok: false, reason: 'illegal_transition', reservation: clone(reservation) };
        }
        reservation.state = 'SIGNED';
        reservation.tx_hash = txHash;
        reservation.signed_tx = signedTx;
        reservation.updated_at = new Date().toISOString();
        return { ok: true, reservation: clone(reservation) };
      });
    },

    transitionReservation({ reservationId, owner, fencingToken, nextState, chainNonce, errorClass, errorDetail, txHash, attempt }) {
      return lock(() => {
        const reservation = reservations.get(reservationId);
        if (!reservation) return { ok: false, reason: 'not_found' };
        const row = ensureAuthority(reservation.network, reservation.sender_address);
        if (owner != null || fencingToken != null) {
          if (row.lease_owner !== owner || row.fencing_token !== fencingToken) {
            return { ok: false, reason: 'fencing' };
          }
        }
        const from = reservation.state;
        const sameRefresh = from === nextState && !TERMINAL.has(from);
        if (!sameRefresh && !(ALLOWED[from] || []).includes(nextState)) {
          return { ok: false, reason: 'illegal_transition', reservation: clone(reservation) };
        }
        reservation.state = nextState;
        if (txHash) reservation.tx_hash = txHash;
        if (errorClass) reservation.error_class = errorClass;
        if (errorDetail) reservation.error_detail = String(errorDetail).slice(0, 500);
        if (attempt != null) reservation.attempt = attempt;
        reservation.updated_at = new Date().toISOString();

        if (TERMINAL.has(nextState) && row.unresolved_reservation_id === reservation.id) {
          row.unresolved_reservation_id = null;
        }
        if (nextState === 'CONFIRMED' || nextState === 'FAILED') {
          const consumedThrough = reservation.nonce + 1;
          row.next_nonce = Math.max(row.next_nonce ?? consumedThrough, consumedThrough);
        }
        if (nextState === 'REJECTED') {
          if (Number.isInteger(chainNonce) && chainNonce > reservation.nonce) {
            row.next_nonce = Math.max(row.next_nonce ?? chainNonce, chainNonce);
          } else if (row.next_nonce === reservation.nonce + 1) {
            row.next_nonce = reservation.nonce;
          }
        }
        return { ok: true, reservation: clone(reservation) };
      });
    },

    beginOperation({
      idempotencyKey,
      requestFingerprint,
      appId,
      network,
      walletAddress,
    }) {
      return lock(() => {
        const key = operationKey(appId, network, walletAddress, idempotencyKey);
        const existing = operations.get(key);
        if (existing) {
          if (existing.request_fingerprint !== requestFingerprint) {
            return { ok: false, reason: 'fingerprint_mismatch', operation: clone(existing) };
          }
          return { ok: true, created: false, operation: clone(existing) };
        }
        const now = new Date().toISOString();
        const operation = {
          id: randomUUID(),
          idempotency_key: idempotencyKey,
          request_fingerprint: requestFingerprint,
          app_id: appId,
          network,
          wallet_address: walletAddress,
          state: 'RECEIVED',
          fee_reservation_id: null,
          primary_reservation_id: null,
          fee_tx_hash: null,
          primary_tx_hash: null,
          fee_amount_wei: null,
          fee_token: null,
          fee_token_identifier: null,
          usd_amount: null,
          skipped_whitelist: false,
          whitelist_reason: null,
          error_class: null,
          error_detail: null,
          result_json: null,
          http_status: null,
          progress_json: null,
          created_at: now,
          updated_at: now,
        };
        operations.set(key, operation);
        return { ok: true, created: true, operation: clone(operation) };
      });
    },

    updateOperation({ id, patch, expectedState }) {
      return lock(() => {
        const operation = [...operations.values()].find((row) => row.id === id);
        if (!operation) return { ok: false, reason: 'not_found' };
        if (expectedState && operation.state !== expectedState) {
          return { ok: false, reason: 'state_conflict', operation: clone(operation) };
        }
        Object.assign(operation, patch, { updated_at: new Date().toISOString() });
        return { ok: true, operation: clone(operation) };
      });
    },

    claimBusiness({ id, owner, ttlMs = 120000, now = Date.now() }) {
      return lock(() => {
        const operation = [...operations.values()].find((row) => row.id === id);
        if (!operation) return { ok: false, reason: 'not_found' };
        if (operation.state === 'OPERATION_CONFIRMED') {
          return { ok: true, claimed: false, reason: 'confirmed', operation: clone(operation) };
        }
        const expires = Date.parse(operation.claim_expires_at || 0);
        const held = operation.state === 'OPERATION_IN_PROGRESS'
          && operation.claim_owner
          && operation.claim_owner !== owner
          && expires > now;
        if (held) {
          return {
            ok: true,
            claimed: false,
            reason: 'in_progress',
            retryAfterMs: Math.max(1, expires - now),
            operation: clone(operation),
          };
        }
        operation.state = 'OPERATION_IN_PROGRESS';
        operation.claim_owner = owner;
        operation.claim_expires_at = new Date(now + ttlMs).toISOString();
        operation.updated_at = new Date().toISOString();
        return { ok: true, claimed: true, operation: clone(operation) };
      });
    },

    finishBusiness({ id, owner, patch, now = Date.now() }) {
      return lock(() => {
        const operation = [...operations.values()].find((row) => row.id === id);
        if (!operation) return { ok: false, reason: 'not_found' };
        const expires = Date.parse(operation.claim_expires_at || 0);
        if (operation.state !== 'OPERATION_IN_PROGRESS' || operation.claim_owner !== owner || expires <= now) {
          const reason = operation.claim_owner !== owner ? 'stale_claim' : 'claim_expired';
          return { ok: false, reason, operation: clone(operation) };
        }
        Object.assign(operation, patch, { updated_at: new Date().toISOString() });
        return { ok: true, operation: clone(operation) };
      });
    },

    getOperation(id) {
      return lock(() => {
        const operation = [...operations.values()].find((row) => row.id === id);
        return clone(operation || null);
      });
    },

    snapshotAuthority(network, sender) {
      return lock(() => clone(authorities.get(authorityKey(network, sender)) || null));
    },
  };
}
