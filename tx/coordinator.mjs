import { randomUUID } from 'node:crypto';
import os from 'node:os';
import { redactPemFromString, sanitizeObjectForLog } from '../makexStandard.mjs';
import {
  createMultiversxChain,
  hashDiagnostic,
  identifyTransaction,
  isTxHash,
  readHashDiagnostic,
  rebuildTransaction,
  signedPlainMatchesRecord,
} from './chain.mjs';
import { classifySendError, safeErrorDetail, TxCoordinationError } from './errors.mjs';
import { createSupabaseStore } from './supabaseStore.mjs';
import { pollTransaction } from './polling.mjs';

const UNRESOLVED = new Set(['RESERVED', 'SIGNED', 'SUBMITTED', 'PENDING', 'UNKNOWN', 'NEEDS_RECONCILIATION']);

function defaultLog(level, message, data = {}) {
  const safe = sanitizeObjectForLog({
    timestamp: new Date().toISOString(),
    level,
    message: redactPemFromString(message),
    component: 'tx-coordinator',
    ...data,
  });
  console.log(JSON.stringify(safe));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function readCoordinatorConfig(env = process.env) {
  const number = (name, fallback) => {
    const raw = env[name];
    if (raw == null || raw === '') return fallback;
    const value = Number(raw);
    if (!Number.isFinite(value) || value <= 0) return fallback;
    return value;
  };
  return {
    network: env.MAKEX_CHAIN_ID || '1',
    leaseTtlMs: number('MAKEX_TX_LEASE_TTL_MS', 150000),
    queueTimeoutMs: number('MAKEX_TX_QUEUE_TIMEOUT_MS', 120000),
    pollIntervalMs: number('MAKEX_TX_POLL_INTERVAL_MS', 2000),
    pollMaxMs: number('MAKEX_TX_POLL_MAX_MS', 90000),
    pollMaxIntervalMs: number('MAKEX_TX_POLL_MAX_INTERVAL_MS', 8000),
    backoff: number('MAKEX_TX_POLL_BACKOFF', 1.5),
    maxRebroadcasts: number('MAKEX_TX_MAX_RECOVERY_ATTEMPTS', 1),
  };
}

function outcomeFrom(reservation, status, details = null) {
  return {
    status,
    txHash: reservation?.tx_hash || null,
    nonce: reservation?.nonce ?? null,
    reservationId: reservation?.id || null,
    details,
    state: reservation?.state || null,
  };
}

export function createTxCoordinator({
  store,
  chain,
  log = defaultLog,
  appId,
  instanceId = process.env.RENDER_INSTANCE_ID || `${os.hostname()}:${process.pid}:${randomUUID()}`,
  config = readCoordinatorConfig(),
  identify = identifyTransaction,
  rebuild = rebuildTransaction,
  sleepFn = sleep,
}) {
  const network = config.network;

  function logEvent(level, message, fields) {
    log(level, message, sanitizeObjectForLog(fields));
  }

  async function withLease(sender, fn) {
    const deadline = Date.now() + config.queueTimeoutMs;
    let lease = null;
    while (Date.now() < deadline) {
      lease = await store.acquireLease({
        network,
        sender,
        owner: instanceId,
        ttlMs: config.leaseTtlMs,
      });
      if (lease.acquired) break;
      await sleepFn(Math.min(400, Math.max(25, lease.retryAfterMs || 200)));
      lease = null;
    }
    if (!lease?.acquired) {
      throw new TxCoordinationError(
        'NONCE_BUSY',
        'This wallet is already sending a MakeX transaction. Retry shortly.',
        { retryable: true, httpStatus: 503 },
      );
    }
    try {
      return await fn(lease);
    } finally {
      await store
        .releaseLease({
          network,
          sender,
          owner: instanceId,
          fencingToken: lease.fencingToken,
        })
        .catch((error) => {
          logEvent('error', 'Failed to release wallet lease', {
            senderAddress: sender,
            errorClass: 'lease_release',
            error: safeErrorDetail(error),
          });
        });
    }
  }

  async function transition(lease, sender, reservation, fields) {
    const result = await store.transitionReservation({
      reservationId: reservation.id,
      owner: instanceId,
      fencingToken: lease.fencingToken,
      ...fields,
    });
    if (!result.ok) {
      throw new TxCoordinationError(
        'FENCING_LOST',
        'Lost the wallet lease while updating transaction state. No new payment was created.',
        { retryable: true, httpStatus: 503, state: reservation.state, txHash: reservation.tx_hash },
      );
    }
    logEvent('info', 'Transaction reservation updated', {
      appId,
      senderAddress: sender,
      purpose: reservation.purpose,
      operationId: reservation.operation_id,
      nonce: reservation.nonce,
      txHash: result.reservation.tx_hash,
      state: result.reservation.state,
      attempt: result.reservation.attempt,
      errorClass: fields.errorClass || null,
    });
    return result.reservation;
  }

  async function refresh(lease, sender) {
    const refreshed = await store.refreshLease({
      network,
      sender,
      owner: instanceId,
      fencingToken: lease.fencingToken,
      ttlMs: config.leaseTtlMs,
    });
    if (!refreshed.ok) {
      throw new TxCoordinationError('FENCING_LOST', 'Lost the wallet lease during confirmation.', {
        retryable: true,
        httpStatus: 503,
      });
    }
  }

  async function poll(hash, sender, lease) {
    return pollTransaction({
      txHash: hash,
      fetchStatus: (value) => chain.getStatus(value),
      maxMs: config.pollMaxMs,
      intervalMs: config.pollIntervalMs,
      maxIntervalMs: config.pollMaxIntervalMs,
      backoff: config.backoff,
      sleep: sleepFn,
      onTick: () => refresh(lease, sender),
    });
  }

  async function blockFor(reservation, code, message) {
    throw new TxCoordinationError(code, message, {
      retryable: true,
      httpStatus: 503,
      txHash: reservation?.tx_hash || null,
      nonce: reservation?.nonce ?? null,
      state: reservation?.state || null,
      operationId: reservation?.operation_id || null,
      errorClass: reservation?.error_class || null,
    });
  }

  function canonicalHashOf(tx) {
    if (!tx || typeof tx.toPlainObject !== 'function') return null;
    try {
      const identified = identify(rebuild(tx.toPlainObject()));
      return isTxHash(identified?.txHash) ? identified.txHash : null;
    } catch {
      return null;
    }
  }

  function canonicalHashOfPlain(plain) {
    if (!plain || typeof plain !== 'object') return null;
    try {
      const identified = identify(rebuild(plain));
      return isTxHash(identified?.txHash) ? identified.txHash : null;
    } catch {
      return null;
    }
  }

  function acceptanceProved(plain, status) {
    if (!status || (status.status !== 'success' && status.status !== 'fail')) return false;
    if (!status.transaction) return true;
    return signedPlainMatchesRecord(plain, status.transaction);
  }

  async function recoverAcceptedHash(lease, sender, reservation) {
    if (!reservation?.signed_tx) return null;
    const canonicalHash = canonicalHashOfPlain(reservation.signed_tx);
    if (!canonicalHash) return null;
    const noted = readHashDiagnostic(reservation.error_detail);
    const gatewayHash = isTxHash(noted.gateway_hash) ? noted.gateway_hash : null;
    if (gatewayHash && gatewayHash !== canonicalHash) return null;
    if (reservation.tx_hash === canonicalHash && !gatewayHash) return null;

    const status = await chain.getStatus(canonicalHash);
    if (status.transaction && !signedPlainMatchesRecord(reservation.signed_tx, status.transaction)) {
      return null;
    }
    if (status.status === 'success') {
      const detail = reservation.error_detail || hashDiagnostic({
        localHash: reservation.tx_hash,
        gatewayHash: canonicalHash,
        canonicalHash,
      });
      const updated = await transition(lease, sender, reservation, {
        nextState: 'CONFIRMED',
        txHash: canonicalHash,
        errorClass: 'hash_mismatch_reconciled',
        errorDetail: detail,
      });
      const outcome = outcomeFrom(updated, 'success');
      outcome.reconciliation = {
        localHash: reservation.tx_hash,
        gatewayHash: canonicalHash,
        canonicalHash,
        nonce: updated.nonce,
      };
      return { action: 'done', outcome };
    }
    if (status.status === 'fail') {
      const updated = await transition(lease, sender, reservation, {
        nextState: 'FAILED',
        txHash: canonicalHash,
        errorClass: 'execution_failed',
        errorDetail: status.details || reservation.error_detail,
      });
      return { action: 'done', outcome: outcomeFrom(updated, 'fail', status.details) };
    }
    if (status.status === 'pending') {
      const updated = await transition(lease, sender, reservation, { nextState: 'PENDING' });
      return { action: 'block', reservation: updated, code: 'TX_PENDING' };
    }
    return null;
  }

  async function reconcileReservation(lease, sender, reservation) {
    if (!reservation) return { action: 'clear' };
    if (reservation.state === 'CONFIRMED') {
      return { action: 'done', outcome: outcomeFrom(reservation, 'success') };
    }
    if (reservation.state === 'FAILED') {
      return { action: 'done', outcome: outcomeFrom(reservation, 'fail', reservation.error_detail) };
    }
    if (reservation.state === 'REJECTED') return { action: 'clear', reservation };

    if (reservation.state === 'RESERVED' && !reservation.tx_hash) {
      const chainNonce = await chain.getAccountNonce(sender);
      const updated = await transition(lease, sender, reservation, {
        nextState: 'REJECTED',
        chainNonce,
        errorClass: 'abandoned_before_sign',
      });
      return { action: 'clear', reservation: updated };
    }

    const status = reservation.tx_hash
      ? await chain.getStatus(reservation.tx_hash)
      : { status: 'not_found' };

    if ((status.status === 'success' || status.status === 'fail')
      && !acceptanceProved(reservation.signed_tx, status)) {
      const updated = await transition(lease, sender, reservation, {
        nextState: 'NEEDS_RECONCILIATION',
        errorClass: 'record_mismatch',
        errorDetail: status.details || 'chain record did not match the signed transaction',
      });
      return { action: 'block', reservation: updated, code: 'TX_NEEDS_RECONCILIATION' };
    }
    if (status.status === 'success') {
      const updated = await transition(lease, sender, reservation, { nextState: 'CONFIRMED' });
      return { action: 'done', outcome: outcomeFrom(updated, 'success') };
    }
    if (status.status === 'fail') {
      const updated = await transition(lease, sender, reservation, {
        nextState: 'FAILED',
        errorClass: 'execution_failed',
        errorDetail: status.details,
      });
      return { action: 'done', outcome: outcomeFrom(updated, 'fail', status.details) };
    }
    if (status.status === 'pending') {
      const updated = await transition(lease, sender, reservation, { nextState: 'PENDING' });
      return { action: 'block', reservation: updated, code: 'TX_PENDING' };
    }
    if (status.status === 'unknown') {
      const updated = await transition(lease, sender, reservation, {
        nextState: 'UNKNOWN',
        errorClass: 'status_unknown',
        errorDetail: status.details,
      });
      return { action: 'block', reservation: updated, code: 'TX_INCONCLUSIVE' };
    }

    const recovered = await recoverAcceptedHash(lease, sender, reservation);
    if (recovered) return recovered;

    const chainNonce = await chain.getAccountNonce(sender);
    if (chainNonce > reservation.nonce) {
      const updated = await transition(lease, sender, reservation, {
        nextState: 'NEEDS_RECONCILIATION',
        chainNonce,
        errorClass: reservation.error_class === 'hash_mismatch' ? 'hash_mismatch' : 'missing_tx_chain_moved',
      });
      return { action: 'block', reservation: updated, code: 'TX_NEEDS_RECONCILIATION' };
    }
    if (chainNonce < reservation.nonce) {
      const updated = await transition(lease, sender, reservation, {
        nextState: 'NEEDS_RECONCILIATION',
        chainNonce,
        errorClass: 'nonce_ahead_of_chain',
      });
      return { action: 'block', reservation: updated, code: 'TX_NEEDS_RECONCILIATION' };
    }

    if (!reservation.signed_tx || reservation.attempt >= config.maxRebroadcasts) {
      const updated = await transition(lease, sender, reservation, {
        nextState: 'NEEDS_RECONCILIATION',
        chainNonce,
        errorClass: 'not_found',
      });
      return { action: 'block', reservation: updated, code: 'TX_NEEDS_RECONCILIATION' };
    }

    try {
      const gatewayHash = await chain.send(rebuild(reservation.signed_tx));
      if (gatewayHash && reservation.tx_hash && gatewayHash !== reservation.tx_hash) {
        const canonicalHash = canonicalHashOfPlain(reservation.signed_tx);
        const detail = hashDiagnostic({
          localHash: reservation.tx_hash,
          gatewayHash,
          canonicalHash,
        });
        const noted = await transition(lease, sender, reservation, {
          nextState: 'NEEDS_RECONCILIATION',
          errorClass: 'hash_mismatch',
          errorDetail: detail,
          attempt: reservation.attempt + 1,
        });
        if (isTxHash(canonicalHash) && gatewayHash === canonicalHash) {
          const polled = await poll(gatewayHash, sender, lease);
          if (polled.status === 'success' && acceptanceProved(reservation.signed_tx, polled)) {
            const confirmed = await transition(lease, sender, noted, {
              nextState: 'CONFIRMED',
              txHash: gatewayHash,
              errorClass: 'hash_mismatch_reconciled',
              errorDetail: detail,
            });
            const outcome = outcomeFrom(confirmed, 'success');
            outcome.reconciliation = {
              localHash: reservation.tx_hash,
              gatewayHash,
              canonicalHash,
              nonce: confirmed.nonce,
            };
            return { action: 'done', outcome };
          }
          if (polled.status === 'fail' && acceptanceProved(reservation.signed_tx, polled)) {
            const failed = await transition(lease, sender, noted, {
              nextState: 'FAILED',
              txHash: gatewayHash,
              errorClass: 'execution_failed',
              errorDetail: polled.details || detail,
            });
            return { action: 'done', outcome: outcomeFrom(failed, 'fail', polled.details) };
          }
        }
        return { action: 'block', reservation: noted, code: 'TX_NEEDS_RECONCILIATION' };
      }
      const updated = await transition(lease, sender, reservation, {
        nextState: 'SUBMITTED',
        attempt: reservation.attempt + 1,
        errorClass: 'rebroadcast',
      });
      return { action: 'poll', reservation: updated };
    } catch (error) {
      const kind = classifySendError(error);
      if (kind.kind === 'rejected') {
        const updated = await transition(lease, sender, reservation, {
          nextState: 'REJECTED',
          chainNonce: await chain.getAccountNonce(sender),
          errorClass: kind.lower ? 'lower_nonce' : 'rejected',
          errorDetail: safeErrorDetail(error),
        });
        return { action: 'clear', reservation: updated };
      }
      const updated = await transition(lease, sender, reservation, {
        nextState: 'UNKNOWN',
        errorClass: 'rebroadcast_ambiguous',
        errorDetail: safeErrorDetail(error),
      });
      return { action: 'block', reservation: updated, code: 'TX_INCONCLUSIVE' };
    }
  }

  async function applyReconciled(lease, sender, reservation, input) {
    const reconciled = await reconcileReservation(lease, sender, reservation);
    const sameWork =
      input.operationId &&
      reservation.operation_id === input.operationId &&
      reservation.purpose === input.purpose;
    if (reconciled.action === 'done') {
      return sameWork ? reconciled.outcome : null;
    }
    if (reconciled.action === 'poll') {
      const polled = await poll(reconciled.reservation.tx_hash, sender, lease);
      const outcome = await finishPolled(lease, sender, reconciled.reservation, polled);
      return sameWork ? outcome : null;
    }
    if (reconciled.action === 'block') {
      await blockFor(
        reconciled.reservation,
        reconciled.code,
        'This wallet has an unresolved transaction. Retry this request. A new nonce was not allocated.',
      );
    }
    return null;
  }

  async function finishPolled(lease, sender, reservation, polled) {
    if ((polled.status === 'success' || polled.status === 'fail')
      && !acceptanceProved(reservation.signed_tx, polled)) {
      const updated = await transition(lease, sender, reservation, {
        nextState: 'NEEDS_RECONCILIATION',
        errorClass: 'record_mismatch',
        errorDetail: polled.details || 'chain record did not match the signed transaction',
      });
      await blockFor(
        updated,
        'TX_NEEDS_RECONCILIATION',
        'The chain record did not match the signed transaction. No replacement payment was created.',
      );
    }
    if (polled.status === 'success') {
      const updated = await transition(lease, sender, reservation, { nextState: 'CONFIRMED' });
      return outcomeFrom(updated, 'success');
    }
    if (polled.status === 'fail') {
      const updated = await transition(lease, sender, reservation, {
        nextState: 'FAILED',
        errorClass: 'execution_failed',
        errorDetail: polled.details,
      });
      return outcomeFrom(updated, 'fail', polled.details);
    }
    const nextState = polled.status === 'unknown' ? 'UNKNOWN' : 'PENDING';
    const updated = await transition(lease, sender, reservation, {
      nextState,
      errorClass: polled.status,
      errorDetail: polled.details,
    });
    await blockFor(
      updated,
      polled.status === 'unknown' ? 'TX_INCONCLUSIVE' : 'TX_PENDING',
      'The transaction was submitted but is not confirmed. Retry this request. It will not be sent again until this transaction is reconciled.',
    );
    return null;
  }

  async function submitAndConfirm(input) {
    const sender = String(input.senderAddress);
    const started = Date.now();
    return withLease(sender, async (lease) => {
      let lowerRetried = false;
      let activeLease = lease;

      let unresolved = activeLease.unresolved;
      if (input.operationId && input.purpose) {
        const prior = await store.getLatestReservation({
          operationId: input.operationId,
          purpose: input.purpose,
        });
        if (prior?.state === 'CONFIRMED') {
          return outcomeFrom(prior, 'success');
        }
        if (prior && UNRESOLVED.has(prior.state)) {
          const reconciled = await applyReconciled(activeLease, sender, prior, input);
          if (reconciled) return reconciled;
          if (unresolved?.id === prior.id) unresolved = null;
        }
      }

      if (unresolved && UNRESOLVED.has(unresolved.state)) {
        const fresh = await store.getReservation(unresolved.id);
        if (fresh && UNRESOLVED.has(fresh.state)) {
          if (input.operationId && fresh.operation_id && fresh.operation_id !== input.operationId) {
            await blockFor(
              fresh,
              'TX_PENDING',
              'This wallet has another unresolved MakeX transaction. Retry after it is confirmed.',
            );
          }
          const reconciled = await applyReconciled(activeLease, sender, fresh, input);
          if (reconciled) return reconciled;
        }
      }

      while (true) {
        const chainNonce = await chain.getAccountNonce(sender);
        const reserved = await store.reserveNonce({
          network,
          sender,
          owner: instanceId,
          fencingToken: activeLease.fencingToken,
          chainNonce,
          operationId: input.operationId || null,
          appId: input.appId || appId || null,
          purpose: input.purpose,
          payloadFingerprint: input.payloadFingerprint || null,
        });
        if (!reserved.ok) {
          throw new TxCoordinationError(
            reserved.reason === 'unresolved' ? 'TX_PENDING' : 'NONCE_RESERVE_FAILED',
            'Could not reserve a nonce safely. No transaction was signed.',
            { retryable: true, httpStatus: 503, state: reserved.reason },
          );
        }

        const tx = await input.buildTx(reserved.reservation.nonce);
        await input.signTx(tx);
        const identity = await identify(tx);
        const saved = await store.saveSigned({
          reservationId: reserved.reservation.id,
          owner: instanceId,
          fencingToken: activeLease.fencingToken,
          txHash: identity.txHash,
          signedTx: identity.plain,
        });
        if (!saved.ok) {
          throw new TxCoordinationError(
            'FENCING_LOST',
            'Lost the wallet lease before broadcast. The transaction was not sent.',
            { retryable: true, httpStatus: 503, nonce: reserved.reservation.nonce },
          );
        }
        if (input.onSigned) await input.onSigned(saved.reservation);
        await refresh(activeLease, sender);

        try {
          const gatewayHash = await chain.send(tx);
          if (gatewayHash && gatewayHash !== identity.txHash) {
            const canonicalHash = canonicalHashOf(tx);
            const detail = hashDiagnostic({
              localHash: identity.txHash,
              gatewayHash,
              canonicalHash,
            });
            const noted = await transition(activeLease, sender, saved.reservation, {
              nextState: 'NEEDS_RECONCILIATION',
              txHash: identity.txHash,
              errorClass: 'hash_mismatch',
              errorDetail: detail,
            });
            logEvent('error', 'Local transaction hash differed from the gateway hash', {
              appId,
              senderAddress: sender,
              purpose: input.purpose,
              operationId: input.operationId || null,
              nonce: saved.reservation.nonce,
              txHash: identity.txHash,
              gatewayHash,
              canonicalHash,
              errorClass: 'hash_mismatch',
            });
            const verified = isTxHash(canonicalHash) && gatewayHash === canonicalHash;
            if (verified) {
              const polled = await poll(gatewayHash, sender, activeLease);
              const proved = acceptanceProved(identity.plain, polled);
              if (polled.status === 'success' && proved) {
                const confirmed = await transition(activeLease, sender, noted, {
                  nextState: 'CONFIRMED',
                  txHash: gatewayHash,
                  errorClass: 'hash_mismatch_reconciled',
                  errorDetail: detail,
                });
                if (input.onSubmitted) await input.onSubmitted(confirmed);
                const outcome = outcomeFrom(confirmed, 'success');
                outcome.reconciliation = {
                  localHash: identity.txHash,
                  gatewayHash,
                  canonicalHash,
                  nonce: confirmed.nonce,
                };
                return outcome;
              }
              if (polled.status === 'fail' && proved) {
                const failed = await transition(activeLease, sender, noted, {
                  nextState: 'FAILED',
                  txHash: gatewayHash,
                  errorClass: 'execution_failed',
                  errorDetail: polled.details || detail,
                });
                return outcomeFrom(failed, 'fail', polled.details);
              }
            }
            throw new TxCoordinationError(
              'TX_NEEDS_RECONCILIATION',
              'The gateway hash did not match the signed transaction. No replacement payment was created.',
              {
                retryable: true,
                httpStatus: 503,
                txHash: identity.txHash,
                gatewayHash,
                canonicalHash,
                nonce: saved.reservation.nonce,
                operationId: input.operationId || null,
                errorClass: 'hash_mismatch',
                state: 'NEEDS_RECONCILIATION',
              },
            );
          }
          const submitted = await transition(activeLease, sender, saved.reservation, {
            nextState: 'SUBMITTED',
            txHash: identity.txHash,
          });
          if (input.onSubmitted) await input.onSubmitted(submitted);
          const polled = await poll(identity.txHash, sender, activeLease);
          const outcome = await finishPolled(activeLease, sender, submitted, polled);
          logEvent('info', 'Coordinated transaction finished', {
            appId,
            senderAddress: sender,
            purpose: input.purpose,
            operationId: input.operationId || null,
            nonce: outcome.nonce,
            txHash: outcome.txHash,
            state: outcome.state,
            elapsedMs: Date.now() - started,
          });
          return outcome;
        } catch (error) {
          if (error instanceof TxCoordinationError) throw error;
          const kind = classifySendError(error);
          const observed = await chain.getStatus(identity.txHash);
          if (observed.status === 'success' || observed.status === 'fail' || observed.status === 'pending') {
            if ((observed.status === 'success' || observed.status === 'fail')
              && !acceptanceProved(identity.plain, observed)) {
              await transition(activeLease, sender, saved.reservation, {
                nextState: 'NEEDS_RECONCILIATION',
                errorClass: 'record_mismatch',
                errorDetail: observed.details || 'chain record did not match the signed transaction',
              });
              throw new TxCoordinationError(
                'TX_NEEDS_RECONCILIATION',
                'The chain record did not match the signed transaction. No replacement payment was created.',
                {
                  retryable: true,
                  httpStatus: 503,
                  txHash: identity.txHash,
                  nonce: saved.reservation.nonce,
                  operationId: input.operationId || null,
                  errorClass: 'record_mismatch',
                  state: 'NEEDS_RECONCILIATION',
                },
              );
            }
            const submitted = await transition(activeLease, sender, saved.reservation, {
              nextState: observed.status === 'success' ? 'CONFIRMED' : observed.status === 'fail' ? 'FAILED' : 'SUBMITTED',
              errorClass: 'broadcast_response_lost',
            });
            if (observed.status === 'pending') {
              const polled = await poll(identity.txHash, sender, activeLease);
              return finishPolled(activeLease, sender, submitted, polled);
            }
            return outcomeFrom(submitted, observed.status === 'success' ? 'success' : 'fail', observed.details);
          }
          if (observed.status === 'unknown') {
            await transition(activeLease, sender, saved.reservation, {
              nextState: 'UNKNOWN',
              errorClass: 'broadcast_ambiguous',
              errorDetail: safeErrorDetail(error),
            });
            await blockFor(
              { ...saved.reservation, state: 'UNKNOWN', tx_hash: identity.txHash },
              'TX_INCONCLUSIVE',
              'The broadcast result is unknown. Retry this request. The same signed transaction will be reconciled, not replaced.',
            );
          }
          if (kind.kind === 'rejected' && observed.status === 'not_found') {
            const chainNonce = await chain.getAccountNonce(sender);
            await transition(activeLease, sender, saved.reservation, {
              nextState: 'REJECTED',
              chainNonce,
              errorClass: kind.lower ? 'lower_nonce' : kind.veryHigh ? 'very_high_nonce' : 'rejected',
              errorDetail: safeErrorDetail(error),
            });
            if (kind.lower && !lowerRetried && chainNonce > reserved.reservation.nonce) {
              lowerRetried = true;
              logEvent('info', 'Retrying once after an explicit lower-nonce rejection', {
                appId,
                senderAddress: sender,
                purpose: input.purpose,
                operationId: input.operationId || null,
                nonce: reserved.reservation.nonce,
                errorClass: 'lower_nonce',
              });
              continue;
            }
            throw new TxCoordinationError(
              kind.veryHigh ? 'TX_NEEDS_RECONCILIATION' : 'TX_REJECTED',
              'The network rejected the transaction before it was accepted. It was not charged. Retry this request.',
              {
                retryable: true,
                httpStatus: 503,
                operationId: input.operationId || null,
                nonce: reserved.reservation.nonce,
                errorClass: kind.lower ? 'lower_nonce' : 'rejected',
              },
            );
          }
          await transition(activeLease, sender, saved.reservation, {
            nextState: 'UNKNOWN',
            errorClass: 'broadcast_ambiguous',
            errorDetail: safeErrorDetail(error),
          });
          await blockFor(
            { ...saved.reservation, state: 'UNKNOWN', tx_hash: identity.txHash },
            'TX_INCONCLUSIVE',
            'The broadcast result is unknown. Retry this request so the same signed transaction can be reconciled.',
          );
        }
      }
    });
  }

  async function reconcileSender(senderAddress) {
    const sender = String(senderAddress);
    return withLease(sender, async (lease) => {
      if (!lease.unresolved) {
        return { state: 'idle', senderAddress: sender, nextNonce: lease.nextNonce };
      }
      const reconciled = await reconcileReservation(lease, sender, lease.unresolved);
      return {
        senderAddress: sender,
        action: reconciled.action,
        reservation: reconciled.reservation || null,
        outcome: reconciled.outcome || null,
        code: reconciled.code || null,
      };
    });
  }

  return {
    store,
    config,
    instanceId,
    network,
    submitAndConfirm,
    reconcileSender,
    submitSequentialBatch,
  };
}

export async function submitSequentialBatch(items, submitItem) {
  const results = [];
  for (let index = 0; index < items.length; index += 1) {
    try {
      const outcome = await submitItem(items[index], index);
      results.push({ index, ...outcome });
      if (outcome.status === 'fail') continue;
      if (outcome.status !== 'success') {
        return { complete: false, retryable: true, results };
      }
    } catch (error) {
      results.push({
        index,
        status: 'stopped',
        error: redactPemFromString(error.message),
        code: error.code || 'BATCH_STOPPED',
        retryable: error.retryable !== false,
      });
      return {
        complete: false,
        retryable: error.retryable !== false,
        results,
        error,
      };
    }
  }
  return { complete: true, retryable: false, results };
}

export function createProductionCoordinator({ supabase, provider, fetchImpl, appId, log }) {
  const store = createSupabaseStore(supabase);
  const chain = createMultiversxChain({ provider, fetchImpl });
  return createTxCoordinator({
    store,
    chain,
    appId,
    log,
  });
}
