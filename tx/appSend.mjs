import { TxCoordinationError } from './errors.mjs';
import { requireOperationUpdate } from './ledgerWrite.mjs';

/**
 * Submit one primary transaction through the shared coordinator and record it
 * on the operation ledger before the HTTP success body is returned.
 */
export async function sendAppTransaction({
  coordinator,
  signer,
  senderAddress,
  buildTx,
  operation,
  purpose = 'primary',
  payloadFingerprint = null,
}) {
  const sender = typeof senderAddress === 'string' ? senderAddress : senderAddress.toString();
  const outcome = await coordinator.submitAndConfirm({
    senderAddress: sender,
    purpose,
    operationId: operation?.id || null,
    appId: operation?.app_id || null,
    payloadFingerprint: payloadFingerprint || purpose,
    buildTx,
    signTx: async (tx) => {
      await signer.sign(tx);
      return tx;
    },
    onSigned: async (reservation) => {
      if (!operation?.id) return;
      await requireOperationUpdate(coordinator.store, {
        id: operation.id,
        phase: 'before_broadcast',
        patch: {
          state: 'OPERATION_PREPARED',
          primary_reservation_id: reservation.id,
          primary_tx_hash: reservation.tx_hash,
        },
      });
    },
    onSubmitted: async (reservation) => {
      if (!operation?.id) return;
      await requireOperationUpdate(coordinator.store, {
        id: operation.id,
        phase: 'after_broadcast',
        patch: {
          state: 'OPERATION_SUBMITTED',
          primary_reservation_id: reservation.id,
          primary_tx_hash: reservation.tx_hash,
        },
      });
    },
  });

  if (operation?.id) {
    const patch = {
      primary_tx_hash: outcome.txHash,
      primary_reservation_id: outcome.reservationId,
    };
    if (outcome.status === 'success') {
      patch.state = 'OPERATION_SUBMITTED';
    } else if (outcome.status === 'fail') {
      patch.state = 'OPERATION_FAILED';
      patch.error_class = 'primary_failed';
      patch.error_detail = outcome.details || null;
    } else {
      patch.state = 'INCONCLUSIVE';
      patch.error_class = outcome.status;
    }
    const updated = await coordinator.store.updateOperation({ id: operation.id, patch });
    if (!updated?.ok) {
      throw new TxCoordinationError(
        'LEDGER_WRITE_FAILED',
        outcome.status === 'success'
          ? 'The transfer was confirmed but the operation ledger could not be updated. Retry the same idempotency key. It will not be sent again.'
          : 'The transfer result could not be recorded. Retry the same idempotency key. It will not be replaced.',
        { retryable: true, httpStatus: 503, txHash: outcome.txHash, operationId: operation.id, state: outcome.state },
      );
    }
  }

  return {
    txHash: outcome.txHash,
    status: outcome.status,
    details: outcome.details || null,
    nonce: outcome.nonce,
  };
}
