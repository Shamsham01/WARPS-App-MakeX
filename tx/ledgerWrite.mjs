import { TxCoordinationError } from './errors.mjs';

export async function requireOperationUpdate(store, { id, patch, phase }) {
  const updated = await store.updateOperation({ id, patch });
  if (!updated?.ok) {
    const beforeBroadcast = phase === 'before_broadcast';
    throw new TxCoordinationError(
      'LEDGER_WRITE_FAILED',
      beforeBroadcast
        ? 'Could not record the signed transaction. It was not broadcast.'
        : 'The transaction was submitted but the operation ledger could not be updated. Retry this request. It will not be replaced.',
      {
        retryable: true,
        httpStatus: 503,
        operationId: id,
        txHash: patch.primary_tx_hash || patch.fee_tx_hash || null,
        state: patch.state || null,
      },
    );
  }
  return updated;
}
