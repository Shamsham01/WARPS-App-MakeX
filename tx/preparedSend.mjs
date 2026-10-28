import { TransactionComputer } from '@multiversx/sdk-core';
import { TxCoordinationError } from './errors.mjs';

function signatureBytes(value) {
  const length = value?.length ?? value?.byteLength ?? 0;
  return length > 0 ? value : null;
}

function walletSignerMismatch(error) {
  const message = String(error?.message || error).toLowerCase();
  return message.includes('serializeforsigning')
    || message.includes('cannot sign')
    || message.includes('is not a function');
}

/**
 * SDK 13+ core signers accept the raw signing bytes.
 * @multiversx/sdk-wallet signers only accept a transaction-like object, so the
 * same bytes are signed with their secret key.
 */
export async function signCoordinatedTransaction(signer, prepared) {
  const bytes = new TransactionComputer().computeBytesForSigning(prepared);
  try {
    const signature = signatureBytes(await signer.sign(bytes));
    if (signature) {
      prepared.signature = signature;
      return prepared;
    }
  } catch (error) {
    const canUseSecret = signer?.secretKey && typeof signer.secretKey.sign === 'function';
    if (!canUseSecret || !walletSignerMismatch(error)) throw error;
  }
  const signature = signatureBytes(signer.secretKey.sign(bytes));
  if (!signature) {
    throw new TxCoordinationError(
      'SIGNING_FAILED',
      'The signer did not produce a transaction signature.',
      { retryable: false, httpStatus: 500 },
    );
  }
  prepared.signature = signature;
  return prepared;
}

export function nextStablePurpose(req, purposePrefix = 'primary') {
  const base = String(purposePrefix || 'primary');
  if (!req) return base;
  if (!req.makexPurposeCounts) req.makexPurposeCounts = Object.create(null);
  const seen = req.makexPurposeCounts[base] || 0;
  req.makexPurposeCounts[base] = seen + 1;
  return seen === 0 ? base : `${base}#${seen}`;
}

/**
 * Sign an already-built transaction with the next coordinated nonce.
 * purposePrefix is the stable identity of this payment. It must not include
 * quote, slippage, or gas values that can change between retries.
 */
export async function sendPreparedTransaction({
  coordinator,
  signer,
  senderAddress,
  tx,
  operationId = null,
  purposePrefix = 'primary',
}) {
  const sender = typeof senderAddress === 'string' ? senderAddress : senderAddress.toString();
  const purpose = String(purposePrefix || 'primary');
  const outcome = await coordinator.submitAndConfirm({
    senderAddress: sender,
    purpose,
    operationId,
    payloadFingerprint: purpose,
    buildTx(nonce) {
      tx.nonce = BigInt(nonce);
      return tx;
    },
    signTx: (prepared) => signCoordinatedTransaction(signer, prepared),
  });

  if (outcome.status !== 'success') {
    throw new TxCoordinationError(
      outcome.status === 'fail' ? 'TRANSACTION_FAILED' : 'TX_INCONCLUSIVE',
      outcome.details || `Transaction ended ${outcome.status || 'unknown'}`,
      {
        retryable: outcome.status !== 'fail',
        httpStatus: outcome.status === 'fail' ? 422 : 503,
        txHash: outcome.txHash,
        nonce: outcome.nonce,
        state: outcome.state,
        operationId,
      },
    );
  }
  return outcome;
}
