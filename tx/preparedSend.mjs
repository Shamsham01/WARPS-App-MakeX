import { createHash } from 'node:crypto';
import { TransactionComputer } from '@multiversx/sdk-core';

/**
 * Sign an already-built transaction with the next coordinated nonce.
 * The nonce baked into the transaction is replaced before signing.
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
  const receiver = tx.receiver?.toString?.() || '';
  const data = tx.data?.toString?.() || '';
  const value = tx.value?.toString?.() || '0';
  const fingerprint = createHash('sha256').update(`${sender}|${receiver}|${value}|${data}`).digest('hex').slice(0, 24);
  const purpose = `${purposePrefix}:${fingerprint}`;

  const outcome = await coordinator.submitAndConfirm({
    senderAddress: sender,
    purpose,
    operationId,
    payloadFingerprint: purpose,
    buildTx(nonce) {
      tx.nonce = BigInt(nonce);
      return tx;
    },
    signTx: async (prepared) => {
      const bytes = new TransactionComputer().computeBytesForSigning(prepared);
      prepared.signature = await signer.sign(bytes);
      return prepared;
    },
  });

  return outcome;
}
