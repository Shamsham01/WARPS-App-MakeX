import { Address, Transaction, TransactionComputer } from '@multiversx/sdk-core';
import { fetchTransactionStatus } from './polling.mjs';

export function toAddress(value) {
  const text = typeof value === 'string' ? value : value.toString();
  if (typeof Address.newFromBech32 === 'function') {
    try {
      return Address.newFromBech32(text);
    } catch {
      // SDK 13 accepts a bech32 string in the constructor.
    }
  }
  return new Address(text);
}

export function createMultiversxChain({
  provider,
  fetchImpl,
  apiBase = process.env.MAKEX_API_BASE || 'https://api.multiversx.com',
}) {
  return {
    async getAccountNonce(address) {
      const account = await provider.getAccount(toAddress(address));
      const nonce = Number(account.nonce);
      if (!Number.isInteger(nonce) || nonce < 0) {
        throw new Error('Gateway returned an invalid account nonce');
      }
      return nonce;
    },
    async send(tx) {
      const hash = await provider.sendTransaction(tx);
      if (hash == null || hash === '') {
        throw new Error('Gateway returned an empty transaction hash');
      }
      return hash.toString();
    },
    getStatus(txHash) {
      return fetchTransactionStatus(txHash, fetchImpl, apiBase);
    },
  };
}

export function identifyTransaction(tx) {
  const computer = new TransactionComputer();
  const rawHash = computer.computeTransactionHash(tx);
  const txHash = typeof rawHash === 'string' ? rawHash : Buffer.from(rawHash).toString('hex');
  const plain = tx.toPlainObject();
  return {
    txHash,
    plain: {
      ...plain,
      sender: String(plain.sender),
      receiver: String(plain.receiver),
    },
  };
}

export function rebuildTransaction(plain) {
  if (typeof Transaction.newFromPlainObject === 'function') {
    return Transaction.newFromPlainObject(plain);
  }
  return Transaction.fromPlainObject(plain);
}
