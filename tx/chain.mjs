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

const TX_HASH = /^[0-9a-f]{64}$/i;

export function isTxHash(value) {
  return TX_HASH.test(String(value || ''));
}

export function hashDiagnostic({ localHash, gatewayHash, canonicalHash }) {
  return [
    `local_hash=${localHash || ''}`,
    `gateway_hash=${gatewayHash || ''}`,
    `canonical_hash=${canonicalHash || ''}`,
  ].join(';');
}

export function readHashDiagnostic(detail) {
  const fields = {};
  for (const part of String(detail || '').split(';')) {
    const index = part.indexOf('=');
    if (index <= 0) continue;
    fields[part.slice(0, index)] = part.slice(index + 1);
  }
  return fields;
}

function sameText(left, right) {
  return String(left ?? '').toLowerCase() === String(right ?? '').toLowerCase();
}

/**
 * The plain object is the gateway-sendable transaction.
 * Sender, receiver, nonce, base64 data, and signature must match.
 * The public API often omits chainID; compare it only when the record includes one.
 */
export function signedPlainMatchesRecord(plain, record) {
  if (!plain || !record) return false;
  const chainID = record.chainID ?? record.chainId;
  const chainOk = chainID == null || String(chainID) === '' || sameText(plain.chainID, chainID);
  return sameText(plain.sender, record.sender)
    && sameText(plain.receiver, record.receiver)
    && Number(plain.nonce) === Number(record.nonce)
    && chainOk
    && sameText(plain.data || '', record.data || '')
    && sameText(plain.signature || '', record.signature || '');
}
