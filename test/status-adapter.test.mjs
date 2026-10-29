import assert from 'node:assert/strict';
import test from 'node:test';
import {
  Address,
  Mnemonic,
  Transaction,
  TransactionComputer,
  UserSecretKey,
  UserSigner,
} from '@multiversx/sdk-core';
import { createMultiversxChain, identifyTransaction, rebuildTransaction, signedPlainMatchesRecord } from '../tx/chain.mjs';
import { createTxCoordinator } from '../tx/coordinator.mjs';
import { createMemoryStore } from '../tx/memoryStore.mjs';
import { apiTransactionRecord, fetchTransactionStatus } from '../tx/polling.mjs';

const TREASURY = 'erd1t2r97zcjg8uvf0e9nk4psj2kvg27mph9kq5xls6xtnyg2aemp8hszcmn8f';
const FOREIGN = 'erd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gq4hu';

function asAddress(value) {
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

function signerPair() {
  const secret = typeof UserSecretKey.generate === 'function'
    ? UserSecretKey.generate()
    : Mnemonic.generate().deriveKey(0);
  const signer = new UserSigner(secret);
  const address = signer.getAddress();
  const bech32 = typeof address.bech32 === 'function' ? address.bech32() : address.toString();
  return { signer, sender: asAddress(bech32), bech32 };
}

function esdtPayload(tokenIdentifier, amountWei) {
  const tokenIdentifierHex = Buffer.from(tokenIdentifier, 'utf8').toString('hex');
  let amountHex = BigInt(amountWei).toString(16);
  if (amountHex.length % 2 !== 0) amountHex = `0${amountHex}`;
  return `ESDTTransfer@${tokenIdentifierHex}@${amountHex}`;
}

async function signedFee(data) {
  const { signer, sender, bech32 } = signerPair();
  const tx = new Transaction({
    sender,
    receiver: asAddress(TREASURY),
    nonce: 13n,
    value: 0n,
    gasLimit: 500000n,
    chainID: '1',
    data,
  });
  const computer = new TransactionComputer();
  tx.signature = await signer.sign(computer.computeBytesForSigning(tx));
  return { tx, signer, bech32 };
}

function publicApiBody(tx, hash, overrides = {}) {
  const plain = identifyTransaction(tx).plain;
  return {
    txHash: hash,
    gasLimit: plain.gasLimit,
    gasPrice: plain.gasPrice,
    gasUsed: plain.gasLimit,
    nonce: plain.nonce,
    round: 20718421,
    value: String(plain.value ?? '0'),
    receiver: overrides.receiver ?? plain.receiver,
    sender: overrides.sender ?? plain.sender,
    receiverShard: 1,
    senderShard: 1,
    signature: overrides.signature ?? plain.signature,
    status: overrides.status ?? 'success',
    fee: '55550000000000',
    timestamp: 1761710451,
    data: overrides.data ?? plain.data,
    function: 'ESDTTransfer',
    type: 'Transaction',
    results: [],
    operations: [],
    ...('chainID' in overrides ? { chainID: overrides.chainID } : {}),
  };
}

function jsonResponse(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

test('the public transaction resource omits chainID and still matches the signed fee', async () => {
  const payload = esdtPayload('REWARD-cf6eac', 40947869622n);
  const { tx } = await signedFee(Buffer.from(payload, 'utf8'));
  const plain = identifyTransaction(tx).plain;
  const hash = identifyTransaction(rebuildTransaction(tx.toPlainObject())).txHash;
  const body = publicApiBody(tx, hash);
  assert.equal(Object.hasOwn(body, 'chainID'), false);
  assert.equal(body.status, 'success');
  assert.equal(body.sender, plain.sender);
  assert.equal(body.data, plain.data);

  const fetchImpl = async (url) => {
    assert.match(url, new RegExp(`/transactions/${hash}`));
    return jsonResponse(200, body);
  };
  const status = await fetchTransactionStatus(hash, fetchImpl, 'https://api.multiversx.com');
  assert.equal(status.status, 'success');
  assert.equal(status.transaction.chainID, undefined);
  assert.equal(signedPlainMatchesRecord(plain, status.transaction), true);
  assert.equal(apiTransactionRecord(body).signature, plain.signature);

  const withChain = await fetchTransactionStatus(hash, async () => jsonResponse(200, { ...body, chainID: '1' }), 'https://api.multiversx.com');
  assert.equal(signedPlainMatchesRecord(plain, withChain.transaction), true);

  const otherChain = await fetchTransactionStatus(hash, async () => jsonResponse(200, { ...body, chainID: 'D' }), 'https://api.multiversx.com');
  assert.equal(signedPlainMatchesRecord(plain, otherChain.transaction), false);

  const foreign = await fetchTransactionStatus(hash, async () => jsonResponse(200, publicApiBody(tx, hash, {
    sender: FOREIGN,
    data: Buffer.from('not-the-fee').toString('base64'),
    signature: 'ab'.repeat(64),
  })), 'https://api.multiversx.com');
  assert.equal(foreign.status, 'success');
  assert.equal(signedPlainMatchesRecord(plain, foreign.transaction), false);
});

function apiBackedChain(mutate) {
  let accountNonce = 13;
  let published = null;
  const sent = [];
  const provider = {
    async getAccount() {
      return { nonce: accountNonce };
    },
    async sendTransaction(tx) {
      const hash = identifyTransaction(rebuildTransaction(tx.toPlainObject())).txHash;
      const body = mutate(publicApiBody(tx, hash));
      published = { hash, body };
      sent.push({ hash, nonce: Number(tx.nonce) });
      accountNonce = Math.max(accountNonce, Number(tx.nonce) + 1);
      return hash;
    },
  };
  const fetchImpl = async (url) => {
    const hash = decodeURIComponent(String(url).split('/transactions/')[1].split('?')[0]);
    if (!published || hash !== published.hash) return jsonResponse(404, { message: 'transaction not found' });
    return jsonResponse(200, published.body);
  };
  const chain = createMultiversxChain({
    provider,
    fetchImpl,
    apiBase: 'https://api.multiversx.com',
  });
  chain.sent = sent;
  return chain;
}

function coordinatorFor(chain) {
  return createTxCoordinator({
    store: createMemoryStore(),
    chain,
    appId: 'makex-transfers',
    instanceId: 'status-adapter',
    log: () => {},
    sleepFn: async () => {},
    config: {
      network: '1',
      leaseTtlMs: 30000,
      queueTimeoutMs: 3000,
      pollIntervalMs: 1,
      pollMaxMs: 15,
      pollMaxIntervalMs: 5,
      backoff: 1,
      maxRebroadcasts: 1,
    },
  });
}

async function feeInput(data, operationId) {
  const { signer, bech32 } = signerPair();
  const computer = new TransactionComputer();
  return {
    senderAddress: bech32,
    purpose: 'fee',
    operationId,
    appId: 'makex-transfers',
    buildTx(nonce) {
      const tx = new Transaction({
        sender: asAddress(bech32),
        receiver: asAddress(TREASURY),
        value: 0n,
        data,
        gasLimit: 500000n,
        chainID: '1',
      });
      tx.nonce = BigInt(nonce);
      return tx;
    },
    signTx: async (tx) => {
      tx.signature = await signer.sign(computer.computeBytesForSigning(tx));
    },
  };
}

test('a string fee payload is confirmed from the public API record without chainID', async () => {
  const chain = apiBackedChain((body) => body);
  const coordinator = coordinatorFor(chain);
  const payload = esdtPayload('USDC-c76f1f', 30000n);
  const input = await feeInput(payload, 'op-api-match');
  const outcome = await coordinator.submitAndConfirm(input);
  assert.equal(outcome.status, 'success');
  assert.equal(outcome.txHash, chain.sent[0].hash);
  assert.equal(outcome.reconciliation.gatewayHash, chain.sent[0].hash);
  assert.notEqual(outcome.reconciliation.localHash, outcome.reconciliation.gatewayHash);
  assert.equal(chain.sent.length, 1);
  const again = await coordinator.submitAndConfirm(input);
  assert.equal(again.txHash, outcome.txHash);
  assert.equal(chain.sent.length, 1);
});

test('a foreign public API record does not confirm the fee through the real status adapter', async () => {
  const chain = apiBackedChain((body) => ({
    ...body,
    sender: FOREIGN,
    data: Buffer.from('not-the-fee').toString('base64'),
    signature: 'cd'.repeat(64),
  }));
  const store = createMemoryStore();
  const coordinator = createTxCoordinator({
    store,
    chain,
    appId: 'makex-transfers',
    instanceId: 'status-adapter-foreign',
    log: () => {},
    sleepFn: async () => {},
    config: {
      network: '1',
      leaseTtlMs: 30000,
      queueTimeoutMs: 3000,
      pollIntervalMs: 1,
      pollMaxMs: 15,
      pollMaxIntervalMs: 5,
      backoff: 1,
      maxRebroadcasts: 1,
    },
  });
  const payload = Buffer.from(esdtPayload('REWARD-cf6eac', 40947869622n), 'utf8');
  const input = await feeInput(payload, 'op-api-foreign');
  await assert.rejects(
    coordinator.submitAndConfirm(input),
    (error) => error.code === 'TX_NEEDS_RECONCILIATION',
  );
  await assert.rejects(
    coordinator.submitAndConfirm(input),
    (error) => error.code === 'TX_NEEDS_RECONCILIATION' || error.code === 'TX_PENDING',
  );
  assert.equal(chain.sent.length, 1);
  const rows = await store.listReservationsForOperation('op-api-foreign');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].state, 'NEEDS_RECONCILIATION');
  assert.equal(rows[0].error_class, 'record_mismatch');
  assert.notEqual(rows[0].state, 'CONFIRMED');
});
