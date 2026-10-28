import assert from 'node:assert/strict';
import test from 'node:test';
import { Address, Mnemonic, Transaction, UserSecretKey, UserSigner } from '@multiversx/sdk-core';
import { identifyTransaction } from '../tx/chain.mjs';
import { createTxCoordinator } from '../tx/coordinator.mjs';
import { createMemoryStore } from '../tx/memoryStore.mjs';
import { sendPreparedTransaction, nextStablePurpose } from '../tx/preparedSend.mjs';
import { sendAppTransaction } from '../tx/appSend.mjs';
import { readIdempotencyKey } from '../tx/fingerprint.mjs';
import {
  classifyBusinessOutcome,
  createUsageFeeMiddleware,
  isConfirmedBusinessSuccess,
  resetUsageFeeStateForTests,
  FALLBACK_PROFILES,
  resolvePaymentToken,
} from '../usageFeeEngine.mjs';

const WALLET = 'erd1t2r97zcjg8uvf0e9nk4psj2kvg27mph9kq5xls6xtnyg2aemp8hszcmn8f';

function createFakeChain(start = 10) {
  let accountNonce = start;
  const statuses = new Map();
  const chain = {
    sent: [],
    async getAccountNonce() {
      return accountNonce;
    },
    async send(tx) {
      if (chain.sendImpl) return chain.sendImpl(tx);
      const hash = tx?.toPlainObject ? identifyTransaction(tx).txHash : tx.txHash;
      const nonce = Number(tx.nonce);
      chain.sent.push({ hash, nonce, purpose: tx.purpose || null, data: tx.data?.toString?.() || tx.data || null });
      statuses.set(hash, { status: 'success' });
      accountNonce = Math.max(accountNonce, nonce + 1);
      return hash;
    },
    async getStatus(hash) {
      if (chain.statusImpl) return chain.statusImpl(hash);
      return statuses.get(hash) || { status: 'not_found' };
    },
  };
  return chain;
}

function makeCoordinator(chain, store, extra = {}) {
  return createTxCoordinator({
    store,
    chain,
    appId: extra.appId || 'makex-transfers',
    instanceId: extra.instanceId || 'review-instance',
    log: () => {},
    sleepFn: async () => {},
    identify(tx) {
      if (tx?.toPlainObject) return identifyTransaction(tx);
      return { txHash: tx.txHash, plain: { ...tx, nonce: Number(tx.nonce) } };
    },
    rebuild(plain) {
      return plain;
    },
    config: {
      network: '1',
      leaseTtlMs: 30000,
      queueTimeoutMs: 3000,
      pollIntervalMs: 1,
      pollMaxMs: 30,
      pollMaxIntervalMs: 5,
      backoff: 1,
      maxRebroadcasts: 1,
    },
  });
}

function feeFetch() {
  return async (url) => {
    const value = String(url);
    if (value.includes('/accounts/')) return { ok: true, json: async () => ({ balance: '100000000' }) };
    if (value.includes('/tokens?')) return { ok: true, json: async () => [{ price: 1 }] };
    if (value.includes('/tokens/')) return { ok: true, json: async () => ({ decimals: 6 }) };
    return { ok: false, status: 404, statusText: 'missing', json: async () => ({}) };
  };
}

function feeMiddleware(coordinator, extra = {}) {
  resetUsageFeeStateForTests();
  return createUsageFeeMiddleware({
    appId: extra.appId || 'makex-transfers',
    supabase: extra.supabase === undefined ? null : extra.supabase,
    coordinator,
    mvxFetch: feeFetch(),
    treasuryWallet: WALLET,
    getPemContent: (req) => req.body?.walletPem || 'test-pem',
    deriveAddress: () => WALLET,
    signFeeTransaction: async (tx) => {
      tx.signature = Buffer.alloc(64, 3);
    },
    log: () => {},
    network: '1',
  });
}

async function invoke(middleware, { body = {}, headers = {}, onNext } = {}) {
  const req = { method: 'POST', path: '/execute/egldTransfer', body, headers, usageFeeAlreadyProcessed: false };
  const res = {
    statusCode: 200,
    body: undefined,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
  };
  let nextCalled = false;
  await middleware(req, res, async () => {
    nextCalled = true;
    if (onNext) await onNext(req, res);
  });
  return { req, res, nextCalled };
}

test('business success is not inferred from HTTP 200 alone', () => {
  assert.equal(isConfirmedBusinessSuccess(200, { status: 'success', result: { txHash: 'abc' } }), true);
  assert.equal(isConfirmedBusinessSuccess(200, { message: 'Rewards distribution completed.' }), true);
  assert.equal(isConfirmedBusinessSuccess(200, { status: 'error', error: 'Herotag registration failed' }), false);
  assert.equal(isConfirmedBusinessSuccess(200, { status: 'partial' }), false);
  assert.equal(isConfirmedBusinessSuccess(200, { status: 'pending' }), false);
  assert.equal(isConfirmedBusinessSuccess(200, { status: 'processing' }), false);
  assert.equal(isConfirmedBusinessSuccess(200, { finalStatus: 'fail', message: 'Transaction failed' }), false);
  assert.equal(isConfirmedBusinessSuccess(200, { finalStatus: 'pending' }), false);
  assert.equal(isConfirmedBusinessSuccess(200, { finalStatus: 'success', finalTxHash: 'abc' }), true);
  assert.equal(classifyBusinessOutcome(200, { status: 'pending' }), 'pending');
  assert.equal(classifyBusinessOutcome(200, { status: 'processing' }), 'pending');
  assert.equal(classifyBusinessOutcome(200, { finalStatus: 'pending' }), 'pending');
  assert.equal(classifyBusinessOutcome(422, { status: 'error', data: { transactionStatus: 'pending' } }), 'pending');
  assert.equal(classifyBusinessOutcome(200, { status: 'partial' }), 'failed');
  assert.equal(isConfirmedBusinessSuccess(200, { success: false }), false);
  assert.equal(isConfirmedBusinessSuccess(422, { status: 'error' }), false);
  assert.equal(isConfirmedBusinessSuccess(504, { status: 'error', retryable: true }), false);
});

test('an HTTP 200 business error is not stored as a successful operation', async () => {
  const store = createMemoryStore();
  const chain = createFakeChain(3);
  const coordinator = makeCoordinator(chain, store);
  const middleware = feeMiddleware(coordinator);
  const body = { idempotencyKey: 'biz-err', recipient: 'erd1dest', amount: 1 };
  const first = await invoke(middleware, {
    body,
    onNext: async (_req, res) => {
      await res.json({ status: 'error', error: 'Herotag registration failed' });
    },
  });
  assert.equal(first.nextCalled, true);
  assert.equal(first.res.body.status, 'error');
  assert.equal((await store.getOperation(first.req.makexOperation.id)).state, 'OPERATION_FAILED');
  const second = await invoke(middleware, {
    body,
    onNext: async (_req, res) => {
      await res.json({ status: 'success', result: { txHash: 'primary-fixed' } });
    },
  });
  assert.equal(second.nextCalled, true);
  assert.equal(chain.sent.length, 1);
  assert.equal((await store.getOperation(first.req.makexOperation.id)).state, 'OPERATION_CONFIRMED');
  assert.equal(second.res.body.result.txHash, 'primary-fixed');
});

test('a failed success ledger write returns 503 and does not hang or double charge', async () => {
  const store = createMemoryStore();
  const original = store.updateOperation.bind(store);
  store.updateOperation = async (args) => {
    if (args.patch?.state === 'OPERATION_CONFIRMED') return { ok: false, reason: 'db_down' };
    return original(args);
  };
  const chain = createFakeChain(8);
  const coordinator = makeCoordinator(chain, store);
  const middleware = feeMiddleware(coordinator);
  const body = { idempotencyKey: 'ledger-down', recipient: 'erd1dest', amount: 1 };
  const first = await invoke(middleware, {
    body,
    onNext: async (_req, res) => {
      await res.json({ status: 'success', result: { txHash: 'kept' } });
    },
  });
  assert.equal(first.res.statusCode, 503);
  assert.equal(first.res.body.code, 'LEDGER_WRITE_FAILED');
  assert.notEqual(first.req.makexOperation.state, 'OPERATION_CONFIRMED');
  const second = await invoke(middleware, { body });
  assert.equal(second.nextCalled, true);
  assert.equal(chain.sent.length, 1);
});

test('identical retries without a client key do not charge twice, and distinct keys do', async () => {
  const store = createMemoryStore();
  const chain = createFakeChain(1);
  const coordinator = makeCoordinator(chain, store);
  const middleware = feeMiddleware(coordinator);
  const body = { recipient: 'erd1dest', amount: 5, tokenTicker: 'USDC-c76f1f' };
  const firstKey = readIdempotencyKey({ method: 'POST', path: '/pay', body, headers: {} });
  const secondKey = readIdempotencyKey({ method: 'POST', path: '/pay', body, headers: {} });
  assert.equal(firstKey.source, 'request');
  assert.equal(firstKey.key, secondKey.key);
  assert.equal(firstKey.key.startsWith('ephemeral:'), false);

  const first = await invoke(middleware, {
    body,
    onNext: async (_req, res) => {
      await res.json({ status: 'success', result: { txHash: 'once' } });
    },
  });
  const retry = await invoke(middleware, { body });
  assert.equal(retry.nextCalled, false);
  assert.equal(retry.res.body.result.txHash, 'once');
  assert.equal(chain.sent.length, 1);

  const separate = await invoke(middleware, {
    body: { ...body, idempotencyKey: 'intentional-second' },
    onNext: async (_req, res) => {
      await res.json({ status: 'success', result: { txHash: 'second' } });
    },
  });
  assert.equal(separate.nextCalled, true);
  assert.equal(chain.sent.length, 2);

  const otherAmount = await invoke(middleware, {
    body: { recipient: 'erd1dest', amount: 9, tokenTicker: 'USDC-c76f1f' },
    onNext: async (_req, res) => {
      await res.json({ status: 'success', result: { txHash: 'different' } });
    },
  });
  assert.equal(otherAmount.nextCalled, true);
  assert.equal(chain.sent.length, 3);
});

test('Make scenario headers form one stable key', () => {
  const key = readIdempotencyKey({
    headers: {
      'x-makex-scenario-id': '42',
      'x-makex-execution-id': '99',
      'x-makex-module-id': '7',
    },
    body: { amount: 1 },
  });
  assert.equal(key.source, 'make');
  assert.equal(key.key, 'make:42:99:7');
});

test('a changed quote does not broadcast a second confirmed primary', async () => {
  const store = createMemoryStore();
  const chain = createFakeChain(20);
  const coordinator = makeCoordinator(chain, store);
  const begun = await store.beginOperation({
    idempotencyKey: 'swap-1',
    requestFingerprint: 'fp',
    appId: 'makex-swap',
    network: '1',
    walletAddress: WALLET,
  });
  const operation = begun.operation;
  const send = (data) => coordinator.submitAndConfirm({
    senderAddress: WALLET,
    purpose: 'xexchange-swap',
    operationId: operation.id,
    payloadFingerprint: 'xexchange-swap',
    buildTx(nonce) {
      return { nonce, txHash: `swap-${data}-${nonce}`, data, purpose: 'xexchange-swap' };
    },
    signTx: async () => {},
  });
  const first = await send('quote-a');
  const second = await send('quote-b');
  assert.equal(first.status, 'success');
  assert.equal(second.txHash, first.txHash);
  assert.equal(chain.sent.length, 1);
  assert.equal(chain.sent[0].data, 'quote-a');
});

test('a ledger failure before broadcast does not send the payment', async () => {
  const store = createMemoryStore();
  const original = store.updateOperation.bind(store);
  store.updateOperation = async (args) => {
    if (args.patch?.state === 'OPERATION_PREPARED') return { ok: false, reason: 'db_down' };
    return original(args);
  };
  const chain = createFakeChain(4);
  const coordinator = makeCoordinator(chain, store);
  const begun = await store.beginOperation({
    idempotencyKey: 'pre-broadcast',
    requestFingerprint: 'fp',
    appId: 'makex-transfers',
    network: '1',
    walletAddress: WALLET,
  });
  await assert.rejects(
    () => sendAppTransaction({
      coordinator,
      signer: { sign: async () => {} },
      senderAddress: WALLET,
      operation: begun.operation,
      purpose: 'primary',
      buildTx(nonce) {
        return { nonce, txHash: `pay-${nonce}`, purpose: 'primary' };
      },
    }),
    (error) => error.code === 'LEDGER_WRITE_FAILED',
  );
  assert.equal(chain.sent.length, 0);
  const reservation = [...(await store.listReservationsForOperation(begun.operation.id))];
  assert.equal(reservation[0].state, 'SIGNED');
});

test('a failed middle batch item stops later sends and a retry does not repeat confirmed items', async () => {
  const store = createMemoryStore();
  const chain = createFakeChain(1);
  const coordinator = makeCoordinator(chain, store);
  const begun = await store.beginOperation({
    idempotencyKey: 'batch',
    requestFingerprint: 'fp',
    appId: 'makex-warps',
    network: '1',
    walletAddress: WALLET,
  });
  const items = ['a', 'b', 'c'];
  const sent = [];
  async function run() {
    const req = {};
    for (const item of items) {
      const purpose = nextStablePurpose(req, `warp:${item}`);
      if (item === 'b') {
        chain.statusImpl = async () => ({ status: 'fail', details: 'middle failed' });
      } else {
        chain.statusImpl = null;
      }
      const outcome = await coordinator.submitAndConfirm({
        senderAddress: WALLET,
        purpose,
        operationId: begun.operation.id,
        buildTx(nonce) {
          return { nonce, txHash: `${item}-${nonce}`, purpose };
        },
        signTx: async () => {},
      });
      if (outcome.status !== 'success') {
        const error = new Error(outcome.details || 'failed');
        error.code = 'TRANSACTION_FAILED';
        throw error;
      }
      sent.push(item);
    }
  }
  await assert.rejects(run, (error) => error.code === 'TRANSACTION_FAILED');
  assert.deepEqual(sent, ['a']);
  assert.equal(chain.sent.length, 2);
  chain.statusImpl = null;
  const req = {};
  const replay = await coordinator.submitAndConfirm({
    senderAddress: WALLET,
    purpose: nextStablePurpose(req, 'warp:a'),
    operationId: begun.operation.id,
    buildTx() {
      throw new Error('confirmed warp item was built again');
    },
    signTx: async () => {},
  });
  assert.equal(replay.status, 'success');
  assert.equal(chain.sent.length, 2);
});

test('premium X billing stays USDC-only at 5 cents with the whitelist off', () => {
  const profile = FALLBACK_PROFILES['makex-twitter-x'];
  assert.equal(profile.usd_fee_usdc, 0.05);
  assert.equal(profile.whitelist_enabled, false);
  assert.deepEqual(profile.allowed_fee_tokens, ['USDC']);
  assert.equal(resolvePaymentToken(profile, { fee_token: 'REWARD' }).feeToken, 'USDC');
  assert.equal(FALLBACK_PROFILES['makex-transfers'].usd_fee_usdc, 0.03);
  assert.equal(FALLBACK_PROFILES['makex-transfers'].usd_fee_reward, 0.02);
});

test('sendPreparedTransaction rejects a confirmed chain failure instead of returning only a hash', async () => {
  const store = createMemoryStore();
  const chain = createFakeChain(2);
  chain.statusImpl = async () => ({ status: 'fail', details: 'not enough gas' });
  const coordinator = makeCoordinator(chain, store);
  const secret = typeof UserSecretKey.generate === 'function'
    ? UserSecretKey.generate()
    : Mnemonic.generate().deriveKey(0);
  const signer = new UserSigner(secret);
  const sender = typeof Address.newFromBech32 === 'function'
    ? Address.newFromBech32(signer.getAddress().toString())
    : signer.getAddress();
  const receiver = typeof Address.newFromBech32 === 'function'
    ? Address.newFromBech32(WALLET)
    : new Address(WALLET);
  const tx = new Transaction({
    sender,
    receiver,
    value: 0n,
    gasLimit: 50000n,
    chainID: '1',
    data: Buffer.from('swap'),
  });
  await assert.rejects(
    () => sendPreparedTransaction({
      coordinator,
      signer,
      senderAddress: signer.getAddress().toString(),
      tx,
      operationId: null,
      purposePrefix: 'xexchange-swap',
    }),
    (error) => error.code === 'TRANSACTION_FAILED' && Boolean(error.txHash) && error.httpStatus === 422,
  );
});

test('a pending response is not completed and a retry finishes it without a second fee', async () => {
  const store = createMemoryStore();
  const chain = createFakeChain(12);
  const coordinator = makeCoordinator(chain, store);
  const middleware = feeMiddleware(coordinator);
  const body = { idempotencyKey: 'still-pending', recipient: 'erd1dest', amount: 1 };
  let runs = 0;
  const first = await invoke(middleware, {
    body,
    onNext: async (_req, res) => {
      runs += 1;
      await res.json({ status: 'pending', message: 'Transaction still pending' });
    },
  });
  assert.equal(first.res.body.status, 'pending');
  assert.equal((await store.getOperation(first.req.makexOperation.id)).state, 'OPERATION_PENDING');
  assert.equal(first.res.body.replayed, undefined);
  const second = await invoke(middleware, {
    body,
    onNext: async (_req, res) => {
      runs += 1;
      await res.json({ status: 'processing' });
    },
  });
  assert.equal(runs, 2);
  assert.equal(chain.sent.length, 1);
  assert.equal((await store.getOperation(first.req.makexOperation.id)).state, 'OPERATION_PENDING');
  const third = await invoke(middleware, {
    body,
    onNext: async (_req, res) => {
      runs += 1;
      await res.json({ status: 'success', result: { txHash: 'finished' } });
    },
  });
  assert.equal(runs, 3);
  assert.equal(chain.sent.length, 1);
  assert.equal((await store.getOperation(first.req.makexOperation.id)).state, 'OPERATION_CONFIRMED');
  const replay = await invoke(middleware, {
    body,
    onNext: async () => {
      runs += 1;
    },
  });
  assert.equal(runs, 3);
  assert.equal(replay.nextCalled, false);
  assert.equal(replay.res.body.result.txHash, 'finished');
});

test('a filtered failure outcome is classified before fields are removed', async () => {
  const store = createMemoryStore();
  const chain = createFakeChain(14);
  const coordinator = makeCoordinator(chain, store);
  const middleware = feeMiddleware(coordinator);
  const response = await invoke(middleware, {
    body: { idempotencyKey: 'filtered-fail', recipient: 'erd1dest', amount: 1 },
    onNext: async (_req, res) => {
      const clean = { finalStatus: 'fail', finalTxHash: 'warp-fail', message: 'Transaction failed' };
      res.makexBusinessOutcome = clean;
      await res.json({ finalTxHash: clean.finalTxHash });
    },
  });
  assert.deepEqual(response.res.body, { finalTxHash: 'warp-fail' });
  assert.equal((await store.getOperation(response.req.makexOperation.id)).state, 'OPERATION_FAILED');
  const partial = await invoke(middleware, {
    body: { idempotencyKey: 'filtered-partial', recipient: 'erd1dest', amount: 2 },
    onNext: async (_req, res) => {
      res.makexBusinessOutcome = { finalStatus: 'partial', finalTxHash: 'warp-partial' };
      await res.json({ finalTxHash: 'warp-partial' });
    },
  });
  assert.equal((await store.getOperation(partial.req.makexOperation.id)).state, 'OPERATION_FAILED');
});

test('concurrent requests with one idempotency key run the business action once', async () => {
  const store = createMemoryStore();
  const chain = createFakeChain(16);
  const coordinator = makeCoordinator(chain, store);
  const middleware = feeMiddleware(coordinator);
  let started = 0;
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const body = { idempotencyKey: 'one-post', text: 'hello' };
  const first = invoke(middleware, {
    body,
    onNext: async (_req, res) => {
      started += 1;
      await gate;
      await res.json({ status: 'success', id: 'tweet-1' });
    },
  });
  while (started < 1) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  const second = await invoke(middleware, {
    body,
    onNext: async (_req, res) => {
      started += 1;
      await res.json({ status: 'success', id: 'tweet-2' });
    },
  });
  assert.equal(started, 1);
  assert.equal(second.res.statusCode, 503);
  assert.equal(second.res.body.code, 'OPERATION_IN_PROGRESS');
  assert.equal(second.nextCalled, false);
  assert.equal(chain.sent.length, 1);
  release();
  const finished = await first;
  assert.equal(finished.res.body.id, 'tweet-1');
  assert.equal(started, 1);
  assert.equal((await store.getOperation(finished.req.makexOperation.id)).state, 'OPERATION_CONFIRMED');
});

test('an expired business claim can be taken by the retry', async () => {
  const store = createMemoryStore();
  const begun = await store.beginOperation({
    idempotencyKey: 'expired-claim',
    requestFingerprint: 'fingerprint',
    appId: 'makex-transfers',
    network: '1',
    walletAddress: WALLET,
  });
  await store.updateOperation({
    id: begun.operation.id,
    patch: { state: 'FEE_CONFIRMED', fee_tx_hash: 'fee-hash' },
  });
  const first = await store.claimBusiness({ id: begun.operation.id, owner: 'owner-a', ttlMs: 60000 });
  const busy = await store.claimBusiness({ id: begun.operation.id, owner: 'owner-b', ttlMs: 60000 });
  assert.equal(first.claimed, true);
  assert.equal(busy.reason, 'in_progress');
  const later = Date.now() + 120000;
  const reclaimed = await store.claimBusiness({ id: begun.operation.id, owner: 'owner-b', ttlMs: 60000, now: later });
  assert.equal(reclaimed.claimed, true);
});
