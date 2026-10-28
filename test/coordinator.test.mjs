import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test from 'node:test';

const require = createRequire(import.meta.url);
import { identifyTransaction } from '../tx/chain.mjs';
import { createTxCoordinator, submitSequentialBatch } from '../tx/coordinator.mjs';
import { createMemoryStore } from '../tx/memoryStore.mjs';
import {
  createUsageFeeMiddleware,
  FALLBACK_PROFILES,
  resetUsageFeeStateForTests,
  resolvePaymentToken,
} from '../usageFeeEngine.mjs';

function createFakeChain(start = 10) {
  let accountNonce = start;
  const statuses = new Map();
  const chain = {
    sent: [],
    get accountNonce() {
      return accountNonce;
    },
    setAccountNonce(nonce) {
      accountNonce = nonce;
    },
    async getAccountNonce() {
      return accountNonce;
    },
    async send(tx) {
      if (chain.sendImpl) return chain.sendImpl(tx);
      return chain.accept(tx);
    },
    accept(tx) {
      const hash = tx?.toPlainObject ? identifyTransaction(tx).txHash : tx.txHash;
      const nonce = Number(tx.nonce);
      chain.sent.push({ hash, nonce, purpose: tx.purpose || null });
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
    appId: 'makex-transfers',
    instanceId: extra.instanceId || 'instance-a',
    log: extra.log || (() => {}),
    sleepFn: async () => {},
    identify(tx) {
      if (tx?.toPlainObject) return identifyTransaction(tx);
      return { txHash: tx.txHash, plain: { ...tx } };
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

function payment(purpose) {
  return {
    senderAddress: 'erd1samewallet',
    purpose,
    appId: 'makex-transfers',
    buildTx(nonce) {
      return { nonce, txHash: `${purpose}-${nonce}`, purpose };
    },
    signTx: async () => {},
  };
}

test('concurrent fee requests for one wallet receive different nonces', async () => {
  const store = createMemoryStore();
  const chain = createFakeChain(4);
  const first = makeCoordinator(chain, store, { instanceId: 'a' });
  const second = makeCoordinator(chain, store, { instanceId: 'b' });
  const results = await Promise.all([
    first.submitAndConfirm(payment('fee-a')),
    second.submitAndConfirm(payment('fee-b')),
  ]);
  const nonces = results.map((result) => result.nonce).sort((a, b) => a - b);
  assert.deepEqual(nonces, [4, 5]);
  assert.equal(new Set(chain.sent.map((tx) => tx.hash)).size, 2);
});

test('different wallets are not blocked by each other', async () => {
  const store = createMemoryStore();
  const chain = createFakeChain(1);
  let releaseSlow;
  const slowGate = new Promise((resolve) => {
    releaseSlow = resolve;
  });
  chain.sendImpl = async (tx) => {
    if (tx.purpose === 'slow') await slowGate;
    return chain.accept(tx);
  };
  const coordinator = makeCoordinator(chain, store);
  const slow = coordinator.submitAndConfirm({
    ...payment('slow'),
    senderAddress: 'erd1walletA',
  });
  await new Promise((resolve) => setTimeout(resolve, 20));
  const fast = await coordinator.submitAndConfirm({
    ...payment('fast'),
    senderAddress: 'erd1walletB',
  });
  assert.equal(fast.nonce, 1);
  releaseSlow();
  const slowResult = await slow;
  assert.equal(slowResult.nonce, 1);
  assert.equal(slowResult.status, 'success');
});

test('a timed-out broadcast that was accepted is not sent again', async () => {
  const store = createMemoryStore();
  const chain = createFakeChain(8);
  let calls = 0;
  chain.sendImpl = async (tx) => {
    calls += 1;
    const hash = chain.accept(tx);
    if (calls === 1) throw new Error('socket timeout of 10000ms exceeded');
    return hash;
  };
  const operationId = 'op-timeout';
  const coordinator = makeCoordinator(chain, store, { instanceId: 'first' });
  const outcome = await coordinator.submitAndConfirm({ ...payment('fee'), operationId });
  assert.equal(outcome.status, 'success');
  assert.equal(calls, 1);

  const restarted = makeCoordinator(chain, store, { instanceId: 'restarted' });
  const replay = await restarted.submitAndConfirm({ ...payment('fee'), operationId });
  assert.equal(replay.txHash, outcome.txHash);
  assert.equal(calls, 1);
});

test('restart keeps an unresolved transaction and does not allocate a new nonce', async () => {
  const store = createMemoryStore();
  const chain = createFakeChain(3);
  chain.statusImpl = async () => ({ status: 'pending' });
  chain.sendImpl = async (tx) => {
    const hash = tx.txHash;
    chain.sent.push({ hash, nonce: tx.nonce });
    return hash;
  };
  const operationId = 'op-pending';
  const first = makeCoordinator(chain, store, { instanceId: 'before-crash' });
  await assert.rejects(
    first.submitAndConfirm({ ...payment('fee'), operationId }),
    (error) => error.code === 'TX_PENDING' || error.code === 'TX_INCONCLUSIVE',
  );
  assert.equal(chain.sent.length, 1);

  chain.statusImpl = async (hash) => (hash === chain.sent[0].hash ? { status: 'success' } : { status: 'not_found' });
  const restarted = makeCoordinator(chain, store, { instanceId: 'after-restart' });
  const outcome = await restarted.submitAndConfirm({ ...payment('fee'), operationId });
  assert.equal(outcome.status, 'success');
  assert.equal(outcome.txHash, chain.sent[0].hash);
  assert.equal(chain.sent.length, 1);
});

test('explicit lower nonce is reconciled once and does not reuse the stale nonce', async () => {
  const store = createMemoryStore();
  const chain = createFakeChain(5);
  const nonces = [];
  chain.sendImpl = async (tx) => {
    nonces.push(tx.nonce);
    if (nonces.length === 1) {
      chain.setAccountNonce(tx.nonce + 1);
      throw new Error('transaction generation failed: invalid transaction lowerNonceInTx: true');
    }
    return chain.accept(tx);
  };
  const coordinator = makeCoordinator(chain, store);
  const outcome = await coordinator.submitAndConfirm(payment('fee'));
  assert.equal(outcome.status, 'success');
  assert.deepEqual(nonces, [5, 6]);
});

test('external wallet activity moves the next nonce forward', async () => {
  const store = createMemoryStore();
  const chain = createFakeChain(2);
  const coordinator = makeCoordinator(chain, store);
  await coordinator.submitAndConfirm(payment('first'));
  chain.setAccountNonce(9);
  const next = await coordinator.submitAndConfirm(payment('second'));
  assert.equal(next.nonce, 9);
});

test('a stale gateway nonce does not move the local nonce backward', async () => {
  const store = createMemoryStore();
  const chain = createFakeChain(10);
  const coordinator = makeCoordinator(chain, store);
  await coordinator.submitAndConfirm(payment('first'));
  chain.setAccountNonce(10);
  const next = await coordinator.submitAndConfirm(payment('second'));
  assert.equal(next.nonce, 11);
});

test('a failed batch item does not skip a nonce', async () => {
  const store = createMemoryStore();
  const chain = createFakeChain(1);
  const coordinator = makeCoordinator(chain, store);
  const attempted = [];
  chain.sendImpl = async (tx) => {
    attempted.push(tx.nonce);
    if (tx.purpose === 'item-b') {
      throw new Error('transaction generation failed: invalid transaction');
    }
    return chain.accept(tx);
  };
  const batch = await submitSequentialBatch(['a', 'b', 'c'], async (item) => {
    return coordinator.submitAndConfirm({
      ...payment(`item-${item}`),
      buildTx(nonce) {
        return { nonce, txHash: `item-${item}-${nonce}`, purpose: `item-${item}` };
      },
    });
  });
  assert.equal(batch.complete, false);
  assert.deepEqual(attempted, [1, 2]);
  const authority = await store.snapshotAuthority('1', 'erd1samewallet');
  assert.equal(authority.next_nonce, 2);
  assert.equal(authority.unresolved_reservation_id, null);
});

test('retired nonce helpers cannot sign a payment', () => {
  let nonce;
  try {
    nonce = require('../utils/nonce.js');
  } catch (error) {
    if (error && error.code === 'MODULE_NOT_FOUND') return;
    throw error;
  }
  assert.throws(() => nonce.runWithNonce('erd1', async () => {}), /retired/);
  assert.throws(() => nonce.syncNonceFromChain('erd1'), /retired/);
});

test('resolvePaymentToken keeps whitelist apps and premium USDC-only pricing', () => {
  assert.equal(resolvePaymentToken(FALLBACK_PROFILES['makex-transfers'], { fee_token: 'REWARD' }).feeToken, 'REWARD');
  assert.equal(resolvePaymentToken(FALLBACK_PROFILES['makex-transfers'], { fee_token: 'USDC' }).feeToken, 'USDC');
  assert.equal(resolvePaymentToken(FALLBACK_PROFILES['makex-twitter-x'], { fee_token: 'REWARD' }).feeToken, 'USDC');
  assert.equal(FALLBACK_PROFILES['makex-transfers'].usd_fee_usdc, 0.03);
  assert.equal(FALLBACK_PROFILES['makex-twitter-x'].usd_fee_usdc, 0.05);
});

const TEST_WALLET = 'erd1t2r97zcjg8uvf0e9nk4psj2kvg27mph9kq5xls6xtnyg2aemp8hszcmn8f';

function feeFetch() {
  return async (url) => {
    const value = String(url);
    if (value.includes('/accounts/')) {
      return { ok: true, json: async () => ({ balance: '100000000' }) };
    }
    if (value.includes('/tokens?')) {
      return { ok: true, json: async () => [{ price: 1 }] };
    }
    if (value.includes('/tokens/')) {
      return { ok: true, json: async () => ({ decimals: 6 }) };
    }
    return { ok: false, status: 404, statusText: 'missing', text: async () => '' };
  };
}

function supabaseFor({ whitelist = null, ledgerErrors = false, ledger = [] } = {}) {
  return {
    from(table) {
      const api = {
        select() {
          return api;
        },
        eq() {
          return api;
        },
        update() {
          return api;
        },
        insert(row) {
          ledger.push(row);
          return Promise.resolve(ledgerErrors ? { error: { message: 'insert failed' } } : { error: null });
        },
        maybeSingle: async () => {
          if (table.includes('whitelist')) return { data: whitelist, error: null };
          if (table.includes('prefs')) return { data: null, error: null };
          if (table.includes('profiles')) return { data: null, error: null };
          return { data: null, error: null };
        },
        single: async () => ({ data: whitelist, error: null }),
      };
      return api;
    },
  };
}

async function invokeFee(middleware, { body, headers = {} , onNext } = {}) {
  const req = {
    method: 'POST',
    path: '/execute/esdtTransfer',
    body,
    headers,
  };
  const res = {
    statusCode: 200,
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

function feeMiddleware(coordinator, extra = {}) {
  resetUsageFeeStateForTests();
  return createUsageFeeMiddleware({
    appId: 'makex-transfers',
    supabase: extra.supabase === undefined ? null : extra.supabase,
    coordinator,
    mvxFetch: feeFetch(),
    treasuryWallet: 'erd1t2r97zcjg8uvf0e9nk4psj2kvg27mph9kq5xls6xtnyg2aemp8hszcmn8f',
    getPemContent: () => 'test-pem',
    deriveAddress: () => TEST_WALLET,
    signFeeTransaction: async (tx) => {
      tx.signature = Buffer.alloc(64, 7);
    },
    log: extra.log || (() => {}),
    network: '1',
  });
}

test('usage fee and primary transfer use successive nonces', async () => {
  const store = createMemoryStore();
  const chain = createFakeChain(15);
  const coordinator = makeCoordinator(chain, store);
  const middleware = feeMiddleware(coordinator);
  const seen = [];
  const response = await invokeFee(middleware, {
    body: { idempotencyKey: 'op-1', recipient: 'erd1dest', amount: 1, tokenTicker: 'USDC-c76f1f' },
    onNext: async (req) => {
      const primary = await coordinator.submitAndConfirm({
        senderAddress: TEST_WALLET,
        purpose: 'primary',
        operationId: req.makexOperation.id,
        buildTx(nonce) {
          return { nonce, txHash: `primary-${nonce}`, purpose: 'primary' };
        },
        signTx: async () => {},
      });
      seen.push(primary.nonce);
      await resJson(req, primary.txHash);
    },
  });
  assert.equal(response.nextCalled, true);
  assert.deepEqual(chain.sent.map((tx) => tx.nonce), [15, 16]);
  assert.deepEqual(seen, [16]);
});

async function resJson(req, txHash) {
  await req.makexCoordinator.store.updateOperation({
    id: req.makexOperation.id,
    patch: { state: 'OPERATION_CONFIRMED', primary_tx_hash: txHash, result_json: { status: 'success', result: { txHash } } },
  });
}

test('duplicate idempotency key does not charge twice', async () => {
  const store = createMemoryStore();
  const chain = createFakeChain(1);
  const coordinator = makeCoordinator(chain, store);
  const middleware = feeMiddleware(coordinator);
  const body = { idempotencyKey: 'same-key', recipient: 'erd1dest', amount: 2, tokenTicker: 'USDC-c76f1f' };
  const first = await invokeFee(middleware, {
    body,
    onNext: async (req) => {
      await resJson(req, 'primary-hash');
    },
  });
  assert.equal(first.nextCalled, true);
  const second = await invokeFee(middleware, { body });
  assert.equal(second.nextCalled, false);
  assert.equal(second.res.body.result.txHash, 'primary-hash');
  assert.equal(chain.sent.length, 1);
});

test('same idempotency key with different parameters is rejected', async () => {
  const store = createMemoryStore();
  const chain = createFakeChain(1);
  const coordinator = makeCoordinator(chain, store);
  const middleware = feeMiddleware(coordinator);
  await invokeFee(middleware, {
    body: { idempotencyKey: 'same-key', recipient: 'erd1dest', amount: 2, tokenTicker: 'USDC-c76f1f' },
    onNext: async (req) => {
      await resJson(req, 'primary-hash');
    },
  });
  const conflict = await invokeFee(middleware, {
    body: { idempotencyKey: 'same-key', recipient: 'erd1other', amount: 9, tokenTicker: 'USDC-c76f1f' },
  });
  assert.equal(conflict.res.statusCode, 409);
  assert.equal(conflict.nextCalled, false);
  assert.equal(chain.sent.length, 1);
});

test('unknown fee status does not start the primary operation', async () => {
  const store = createMemoryStore();
  const chain = createFakeChain(4);
  chain.statusImpl = async () => ({ status: 'pending' });
  const coordinator = makeCoordinator(chain, store);
  const middleware = feeMiddleware(coordinator);
  const response = await invokeFee(middleware, {
    body: { idempotencyKey: 'pending-fee', recipient: 'erd1dest', amount: 1, tokenTicker: 'USDC-c76f1f' },
  });
  assert.equal(response.nextCalled, false);
  assert.equal(response.res.statusCode, 503);
  assert.equal(response.res.body.data.retryable, true);
  assert.equal(chain.sent.length, 1);
});

test('a confirmed fee is reused when the primary transfer failed', async () => {
  const store = createMemoryStore();
  const chain = createFakeChain(6);
  const coordinator = makeCoordinator(chain, store);
  const middleware = feeMiddleware(coordinator);
  const body = { idempotencyKey: 'resume-fee', recipient: 'erd1dest', amount: 1, tokenTicker: 'USDC-c76f1f' };
  const first = await invokeFee(middleware, {
    body,
    onNext: async (req) => {
      await coordinator.store.updateOperation({
        id: req.makexOperation.id,
        patch: { state: 'OPERATION_FAILED', error_class: 'primary_failed' },
      });
    },
  });
  assert.equal(first.nextCalled, true);
  const second = await invokeFee(middleware, { body });
  assert.equal(second.nextCalled, true);
  assert.equal(chain.sent.length, 1);
  assert.equal(second.req.usageFeeHash, first.req.usageFeeHash);
});

test('whitelisted wallets are not charged', async () => {
  const store = createMemoryStore();
  const chain = createFakeChain(1);
  const coordinator = makeCoordinator(chain, store);
  const middleware = feeMiddleware(coordinator, {
    supabase: supabaseFor({
      whitelist: {
        id: 'wl-1',
        wallet_address: TEST_WALLET,
        whitelist_end: new Date(Date.now() + 86_400_000).toISOString(),
        status: 'valid',
      },
    }),
  });
  const response = await invokeFee(middleware, {
    body: { idempotencyKey: 'wl', recipient: 'erd1dest', amount: 1, tokenTicker: 'USDC-c76f1f' },
  });
  assert.equal(response.nextCalled, true);
  assert.equal(chain.sent.length, 0);
  assert.equal(response.req.makexOperation.skipped_whitelist, true);
});

test('logs redact PEM material', async () => {
  const logs = [];
  const store = createMemoryStore();
  const chain = createFakeChain(1);
  const coordinator = makeCoordinator(chain, store, {
    log(_level, message, fields) {
      logs.push(JSON.stringify({ message, fields }));
    },
  });
  chain.sendImpl = async () => {
    throw new Error('broadcast failed -----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----');
  };
  await assert.rejects(coordinator.submitAndConfirm(payment('fee')));
  const rendered = logs.join('\n');
  assert.equal(rendered.includes('SECRET'), false);
  assert.equal(rendered.includes('BEGIN PRIVATE KEY'), false);
});

test('ledger insert errors are visible and do not hide a confirmed fee', async () => {
  const logs = [];
  const store = createMemoryStore();
  const chain = createFakeChain(2);
  const coordinator = makeCoordinator(chain, store);
  const ledger = [];
  const middleware = feeMiddleware(coordinator, {
    supabase: supabaseFor({ ledgerErrors: true, ledger }),
    log(level, message, fields) {
      logs.push({ level, message, fields });
    },
  });
  const response = await invokeFee(middleware, {
    body: { idempotencyKey: 'ledger', recipient: 'erd1dest', amount: 1, tokenTicker: 'USDC-c76f1f' },
  });
  assert.equal(response.nextCalled, true);
  assert.equal(logs.some((entry) => entry.message === 'Usage fee ledger insert failed'), true);
  assert.equal(chain.sent.length, 1);
});
