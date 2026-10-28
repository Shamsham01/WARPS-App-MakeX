import assert from 'node:assert/strict';
import test from 'node:test';
import { createTxCoordinator } from '../tx/coordinator.mjs';
import { createMemoryStore } from '../tx/memoryStore.mjs';
import { createUsageFeeMiddleware, resetUsageFeeStateForTests } from '../usageFeeEngine.mjs';
import { presentWarpResponse, warpResponseLogMessage } from '../warpResponse.mjs';

const WALLET = 'erd1t2r97zcjg8uvf0e9nk4psj2kvg27mph9kq5xls6xtnyg2aemp8hszcmn8f';

function middleware() {
  resetUsageFeeStateForTests();
  const chain = {
    sent: [],
    async getAccountNonce() { return 3; },
    async send(tx) { chain.sent.push(tx); return 'fee-hash'; },
    async getStatus() { return { status: 'success' }; },
  };
  const store = createMemoryStore();
  const coordinator = createTxCoordinator({
    store,
    chain,
    appId: 'makex-warps',
    instanceId: 'warp-response-test',
    log: () => {},
    sleepFn: async () => {},
    identify() { return { txHash: 'fee-hash', plain: { nonce: 3 } }; },
    rebuild(plain) { return plain; },
    config: {
      network: '1', leaseTtlMs: 30000, queueTimeoutMs: 3000, pollIntervalMs: 1,
      pollMaxMs: 20, pollMaxIntervalMs: 5, backoff: 1, maxRebroadcasts: 1,
    },
  });
  const handleUsageFee = createUsageFeeMiddleware({
    appId: 'makex-warps',
    supabase: null,
    coordinator,
    mvxFetch: async (url) => {
      const value = String(url);
      if (value.includes('/accounts/')) return { ok: true, json: async () => ({ balance: '100000000' }) };
      if (value.includes('/tokens?')) return { ok: true, json: async () => [{ price: 1 }] };
      if (value.includes('/tokens/')) return { ok: true, json: async () => ({ decimals: 6 }) };
      return { ok: false, status: 404, statusText: 'missing', json: async () => ({}) };
    },
    treasuryWallet: WALLET,
    getPemContent: () => 'test-pem',
    deriveAddress: () => WALLET,
    signFeeTransaction: async (tx) => { tx.signature = Buffer.alloc(64, 2); },
    log: () => {},
    network: '1',
  });
  return { store, chain, handleUsageFee };
}

async function execute(handleUsageFee, body, fields, clean) {
  const req = { method: 'POST', path: '/executeWarp', body, headers: {} };
  const res = {
    statusCode: 200,
    body: undefined,
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.body = payload; return this; },
  };
  await handleUsageFee(req, res, async () => {
    const filtered = presentWarpResponse(res, clean, fields);
    await res.json(filtered);
  });
  return { req, res };
}

test('fields that hide finalStatus still keep a failed warp incomplete', async () => {
  const { store, chain, handleUsageFee } = middleware();
  const failed = { finalStatus: 'fail', finalTxHash: 'warp-fail', message: 'Transaction failed', results: [] };
  const response = await execute(
    handleUsageFee,
    { idempotencyKey: 'warp-fields', warpId: 'warp-1' },
    ['finalTxHash'],
    failed,
  );
  assert.deepEqual(response.res.body, { finalTxHash: 'warp-fail' });
  assert.equal(warpResponseLogMessage(failed), 'Sending non-success response');
  assert.equal((await store.getOperation(response.req.makexOperation.id)).state, 'OPERATION_FAILED');
  assert.equal(chain.sent.length, 1);

  const partial = { finalStatus: 'partial', finalTxHash: 'warp-partial', results: [{ ok: false }] };
  const second = await execute(
    handleUsageFee,
    { idempotencyKey: 'warp-partial', warpId: 'warp-1' },
    ['finalTxHash'],
    partial,
  );
  assert.deepEqual(second.res.body, { finalTxHash: 'warp-partial' });
  assert.equal((await store.getOperation(second.req.makexOperation.id)).state, 'OPERATION_FAILED');
});

test('a pending warp response is not logged or stored as success', async () => {
  const { store, handleUsageFee } = middleware();
  const pending = { finalStatus: 'pending', finalTxHash: 'warp-pending', message: 'Still pending' };
  const response = await execute(
    handleUsageFee,
    { idempotencyKey: 'warp-pending', warpId: 'warp-1' },
    ['finalTxHash'],
    pending,
  );
  assert.equal(warpResponseLogMessage(pending), 'Sending non-success response');
  assert.equal((await store.getOperation(response.req.makexOperation.id)).state, 'OPERATION_PENDING');
  assert.equal(response.res.body.finalStatus, undefined);
});
