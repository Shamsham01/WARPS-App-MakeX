import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test from 'node:test';

const require = createRequire(import.meta.url);

test('production install resolves the protobuf runtime required by MultiversX SDK 15', async () => {
  // Render installs with --legacy-peer-deps; peer-only SDK dependencies
  // must also be declared explicitly by this application.
  assert.doesNotThrow(() => require.resolve('protobufjs/minimal'));

  const { TransactionComputer } = await import('@multiversx/sdk-core');
  assert.equal(typeof TransactionComputer, 'function');
  assert.ok(new TransactionComputer());
});
