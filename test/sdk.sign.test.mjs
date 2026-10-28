import assert from 'node:assert/strict';
import test from 'node:test';
import { Address, Mnemonic, Transaction, TransactionComputer, UserSecretKey, UserSigner } from '@multiversx/sdk-core';
import { identifyTransaction, rebuildTransaction } from '../tx/chain.mjs';
import { signCoordinatedTransaction } from '../tx/preparedSend.mjs';

const RECEIVER = 'erd1t2r97zcjg8uvf0e9nk4psj2kvg27mph9kq5xls6xtnyg2aemp8hszcmn8f';

function asAddress(value) {
  const text = typeof value === 'string' ? value : value.toString();
  if (typeof Address.newFromBech32 === 'function') {
    try {
      return Address.newFromBech32(text);
    } catch {
      // SDK 13 accepts the bech32 constructor.
    }
  }
  return new Address(text);
}

test('the installed MultiversX SDK can sign, hash, and rebuild the same transaction', async () => {
  const secret = typeof UserSecretKey.generate === 'function'
    ? UserSecretKey.generate()
    : Mnemonic.generate().deriveKey(0);
  const signer = new UserSigner(secret);
  const sender = asAddress(signer.getAddress());
  const tx = new Transaction({
    sender,
    receiver: asAddress(RECEIVER),
    nonce: 4n,
    value: 0n,
    gasLimit: 50000n,
    chainID: '1',
    data: Buffer.from('ESDTTransfer'),
  });
  const computer = new TransactionComputer();
  tx.signature = await signer.sign(computer.computeBytesForSigning(tx));
  assert.ok(tx.signature?.length > 0);

  const identified = identifyTransaction(tx);
  assert.match(identified.txHash, /^[0-9a-f]{64}$/);
  const rebuilt = rebuildTransaction(identified.plain);
  const again = identifyTransaction(rebuilt);
  assert.equal(again.txHash, identified.txHash);

  const changed = rebuildTransaction(identified.plain);
  changed.nonce = 5n;
  changed.signature = await signer.sign(computer.computeBytesForSigning(changed));
  assert.notEqual(identifyTransaction(changed).txHash, identified.txHash);

  const throughAdapter = rebuildTransaction(identified.plain);
  await signCoordinatedTransaction(signer, throughAdapter);
  assert.equal(identifyTransaction(throughAdapter).txHash, identified.txHash);
});

test('the installed wallet signer can sign a core transaction when that package is present', async () => {
  let wallet;
  try {
    wallet = await import('@multiversx/sdk-wallet');
  } catch {
    return;
  }
  const coreKey = Mnemonic.generate().deriveKey(0);
  const walletKey = wallet.UserSecretKey.fromString(coreKey.hex());
  const signer = new wallet.UserSigner(walletKey);
  const walletAddress = signer.getAddress();
  const sender = asAddress(typeof walletAddress.bech32 === 'function' ? walletAddress.bech32() : walletAddress.toString());
  const tx = new Transaction({
    sender,
    receiver: asAddress(RECEIVER),
    nonce: 4n,
    value: 0n,
    gasLimit: 50000n,
    chainID: '1',
    data: Buffer.from('ESDTTransfer'),
  });
  await signCoordinatedTransaction(signer, tx);
  assert.ok(tx.signature?.length > 0);
  const identified = identifyTransaction(tx);
  assert.match(identified.txHash, /^[0-9a-f]{64}$/);
  assert.equal(identifyTransaction(rebuildTransaction(identified.plain)).txHash, identified.txHash);
});
