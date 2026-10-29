import assert from 'node:assert/strict';
import test from 'node:test';
import { Address, Mnemonic, Transaction, TransactionComputer, UserSecretKey, UserSigner } from '@multiversx/sdk-core';
import { identifyTransaction, rebuildTransaction, signedPlainMatchesRecord } from '../tx/chain.mjs';
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

function esdtPayload(tokenIdentifier, amountWei) {
  const tokenIdentifierHex = Buffer.from(tokenIdentifier, 'utf8').toString('hex');
  let amountHex = BigInt(amountWei).toString(16);
  if (amountHex.length % 2 !== 0) amountHex = `0${amountHex}`;
  return `ESDTTransfer@${tokenIdentifierHex}@${amountHex}`;
}

test('string fee payloads hash differently from the gateway-sendable bytes for REWARD and USDC', async () => {
  const secret = typeof UserSecretKey.generate === 'function'
    ? UserSecretKey.generate()
    : Mnemonic.generate().deriveKey(0);
  const signer = new UserSigner(secret);
  const sender = asAddress(signer.getAddress());
  const computer = new TransactionComputer();
  const cases = [
    ['REWARD', esdtPayload('REWARD-cf6eac', 40947869622n)],
    ['USDC', esdtPayload('USDC-c76f1f', 30000n)],
  ];

  for (const [token, payload] of cases) {
    const stringTx = new Transaction({
      sender,
      receiver: asAddress(RECEIVER),
      nonce: 13n,
      value: 0n,
      gasLimit: 500000n,
      chainID: '1',
      data: payload,
    });
    const bytesTx = new Transaction({
      sender,
      receiver: asAddress(RECEIVER),
      nonce: 13n,
      value: 0n,
      gasLimit: 500000n,
      chainID: '1',
      data: Buffer.from(payload, 'utf8'),
    });
    stringTx.signature = await signer.sign(computer.computeBytesForSigning(stringTx));
    bytesTx.signature = await signer.sign(computer.computeBytesForSigning(bytesTx));

    const stringLocal = identifyTransaction(stringTx).txHash;
    const stringSendable = identifyTransaction(rebuildTransaction(stringTx.toPlainObject())).txHash;
    const bytesLocal = identifyTransaction(bytesTx).txHash;
    const bytesSendable = identifyTransaction(rebuildTransaction(bytesTx.toPlainObject())).txHash;

    assert.equal(typeof stringTx.data, 'string', `${token} string payload stays a string`);
    assert.ok(bytesTx.data instanceof Uint8Array, `${token} corrected payload is bytes`);
    assert.notEqual(stringLocal, stringSendable, `${token} string payload must not match the gateway hash`);
    assert.equal(bytesLocal, bytesSendable, `${token} UTF-8 bytes must match the gateway hash`);
    assert.equal(bytesLocal, stringSendable, `${token} byte hash is the hash the gateway would return`);
    assert.equal(stringTx.toPlainObject().data, bytesTx.toPlainObject().data);
    assert.ok(Buffer.from(stringTx.signature).equals(Buffer.from(bytesTx.signature)));
    assert.equal(signedPlainMatchesRecord(bytesTx.toPlainObject(), {
      sender: bytesTx.toPlainObject().sender,
      receiver: bytesTx.toPlainObject().receiver,
      nonce: bytesTx.toPlainObject().nonce,
      chainID: bytesTx.toPlainObject().chainID,
      data: bytesTx.toPlainObject().data,
      signature: bytesTx.toPlainObject().signature,
    }), true);
    assert.equal(signedPlainMatchesRecord(bytesTx.toPlainObject(), {
      ...bytesTx.toPlainObject(),
      nonce: 14,
    }), false);
  }
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
