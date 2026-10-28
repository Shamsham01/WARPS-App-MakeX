# Nonce coordination and usage-fee safety

This document is the root-cause analysis, architecture, rollout, and recovery guide for the 2026-10-28 `lowerNonceInTx` failure in `makex-transfers`.

## Root cause

The production error was raised inside usage-fee handling, before the customer transfer:

```text
Error processing usage fee
Failed to send transaction:
transaction generation failed: invalid transaction
lowerNonceInTx: true
```

`lowerNonceInTx` means the nonce in the signed transaction was already consumed on chain. Two defects produce that result, and a third makes retries financially unsafe.

1. **Usage fees bypassed nonce coordination.** `sendUsageFee()` in `usageFeeEngine.mjs` called `provider.getAccount()` and signed with `account.nonce`. EGLD, ESDT, NFT, SFT, Meta-ESDT, and mint calls went through `runWithNonce()`. Concurrent Make.com runs, or a fee overlapping another MakeX app using the same wallet, could both observe the same account nonce. The loser was rejected with `lowerNonceInTx`.

2. **The in-process cache was not a source of truth.** `utils/nonce.js` kept a per-process map and a per-process promise lock. After the 2026-10 nonce change, `syncNonceFromChain()` replaced the cached nonce whenever it differed from the gateway nonce, including when the cache was ahead because a broadcast had not been indexed yet. That reissued an already used nonce. The cache also disappeared on restart and was invisible to other Render services.

3. **A pending or unknown fee was treated as collected.** `pendingUsageFeeTransactions` was an in-memory map keyed only by wallet. `sendUsageFee()` returned the hash for `pending`, `timeout`, and `unknown`. The middleware then set `usageFeeHash` and called `onUsageFeeConfirmed()`, which resynced the nonce and let the primary transfer start. A lost API response could therefore be retried as a new payment, and a restart forgot the in-flight fee.

Legacy files `transfers.js` and `utils/transactions.js` are not mounted by `index.js`. They still built transactions from the old nonce helpers and `transfers.js` carried a different treasury default. That router now refuses requests so it cannot be wired back in accidentally. The live treasury address and fee amounts are unchanged.

## Architecture

One PostgreSQL authority, shared by every MakeX service that uses the same Supabase project, coordinates nonces per `(network, sender address)`.

- `makex_wallet_tx_authority` holds the lease, fencing token, and next nonce.
- `makex_tx_reservations` holds one signed-transaction record per attempt. At most one unresolved reservation may exist for a wallet.
- `makex_operations` is the idempotency ledger. A key is scoped by app, network, and wallet. The request fingerprint excludes PEM material and the idempotency key itself. Reusing a key with different payment parameters returns `409 IDEMPOTENCY_CONFLICT`.

Database calls are short. The lease is a timestamp plus fencing token, refreshed while polling. Gateway I/O never runs inside an open Postgres transaction. A process that loses the lease refreshes immediately before broadcast and does not send if the refresh fails. Rebroadcasts use the stored signed transaction, not a newly signed payment.

Confirmed or included-failed transactions consume the nonce. A pre-broadcast rejection can rewind the nonce only when the chain has not moved past it. External transactions move `next_nonce` forward. A gateway nonce older than `next_nonce` does not move it backward.

### Fee policy

- A confirmed fee is never charged again for the same operation.
- A fee that is pending, unknown, or needs reconciliation blocks the primary transfer.
- An included fee transaction that fails did not transfer tokens. A later retry of the same operation may submit a new fee. That is a first successful charge, not a second one.
- A confirmed fee is kept when the primary transfer fails. The primary transfer may be retried without another fee.
- Whitelist exemptions, USDC/REWARD preferences, premium USDC-only pricing, and the treasury address are unchanged.
- The legacy `makex_usage_fee_ledger` insert is still attempted after confirmation. A ledger error is logged and does not hide the confirmed fee. The operation row is the source of truth, and its write is checked.

### Idempotency migration for Make.com

Requests may send `idempotencyKey` in the JSON body, `x-makex-idempotency-key`, or the three headers `x-makex-scenario-id`, `x-makex-execution-id`, and `x-makex-module-id`. The key must stay the same when Make.com retries that module and must change when the user intentionally repeats an identical payment.

Make custom-app base headers should send:

```json
"x-makex-idempotency-key": "{{ifempty(parameters.idempotencyKey; '')}}"
```

Add an optional module parameter named `idempotencyKey`. Leave it empty to dedupe an identical retry. Map a new value to repeat an identical payment on purpose. Make.com custom-app IML cannot read the scenario execution id, so the app cannot invent that id by itself.

If no key is sent, the API uses `request:` plus the canonical request fingerprint. A retry of the same request does not charge again. Two different explicit keys still create two payments, even when the amount and recipient match. A random `ephemeral:` key is no longer used.

An HTTP 200 body is stored as `OPERATION_CONFIRMED` only when it is a business success. Bodies with `status` of `error`, `fail`, `failed`, `partial`, or `inconclusive` are stored as `OPERATION_FAILED`. The confirmed fee is kept and a retry does not charge it again. A failed ledger write on a successful result returns HTTP 503 instead of hanging the request.

### Make.com errors

Retryable failures use HTTP 503 or 504 and `data.retryable: true`. Examples: `NONCE_BUSY`, `TX_PENDING`, `TX_INCONCLUSIVE`, `TX_NEEDS_RECONCILIATION`, `LEDGER_WRITE_FAILED`. Permanent conflicts use 409 or 422. Insufficient USDC/REWARD responses are unchanged. Transfer errors still include a string `error` field so existing Make mappings keep reading it.

## Deployment

The migration `20261028220000_makex_tx_coordinator.sql` is already applied on production project `yalewhpzptgtfzwpzhjm`. Do not run it again. A later schema change must be a new migration file.

1. Confirm Render `SUPABASE_URL` contains `yalewhpzptgtfzwpzhjm`.
2. Confirm `select public.makex_tx_health();` returns `{"ok": true, "version": 1, "store": "supabase"}` when called with the service role.
3. Deploy one MakeX service after review. Do not deploy all six at once.
4. Watch for `[TX_COORDINATOR] schema ready` in the Render log. Payments fail closed with `COORDINATOR_SCHEMA_MISSING` if the migration is absent. They do not fall back to the in-memory nonce cache.

`MAKEX_CHAIN_ID` must stay `1` in production. It is the authority partition and the fee transaction chain id. Do not point it at devnet while the wallet still signs mainnet transactions.

Polling defaults: 2s interval, 1.5x backoff, 8s cap, 90s maximum. Override with `MAKEX_TX_POLL_*`. One identical rebroadcast is allowed after an ambiguous submission (`MAKEX_TX_MAX_RECOVERY_ATTEMPTS`).

## Recovery

`POST /admin/tx/reconcile` with the existing bearer token and `{ "walletAddress": "erd1..." }` re-reads the unresolved reservation. It can mark a transaction confirmed, failed, or rejected, and it may rebroadcast the stored signed transaction. It does not create a new payment.

Find operations that need a human:

```sql
select id, app_id, wallet_address, state, fee_tx_hash, primary_tx_hash, error_class, updated_at
from public.makex_operations
where state in ('INCONCLUSIVE', 'NEEDS_RECONCILIATION', 'FEE_SUBMITTED', 'OPERATION_SUBMITTED')
order by updated_at;
```

Find unresolved nonces:

```sql
select sender_address, nonce, purpose, state, tx_hash, error_class, updated_at
from public.makex_tx_reservations
where state in ('RESERVED', 'SIGNED', 'SUBMITTED', 'PENDING', 'UNKNOWN', 'NEEDS_RECONCILIATION')
order by updated_at;
```

Historical duplicate ledger rows, from before this change, are audit-only. Do not delete them. Compare `tx_hash` on chain before any refund. This release does not move funds to correct old duplicates.

```sql
select wallet_address, tx_hash, count(*)
from public.makex_usage_fee_ledger
where tx_hash is not null
group by 1, 2
having count(*) > 1;
```

## Rollback

1. Redeploy the previous `makex-transfers` image. Do not drop the new tables. Old code ignores them.
2. If a reservation is still unresolved, reconcile it with the admin route or the SQL above before sending manually from that wallet. Dropping the tables while a signed transaction is in flight removes the record needed to avoid a second payment.
3. Fee amounts, treasury address, and whitelist behavior are unchanged, so rolling back does not retariff customers.

## Tests

`npm test` runs `test/coordinator.test.mjs` against the in-memory store and a fake gateway. No mainnet transaction is signed or broadcast. Covered cases include concurrent fees, separate wallets, fee-then-primary order, idempotent retries, fingerprint conflicts, unknown fees, fee reuse after a failed primary, whitelist skip, lower-nonce recovery, stale gateway nonces, external nonce jumps, crash recovery, ambiguous broadcast, batch rejection without a nonce gap, PEM redaction, and a failed legacy ledger insert.

Devnet submission was not run. Do that only with an explicit approval and a devnet PEM.

## Security review

- Tables enable row level security and have no policies. `anon` and `authenticated` have no grants. Execute rights on the coordinator functions are revoked from those roles and granted to `service_role`.
- Functions are `SECURITY INVOKER` with `search_path = public`. They are not placed in an exposed security-definer surface.
- The signed transaction JSON is stored so an ambiguous broadcast can be retried identically. It does not contain a PEM or private key. Logs pass through `sanitizeObjectForLog` and PEM redaction.
- The admin reconcile route uses the same bearer token as the payment API. It does not accept a PEM.
- A lost broadcast is never treated as proof that the transaction was rejected.
- Only `success` from the MultiversX transaction record, with the existing smart-contract failure checks, becomes `CONFIRMED`.

## Rollout to the other MakeX apps

Do not deploy those services in the same change. They still have their own copy of the old `usageFeeEngine.mjs`, and several also read `getAccount().nonce` for the primary transaction.

| App | Repository | Current risk | Follow-up |
| --- | --- | --- | --- |
| ESDT Transfers | `JS-API-Make-MultiversX-ESDT-Transfers` | Fixed on this branch | Deploy after the migration |
| Snapshots | `NftOwnersSnapshotAndDraw` | Fee uses `getAccount` directly | Copy `tx/` and the updated engine after transfers is stable |
| Warps | `WARPS-App-MakeX` | Same fee bug, plus `wallet.sendTransaction` batches | Separate PR. Route primary sends through `submitAndConfirm` |
| ESDT Manager | `mvx-assets-manager-makex-api` | Same fee bug, and many routes call `getAccount` then `sendTransaction` | Separate PR. One route family at a time |
| Swap | `swap-ESDT-MakeX-API` | Same fee bug, and swap routes read `getAccount` | Separate PR |
| X | `makex-x` / TwitterX App | Same fee bug. Primary actions are X API calls, not chain transfers | Copy the updated fee engine after the migration is live |

The coordinator tables are global for a Supabase project. Once the migration is applied, another app can share the authority by using this `tx/` implementation and the same `MAKEX_CHAIN_ID`. Keep the copied files identical until they move into a versioned package. Update one production service, watch `makex_operations` and `lowerNonceInTx` logs, then continue.

Suggested package split, after the transfers deployment is quiet: publish `tx/` plus the fee engine as an internal package, and delete the per-app copies. Do not do that in this pull request.
