/**
 * Shared MakeX usage-fee engine: USDC/REWARD billing, whitelist, app profiles, ledger.
 * Copy unchanged into each Render service folder (same pattern as makexStandard.mjs).
 */

import { randomUUID } from 'node:crypto';
import {
  Address,
  ProxyNetworkProvider,
  Transaction,
  TransactionComputer,
  UserSigner,
} from '@multiversx/sdk-core';
import BigNumber from 'bignumber.js';
import { createClient } from '@supabase/supabase-js';
import { hashDiagnostic } from './tx/chain.mjs';
import { createProductionCoordinator } from './tx/coordinator.mjs';
import { TxCoordinationError } from './tx/errors.mjs';
import { fingerprintRequest, readIdempotencyKey } from './tx/fingerprint.mjs';
import { requireOperationUpdate } from './tx/ledgerWrite.mjs';
import {
  buildInsufficientRewardResponse,
  buildInsufficientUsdcResponse,
  buildMakeComErrorResponse,
  DEFAULT_REWARD_TOKEN_ID,
  DEFAULT_USDC_TOKEN_ID,
  fetchAccountEsdtBalanceWei,
  insufficientTokenBalance,
  isLikelyInsufficientRewardFailure,
  redactPemFromString,
  sanitizeObjectForLog,
  usageFeeTopupMessage,
  USAGE_FEE_TOPUP_USER_MESSAGE,
} from './makexStandard.mjs';

const WHITELIST_TABLE = 'makex_usage_fee_whitelist';
const PREFS_TABLE = 'makex_wallet_billing_prefs';
const PROFILES_TABLE = 'makex_app_billing_profiles';
const LEDGER_TABLE = 'makex_usage_fee_ledger';

const DEFAULT_TREASURY_WALLET =
  process.env.MAKEX_TREASURY_WALLET ||
  'erd1t2r97zcjg8uvf0e9nk4psj2kvg27mph9kq5xls6xtnyg2aemp8hszcmn8f';

const PROFILE_CACHE_MS = 5 * 60 * 1000;

const FALLBACK_PROFILES = {
  'makex-warps': {
    app_id: 'makex-warps',
    tier: 'standard',
    usd_fee_usdc: 0.03,
    usd_fee_reward: 0.02,
    whitelist_enabled: true,
    allowed_fee_tokens: ['USDC', 'REWARD'],
  },
  'makex-transfers': {
    app_id: 'makex-transfers',
    tier: 'standard',
    usd_fee_usdc: 0.03,
    usd_fee_reward: 0.02,
    whitelist_enabled: true,
    allowed_fee_tokens: ['USDC', 'REWARD'],
  },
  'makex-swap': {
    app_id: 'makex-swap',
    tier: 'standard',
    usd_fee_usdc: 0.03,
    usd_fee_reward: 0.02,
    whitelist_enabled: true,
    allowed_fee_tokens: ['USDC', 'REWARD'],
  },
  'makex-assets': {
    app_id: 'makex-assets',
    tier: 'standard',
    usd_fee_usdc: 0.03,
    usd_fee_reward: 0.02,
    whitelist_enabled: true,
    allowed_fee_tokens: ['USDC', 'REWARD'],
  },
  'makex-nft-snapshot': {
    app_id: 'makex-nft-snapshot',
    tier: 'standard',
    usd_fee_usdc: 0.03,
    usd_fee_reward: 0.02,
    whitelist_enabled: true,
    allowed_fee_tokens: ['USDC', 'REWARD'],
  },
  'makex-twitter-x': {
    app_id: 'makex-twitter-x',
    tier: 'premium',
    usd_fee_usdc: 0.05,
    usd_fee_reward: null,
    whitelist_enabled: false,
    allowed_fee_tokens: ['USDC'],
  },
};

const TOKEN_ID_BY_SYMBOL = {
  USDC: DEFAULT_USDC_TOKEN_ID,
  REWARD: DEFAULT_REWARD_TOKEN_ID,
};

let profileCache = { appId: null, profile: null, fetchedAt: 0 };

const FEE_SETTLED_STATES = new Set([
  'FEE_CONFIRMED',
  'OPERATION_PREPARED',
  'OPERATION_SUBMITTED',
  'OPERATION_CONFIRMED',
  'OPERATION_FAILED',
  'OPERATION_PENDING',
]);

const FAILED_BUSINESS_MARKERS = new Set(['error', 'fail', 'failed', 'partial', 'inconclusive']);
const PENDING_BUSINESS_MARKERS = new Set(['pending', 'processing', 'in_progress', 'in-progress', 'submitted']);

export function resetUsageFeeStateForTests() {
  profileCache = { appId: null, profile: null, fetchedAt: 0 };
}

function getSupabase() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) return null;
  return createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

function defaultLog(level, message, data = {}) {
  console.log(
    JSON.stringify({
      timestamp: new Date().toISOString(),
      level,
      message,
      ...sanitizeObjectForLog(data),
    }),
  );
}

function defaultGetPemContent(req) {
  const pemContent = req.body?.walletPem;
  if (!pemContent || typeof pemContent !== 'string') {
    throw new Error('Missing or invalid PEM content');
  }
  if (!pemContent.includes('-----BEGIN')) {
    throw new Error('Invalid PEM format');
  }
  return pemContent;
}

function deriveWhitelistStatus(whitelistEnd) {
  const endDate = new Date(whitelistEnd);
  if (Number.isNaN(endDate.getTime())) return 'expired';
  return endDate.getTime() > Date.now() ? 'valid' : 'expired';
}

async function loadAppProfile(appId, supabase) {
  const now = Date.now();
  if (profileCache.appId === appId && now - profileCache.fetchedAt < PROFILE_CACHE_MS) {
    return profileCache.profile;
  }

  let profile = FALLBACK_PROFILES[appId];
  if (!profile) {
    throw new Error(`Unknown MAKEX_APP_ID: ${appId}`);
  }

  if (supabase) {
    const { data, error } = await supabase
      .from(PROFILES_TABLE)
      .select('app_id, tier, usd_fee_usdc, usd_fee_reward, whitelist_enabled, allowed_fee_tokens')
      .eq('app_id', appId)
      .eq('is_active', true)
      .maybeSingle();

    if (!error && data) {
      profile = {
        app_id: data.app_id,
        tier: data.tier,
        usd_fee_usdc: Number(data.usd_fee_usdc),
        usd_fee_reward: data.usd_fee_reward != null ? Number(data.usd_fee_reward) : null,
        whitelist_enabled: data.whitelist_enabled,
        allowed_fee_tokens: data.allowed_fee_tokens || ['USDC'],
      };
    }
  }

  profileCache = { appId, profile, fetchedAt: now };
  return profile;
}

async function getWhitelistEligibility(walletAddress, supabase) {
  if (!supabase) {
    return { skipUsageFee: false, reason: 'no_whitelist_db' };
  }

  const { data: entry, error } = await supabase
    .from(WHITELIST_TABLE)
    .select('id, wallet_address, whitelist_end, status')
    .eq('wallet_address', walletAddress)
    .maybeSingle();

  if (error) {
    throw new Error(`Failed to load whitelist entry: ${error.message}`);
  }
  if (!entry) {
    return { skipUsageFee: false, reason: 'not_whitelisted' };
  }

  const computedStatus = deriveWhitelistStatus(entry.whitelist_end);
  if (entry.status !== computedStatus) {
    const { data: updatedEntry, error: updateError } = await supabase
      .from(WHITELIST_TABLE)
      .update({ status: computedStatus, updated_at: new Date().toISOString() })
      .eq('id', entry.id)
      .select('id, wallet_address, whitelist_end, status')
      .single();

    if (updateError) {
      throw new Error(`Failed to update whitelist status: ${updateError.message}`);
    }

    return {
      skipUsageFee: updatedEntry.status === 'valid',
      reason: updatedEntry.status === 'valid' ? 'valid' : 'expired',
      entry: updatedEntry,
    };
  }

  return {
    skipUsageFee: entry.status === 'valid',
    reason: entry.status === 'valid' ? 'valid' : 'expired',
    entry,
  };
}

async function getWalletBillingPrefs(walletAddress, supabase) {
  if (!supabase) {
    return { fee_token: 'USDC', fee_token_identifier: DEFAULT_USDC_TOKEN_ID };
  }

  const { data, error } = await supabase
    .from(PREFS_TABLE)
    .select('fee_token, fee_token_identifier')
    .eq('wallet_address', walletAddress)
    .maybeSingle();

  if (error) {
    throw new Error(`Failed to load billing preferences: ${error.message}`);
  }

  if (!data) {
    return { fee_token: 'USDC', fee_token_identifier: DEFAULT_USDC_TOKEN_ID };
  }

  return {
    fee_token: data.fee_token,
    fee_token_identifier: data.fee_token_identifier,
  };
}

function resolvePaymentToken(profile, prefs) {
  const allowed = profile.allowed_fee_tokens || ['USDC'];
  if (profile.tier === 'premium' || !allowed.includes('REWARD')) {
    return { feeToken: 'USDC', tokenIdentifier: DEFAULT_USDC_TOKEN_ID, usdFee: profile.usd_fee_usdc };
  }

  const preferred = prefs.fee_token === 'REWARD' && allowed.includes('REWARD') ? 'REWARD' : 'USDC';
  if (preferred === 'REWARD') {
    return {
      feeToken: 'REWARD',
      tokenIdentifier: DEFAULT_REWARD_TOKEN_ID,
      usdFee: profile.usd_fee_reward ?? 0.02,
    };
  }

  return { feeToken: 'USDC', tokenIdentifier: DEFAULT_USDC_TOKEN_ID, usdFee: profile.usd_fee_usdc };
}

async function getTokenDecimals(tokenTicker, mvxFetch) {
  const response = await mvxFetch(`https://api.multiversx.com/tokens/${tokenTicker}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch token info: ${response.statusText}`);
  }
  const tokenInfo = await response.json();
  return tokenInfo.decimals || 0;
}

async function getTokenPrice(tokenIdentifier, mvxFetch) {
  const tokenResponse = await mvxFetch(`https://api.multiversx.com/tokens?search=${tokenIdentifier}`);
  if (!tokenResponse.ok) {
    throw new Error(`Failed to fetch token info: ${tokenResponse.statusText}`);
  }

  const tokenData = await tokenResponse.json();
  if (!tokenData?.length || !tokenData[0].price) {
    throw new Error('Token price not available');
  }

  const tokenPrice = new BigNumber(tokenData[0].price);
  if (tokenPrice.isZero() || !tokenPrice.isFinite()) {
    throw new Error('Invalid token price from API');
  }

  return tokenPrice.toNumber();
}

function convertAmountToBlockchainValue(amount, decimals) {
  const factor = new BigNumber(10).pow(decimals);
  return new BigNumber(amount).multipliedBy(factor).toFixed(0);
}

async function calculateDynamicUsageFee(usdFee, tokenIdentifier, mvxFetch) {
  const tokenPrice = await getTokenPrice(tokenIdentifier, mvxFetch);
  if (tokenPrice <= 0) throw new Error(`Invalid ${tokenIdentifier} token price`);

  const tokenAmount = new BigNumber(usdFee).dividedBy(tokenPrice);
  const decimals = await getTokenDecimals(tokenIdentifier, mvxFetch);
  if (!tokenAmount.isFinite() || tokenAmount.isZero()) {
    throw new Error('Invalid usage fee calculation');
  }

  return convertAmountToBlockchainValue(tokenAmount, decimals);
}

function buildEsdtTransferData(tokenIdentifier, amountWei) {
  const tokenIdentifierHex = Buffer.from(tokenIdentifier, 'utf8').toString('hex');
  let amountHex = BigInt(amountWei).toString(16);
  if (amountHex.length % 2 !== 0) amountHex = `0${amountHex}`;
  return `ESDTTransfer@${tokenIdentifierHex}@${amountHex}`;
}

async function insertLedgerEntry(supabase, entry, log = defaultLog) {
  if (!supabase) return { ok: true, skipped: true };
  const result = await supabase.from(LEDGER_TABLE).insert(entry);
  if (result?.error) {
    log('error', 'Usage fee ledger insert failed', {
      error: result.error.message,
      txHash: entry.tx_hash,
      appId: entry.app_id,
      walletAddress: entry.wallet_address,
    });
    return { ok: false, error: result.error };
  }
  return { ok: true };
}

function feeIsSettled(operation) {
  if (operation?.fee_tx_hash || operation?.skipped_whitelist) return true;
  return FEE_SETTLED_STATES.has(operation?.state);
}

function throwInsufficientFee({ tokenIdentifier, walletAddress, balanceWei, requiredWei }) {
  const err = new Error(usageFeeTopupMessage(tokenIdentifier));
  err.code =
    tokenIdentifier === DEFAULT_USDC_TOKEN_ID ? 'INSUFFICIENT_USDC_BALANCE' : 'INSUFFICIENT_REWARD_BALANCE';
  err.insufficientFeeBalance = true;
  err.tokenIdentifier = tokenIdentifier;
  err.walletAddress = walletAddress;
  err.balanceWei = balanceWei;
  err.requiredWei = requiredWei;
  return err;
}

async function sendUsageFee({
  pemContent,
  walletAddress,
  tokenIdentifier,
  usdFee,
  treasuryWallet,
  mvxFetch,
  coordinator,
  operation,
  appId,
  network,
  signFeeTransaction,
}) {
  const latest = operation?.id
    ? await coordinator.store.getLatestReservation({ operationId: operation.id, purpose: 'fee' })
    : null;
  if (latest?.state === 'CONFIRMED' && latest.tx_hash) {
    return {
      txHash: latest.tx_hash,
      amountWei: operation.fee_amount_wei,
      reservationId: latest.id,
      replayed: true,
    };
  }

  const dynamicFeeAmount = operation?.fee_amount_wei && latest && latest.state !== 'REJECTED' && latest.state !== 'FAILED'
    ? operation.fee_amount_wei
    : await calculateDynamicUsageFee(usdFee, tokenIdentifier, mvxFetch);

  const balanceWei = await fetchAccountEsdtBalanceWei(walletAddress, tokenIdentifier, mvxFetch);
  if (!latest || latest.state === 'REJECTED' || latest.state === 'FAILED') {
    if (insufficientTokenBalance(balanceWei, dynamicFeeAmount)) {
      throw throwInsufficientFee({
        tokenIdentifier,
        walletAddress,
        balanceWei,
        requiredWei: dynamicFeeAmount,
      });
    }
  }

  const senderAddress = new Address(walletAddress);
  const receiverAddress = new Address(treasuryWallet);
  const outcome = await coordinator.submitAndConfirm({
    senderAddress: walletAddress,
    purpose: 'fee',
    operationId: operation?.id || null,
    appId,
    payloadFingerprint: operation?.request_fingerprint || null,
    buildTx(nonce) {
      const tx = new Transaction({
        sender: senderAddress,
        receiver: receiverAddress,
        value: BigInt(0),
        data: Buffer.from(buildEsdtTransferData(tokenIdentifier, dynamicFeeAmount), 'utf8'),
        gasLimit: BigInt(500000),
        chainID: network,
      });
      tx.nonce = BigInt(nonce);
      return tx;
    },
    signTx: async (tx) => {
      if (signFeeTransaction) {
        await signFeeTransaction(tx, pemContent);
        return tx;
      }
      const signer = UserSigner.fromPem(pemContent);
      tx.signature = await signer.sign(new TransactionComputer().computeBytesForSigning(tx));
      return tx;
    },
    onSigned: async (reservation) => {
      if (!operation?.id) return;
      await requireOperationUpdate(coordinator.store, {
        id: operation.id,
        phase: 'before_broadcast',
        patch: {
          state: 'FEE_PREPARED',
          fee_reservation_id: reservation.id,
          fee_tx_hash: reservation.tx_hash,
          fee_amount_wei: String(dynamicFeeAmount),
          fee_token_identifier: tokenIdentifier,
        },
      });
    },
    onSubmitted: async (reservation) => {
      if (!operation?.id) return;
      await requireOperationUpdate(coordinator.store, {
        id: operation.id,
        phase: 'after_broadcast',
        patch: {
          state: 'FEE_SUBMITTED',
          fee_reservation_id: reservation.id,
          fee_tx_hash: reservation.tx_hash,
        },
      });
    },
  });

  if (outcome.status === 'fail') {
    const chainDetail = outcome.details || '';
    const likelyInsufficient = isLikelyInsufficientRewardFailure(chainDetail);
    const err = new Error(
      likelyInsufficient ? usageFeeTopupMessage(tokenIdentifier) : chainDetail || usageFeeTopupMessage(tokenIdentifier),
    );
    err.code = likelyInsufficient
      ? tokenIdentifier === DEFAULT_USDC_TOKEN_ID
        ? 'INSUFFICIENT_USDC_BALANCE'
        : 'INSUFFICIENT_REWARD_BALANCE'
      : 'USAGE_FEE_TX_FAILED';
    err.insufficientFeeBalance = likelyInsufficient;
    err.tokenIdentifier = tokenIdentifier;
    err.walletAddress = walletAddress;
    err.txHashUsageFee = outcome.txHash;
    err.chainDetail = chainDetail;
    throw err;
  }

  if (outcome.status !== 'success') {
    throw new TxCoordinationError(
      'TX_INCONCLUSIVE',
      'Usage fee transaction is not confirmed. The primary operation was not started.',
      {
        retryable: true,
        httpStatus: 503,
        txHash: outcome.txHash,
        operationId: operation?.id || null,
        state: outcome.state,
      },
    );
  }

  return {
    txHash: outcome.txHash,
    amountWei: dynamicFeeAmount,
    reservationId: outcome.reservationId,
    replayed: false,
    reconciliation: outcome.reconciliation || null,
  };
}

function feeReconciliationPatch(operation, reconciliation) {
  if (!reconciliation) return {};
  return {
    progress_json: {
      ...(operation?.progress_json || {}),
      fee_reconciliation: {
        ...reconciliation,
        recordedAt: new Date().toISOString(),
      },
    },
  };
}

function businessMarkers(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return [];
  return [body.status, body.finalStatus, body.transactionStatus, body.data?.transactionStatus]
    .filter((value) => typeof value === 'string' && value.trim())
    .map((value) => value.toLowerCase());
}

/**
 * confirmed: safe to replay on the next identical request.
 * failed: terminal business failure; the fee stays settled and the handler may run again.
 * pending: still in progress; do not replay it as a completed result.
 */
export function classifyBusinessOutcome(status, body) {
  const markers = businessMarkers(body);
  const pending = markers.some((marker) => PENDING_BUSINESS_MARKERS.has(marker));
  if (!Number.isInteger(status) || status < 200 || status >= 400) {
    return pending ? 'pending' : 'failed';
  }
  if (body == null || typeof body !== 'object' || Array.isArray(body)) return 'confirmed';
  if (pending) return 'pending';
  if (markers.some((marker) => FAILED_BUSINESS_MARKERS.has(marker))) return 'failed';
  if (body.success === false) return 'failed';
  const state = typeof body.status === 'string' ? body.status.toLowerCase() : '';
  if (typeof body.error === 'string' && body.error && state !== 'success') return 'failed';
  return 'confirmed';
}

export function isConfirmedBusinessSuccess(status, body) {
  return classifyBusinessOutcome(status, body) === 'confirmed';
}

function primaryHashFromBody(body, operation) {
  if (!body || typeof body !== 'object') return operation?.primary_tx_hash || null;
  return (
    body.txHash ||
    body.finalTxHash ||
    body.result?.txHash ||
    body.data?.transactionHash ||
    body.data?.txHash ||
    body.transactionHash ||
    operation?.primary_tx_hash ||
    null
  );
}

function businessErrorDetail(body) {
  const detail = body?.error || body?.message || body?.status || 'business_response';
  return redactPemFromString(typeof detail === 'string' ? detail : JSON.stringify(detail)).slice(0, 500);
}

function ledgerFailureBody(operation, req) {
  return buildMakeComErrorResponse({
    code: 'LEDGER_WRITE_FAILED',
    message: 'The operation result could not be stored. Retry the same idempotency key. It will not be charged again.',
    data: {
      retryable: true,
      operationId: operation.id,
      usageFeeHash: req.usageFeeHash || null,
    },
  });
}

function unstoredBusinessBody(operation, req, body) {
  return buildMakeComErrorResponse({
    code: 'BUSINESS_RESULT_UNSTORED',
    message: 'The external action may already have completed, but its result was not stored. Do not run it again until this operation is reconciled. The usage fee will not be charged again.',
    data: {
      retryable: false,
      operationId: operation.id,
      usageFeeHash: req.usageFeeHash || operation.fee_tx_hash || null,
      result: body,
    },
  });
}

function abandonedBusinessBody(operation, req) {
  return buildMakeComErrorResponse({
    code: 'BUSINESS_ABANDONED',
    message: 'The operation ended before its result was stored. Do not run it again until it is reconciled. The usage fee will not be charged again.',
    data: {
      retryable: false,
      operationId: operation.id,
      usageFeeHash: req.usageFeeHash || operation.fee_tx_hash || null,
      result: operation.result_json || null,
    },
  });
}

function staleClaimBody(operation) {
  return buildMakeComErrorResponse({
    code: 'STALE_CLAIM',
    message: 'This worker lost the operation claim and did not store its result. Reconcile the operation before running it again.',
    data: { retryable: false, operationId: operation.id },
  });
}

function irreversibleResultMissing(operation) {
  return operation?.state === 'NEEDS_RECONCILIATION'
    && (operation.error_class === 'business_result_unstored' || operation.error_class === 'business_abandoned');
}

async function parkOwnedClaim(req, operation, patch) {
  const store = req.makexCoordinator?.store;
  const owner = req.makexClaimOwner;
  if (!store || !owner || !operation?.id || req.makexClaimLost) return null;
  const now = req.makexClaimNow ? req.makexClaimNow() : Date.now();
  const held = await store.finishBusiness({ id: operation.id, owner, patch, now }).catch(() => null);
  if (held?.ok || held?.reason === 'stale_claim') return held;
  const reclaimed = await store.claimBusiness({
    id: operation.id,
    owner,
    ttlMs: req.makexClaimTtlMs || 120000,
    now,
  }).catch(() => null);
  if (!reclaimed?.claimed) return reclaimed;
  return store.finishBusiness({
    id: operation.id,
    owner,
    patch,
    now: req.makexClaimNow ? req.makexClaimNow() : Date.now(),
  }).catch(() => null);
}

function operationPatchForOutcome(outcome, status, responseBody, ledgerBody, operation) {
  if (outcome === 'confirmed') {
    return {
      state: 'OPERATION_CONFIRMED',
      result_json: responseBody,
      http_status: status,
      primary_tx_hash: primaryHashFromBody(ledgerBody, operation),
      error_class: null,
      error_detail: null,
    };
  }
  if (outcome === 'pending') {
    return {
      state: 'OPERATION_PENDING',
      result_json: null,
      http_status: status,
      error_class: 'business_pending',
      error_detail: businessErrorDetail(ledgerBody),
    };
  }
  return {
    state: 'OPERATION_FAILED',
    result_json: null,
    http_status: status,
    error_class: 'business_response',
    error_detail: businessErrorDetail(ledgerBody),
  };
}

function continueAfterFee(req, res, next, operation) {
  if (!res.makexJsonWrapped) {
    const originalJson = res.json.bind(res);
    res.json = (body) => {
      const status = res.statusCode || 200;
      if (!operation?.id) return originalJson(body);
      const ledgerBody = res.makexBusinessOutcome || body;
      const outcome = classifyBusinessOutcome(status, ledgerBody);
      if (req.makexResultSettled) {
        res.status(503);
        return originalJson(req.makexClaimLost ? staleClaimBody(operation) : abandonedBusinessBody(operation, req));
      }
      req.makexResultSettled = true;
      const patch = operationPatchForOutcome(outcome, status, body, ledgerBody, operation);
      const finish = (nextPatch) => req.makexCoordinator.store.finishBusiness({
        id: operation.id,
        owner: req.makexClaimOwner,
        patch: nextPatch,
        now: req.makexClaimNow ? req.makexClaimNow() : Date.now(),
      });
      const releaseRetryable = () => finish({
        state: operation.fee_tx_hash || operation.skipped_whitelist ? 'FEE_CONFIRMED' : 'RECEIVED',
      }).catch(() => {});
      const stopRenewal = () => req.makexStopClaimRenewal?.();
      return Promise.resolve()
        .then(() => {
          if (req.makexClaimLost) return { ok: false, reason: 'stale_claim' };
          return finish(patch);
        })
        .then(async (updated) => {
          if (updated?.ok) return originalJson(body);
          if (updated?.reason === 'stale_claim') {
            res.status(503);
            return originalJson(staleClaimBody(operation));
          }
          if (updated?.reason === 'claim_expired') {
            await parkOwnedClaim(req, operation, {
              state: 'NEEDS_RECONCILIATION',
              error_class: 'business_abandoned',
              error_detail: 'The business claim lapsed before the result was stored.',
              result_json: body,
              http_status: status,
            });
            res.status(503);
            return originalJson(abandonedBusinessBody(operation, req));
          }
          if (outcome === 'confirmed') {
            await finish({
              state: 'NEEDS_RECONCILIATION',
              error_class: 'business_result_unstored',
              error_detail: 'External action completed but the operation result was not stored.',
              result_json: body,
              http_status: status,
              primary_tx_hash: primaryHashFromBody(ledgerBody, operation),
            }).catch(() => {});
            res.status(503);
            return originalJson(unstoredBusinessBody(operation, req, body));
          }
          await releaseRetryable();
          return originalJson(body);
        })
        .catch(async () => {
          if (outcome === 'confirmed') {
            await finish({
              state: 'NEEDS_RECONCILIATION',
              error_class: 'business_result_unstored',
              error_detail: 'External action completed but the operation result was not stored.',
              result_json: body,
              http_status: status,
              primary_tx_hash: primaryHashFromBody(ledgerBody, operation),
            }).catch(() => {});
            res.status(503);
            return originalJson(unstoredBusinessBody(operation, req, body));
          }
          await releaseRetryable();
          return originalJson(body);
        })
        .finally(stopRenewal);
    };
    res.makexJsonWrapped = true;
  }
  return next();
}

function replayConfirmed(res, operation) {
  if (operation?.result_json) {
    return res.status(operation.http_status || 200).json(operation.result_json);
  }
  return res.status(200).json({
    status: 'success',
    success: true,
    replayed: true,
    message: 'Operation already confirmed.',
    usageFeeHash: operation?.fee_tx_hash,
    txHash: operation?.primary_tx_hash,
    result: { txHash: operation?.primary_tx_hash, status: 'success' },
  });
}

async function releaseBusinessClaim(store, operation) {
  if (!operation?.id) return;
  const settled = operation.fee_tx_hash || operation.skipped_whitelist;
  await store.updateOperation({
    id: operation.id,
    expectedState: 'OPERATION_IN_PROGRESS',
    patch: { state: settled ? 'FEE_CONFIRMED' : 'RECEIVED' },
  });
}

async function runBusiness(req, res, next, operation, claimOptions = {}) {
  const claimTtlMs = claimOptions.claimTtlMs || 120000;
  const claimRenewMs = claimOptions.claimRenewMs || 30000;
  const clock = claimOptions.now || (() => Date.now());
  const scheduleClaimRenewal = claimOptions.scheduleClaimRenewal || ((callback, intervalMs) => {
    const timer = setInterval(callback, intervalMs);
    if (typeof timer.unref === 'function') timer.unref();
    return () => clearInterval(timer);
  });
  const owner = `${req.makexCoordinator?.instanceId || 'local'}:${randomUUID()}`;
  const claim = await req.makexCoordinator.store.claimBusiness({
    id: operation.id,
    owner,
    ttlMs: claimTtlMs,
    now: clock(),
  });
  if (!claim?.ok) {
    throw new TxCoordinationError('LEDGER_WRITE_FAILED', 'Could not claim the operation before running it.', {
      retryable: true,
      httpStatus: 503,
      operationId: operation.id,
    });
  }
  if (!claim.claimed) {
    if (claim.reason === 'confirmed') return replayConfirmed(res, claim.operation);
    return res.status(503).json(buildMakeComErrorResponse({
      code: 'OPERATION_IN_PROGRESS',
      message: 'This operation is already running. Retry the same idempotency key after it finishes. That retry does not start a second external action while the claim is held. Exactly-once delivery cannot be guaranteed if the process stops after the external call and before the result is stored. Send a new idempotency key to repeat an identical action on purpose.',
      data: {
        retryable: true,
        operationId: operation.id,
        retryAfterMs: claim.retryAfterMs || 1000,
      },
    }));
  }
  req.makexOperation = claim.operation;
  req.makexClaimOwner = owner;
  req.makexClaimNow = clock;
  req.makexClaimTtlMs = claimTtlMs;
  req.makexClaimLost = false;
  req.makexResultSettled = false;
  let renewalStopped = false;
  let stopTimer = () => {};
  const stopRenewal = () => {
    if (renewalStopped) return;
    renewalStopped = true;
    stopTimer();
  };
  req.makexStopClaimRenewal = stopRenewal;
  const renewClaim = async () => {
    if (renewalStopped || req.makexClaimLost) return;
    try {
      const renewed = await req.makexCoordinator.store.claimBusiness({
        id: operation.id,
        owner,
        ttlMs: claimTtlMs,
        now: clock(),
      });
      if (renewalStopped || req.makexClaimLost) return;
      if (!renewed?.claimed) {
        req.makexClaimLost = true;
        stopRenewal();
      }
    } catch {
      // A failed renewal leaves the current lease unchanged. Do not release it
      // and do not write over a claim that may now belong to another worker.
    }
  };
  stopTimer = scheduleClaimRenewal(() => renewClaim().catch(() => {}), claimRenewMs);
  if (typeof res.on === 'function') {
    const noteResponseEnded = () => {
      if (req.makexResultSettled) {
        stopRenewal();
        return;
      }
      req.makexResultSettled = true;
      stopRenewal();
      parkOwnedClaim(req, operation, {
        state: 'NEEDS_RECONCILIATION',
        error_class: 'business_abandoned',
        error_detail: 'The response ended before the business result was stored.',
      }).catch(() => {});
    };
    res.on('finish', noteResponseEnded);
    res.on('close', noteResponseEnded);
  }
  // Express next() returns undefined before an async route handler finishes.
  // Renewal stays armed until that handler stores its result or the response ends.
  return continueAfterFee(req, res, next, claim.operation);
}

function buildInsufficientFeeResponse(error) {
  const tokenIdentifier = error.tokenIdentifier || DEFAULT_REWARD_TOKEN_ID;
  const payload = {
    walletAddress: error.walletAddress,
    balanceWei: error.balanceWei,
    requiredWei: error.requiredWei,
    tokenIdentifier,
    txHash: error.txHashUsageFee || null,
    chainDetail: error.chainDetail || null,
  };

  if (tokenIdentifier === DEFAULT_USDC_TOKEN_ID) {
    return buildInsufficientUsdcResponse(payload);
  }
  return buildInsufficientRewardResponse(payload);
}

export function usageFeeFields(req) {
  return req.usageFeeHash ? { usageFeeHash: req.usageFeeHash } : {};
}

/**
 * @param {object} opts
 * @param {string} opts.appId - MAKEX_APP_ID (falls back to process.env.MAKEX_APP_ID)
 * @param {function} [opts.log]
 * @param {import('@multiversx/sdk-network-providers').ProxyNetworkProvider} [opts.provider]
 * @param {function} [opts.mvxFetch]
 * @param {function} [opts.getPemContent]
 * @param {string} [opts.treasuryWallet]
 * @param {string} [opts.clientName] - ProxyNetworkProvider client name
 * @param {function} [opts.onUsageFeeConfirmed] - Called only after a usage-fee tx is confirmed successful
 * @param {object} [opts.coordinator] - Shared transaction coordinator. Created from Supabase when omitted.
 * @param {object|null} [opts.supabase] - Pass null in tests to skip whitelist lookups.
 * @param {function} [opts.deriveAddress]
 * @param {function} [opts.signFeeTransaction]
 * @param {string} [opts.network]
 */
export function createUsageFeeMiddleware({
  appId = process.env.MAKEX_APP_ID,
  log = defaultLog,
  provider: providerOverride,
  mvxFetch: mvxFetchOverride,
  getPemContent = defaultGetPemContent,
  treasuryWallet = DEFAULT_TREASURY_WALLET,
  clientName = 'makex-usage-fee',
  onUsageFeeConfirmed,
  coordinator: coordinatorOverride,
  supabase: supabaseOverride,
  deriveAddress,
  signFeeTransaction,
  network = process.env.MAKEX_CHAIN_ID || '1',
  claimTtlMs = 120000,
  claimRenewMs = 30000,
  now,
  scheduleClaimRenewal,
} = {}) {
  if (!appId) {
    throw new Error('MAKEX_APP_ID is required for usage fee middleware');
  }

  const supabase = supabaseOverride !== undefined ? supabaseOverride : getSupabase();
  const provider =
    providerOverride ||
    new ProxyNetworkProvider('https://gateway.multiversx.com', { clientName });

  let lastApiCall = 0;
  const API_RATE_LIMIT_MS = 500;

  let mvxFetch = mvxFetchOverride;
  if (!mvxFetch) {
    mvxFetch = async (url, options = {}) => {
      const now = Date.now();
      const waitMs = API_RATE_LIMIT_MS - (now - lastApiCall);
      if (waitMs > 0) await new Promise((resolve) => setTimeout(resolve, waitMs));
      lastApiCall = Date.now();
      return fetch(url, {
        ...options,
        headers: {
          'User-Agent': `${clientName}/1.0`,
          ...(options.headers || {}),
        },
      });
    };
  }

  let coordinatorRef = coordinatorOverride || null;
  const getCoordinator = () => {
    if (!coordinatorRef) {
      coordinatorRef = createProductionCoordinator({
        supabase,
        provider,
        fetchImpl: mvxFetch,
        appId,
        log,
      });
    }
    return coordinatorRef;
  };

  return async function handleUsageFee(req, res, next) {
    let walletAddress;
    try {
      const pemContent = getPemContent(req);
      const senderAddress = deriveAddress
        ? deriveAddress(pemContent)
        : UserSigner.fromPem(pemContent).getAddress();
      walletAddress = typeof senderAddress === 'string' ? senderAddress : senderAddress.toString();
      const coordinator = getCoordinator();
      const idempotency = readIdempotencyKey(req);
      const requestFingerprint = fingerprintRequest(req);
      const begun = await coordinator.store.beginOperation({
        idempotencyKey: idempotency.key,
        requestFingerprint,
        appId,
        network: coordinator.config?.network || network,
        walletAddress,
      });
      if (!begun.ok && begun.reason === 'fingerprint_mismatch') {
        return res.status(409).json(
          buildMakeComErrorResponse({
            code: 'IDEMPOTENCY_CONFLICT',
            message: 'This idempotency key was already used for a different operation. Use a new key for a new payment.',
            data: { retryable: false, operationId: begun.operation?.id || null },
          }),
        );
      }
      if (!begun.ok) {
        throw new TxCoordinationError('COORDINATOR_DB_ERROR', 'Could not record the operation before charging.', {
          retryable: true,
          httpStatus: 503,
        });
      }

      let operation = begun.operation;
      req.makexOperation = operation;
      req.makexCoordinator = coordinator;
      req.makexIdempotencyEphemeral = idempotency.ephemeral;

      if (operation.state === 'OPERATION_CONFIRMED') {
        return replayConfirmed(res, operation);
      }

      if (irreversibleResultMissing(operation)) {
        const abandoned = operation.error_class === 'business_abandoned';
        return res.status(503).json(abandoned
          ? abandonedBusinessBody(operation, req)
          : unstoredBusinessBody(operation, req, operation.result_json || null));
      }

      if (operation.state === 'INCONCLUSIVE' || operation.state === 'NEEDS_RECONCILIATION' || operation.state === 'FEE_SUBMITTED' || operation.state === 'FEE_PREPARED') {
        const resumed = await sendUsageFee({
          pemContent,
          walletAddress,
          tokenIdentifier: operation.fee_token_identifier || DEFAULT_USDC_TOKEN_ID,
          usdFee: operation.usd_amount,
          treasuryWallet,
          mvxFetch,
          coordinator,
          operation,
          appId,
          network: coordinator.config?.network || network,
          signFeeTransaction,
        });
        if (!resumed?.txHash) {
          throw new TxCoordinationError('TX_INCONCLUSIVE', 'Usage fee is not confirmed. The primary operation was not started.', {
            retryable: true,
            httpStatus: 503,
            operationId: operation.id,
          });
        }
        const settled = await coordinator.store.updateOperation({
          id: operation.id,
          patch: {
            state: 'FEE_CONFIRMED',
            fee_tx_hash: resumed.txHash,
            fee_reservation_id: resumed.reservationId,
            ...feeReconciliationPatch(operation, resumed.reconciliation),
          },
        });
        if (!settled.ok) {
          throw new TxCoordinationError('LEDGER_WRITE_FAILED', 'Usage fee is confirmed but the operation ledger could not be updated.', {
            retryable: true,
            httpStatus: 503,
            txHash: resumed.txHash,
            operationId: operation.id,
          });
        }
        operation = settled.operation;
        req.makexOperation = operation;
        req.usageFeeHash = resumed.txHash;
        return await runBusiness(req, res, next, operation, { claimTtlMs, claimRenewMs, now, scheduleClaimRenewal });
      }

      const profile = await loadAppProfile(appId, supabase);
      let whitelistReason = operation.whitelist_reason || 'whitelist_disabled';
      if (!feeIsSettled(operation) && profile.whitelist_enabled) {
        const whitelistEligibility = await getWhitelistEligibility(walletAddress, supabase);
        whitelistReason = whitelistEligibility.reason;
        if (whitelistEligibility.skipUsageFee) {
          const skipped = await coordinator.store.updateOperation({
            id: operation.id,
            patch: {
              state: 'FEE_CONFIRMED',
              skipped_whitelist: true,
              whitelist_reason: whitelistReason,
            },
          });
          if (!skipped.ok) {
            throw new TxCoordinationError('LEDGER_WRITE_FAILED', 'Could not record the whitelist exemption.', {
              retryable: true,
              httpStatus: 503,
              operationId: operation.id,
            });
          }
          log('info', 'Skipping usage fee for whitelisted wallet', {
            walletAddress,
            status: whitelistEligibility.reason,
            appId,
            operationId: operation.id,
          });
          req.makexOperation = skipped.operation;
          return await runBusiness(req, res, next, skipped.operation, { claimTtlMs, claimRenewMs, now, scheduleClaimRenewal });
        }
        if (whitelistEligibility.reason === 'expired') {
          log('info', 'Whitelist entry expired, charging usage fee', { walletAddress, appId, operationId: operation.id });
        }
      }

      if (!feeIsSettled(operation)) {
        const prefs = await getWalletBillingPrefs(walletAddress, supabase);
        const payment = resolvePaymentToken(profile, prefs);
        const { txHash, amountWei, reservationId, reconciliation } = await sendUsageFee({
          pemContent,
          walletAddress,
          tokenIdentifier: payment.tokenIdentifier,
          usdFee: payment.usdFee,
          treasuryWallet,
          mvxFetch,
          coordinator,
          operation,
          appId,
          network: coordinator.config?.network || network,
          signFeeTransaction,
        });

        const recorded = await coordinator.store.updateOperation({
          id: operation.id,
          patch: {
            state: 'FEE_CONFIRMED',
            fee_tx_hash: txHash,
            fee_reservation_id: reservationId,
            fee_amount_wei: String(amountWei),
            fee_token: payment.feeToken,
            fee_token_identifier: payment.tokenIdentifier,
            usd_amount: payment.usdFee,
            skipped_whitelist: false,
            whitelist_reason: whitelistReason,
            ...feeReconciliationPatch(operation, reconciliation),
          },
        });
        if (!recorded.ok) {
          throw new TxCoordinationError(
            'LEDGER_WRITE_FAILED',
            'Usage fee was confirmed but the operation ledger could not be updated. Retry this request. It will not be charged again.',
            { retryable: true, httpStatus: 503, txHash, operationId: operation.id },
          );
        }
        operation = recorded.operation;
        req.makexOperation = operation;
        req.usageFeeHash = txHash;
        log('info', 'Usage fee collected', {
          walletAddress,
          usageFeeHash: txHash,
          usdFee: payment.usdFee,
          feeToken: payment.feeToken,
          tokenIdentifier: payment.tokenIdentifier,
          appId,
          operationId: operation.id,
          nonce: null,
        });
        await insertLedgerEntry(supabase, {
          wallet_address: walletAddress,
          app_id: appId,
          tx_hash: txHash,
          fee_token: payment.feeToken,
          fee_token_identifier: payment.tokenIdentifier,
          amount_wei: String(amountWei),
          usd_amount: payment.usdFee,
          skipped_whitelist: false,
          whitelist_reason: whitelistReason,
        }, log);
        if (onUsageFeeConfirmed) {
          await onUsageFeeConfirmed(senderAddress);
        }
      } else {
        req.usageFeeHash = operation.fee_tx_hash || undefined;
        log('info', 'Reusing confirmed usage fee', {
          walletAddress,
          usageFeeHash: operation.fee_tx_hash,
          appId,
          operationId: operation.id,
          state: operation.state,
        });
      }

      return await runBusiness(req, res, next, operation, { claimTtlMs, claimRenewMs, now, scheduleClaimRenewal });
    } catch (error) {
      const failedOperation = req.makexOperation;
      if (
        failedOperation?.id
        && req.makexCoordinator?.store
        && error?.code === 'TX_NEEDS_RECONCILIATION'
        && error?.errorClass === 'hash_mismatch'
      ) {
        await req.makexCoordinator.store.updateOperation({
          id: failedOperation.id,
          patch: {
            state: 'NEEDS_RECONCILIATION',
            error_class: 'hash_mismatch',
            error_detail: hashDiagnostic({
              localHash: error.txHash,
              gatewayHash: error.gatewayHash,
              canonicalHash: error.canonicalHash,
            }).slice(0, 500),
            progress_json: {
              ...(failedOperation.progress_json || {}),
              fee_reconciliation: {
                localHash: error.txHash || null,
                gatewayHash: error.gatewayHash || null,
                canonicalHash: error.canonicalHash || null,
                nonce: error.nonce ?? null,
                recordedAt: new Date().toISOString(),
                primaryExecuted: false,
              },
            },
          },
        }).catch(() => {});
      }
      log('error', 'Error processing usage fee', {
        error: redactPemFromString(error.message),
        appId,
      });

      const insufficient =
        error.insufficientFeeBalance === true ||
        error.code === 'INSUFFICIENT_REWARD_BALANCE' ||
        error.code === 'INSUFFICIENT_USDC_BALANCE' ||
        isLikelyInsufficientRewardFailure(error.message) ||
        isLikelyInsufficientRewardFailure(error.chainDetail);

      if (insufficient) {
        return res.status(422).json(buildInsufficientFeeResponse(error));
      }

      const retryable = error.retryable === true;
      const httpStatus = error.httpStatus || (error.code === 'USAGE_FEE_TX_FAILED' ? 502 : retryable ? 503 : 400);
      return res.status(httpStatus).json(
        buildMakeComErrorResponse({
          code: error.code || 'USAGE_FEE_FAILED',
          message: redactPemFromString(error.message) || USAGE_FEE_TOPUP_USER_MESSAGE,
          data: {
            retryable,
            ...(error.chainDetail ? { chainDetail: error.chainDetail } : {}),
            ...(error.txHashUsageFee || error.txHash ? { txHash: error.txHashUsageFee || error.txHash } : {}),
            ...(error.gatewayHash ? { gatewayHash: error.gatewayHash } : {}),
            ...(error.canonicalHash ? { canonicalHash: error.canonicalHash } : {}),
            ...(error.operationId ? { operationId: error.operationId } : {}),
            ...(error.state ? { state: error.state } : {}),
          },
        }),
      );
    }
  };
}

export {
  DEFAULT_TREASURY_WALLET,
  FALLBACK_PROFILES,
  TOKEN_ID_BY_SYMBOL,
  WHITELIST_TABLE,
  PREFS_TABLE,
  PROFILES_TABLE,
  LEDGER_TABLE,
  resolvePaymentToken,
};
