/**
 * Shared MakeX usage-fee engine: USDC/REWARD billing, whitelist, app profiles, ledger.
 * Copy unchanged into each Render service folder (same pattern as makexStandard.mjs).
 */

import {
  Address,
  ProxyNetworkProvider,
  Transaction,
  TransactionComputer,
  UserSigner,
} from '@multiversx/sdk-core';
import BigNumber from 'bignumber.js';
import { createClient } from '@supabase/supabase-js';
import {
  buildInsufficientRewardResponse,
  buildInsufficientUsdcResponse,
  checkTransactionStatus,
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
const pendingUsageFeeTransactions = new Map();

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

async function insertLedgerEntry(supabase, entry) {
  if (!supabase) return;
  try {
    await supabase.from(LEDGER_TABLE).insert(entry);
  } catch {
    // Non-blocking audit logging
  }
}

async function sendUsageFee({
  pemContent,
  walletAddress,
  tokenIdentifier,
  usdFee,
  provider,
  treasuryWallet,
  mvxFetch,
}) {
  const pendingTx = pendingUsageFeeTransactions.get(walletAddress);
  if (pendingTx) {
    const status = await checkTransactionStatus(pendingTx.txHash, 15, 2000, mvxFetch);
    if (status.status === 'success') {
      pendingUsageFeeTransactions.delete(walletAddress);
      return { txHash: pendingTx.txHash, amountWei: pendingTx.amountWei };
    }
    if (status.status !== 'pending' && status.status !== 'timeout' && status.status !== 'unknown') {
      pendingUsageFeeTransactions.delete(walletAddress);
    } else {
      return { txHash: pendingTx.txHash, amountWei: pendingTx.amountWei };
    }
  }

  const signer = UserSigner.fromPem(pemContent);
  const senderAddress = signer.getAddress();
  const receiverAddress = new Address(treasuryWallet);
  const accountOnNetwork = await provider.getAccount(senderAddress);
  const dynamicFeeAmount = await calculateDynamicUsageFee(usdFee, tokenIdentifier, mvxFetch);

  const balanceWei = await fetchAccountEsdtBalanceWei(
    senderAddress.toString(),
    tokenIdentifier,
    mvxFetch,
  );

  if (insufficientTokenBalance(balanceWei, dynamicFeeAmount)) {
    const err = new Error(usageFeeTopupMessage(tokenIdentifier));
    err.code =
      tokenIdentifier === DEFAULT_USDC_TOKEN_ID
        ? 'INSUFFICIENT_USDC_BALANCE'
        : 'INSUFFICIENT_REWARD_BALANCE';
    err.insufficientFeeBalance = true;
    err.tokenIdentifier = tokenIdentifier;
    err.walletAddress = senderAddress.toString();
    err.balanceWei = balanceWei;
    err.requiredWei = dynamicFeeAmount;
    throw err;
  }

  const tx = new Transaction({
    sender: senderAddress,
    receiver: receiverAddress,
    value: BigInt(0),
    data: buildEsdtTransferData(tokenIdentifier, dynamicFeeAmount),
    gasLimit: BigInt(500000),
    chainID: '1',
  });

  tx.nonce = accountOnNetwork.nonce;
  tx.signature = await signer.sign(new TransactionComputer().computeBytesForSigning(tx));

  let txHash;
  try {
    txHash = await provider.sendTransaction(tx);
  } catch (err) {
    throw new Error(`Failed to send transaction: ${err.message}`);
  }
  if (!txHash) throw new Error('Transaction hash is undefined after sending transaction.');

  const txHashStr = txHash.toString();
  pendingUsageFeeTransactions.set(walletAddress, {
    txHash: txHashStr,
    amountWei: dynamicFeeAmount,
    timestamp: Date.now(),
  });

  const status = await checkTransactionStatus(txHashStr, 15, 2000, mvxFetch);
  if (status.status === 'success') {
    pendingUsageFeeTransactions.delete(walletAddress);
  } else if (status.status === 'fail') {
    pendingUsageFeeTransactions.delete(walletAddress);
    const chainDetail = status.details || '';
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
    err.walletAddress = senderAddress.toString();
    err.txHashUsageFee = txHashStr;
    err.chainDetail = chainDetail;
    throw err;
  }

  return { txHash: txHashStr, amountWei: dynamicFeeAmount };
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
 */
export function createUsageFeeMiddleware({
  appId = process.env.MAKEX_APP_ID,
  log = defaultLog,
  provider: providerOverride,
  mvxFetch: mvxFetchOverride,
  getPemContent = defaultGetPemContent,
  treasuryWallet = DEFAULT_TREASURY_WALLET,
  clientName = 'makex-usage-fee',
} = {}) {
  if (!appId) {
    throw new Error('MAKEX_APP_ID is required for usage fee middleware');
  }

  const supabase = getSupabase();
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

  return async function handleUsageFee(req, res, next) {
    let walletAddress;
    try {
      const pemContent = getPemContent(req);
      walletAddress = UserSigner.fromPem(pemContent).getAddress().toString();

      const profile = await loadAppProfile(appId, supabase);

      let whitelistReason = 'whitelist_disabled';
      if (profile.whitelist_enabled) {
        const whitelistEligibility = await getWhitelistEligibility(walletAddress, supabase);
        whitelistReason = whitelistEligibility.reason;
        if (whitelistEligibility.skipUsageFee) {
          log('info', 'Skipping usage fee for whitelisted wallet', {
            walletAddress,
            status: whitelistEligibility.reason,
            appId,
          });
          return next();
        }
        if (whitelistEligibility.reason === 'expired') {
          log('info', 'Whitelist entry expired, charging usage fee', { walletAddress, appId });
        }
      }

      const prefs = await getWalletBillingPrefs(walletAddress, supabase);
      const payment = resolvePaymentToken(profile, prefs);

      const { txHash, amountWei } = await sendUsageFee({
        pemContent,
        walletAddress,
        tokenIdentifier: payment.tokenIdentifier,
        usdFee: payment.usdFee,
        provider,
        treasuryWallet,
        mvxFetch,
      });

      req.usageFeeHash = txHash;
      log('info', 'Usage fee collected', {
        walletAddress,
        usageFeeHash: txHash,
        usdFee: payment.usdFee,
        feeToken: payment.feeToken,
        tokenIdentifier: payment.tokenIdentifier,
        appId,
      });

      insertLedgerEntry(supabase, {
        wallet_address: walletAddress,
        app_id: appId,
        tx_hash: txHash,
        fee_token: payment.feeToken,
        fee_token_identifier: payment.tokenIdentifier,
        amount_wei: amountWei,
        usd_amount: payment.usdFee,
        skipped_whitelist: false,
        whitelist_reason: whitelistReason,
      }).catch(() => {});

      return next();
    } catch (error) {
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

      return res.status(error.code === 'USAGE_FEE_TX_FAILED' ? 502 : 400).json({
        status: 'error',
        code: error.code || 'USAGE_FEE_FAILED',
        message: redactPemFromString(error.message) || USAGE_FEE_TOPUP_USER_MESSAGE,
        data: {
          ...(error.chainDetail ? { chainDetail: error.chainDetail } : {}),
          ...(error.txHashUsageFee ? { txHash: error.txHashUsageFee } : {}),
          timestamp: new Date().toISOString(),
        },
      });
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
};
