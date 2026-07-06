/**
 * Shared MakeX API helpers: strict MultiversX tx verification, usage-fee errors, logging PEM safety.
 * Copy this file unchanged into each Render service folder.
 */

export const DEFAULT_REWARD_TOKEN_ID = 'REWARD-cf6eac';
export const DEFAULT_USDC_TOKEN_ID = 'USDC-c76f1f';

export const INSUFFICIENT_REWARD_CODE = 'INSUFFICIENT_REWARD_BALANCE';
export const INSUFFICIENT_USDC_CODE = 'INSUFFICIENT_USDC_BALANCE';

/** User-facing copy — keep identical across all MakeX apps for Make.com parsers. */
export const USAGE_FEE_TOPUP_USER_MESSAGE =
  'Your wallet does not hold enough REWARD to pay the usage fee. Top up REWARD (REWARD-cf6eac) on the same wallet you connect to this integration, then retry.';

export const USAGE_FEE_TOPUP_USDC_MESSAGE =
  'Your wallet does not hold enough USDC to pay the usage fee. Top up USDC (USDC-c76f1f) on the same wallet you connect to this integration, then retry.';

export function usageFeeTopupMessage(tokenIdentifier) {
  if (tokenIdentifier === DEFAULT_USDC_TOKEN_ID) return USAGE_FEE_TOPUP_USDC_MESSAGE;
  if (tokenIdentifier === DEFAULT_REWARD_TOKEN_ID) return USAGE_FEE_TOPUP_USER_MESSAGE;
  return `Your wallet does not hold enough ${tokenIdentifier} to pay the usage fee. Top up on the same wallet you connect to this integration, then retry.`;
}

export const TRANSACTION_FAILED_CODE = 'TRANSACTION_FAILED';

export const TRANSACTION_INCONCLUSIVE_CODE = 'TRANSACTION_STATUS_INCONCLUSIVE';

export const INSUFFICIENT_EGLD_GAS_CODE = 'INSUFFICIENT_EGLD_GAS';

export const EGLD_GAS_TOPUP_USER_MESSAGE =
  'Your wallet does not hold enough EGLD to pay MultiversX network fees for this transaction. Add EGLD to the same wallet you use for this integration, then retry.';

export const INSUFFICIENT_TOKEN_BALANCE_CODE = 'INSUFFICIENT_TOKEN_BALANCE';

export const AUTHORIZATION_SUCCESS_CODE = 'AUTHORIZATION_SUCCESS';

export const UNAUTHORIZED_CODE = 'UNAUTHORIZED';

const PEM_BLOCKS =
  /-----BEGIN[A-Z0-9 -]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END[A-Z0-9 -]*PRIVATE KEY(?: BLOCK)?-----/gi;

export function redactPemFromString(input) {
  if (input == null) return input;
  if (typeof input !== 'string') return input;
  return input.replace(PEM_BLOCKS, '[REDACTED_PEM]');
}

export function sanitizeObjectForLog(obj, depth = 0) {
  if (depth > 12 || obj === undefined) return obj;
  if (obj === null) return null;
  if (typeof obj === 'string') return redactPemFromString(obj);
  if (typeof obj === 'bigint') return obj.toString();
  if (typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map((x) => sanitizeObjectForLog(x, depth + 1));
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    const lower = k.toLowerCase();
    if (
      k === 'walletPem' ||
      k === 'pemContent' ||
      k === 'privateKey' ||
      lower.includes('pem') ||
      lower === 'wallet_pem'
    ) {
      out[k] = v != null && v !== '' ? '[REDACTED]' : v;
      continue;
    }
    out[k] = sanitizeObjectForLog(v, depth + 1);
  }
  return out;
}

export function safeJsonStringifyForLog(value, space = 0) {
  try {
    return JSON.stringify(sanitizeObjectForLog(value), space);
  } catch {
    return '"[SERIALIZE_ERROR]"';
  }
}

/** Field types and PEM presence without logging secret material. */
export function describeRequestBodyForLog(body) {
  if (body == null) {
    return { bodyType: body === null ? 'null' : 'undefined', keys: [] };
  }
  if (typeof body !== 'object' || Array.isArray(body)) {
    return { bodyType: Array.isArray(body) ? 'array' : typeof body, sanitizedPreview: sanitizeObjectForLog(body) };
  }
  const keys = Object.keys(body);
  const fieldTypes = {};
  for (const k of keys) {
    const v = body[k];
    if (v == null) fieldTypes[k] = 'null';
    else if (Array.isArray(v)) fieldTypes[k] = `array(${v.length})`;
    else fieldTypes[k] = typeof v;
  }
  const walletPem = body.walletPem;
  const pemStr = typeof walletPem === 'string' ? walletPem : '';
  return {
    keys,
    fieldTypes,
    walletPemPresent: pemStr.length > 0,
    walletPemLength: pemStr.length || null,
    walletPemHasBeginMarker: pemStr.includes('-----BEGIN'),
    sanitizedBody: sanitizeObjectForLog(body),
  };
}

export function describeRequestHeadersForLog(headers = {}) {
  const ua = headers['user-agent'] || headers['User-Agent'] || '';
  const uaLower = String(ua).toLowerCase();
  return {
    contentType: headers['content-type'] || headers['Content-Type'] || null,
    contentLength: headers['content-length'] || headers['Content-Length'] || null,
    authorizationPresent: Boolean(headers.authorization || headers.Authorization),
    userAgent: ua || null,
    likelyMakeClient: uaLower.includes('make') || uaLower.includes('integromat'),
    xForwardedFor: headers['x-forwarded-for'] || headers['X-Forwarded-For'] || null,
    cfRay: headers['cf-ray'] || headers['CF-Ray'] || null,
  };
}

/** Structured, PEM-safe log line for debugging Make.com vs other clients. */
export function logIncomingApiRequest(req, label) {
  const payload = {
    label,
    timestamp: new Date().toISOString(),
    method: req?.method,
    path: req?.path,
    originalUrl: req?.originalUrl,
    headers: describeRequestHeadersForLog(req?.headers),
    body: describeRequestBodyForLog(req?.body),
  };
  console.log(`${label}.incoming`, safeJsonStringifyForLog(payload));
}

export function weiStringToEgldDisplay(weiStr, fractionDigits = 6) {
  const raw = String(weiStr ?? '0').trim().split('.')[0] || '0';
  const neg = raw.startsWith('-');
  const digits = neg ? raw.slice(1) : raw;
  if (!/^\d+$/.test(digits)) return `0.${'0'.repeat(fractionDigits)}`;
  const w = BigInt(digits);
  const base = 10n ** 18n;
  const whole = w / base;
  const frac = w % base;
  const mult = 10n ** BigInt(Math.min(18, Math.max(1, fractionDigits)));
  const fracScaled = Number(fractionDigits) > 0 ? (frac * mult) / base : 0n;
  const fracPadded = String(fracScaled).padStart(Number(fractionDigits), '0').slice(0, Number(fractionDigits));
  const signed = neg ? '-' : '';
  return `${signed}${whole}.${fracPadded}`;
}

export function buildInsufficientEGLDGasResponse({
  walletAddress,
  balanceWei,
  requiredWei,
  balanceEgld = null,
  requiredEgld = null,
  shortfallEgld = null,
  usageFeeHash = null,
  chainDetail = null,
  operationContext = null,
} = {}) {
  let shortWei = '0';
  try {
    if (requiredWei != null && balanceWei != null) {
      const req = BigInt(String(requiredWei));
      const bal = BigInt(String(balanceWei));
      shortWei = req > bal ? (req - bal).toString() : '0';
    }
  } catch {
    shortWei = '0';
  }

  const data = {
    insufficientEgldGas: true,
    troubleshooting: EGLD_GAS_TOPUP_USER_MESSAGE,
    timestamp: new Date().toISOString(),
  };
  if (walletAddress != null) data.walletAddress = String(walletAddress);
  if (balanceWei != null) data.balanceWei = String(balanceWei);
  if (requiredWei != null) data.requiredWei = String(requiredWei);
  data.balanceEgld = balanceEgld != null ? String(balanceEgld) : weiStringToEgldDisplay(balanceWei ?? '0', 6);
  data.requiredEgld = requiredEgld != null ? String(requiredEgld) : weiStringToEgldDisplay(requiredWei ?? '0', 6);
  data.shortfallEgld = shortfallEgld != null ? String(shortfallEgld) : weiStringToEgldDisplay(shortWei, 6);
  if (usageFeeHash != null) data.usageFeeHash = usageFeeHash;
  if (chainDetail != null) data.chainDetail = String(chainDetail);
  if (operationContext != null && typeof operationContext === 'object') {
    data.operationContext = sanitizeObjectForLog(operationContext);
  }

  return {
    status: 'error',
    code: INSUFFICIENT_EGLD_GAS_CODE,
    message: EGLD_GAS_TOPUP_USER_MESSAGE,
    data,
  };
}

export function buildInsufficientTokenBalanceResponse({
  tokenIdentifier,
  walletAddress,
  balanceWei,
  requiredWei,
  usageFeeHash = null,
  message = null,
  troubleshooting = null,
  decimalsHint = null,
} = {}) {
  const tip =
    troubleshooting ||
    `Your wallet does not hold enough ${String(tokenIdentifier || 'token')} for this operation. Top up on the same wallet you connect to this integration, then retry.`;
  const data = {
    insufficientTokenBalance: true,
    tokenIdentifier: tokenIdentifier != null ? String(tokenIdentifier) : undefined,
    troubleshooting: tip,
    timestamp: new Date().toISOString(),
  };
  if (walletAddress != null) data.walletAddress = String(walletAddress);
  if (balanceWei != null) data.balanceWei = String(balanceWei);
  if (requiredWei != null) data.requiredWei = String(requiredWei);
  if (decimalsHint != null) data.decimals = decimalsHint;
  if (usageFeeHash != null) data.usageFeeHash = usageFeeHash;
  return {
    status: 'error',
    code: INSUFFICIENT_TOKEN_BALANCE_CODE,
    message: message || tip,
    data,
  };
}

export function isLikelyInsufficientEgldGasFailure(text) {
  if (text == null) return false;
  const s = String(text).toLowerCase();
  return (
    s.includes('insufficient funds') ||
    s.includes('not enough funds') ||
    s.includes('would burn') ||
    (s.includes('gas') && s.includes('egld')) ||
    (s.includes('insufficient') && s.includes('fee'))
  );
}

export function buildAuthorizationSuccessResponse({ walletAddress = null } = {}) {
  const data = { timestamp: new Date().toISOString() };
  if (walletAddress != null) data.walletAddress = String(walletAddress);
  return {
    status: 'success',
    code: AUTHORIZATION_SUCCESS_CODE,
    message: 'Authorization successful',
    data,
  };
}

export function buildUnauthorizedResponse() {
  return {
    status: 'error',
    code: UNAUTHORIZED_CODE,
    message: 'Unauthorized',
    data: { timestamp: new Date().toISOString() },
  };
}

/**
 * @param {object} opts
 * @returns {{ status: string, code: string, message: string, data: object }}
 */
export function buildInsufficientUsdcResponse({
  walletAddress,
  balanceWei = null,
  requiredWei = null,
  tokenIdentifier = DEFAULT_USDC_TOKEN_ID,
  usageFeeHash = null,
  txHash = null,
  chainDetail = null,
  decimals = null,
} = {}) {
  const data = {
    insufficientUsdc: true,
    tokenIdentifier,
    troubleshooting: USAGE_FEE_TOPUP_USDC_MESSAGE,
    timestamp: new Date().toISOString(),
  };
  if (walletAddress != null) data.walletAddress = String(walletAddress);
  if (balanceWei != null) data.balanceWei = String(balanceWei);
  if (requiredWei != null) data.requiredWei = String(requiredWei);
  if (decimals != null) data.decimals = decimals;
  if (usageFeeHash != null) data.usageFeeHash = usageFeeHash;
  if (txHash != null) data.txHash = txHash;
  if (chainDetail) data.chainDetail = String(chainDetail);

  return {
    status: 'error',
    code: INSUFFICIENT_USDC_CODE,
    message: USAGE_FEE_TOPUP_USDC_MESSAGE,
    data,
  };
}

export function buildInsufficientRewardResponse({
  walletAddress,
  balanceWei = null,
  requiredWei = null,
  tokenIdentifier = DEFAULT_REWARD_TOKEN_ID,
  usageFeeHash = null,
  txHash = null,
  chainDetail = null,
  decimals = null,
} = {}) {
  const data = {
    insufficientReward: true,
    tokenIdentifier,
    troubleshooting: USAGE_FEE_TOPUP_USER_MESSAGE,
    timestamp: new Date().toISOString(),
  };
  if (walletAddress != null) data.walletAddress = String(walletAddress);
  if (balanceWei != null) data.balanceWei = String(balanceWei);
  if (requiredWei != null) data.requiredWei = String(requiredWei);
  if (decimals != null) data.decimals = decimals;
  if (usageFeeHash != null) data.usageFeeHash = usageFeeHash;
  if (txHash != null) data.txHash = txHash;
  if (chainDetail) data.chainDetail = String(chainDetail);

  return {
    status: 'error',
    code: INSUFFICIENT_REWARD_CODE,
    message: USAGE_FEE_TOPUP_USER_MESSAGE,
    data,
  };
}

export function buildTransactionFailureResponse({
  txHash,
  details,
  usageFeeHash = null,
  code = TRANSACTION_FAILED_CODE,
} = {}) {
  const data = {
    txHash: txHash != null ? String(txHash) : undefined,
    chainDetail: details != null ? String(details) : 'Transaction failed on-chain',
    timestamp: new Date().toISOString(),
  };
  if (usageFeeHash != null) data.usageFeeHash = usageFeeHash;
  return {
    status: 'error',
    code,
    message:
      code === TRANSACTION_INCONCLUSIVE_CODE
        ? 'The transaction was sent but a final success status could not be confirmed in time. Verify the transaction hash in the MultiversX explorer before retrying.'
        : 'MultiversX reported that the transaction did not complete successfully.',
    data,
  };
}

export async function fetchAccountEsdtBalanceWei(bech32Address, tokenIdentifier, fetchImpl = globalThis.fetch) {
  const enc = encodeURIComponent(tokenIdentifier);
  const res = await fetchImpl(`https://api.multiversx.com/accounts/${bech32Address}/tokens/${enc}`, {
    headers: { Accept: 'application/json' },
  });
  if (!res.ok) {
    if (res.status === 404) return '0';
    const t = await res.text().catch(() => '');
    throw new Error(`Failed to fetch token balance: ${res.status} ${res.statusText} ${t}`.trim());
  }
  const data = await res.json();
  const raw = data?.balance ?? data?.value ?? '0';
  return String(raw);
}

export function insufficientTokenBalance(balanceWeiStr, requiredWeiStr) {
  try {
    return BigInt(balanceWeiStr) < BigInt(requiredWeiStr);
  } catch {
    return true;
  }
}

export function insufficientRewardBalance(balanceWeiStr, requiredWeiStr) {
  return insufficientTokenBalance(balanceWeiStr, requiredWeiStr);
}

export function isLikelyInsufficientRewardFailure(text) {
  if (text == null) return false;
  const s = String(text).toLowerCase();
  return (
    s.includes('insufficient funds') ||
    s.includes('not enough esdt') ||
    s.includes('insufficient esdt') ||
    s.includes('not enough funds') ||
    s.includes('more funds than available') ||
    s.includes('not enough balance')
  );
}

function extractTxFailureDetails(txData) {
  if (!txData || typeof txData !== 'object') return 'Unknown failure';

  const direct =
    txData.failReason ||
    txData.error ||
    (txData.results && txData.results[0]?.returnMessage) ||
    (txData.operations && txData.operations[0]?.message) ||
    txData?.receipt?.data;
  if (direct) return String(direct);

  if (Array.isArray(txData.operations)) {
    const errorOp = txData.operations.find((op) => op.action === 'signalError' || op.type === 'error');
    if (errorOp?.message) return String(errorOp.message);
    if (errorOp?.data) {
      try {
        return Buffer.from(errorOp.data, 'base64').toString('utf8');
      } catch {
        return String(errorOp.data);
      }
    }
  }

  if (txData.logs?.events?.length) {
    const ev = txData.logs.events.find((e) => e.identifier === 'signalError' || e.identifier === 'executeError');
    if (ev?.topics?.length) {
      try {
        return ev.topics.map((t) => Buffer.from(t, 'base64').toString('utf8')).join(' | ');
      } catch {
        return JSON.stringify(ev.topics);
      }
    }
  }

  return txData.status ? `Transaction status: ${txData.status}` : 'Transaction failed';
}

/**
 * Strict: only MultiversX API `status === "success"` passes.
 * @returns {Promise<{ txHash: string, status: 'success'|'fail'|'pending'|'unknown'|'timeout', details?: string }>}
 */
export async function checkTransactionStatus(txHash, maxRetries = 20, retryInterval = 2000, fetchImpl = globalThis.fetch) {
  const hash = String(txHash);

  for (let i = 0; i < maxRetries; i++) {
    try {
      const txStatusUrl = `https://api.multiversx.com/transactions/${encodeURIComponent(hash)}?withResults=true`;
      const response = await fetchImpl(txStatusUrl, {
        headers: { Accept: 'application/json' },
      });

      if (!response.ok) {
        if (response.status === 404) {
          await new Promise((r) => setTimeout(r, retryInterval));
          continue;
        }
        const responseText = await response.text().catch(() => '');
        throw new Error(`MultiversX API ${response.status}: ${response.statusText} ${responseText}`.trim());
      }

      const txData = await response.json();
      const scResults = txData.results || txData.smartContractResults || [];
      const anyResultPending = scResults.some((r) => (r.status || r.returnCode) === 'pending');

      if (txData.status === 'pending' || txData.pendingResults === true || anyResultPending) {
        await new Promise((r) => setTimeout(r, retryInterval));
        continue;
      }

      if (txData.status !== 'success') {
        return { txHash: hash, status: 'fail', details: extractTxFailureDetails(txData) };
      }

      if (txData.receipt?.status === 'fail') {
        return { txHash: hash, status: 'fail', details: extractTxFailureDetails(txData) };
      }

      if (txData.logs?.events) {
        const failEvents = txData.logs.events.filter(
          (event) => event.identifier === 'signalError' || event.identifier === 'executeError',
        );
        if (failEvents.length > 0) {
          return {
            txHash: hash,
            status: 'fail',
            details: extractTxFailureDetails(txData),
          };
        }
      }

      if (scResults.length > 0) {
        const failResults = scResults.filter((r) => {
          const s = (r.status || r.returnCode || '').toString().toLowerCase();
          return s === 'fail' || (s !== 'success' && s !== 'ok' && s !== '0' && s !== 'completed');
        });
        if (failResults.length > 0) {
          const msg = failResults[0].returnMessage || failResults[0].message || 'Smart contract execution failed';
          return { txHash: hash, status: 'fail', details: String(msg) };
        }
      }

      return { txHash: hash, status: 'success', details: null };
    } catch (error) {
      if (i === maxRetries - 1) {
        return { txHash: hash, status: 'unknown', details: `Failed to check status: ${error.message}` };
      }
      await new Promise((r) => setTimeout(r, retryInterval));
    }
  }

  return { txHash: hash, status: 'timeout', details: `Timed out after ${maxRetries} attempts` };
}

