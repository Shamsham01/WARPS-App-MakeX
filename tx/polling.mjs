import { interpretTransactionRecord } from '../makexStandard.mjs';

const RETRYABLE_HTTP = new Set([429, 502, 503, 504]);

/**
 * The public `/transactions/{hash}` resource is the transaction itself.
 * It includes sender, receiver, nonce, base64 `data`, and hex `signature`.
 * `chainID` is often absent; keep it only when the API sends one.
 */
export function apiTransactionRecord(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  const looksLikeTransaction = body.sender != null || body.txHash != null || body.nonce != null || body.status != null;
  if (!looksLikeTransaction) return null;
  const chainID = body.chainID ?? body.chainId;
  const record = {
    sender: body.sender == null ? '' : String(body.sender),
    receiver: body.receiver == null ? '' : String(body.receiver),
    nonce: body.nonce,
    data: body.data == null ? '' : String(body.data),
    signature: body.signature == null ? '' : String(body.signature),
  };
  if (chainID != null && String(chainID) !== '') record.chainID = String(chainID);
  return record;
}

export async function fetchTransactionStatus(txHash, fetchImpl, apiBase = 'https://api.multiversx.com') {
  const hash = String(txHash);
  const url = `${apiBase}/transactions/${encodeURIComponent(hash)}?withResults=true`;
  let response;
  try {
    response = await fetchImpl(url, { headers: { Accept: 'application/json' } });
  } catch (error) {
    return { status: 'unknown', details: `Failed to check status: ${error.message}` };
  }

  if (response.status === 404) return { status: 'not_found', details: null };
  if (RETRYABLE_HTTP.has(response.status)) {
    return { status: 'unknown', details: `MultiversX API ${response.status}` };
  }
  if (!response.ok) {
    const text = await response.text().catch(() => '');
    return { status: 'unknown', details: `MultiversX API ${response.status} ${text}`.trim() };
  }

  try {
    const body = await response.json();
    const interpreted = interpretTransactionRecord(body);
    const transaction = apiTransactionRecord(body);
    return transaction ? { ...interpreted, transaction } : interpreted;
  } catch (error) {
    return { status: 'unknown', details: `Failed to read transaction status: ${error.message}` };
  }
}

export async function pollTransaction({
  txHash,
  fetchStatus,
  maxMs,
  intervalMs,
  maxIntervalMs,
  backoff,
  onTick,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
}) {
  const started = Date.now();
  let interval = intervalMs;
  let last = { status: 'pending', details: null };

  while (Date.now() - started <= maxMs) {
    if (onTick) await onTick();
    last = await fetchStatus(txHash);
    if (last.status === 'success' || last.status === 'fail') return last;
    const elapsed = Date.now() - started;
    if (elapsed >= maxMs) break;
    await sleep(Math.min(interval, maxMs - elapsed));
    interval = Math.min(Math.round(interval * backoff), maxIntervalMs);
  }

  if (last.status === 'not_found') {
    return { status: 'timeout', details: 'Timed out before the transaction was visible' };
  }
  if (last.status === 'unknown') {
    return { status: 'unknown', details: last.details || 'Transaction status could not be determined' };
  }
  return { status: 'timeout', details: last.details || 'Timed out while the transaction was still pending' };
}
