import { redactPemFromString } from '../makexStandard.mjs';

export class TxCoordinationError extends Error {
  constructor(code, message, extra = {}) {
    super(redactPemFromString(message));
    this.name = 'TxCoordinationError';
    this.code = code;
    this.retryable = extra.retryable === true;
    this.httpStatus = extra.httpStatus || (this.retryable ? 503 : 400);
    this.operationId = extra.operationId || null;
    this.txHash = extra.txHash || null;
    this.nonce = extra.nonce ?? null;
    this.state = extra.state || null;
    this.errorClass = extra.errorClass || null;
  }
}

export function classifySendError(error) {
  const message = String(error?.message || error || '').toLowerCase();
  const httpStatus = Number(error?.status || error?.statusCode || error?.response?.status || 0);
  const lower = message.includes('lowernonceintx') || message.includes('lower nonce');
  const veryHigh = message.includes('veryhighnonceintx') || message.includes('very high nonce');
  const explicitReject =
    lower ||
    veryHigh ||
    message.includes('transaction generation failed') ||
    message.includes('invalid transaction');
  const ambiguousHttp = httpStatus === 429 || httpStatus === 502 || httpStatus === 503 || httpStatus === 504;
  const ambiguousText =
    message.includes('timeout') ||
    message.includes('timed out') ||
    message.includes('econnreset') ||
    message.includes('econnrefused') ||
    message.includes('socket') ||
    message.includes('network') ||
    message.includes('fetch failed');

  if (explicitReject && !ambiguousHttp) {
    return { kind: 'rejected', lower, veryHigh, httpStatus };
  }
  if (ambiguousHttp || ambiguousText || !explicitReject) {
    return { kind: 'ambiguous', lower, veryHigh, httpStatus };
  }
  return { kind: 'ambiguous', lower, veryHigh, httpStatus };
}

export function safeErrorDetail(error) {
  return redactPemFromString(String(error?.message || error || 'unknown error')).slice(0, 500);
}
