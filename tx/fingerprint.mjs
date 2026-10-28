import { createHash, randomUUID } from 'node:crypto';

const SECRET_KEYS = new Set([
  'walletpem',
  'pemcontent',
  'privatekey',
  'authorization',
  'secure_token',
  'password',
  'secret',
  'idempotencykey',
]);

function canonicalize(value) {
  if (Array.isArray(value)) return value.map((item) => canonicalize(item));
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      if (SECRET_KEYS.has(key.toLowerCase())) continue;
      out[key] = canonicalize(value[key]);
    }
    return out;
  }
  return value;
}

export function fingerprintRequest(req) {
  const body = req?.body && typeof req.body === 'object' ? req.body : {};
  const payload = {
    method: req?.method || 'POST',
    path: req?.path || req?.originalUrl || '',
    body: canonicalize(body),
  };
  return createHash('sha256').update(JSON.stringify(payload)).digest('hex');
}

export function readIdempotencyKey(req) {
  const header = req?.headers?.['x-makex-idempotency-key'] || req?.headers?.['X-MakeX-Idempotency-Key'];
  const bodyKey = req?.body?.idempotencyKey;
  const key = String(header || bodyKey || '').trim();
  if (!key) {
    return { key: `ephemeral:${randomUUID()}`, ephemeral: true };
  }
  if (key.length > 200) {
    throw new Error('idempotencyKey must be 200 characters or fewer');
  }
  return { key, ephemeral: false };
}
