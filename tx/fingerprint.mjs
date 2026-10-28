import { createHash } from 'node:crypto';

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

function headerValue(req, name) {
  const headers = req?.headers || {};
  const raw = headers[name] || headers[name.toLowerCase()] || '';
  return Array.isArray(raw) ? raw[0] : raw;
}

function cleanKey(value) {
  const key = String(value || '').trim();
  if (!key || key.includes('{{') || key.includes('}}')) return '';
  if (key.length > 200) {
    throw new Error('idempotencyKey must be 200 characters or fewer');
  }
  return key;
}

/**
 * A retry of the same Make module must reuse one key.
 * An explicit key keeps two identical payments separate.
 * Without one, the key is the canonical request fingerprint, so a retry cannot
 * create a second fee. It is not a random value.
 */
export function readIdempotencyKey(req) {
  const explicit = cleanKey(headerValue(req, 'x-makex-idempotency-key') || req?.body?.idempotencyKey);
  if (explicit) return { key: explicit, ephemeral: false, source: 'client' };

  const scenario = cleanKey(headerValue(req, 'x-makex-scenario-id'));
  const execution = cleanKey(headerValue(req, 'x-makex-execution-id'));
  const moduleId = cleanKey(headerValue(req, 'x-makex-module-id'));
  if (scenario && execution && moduleId) {
    return {
      key: `make:${scenario}:${execution}:${moduleId}`,
      ephemeral: false,
      source: 'make',
    };
  }

  return {
    key: `request:${fingerprintRequest(req)}`,
    ephemeral: false,
    source: 'request',
  };
}
