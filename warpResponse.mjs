import { classifyBusinessOutcome } from './usageFeeEngine.mjs';

export function filterResponseFields(response, fields) {
  if (!fields || !Array.isArray(fields) || fields.length === 0) return response;
  const filtered = {};
  for (const key of fields) {
    if (key in response) filtered[key] = response[key];
  }
  return filtered;
}

export function presentWarpResponse(res, cleanResponse, fields) {
  res.makexBusinessOutcome = cleanResponse;
  return filterResponseFields(cleanResponse, fields);
}

export function warpResponseLogMessage(cleanResponse) {
  return classifyBusinessOutcome(200, cleanResponse) === 'confirmed'
    ? 'Sending response'
    : 'Sending non-success response';
}
