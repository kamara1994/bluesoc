/**
 * BLUE SOC private backend for Vercel.
 * All credentials stay in server-side environment variables.
 * Never expose a JSONBin master key or private n8n webhooks in browser code.
 */
import { timingSafeEqual } from 'node:crypto';

const NO_STORE = 'private, no-store, max-age=0';
const MAX_MESSAGE = 2000;
const waitMs = 9000;

function fail(res, status, message) {
  return res.status(status).json({ ok: false, error: message });
}
function clip(value, size = 500) {
  return String(value ?? '').slice(0, size);
}
function boundedNumber(value) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.max(0, Math.floor(n)) : 0;
}
function isAuthorized(req) {
  const expected = process.env.BLUE_SOC_ADMIN_TOKEN || '';
  const auth = req.headers.authorization || '';
  const supplied = typeof auth === 'string' && auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (expected.length < 24 || !supplied || supplied.length !== expected.length) return false;
  return timingSafeEqual(Buffer.from(supplied), Buffer.from(expected));
}
function originAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    const url = new URL(origin);
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    return url.protocol === 'https:' && url.host === host
      || (process.env.NODE_ENV !== 'production' && url.protocol === 'http:' && url.host === host);
  } catch {
    return false;
  }
}
function urlFromEnv(key) {
  const raw = process.env[key];
  if (!raw) return null;
  try {
    const url = new URL(raw);
    return url.protocol === 'https:' ? url.href : null;
  } catch {
    return null;
  }
}
async function requestUpstream(url, init) {
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(waitMs) });
  if (!response.ok) throw new Error('upstream HTTP ' + response.status);
  return response;
}
function normalizeRecord(record) {
  const data = record && typeof record === 'object' && !Array.isArray(record) ? record : {};
  const events = Array.isArray(data.events) ? data.events.slice(-100).map(e => ({
    event_type: clip(e?.event_type || e?.type || 'event', 90),
    severity: clip(e?.severity || 'info', 25).toLowerCase(),
    timestamp: clip(e?.timestamp || '', 64),
    message: clip(e?.message || '', 500),
    source_ip: clip(e?.source_ip || '', 64),
    dest_ip: clip(e?.dest_ip || '', 64),
  })) : [];
  const blocked_ips = Array.isArray(data.blocked_ips) ? data.blocked_ips.slice(-100).map(b => {
    if (typeof b === 'string') return { ip: clip(b, 64), reason: 'Reported block', time: '' };
    return {
      ip: clip(b?.ip || '', 64),
      reason: clip(b?.reason || 'Reported block', 200),
      time: clip(b?.time || b?.timestamp || '', 64),
    };
  }) : [];
  let analysis = data.analysis;
  if (typeof analysis === 'string') {
    try { analysis = JSON.parse(analysis); } catch { analysis = { summary: clip(analysis, 750) }; }
  }
  if (!analysis || typeof analysis !== 'object' || Array.isArray(analysis)) analysis = {};
  return {
    events,
    blocked_ips,
    runs: boundedNumber(data.runs),
    last_run: clip(data.last_run || '', 64),
    analysis: {
      threat_level: clip(analysis.threat_level || '', 24),
      offending_ip: clip(analysis.offending_ip || '', 64),
      activity: clip(analysis.activity || analysis.summary || '', 500),
    },
    fetched_at: new Date().toISOString(),
    source: 'jsonbin',
  };
}
async function telemetry(req, res) {
  const binId = process.env.BLUE_SOC_JSONBIN_ID || '';
  const key = process.env.BLUE_SOC_JSONBIN_READ_KEY || process.env.BLUE_SOC_JSONBIN_MASTER_KEY || '';
  if (!/^[a-zA-Z0-9]{12,40}$/.test(binId) || !key)
    return fail(res, 503, 'Telemetry is not configured on the server');
  const header = process.env.BLUE_SOC_JSONBIN_READ_KEY ? 'X-Access-Key' : 'X-Master-Key';
  try {
    const response = await requestUpstream(
      'https://api.jsonbin.io/v3/b/' + encodeURIComponent(binId) + '/latest',
      { headers: { [header]: key, 'X-Bin-Meta': 'false' } },
    );
    const result = await response.json();
    const record = result?.record ?? result;
    return res.status(200).json({ ok: true, data: normalizeRecord(record) });
  } catch {
    return fail(res, 502, 'Telemetry source unavailable');
  }
}
async function webhook(res, action, data) {
  const envKey = action === 'scan' ? 'BLUE_SOC_SCAN_WEBHOOK' : 'BLUE_SOC_CHAT_WEBHOOK';
  const url = urlFromEnv(envKey);
  if (!url) return fail(res, 503, 'This workflow is not configured');
  if (action === 'scan' && process.env.BLUE_SOC_ALLOW_SCAN !== 'true')
    return fail(res, 403, 'Scan triggering is disabled by the administrator');
  try {
    const response = await requestUpstream(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (action === 'scan') return res.status(202).json({ ok: true, message: 'Workflow request accepted; verification pending' });
    const raw = await response.text();
    let responseData;
    try { responseData = JSON.parse(raw); } catch { responseData = raw; }
    if (Array.isArray(responseData)) responseData = responseData[0];
    const reply = typeof responseData === 'string' ? responseData :
      responseData?.reply ?? responseData?.response ?? responseData?.output ??
      responseData?.message ?? 'The workflow returned no response.';
    return res.status(200).json({ ok: true, reply: clip(reply, 2000) });
  } catch {
    return fail(res, 502, 'The configured workflow did not respond');
  }
}
export default async function handler(req, res) {
  res.setHeader('Cache-Control', NO_STORE);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  if (!isAuthorized(req)) return fail(res, 401, 'Authentication required');
  if (!originAllowed(req)) return fail(res, 403, 'Request origin not allowed');
  if (req.method === 'GET') return telemetry(req, res);
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST');
    return fail(res, 405, 'Method not allowed');
  }
  const data = req.body && typeof req.body === 'object' ? req.body : {};
  if (data.action === 'scan') return webhook(res, 'scan', {
    source: 'blue-soc-admin-dashboard',
    timestamp: new Date().toISOString(),
    approved: true,
  });
  if (data.action === 'chat') {
    const message = typeof data.message === 'string' ? data.message.trim() : '';
    if (!message || message.length > MAX_MESSAGE) return fail(res, 400, 'Invalid message');
    return webhook(res, 'chat', {
      message,
      source: 'blue-soc-admin-dashboard',
      mode: data.mode === 'telegram' ? 'telegram' : 'dashboard',
      timestamp: new Date().toISOString(),
    });
  }
  return fail(res, 400, 'Unknown action');
}
