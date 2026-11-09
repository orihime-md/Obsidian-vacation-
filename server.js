'use strict';
/**
 * OBSIDIAN · Vacation Checker — Render backend (zero dependencies, Node >= 18)
 *
 * Environment variables (set them in Render > Environment):
 *   APP_PASSWORD       the password people must enter in the app      (required)
 *   BANCHECK_API_KEY   your Baron API key                             (required)
 *   TOKEN_SECRET       any long random string (signs login tokens)    (recommended)
 *   ALLOWED_ORIGIN     lock CORS to your app origin, default "*"      (optional)
 */
const http = require('http');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;
const APP_PASSWORD = process.env.APP_PASSWORD || '';
const BARON_KEY = process.env.BANCHECK_API_KEY || '';
const BARON_BASE = 'https://baron0.com';
const ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const SECRET = process.env.TOKEN_SECRET || crypto.randomBytes(32).toString('hex');
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000;

if (!APP_PASSWORD) console.warn('[warn] APP_PASSWORD is not set — nobody can log in.');
if (!BARON_KEY) console.warn('[warn] BANCHECK_API_KEY is not set — checks will fail.');

// ── helpers ──
const pad = (n) => String(n).padStart(2, '0');
function utcStamp(value) {
  if (!value) return 'Not reported';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value).slice(0, 40);
  return `${pad(d.getUTCDate())}.${pad(d.getUTCMonth() + 1)}.${d.getUTCFullYear()} ${pad(d.getUTCHours())}.${pad(d.getUTCMinutes())} UTC`;
}
function clip(value, max = 60) {
  const t = String(value ?? '').replace(/\s+/g, ' ').trim();
  if (!t) return 'Not reported';
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}
function normalizeNumber(input) {
  if (!input) return null;
  let n = String(input).replace(/[^0-9+]/g, '');
  if (n.startsWith('+')) n = n.slice(1);
  n = n.replace(/\D/g, '');
  if (n.length < 8 || n.length > 15) return null;
  return n;
}
const pick = (obj, keys) => {
  for (const k of keys) {
    const v = obj?.[k];
    if (v !== undefined && v !== null && v !== '') return v;
  }
  return undefined;
};
// Flatten any nested response into { lowercasedKey: value } (leaf keys, first one wins)
function flatten(obj, out = {}, depth = 0) {
  if (!obj || typeof obj !== 'object' || depth > 4) return out;
  for (const [k, v] of Object.entries(obj)) {
    if (v && typeof v === 'object') flatten(v, out, depth + 1);
    else if (v !== undefined && v !== null && v !== '' && !(k.toLowerCase() in out)) out[k.toLowerCase()] = v;
  }
  return out;
}
const asBool = (v) => {
  if (typeof v === 'boolean') return v;
  if (typeof v === 'number') return v === 1 ? true : v === 0 ? false : undefined;
  if (typeof v === 'string') {
    if (/^(true|yes|y|1)$/i.test(v.trim())) return true;
    if (/^(false|no|n|0)$/i.test(v.trim())) return false;
  }
  return undefined;
};
/**
 * Works out permanent / temporary from whatever the checker sends:
 *  1. an explicit flag (permanent, isPermanent, is_permanent, perm ...)
 *  2. a "temporary" flag (temporary, isTemporary ...) – inverted
 *  3. text in type/status/duration fields containing "perm" or "temp"
 *  4. an expiry / unban / remaining-time field → temporary
 *  5. text in the reason containing "permanent" / "temporar"
 */
function detectPermanence(flat) {
  for (const [k, v] of Object.entries(flat)) {
    if (/^(is_?)?perm(anent)?(_?ban(ned)?)?$/.test(k)) { const b = asBool(v); if (b !== undefined) return b; }
  }
  for (const [k, v] of Object.entries(flat)) {
    if (/^(is_?)?temp(orary)?(_?ban(ned)?)?$/.test(k)) { const b = asBool(v); if (b !== undefined) return !b; }
  }
  for (const [k, v] of Object.entries(flat)) {
    if (typeof v === 'string' && /(type|status|kind|duration|severity|ban)/.test(k)) {
      if (/perm/i.test(v)) return true;
      if (/temp/i.test(v)) return false;
    }
  }
  for (const [k, v] of Object.entries(flat)) {
    if (/(expire|expiry|expires|until|unban|ends?_?at|remaining|lift)/.test(k) && v) return false;
  }
  for (const [k, v] of Object.entries(flat)) {
    if (typeof v === 'string' && /(reason|message|detail|description|note)/.test(k)) {
      if (/permanent/i.test(v)) return true;
      if (/temporar/i.test(v)) return false;
    }
  }
  return undefined;
}

// ── Baron API (same logic as the bot) ──
async function checkNumber(number) {
  if (!BARON_KEY) throw Object.assign(new Error('Service is not configured.'), { status: 503 });
  let res;
  try {
    res = await fetch(`${BARON_BASE}/api/v2/check`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${BARON_KEY}`,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({ number: `+${number}` }),
      signal: AbortSignal.timeout(20000),
    });
  } catch (e) {
    console.error('[baron] request failed:', e.message);
    throw Object.assign(new Error('Checker is not responding. Try again.'), { status: 504 });
  }
  let body;
  try { body = await res.json(); } catch (_) {
    console.error('[baron] non-JSON, HTTP', res.status);
    throw Object.assign(new Error('Checker returned an invalid response.'), { status: 502 });
  }
  if (!res.ok) {
    console.error('[baron] error:', res.status, body?.title || '', body?.detail || body?.error || '');
    throw Object.assign(new Error('Checker error. Try again shortly.'), { status: 502 });
  }
  if (typeof body?.banned !== 'boolean') {
    throw Object.assign(new Error('Checker returned an invalid result.'), { status: 502 });
  }
  const flat = flatten(body);
  if (process.env.DEBUG_RAW) {
    console.log('[baron] raw keys:', JSON.stringify(Object.fromEntries(Object.entries(flat).map(([k, v]) => [k, typeof v === 'string' ? v.slice(0, 40) : v]))));
  }
  const banType = pick(flat, ['bantype', 'ban_type', 'type', 'bankind', 'ban_kind', 'category']);
  return {
    banned: body.banned,
    reason: pick(flat, ['reason', 'banreason', 'ban_reason']),
    banType: typeof banType === 'string' ? banType : undefined,
    permanent: detectPermanence(flat),
    review: pick(flat, ['review', 'reviewnote', 'review_status', 'reviewstatus']),
    bannedAt: pick(flat, ['bannedat', 'banned_at', 'bannedon', 'banned_on', 'bandate', 'ban_date']),
  };
}

function describe(number, data, now = new Date()) {
  const permanence = data.permanent === true ? 'Permanent' : data.permanent === false ? 'Temporary' : 'Not reported';
  const type = data.banType ? clip(data.banType, 30) : null;
  return {
    number: `+${number}`,
    banned: data.banned === true,
    statusText: data.banned ? '🔴 𝐁𝐀𝐍𝐍𝐄𝐃' : '🟢 𝐀𝐂𝐓𝐈𝐕𝐄',
    plainStatus: data.banned ? 'BANNED' : 'ACTIVE',
    vacationLine: data.banned
      ? (data.permanent === true ? 'ON A PERMANENT VACATION' : 'ON A VACATION')
      : 'NO RESTRICTION FOUND',
    reason: clip(data.reason, 120),
    permanence: type ? `${permanence} • ${type}` : permanence,
    bannedAt: utcStamp(data.bannedAt),
    review: data.review ? `${clip(data.review, 120)} • ${utcStamp(now)}` : `No review available • ${utcStamp(now)}`,
    checkedAt: utcStamp(now),
  };
}

// Exact same message the bot sends
function banCheckText(d) {
  return [
    '╭━━━━━━━━━━━━━━━━━━╮',
    '┃ 𓆩 『 O B S I D I A N 』 𓆪',
    '┃ 𝐕𝐀𝐂𝐀𝐓𝐈𝐎𝐍 𝐂𝐇𝐄𝐂𝐊𝐄𝐑',
    '┣━━━━━━━━━━━━━━━━━━',
    '┃ ☎️ 𝐍𝐔𝐌𝐁𝐄𝐑',
    `┃ ${d.number}`,
    '┣━━━━━━━━━━━━━━━━━━',
    '┃ 𝐒𝐓𝐀𝐓𝐔𝐒',
    `┃ ${d.statusText}`,
    ...(d.banned
      ? ['┃ ⫷ OBSIDIAN SENT THIS USER', `┃ ${d.vacationLine} ⫸`]
      : ['┃ ⫷ NO RESTRICTION FOUND ⫸']),
    '┣━━━━━━━━━━━━━━━━━━',
    '┃ 𝐑𝐄𝐀𝐒𝐎𝐍',
    `┃ ${d.reason}`,
    '┣━━━━━━━━━━━━━━━━━━',
    '┃ 𝐏𝐄𝐑𝐌𝐀𝐍𝐄𝐍𝐂𝐘 / 𝐓𝐘𝐏𝐄',
    `┃ ${d.permanence}`,
    '┣━━━━━━━━━━━━━━━━━━',
    '┃ 𝐑𝐄𝐕𝐈𝐄𝐖',
    `┃ ${d.review}`,
    '┣━━━━━━━━━━━━━━━━━━',
    '┃ 𝐁𝐀𝐍𝐍𝐄𝐃 𝐀𝐓',
    `┃ ${d.bannedAt}`,
    '╰━━━━━━━━━━━━━━━━━━╯',
    '',
    '⫷╱◈╲⫸ 『 O B S I D I A N 』 ⫷╱◈╲⫸',
    '',
    'Results depend on the checker service. Invalid or missing fields are not independently verified.',
  ].join('\n');
}

// ── auth tokens (HMAC signed, stateless) ──
const b64 = (b) => Buffer.from(b).toString('base64url');
function signToken() {
  const payload = b64(JSON.stringify({ exp: Date.now() + TOKEN_TTL_MS }));
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}
function verifyToken(token) {
  if (!token || typeof token !== 'string') return false;
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return false;
  const good = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(good);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  try { return JSON.parse(Buffer.from(payload, 'base64url').toString()).exp > Date.now(); } catch (_) { return false; }
}
function safeEqual(x, y) {
  const a = crypto.createHash('sha256').update(String(x)).digest();
  const b = crypto.createHash('sha256').update(String(y)).digest();
  return crypto.timingSafeEqual(a, b);
}

// ── tiny rate limiter ──
const hits = new Map();
function limited(key, max, windowMs) {
  const now = Date.now();
  const arr = (hits.get(key) || []).filter((t) => now - t < windowMs);
  arr.push(now);
  hits.set(key, arr);
  if (hits.size > 5000) hits.clear();
  return arr.length > max;
}

// ── server ──
function send(res, status, obj) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': ORIGIN,
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Cache-Control': 'no-store',
  });
  res.end(JSON.stringify(obj));
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > 10_000) { reject(Object.assign(new Error('Too large'), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString() || '{}')); } catch (_) { reject(Object.assign(new Error('Bad request'), { status: 400 })); } });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  const url = new URL(req.url, 'http://x');
  try {
    if (req.method === 'OPTIONS') return send(res, 204, {});

    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/api/health')) {
      return send(res, 200, { ok: true });
    }

    if (req.method === 'POST' && url.pathname === '/api/login') {
      if (limited(`login:${ip}`, 8, 10 * 60 * 1000)) return send(res, 429, { error: 'Too many attempts. Wait a few minutes.' });
      const { password } = await readJson(req);
      if (!APP_PASSWORD || !safeEqual(password || '', APP_PASSWORD)) return send(res, 401, { error: 'Wrong password.' });
      return send(res, 200, { token: signToken() });
    }

    if (req.method === 'POST' && url.pathname === '/api/check') {
      const auth = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
      if (!verifyToken(auth)) return send(res, 401, { error: 'Session expired. Enter the password again.' });
      if (limited(`check:${ip}`, 30, 60 * 1000)) return send(res, 429, { error: 'Slow down a little.' });
      const { number: raw } = await readJson(req);
      const number = normalizeNumber(raw);
      if (!number) return send(res, 400, { error: 'Enter a valid number with country code.' });
      const data = await checkNumber(number);
      const d = describe(number, data, new Date());
      return send(res, 200, { data: d, text: banCheckText(d) });
    }

    return send(res, 404, { error: 'Not found' });
  } catch (e) {
    return send(res, e.status || 500, { error: e.status ? e.message : 'Something went wrong.' });
  }
});

server.listen(PORT, () => console.log(`[obsidian] listening on ${PORT}`));
