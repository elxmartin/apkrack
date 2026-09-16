const encoder = new TextEncoder();
const decoder = new TextDecoder();
const TOKEN_TTL_SECONDS = 8 * 60 * 60;
const ALLOWED_REPORT_FILES = new Set(['secrets.txt.enc', 'mobsfscan.json.enc', 'cve.json.enc']);

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const headers = responseHeaders(request, env);

    if (request.method === 'OPTIONS') return new Response(null, { headers });
    if (!isAllowedOrigin(request, env)) return textResponse('Forbidden', 403, headers);

    try {
      if (url.pathname === '/api/login' && request.method === 'POST') {
        return await handleLogin(request, env, headers);
      }

      const session = await authenticateRequest(request, env);
      if (!session) return textResponse('Unauthorized', 401, headers);

      if (url.pathname === '/api/status' && request.method === 'GET') {
        return await fetchProtectedAsset('/status.enc', env, headers);
      }
      if (url.pathname === '/api/report' && request.method === 'GET') {
        return await handleReportRequest(url, env, headers);
      }

      return textResponse('Not found', 404, headers);
    } catch (error) {
      console.error('Workspace gateway error', error);
      return textResponse('Service unavailable', 503, headers);
    }
  }
};

async function handleLogin(request, env, headers) {
  if (!env.DASHBOARD_USERNAME || !env.DASHBOARD_PASSWORD_HASH || !env.AUTH_SESSION_SECRET) {
    console.error('Required authentication secrets are not configured.');
    return textResponse('Service unavailable', 503, headers);
  }

  let credentials;
  try {
    credentials = await request.json();
  } catch {
    return textResponse('Invalid credentials', 401, headers);
  }

  const username = typeof credentials.username === 'string' ? credentials.username : '';
  const password = typeof credentials.password === 'string' ? credentials.password : '';
  const validUsername = await timingSafeEqual(username, env.DASHBOARD_USERNAME);
  const validPassword = await verifyPassword(password, env.DASHBOARD_PASSWORD_HASH);
  if (!validUsername || !validPassword) return textResponse('Invalid credentials', 401, headers);

  const now = Math.floor(Date.now() / 1000);
  const token = await signSession({ iat: now, exp: now + TOKEN_TTL_SECONDS }, env.AUTH_SESSION_SECRET);
  return jsonResponse({ token, expiresAt: now + TOKEN_TTL_SECONDS }, 200, headers);
}

async function authenticateRequest(request, env) {
  if (!env.AUTH_SESSION_SECRET) return false;
  const authorization = request.headers.get('Authorization') || '';
  if (!authorization.startsWith('Bearer ')) return false;
  const payload = await verifySession(authorization.slice(7), env.AUTH_SESSION_SECRET);
  return payload && payload.exp > Math.floor(Date.now() / 1000);
}

async function handleReportRequest(url, env, headers) {
  const id = url.searchParams.get('id') || '';
  const file = url.searchParams.get('file') || '';
  if (!/^[a-f0-9]{64}$/.test(id) || !ALLOWED_REPORT_FILES.has(file)) {
    return textResponse('Not found', 404, headers);
  }
  return fetchProtectedAsset(`/reports/${id}/${file}`, env, headers);
}

async function fetchProtectedAsset(path, env, headers) {
  const siteOrigin = (env.PUBLIC_SITE_ORIGIN || 'https://elxmartin.github.io/apkrack').replace(/\/$/, '');
  const assetResponse = await fetch(`${siteOrigin}${path}`, { cf: { cacheTtl: 60, cacheEverything: true } });
  if (!assetResponse.ok) return textResponse('Not found', assetResponse.status, headers);
  return new Response(assetResponse.body, {
    status: 200,
    headers: { ...headers, 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }
  });
}

async function verifyPassword(password, storedHash) {
  // Stored form: pbkdf2-sha256$iterations$base64-salt$base64-hash
  const parts = storedHash.split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2-sha256' || !/^\d+$/.test(parts[1])) return false;
  const iterations = Number(parts[1]);
  if (iterations < 100000 || iterations > 1000000) return false;
  try {
    const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: fromBase64(parts[2]), iterations }, key, 256
    );
    return timingSafeEqualBytes(new Uint8Array(bits), fromBase64(parts[3]));
  } catch {
    return false;
  }
}

async function signSession(payload, secret) {
  const encodedPayload = toBase64Url(encoder.encode(JSON.stringify(payload)));
  const signature = await hmac(encodedPayload, secret);
  return `${encodedPayload}.${toBase64Url(signature)}`;
}

async function verifySession(token, secret) {
  const [encodedPayload, encodedSignature, ...extra] = token.split('.');
  if (!encodedPayload || !encodedSignature || extra.length) return false;
  const expected = await hmac(encodedPayload, secret);
  if (!timingSafeEqualBytes(expected, fromBase64Url(encodedSignature))) return false;
  try {
    const payload = JSON.parse(decoder.decode(fromBase64Url(encodedPayload)));
    return Number.isSafeInteger(payload.iat) && Number.isSafeInteger(payload.exp) ? payload : false;
  } catch {
    return false;
  }
}

async function hmac(value, secret) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(value)));
}

async function timingSafeEqual(value, expected) {
  return timingSafeEqualBytes(encoder.encode(value), encoder.encode(expected));
}

function timingSafeEqualBytes(left, right) {
  const maxLength = Math.max(left.length, right.length);
  let difference = left.length ^ right.length;
  for (let i = 0; i < maxLength; i++) difference |= (left[i % left.length] || 0) ^ (right[i % right.length] || 0);
  return difference === 0;
}

function responseHeaders(request, env) {
  return {
    'Access-Control-Allow-Origin': env.DASHBOARD_ORIGIN || 'https://elxmartin.github.io',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Vary': 'Origin',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer'
  };
}

function isAllowedOrigin(request, env) {
  const origin = request.headers.get('Origin');
  return !origin || origin === (env.DASHBOARD_ORIGIN || 'https://elxmartin.github.io');
}

function jsonResponse(body, status, headers) {
  return new Response(JSON.stringify(body), { status, headers: { ...headers, 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
}

function textResponse(body, status, headers) {
  return new Response(body, { status, headers: { ...headers, 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } });
}

function fromBase64(value) {
  return Uint8Array.from(atob(value), char => char.charCodeAt(0));
}

function fromBase64Url(value) {
  return fromBase64(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4));
}

function toBase64Url(bytes) {
  let binary = '';
  bytes.forEach(byte => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
