import assert from 'node:assert/strict';
import pg from 'pg';

export const IDP = process.env.TEST_IDP || 'http://localhost:8000';
export const RP = process.env.TEST_RP || 'http://localhost:8001';
export const DB_URL = process.env.DATABASE_URL || 'postgres://postgres:test123@127.0.0.1:5433/auth_test';

export const ACCOUNT = process.env.TEST_ACCOUNT || 'oidcuser';
export const PASSWORD = process.env.TEST_PASSWORD || 'Passw0rd!123';

/** 极简 cookie jar：跨 redirect 保存 Set-Cookie */
export class CookieJar {
  constructor() {
    this.map = new Map();
  }

  store(res) {
    const list = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
    for (const raw of list) {
      const [pair] = raw.split(';');
      const eq = pair.indexOf('=');
      if (eq < 0) continue;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      const expired = /max-age=0/i.test(raw) || value === '';
      if (expired) this.map.delete(name);
      else this.map.set(name, value);
    }
  }

  header() {
    return [...this.map.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  clear() {
    this.map.clear();
  }
}

export function absolutize(location, base) {
  if (!location) return null;
  if (/^https?:\/\//.test(location)) return location;
  return new URL(location, base).href;
}

async function send(jar, url, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  const cookie = jar.header();
  if (cookie) headers.cookie = cookie;

  const res = await fetch(url, { ...opts, headers, redirect: 'manual' });
  jar.store(res);
  return res;
}

export function get(jar, url) {
  return send(jar, url);
}

export function postForm(jar, url, data) {
  return send(jar, url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(data).toString(),
  });
}

/** 服务可达性检查 */
export async function assertUp(url, name) {
  try {
    const res = await fetch(url, { redirect: 'manual' });
    assert.ok(res.status < 500, `${name} 返回 ${res.status}`);
  } catch (e) {
    throw new Error(
      `${name} 不可达（${url}）。请先启动：\n` +
        '  cd poc && node src/server.js\n' +
        '  cd poc && node src/rp-demo.js'
    );
  }
}

/**
 * 走完整授权流程：RP 发起 → IdP 登录页 → 提交账号 → （consent 自动通过）→ RP 回调
 * 返回 { ok, error, interactionUrl }
 */
export async function authorize(jar, {
  account = ACCOUNT,
  password = PASSWORD,
  totp = '',
  scope = 'openid email profile offline_access',
} = {}) {
  let res = await get(jar, `${RP}/login`);
  let loc = res.headers.get('location');
  assert.ok(loc, 'RP /login 应当重定向到 IdP');

  res = await get(jar, loc);
  loc = res.headers.get('location');
  assert.ok(loc && loc.includes('/interaction/'), `IdP 应重定向到交互页，实际: ${loc}`);

  const interactionUrl = absolutize(loc, IDP);

  res = await get(jar, interactionUrl);
  const page = await res.text();
  assert.match(page, /认证中心/, '应渲染自定义登录页');

  res = await postForm(jar, interactionUrl, { login: account, password, totp });

  if (res.status !== 303) {
    const body = await res.text();
    const m = body.match(/<div class="err">([^<]*)<\/div>/);
    return { ok: false, error: m ? m[1] : `HTTP ${res.status}`, interactionUrl };
  }

  // 303 之后可能还要经过一次 consent 交互，循环跟随直到 callback
  loc = res.headers.get('location');
  let hops = 0;
  let callbackUrl = null;
  while (loc && hops < 6) {
    hops += 1;
    const url = absolutize(loc, IDP);
    res = await get(jar, url);
    if (url.startsWith(`${RP}/callback`)) {
      callbackUrl = url;
      break;
    }
    loc = res.headers.get('location');
  }

  return { ok: true, callbackUrl, interactionUrl };
}

/** 用当前会话查 RP 的会话状态 */
export async function rpSession(jar) {
  const res = await get(jar, `${RP}/me`);
  if (res.status !== 200) return null;
  return res.json();
}

/** 直接连库（测试需要改 TOTP / 状态） */
export function dbClient() {
  return new pg.Client({ connectionString: DB_URL });
}

// ---------- 直连 IdP 的授权流程（不经 RP，用于测试 token 端点） ----------

import crypto from 'node:crypto';

export const CLIENT_ID = process.env.TEST_CLIENT_ID || 'demo-app';
export const CLIENT_SECRET = process.env.TEST_CLIENT_SECRET || 'demo-secret';
export const REDIRECT_URI = `${RP}/callback`;

export async function rawAuthorize(jar, {
  account = ACCOUNT,
  password = PASSWORD,
  totp = '',
  scope = 'openid email profile offline_access',
} = {}) {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');

  const qs = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope,
    prompt: 'consent',
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });

  let res = await get(jar, `${IDP}/auth?${qs}`);
  let loc = res.headers.get('location');
  assert.ok(loc && loc.includes('/interaction/'), `应跳转交互页，实际 ${loc}`);
  const interactionUrl = absolutize(loc, IDP);
  await get(jar, interactionUrl);

  res = await postForm(jar, interactionUrl, { login: account, password, totp });
  assert.equal(res.status, 303, '登录提交应返回 303');

  loc = res.headers.get('location');
  for (let i = 0; i < 6 && loc; i += 1) {
    const url = absolutize(loc, IDP);
    if (url.startsWith(REDIRECT_URI)) {
      const u = new URL(url);
      return {
        code: u.searchParams.get('code'),
        error: u.searchParams.get('error'),
        verifier,
        state,
        nonce,
        callbackUrl: url,
      };
    }
    res = await get(jar, url);
    loc = res.headers.get('location');
  }
  throw new Error('未拿到授权码');
}

export async function exchangeCode(code, verifier) {
  const res = await fetch(`${IDP}/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64')}`,
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
    }).toString(),
  });
  const body = await res.json();
  assert.equal(res.status, 200, `token 交换失败: ${JSON.stringify(body)}`);
  return body;
}

export async function grantRefresh(refreshToken) {
  const res = await fetch(`${IDP}/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64')}`,
    },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
    }).toString(),
  });
  return { ok: res.ok, status: res.status, body: await res.json() };
}
