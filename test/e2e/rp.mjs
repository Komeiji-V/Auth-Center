import express from 'express';
import crypto from 'node:crypto';
import * as oidc from 'openid-client';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const ISSUER = process.env.ISSUER || 'http://localhost:8000';
const CLIENT_ID = process.env.RP_CLIENT_ID || 'demo-app';
const CLIENT_SECRET = process.env.RP_CLIENT_SECRET || 'demo-secret';
const PORT = parseInt(process.env.RP_PORT || '8001', 10);
const REDIRECT_URI = `http://localhost:${PORT}/callback`;
const BACKCHANNEL_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

// 内存会话：sid(cookie) -> { sub, sid, claims, at }
const sessions = new Map();
// 登录中的临时状态：state -> { verifier, nonce }
const pending = new Map();

let config;
let JWKS;

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function currentSession(req) {
  const sid = parseCookies(req).rp_sid;
  return sid ? sessions.get(sid) : undefined;
}

function page(title, body) {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>${title}</title>
<style>body{font-family:system-ui,sans-serif;max-width:640px;margin:40px auto;line-height:1.7}
code{background:#f4f4f5;padding:2px 6px;border-radius:4px}a.btn{display:inline-block;padding:8px 16px;
background:#2563eb;color:#fff;text-decoration:none;border-radius:6px}</style></head>
<body>${body}</body></html>`;
}

// ---------- BFF 静默续期 ----------
// access token 剩余不足 60 秒时，用 refresh token 换新。
// 同一会话的并发请求必须复用同一次刷新：refresh token 是轮换的，
// 并发刷新会触发 IdP 的重放检测，导致整个 grant 被吊销。
async function ensureFreshTokens(req, res, next) {
  // 调试端点不参与续期，否则 /debug/session 一读就被续，测试无法观察真实剩余时间
  if (req.path.startsWith('/debug/')) return next();

  const s = currentSession(req);
  if (!s || !config) return next();

  const remain = s.tokens.expires_at - Date.now();
  if (remain > 60_000) return next();
  if (!s.tokens.refresh_token) return next();

  if (!s.refreshing) {
    s.refreshing = (async () => {
      const tokens = await oidc.refreshTokenGrant(config, s.tokens.refresh_token);
      s.tokens.access_token = tokens.access_token;
      s.tokens.id_token = tokens.id_token;
      if (tokens.refresh_token) s.tokens.refresh_token = tokens.refresh_token;
      s.tokens.expires_at = Date.now() + (tokens.expires_in || 0) * 1000;
      s.refreshCount = (s.refreshCount || 0) + 1;
      console.log(
        `[rp] 静默续期 #${s.refreshCount}（sub=${s.sub}）新过期 ${new Date(s.tokens.expires_at).toISOString()}`
      );
    })().finally(() => {
      s.refreshing = null;
    });
  }

  try {
    await s.refreshing;
  } catch (e) {
    console.error('[rp] 静默续期失败:', e.message);
    // 续期失败（refresh 过期或被吊销）：销毁本地会话，下次访问重新走登录
    for (const [k, v] of sessions) if (v === s) sessions.delete(k);
  }

  return next();
}

app.use(ensureFreshTokens);

// ---------- 首页 ----------
app.get('/', (req, res) => {
  const s = currentSession(req);
  if (!s) {
    res.send(page('未登录', `
      <h2>演示小站（RP）</h2>
      <p>当前状态：<b>未登录</b></p>
      <p><a class="btn" href="/login">用认证中心登录</a></p>
    `));
    return;
  }
  res.send(page('已登录', `
    <h2>演示小站（RP）</h2>
    <p>当前状态：<b>已登录</b></p>
    <ul>
      <li>sub: <code>${s.sub}</code></li>
      <li>sid: <code>${s.sid}</code></li>
      <li>username: <code>${s.claims.preferred_username || '-'}</code></li>
      <li>email: <code>${s.claims.email || '-'}</code></li>
    </ul>
    <p><a class="btn" href="/me">查看 /me</a></p>
  `));
});

// ---------- 发起登录 ----------
app.get('/login', async (req, res) => {
  const verifier = oidc.randomPKCECodeVerifier();
  const challenge = await oidc.calculatePKCECodeChallenge(verifier);
  const state = oidc.randomState();
  const nonce = oidc.randomNonce();

  pending.set(state, { verifier, nonce, at: Date.now() });

  const url = oidc.buildAuthorizationUrl(config, {
    redirect_uri: REDIRECT_URI,
    // offline_access 才会签发 refresh_token
    scope: 'openid email profile offline_access',
    // oidc-provider 的规范行为：没有 prompt=consent 时会从 scope 里移除 offline_access
    // 这里的 consent 由 IdP 侧自动通过，用户不会看到确认页
    prompt: 'consent',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
    nonce,
  });

  res.redirect(url.href);
});

// ---------- 回调 ----------
app.get('/callback', async (req, res) => {
  try {
    const currentUrl = new URL(req.originalUrl, `http://localhost:${PORT}`);
    const state = currentUrl.searchParams.get('state');
    const p = pending.get(state);
    if (!p) return res.status(400).send('state 不匹配或已过期');

    const tokens = await oidc.authorizationCodeGrant(config, currentUrl, {
      pkceCodeVerifier: p.verifier,
      expectedState: state,
      expectedNonce: p.nonce,
    });
    pending.delete(state);

    const claims = tokens.claims();
    const sessionId = crypto.randomUUID();

    // sid 来自 ID Token，back-channel logout 会带回来
    sessions.set(sessionId, {
      sub: claims.sub,
      sid: claims.sid,
      claims,
      scope: tokens.scope,
      // BFF 雏形：token 存在服务端，浏览器只拿 HttpOnly cookie
      tokens: {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        id_token: tokens.id_token,
        expires_at: Date.now() + (tokens.expires_in || 0) * 1000,
      },
      at: Date.now(),
    });

    res.setHeader('Set-Cookie', `rp_sid=${sessionId}; HttpOnly; Path=/; SameSite=Lax`);
    res.redirect('/');
  } catch (e) {
    console.error('[rp] callback 失败:', e);
    res.status(500).send(`登录失败: ${e.message}`);
  }
});

// ---------- Back-Channel Logout（核心） ----------
app.post('/backchannel-logout', async (req, res) => {
  const logoutToken = req.body && req.body.logout_token;
  if (!logoutToken) return res.status(400).send('缺少 logout_token');

  try {
    const { payload } = await jwtVerify(logoutToken, JWKS, {
      issuer: ISSUER,
      audience: CLIENT_ID,
    });

    if (!payload.events || !payload.events[BACKCHANNEL_EVENT]) {
      return res.status(400).send('不是 logout token');
    }

    let removed = 0;
    for (const [key, s] of sessions) {
      if (s.sub !== payload.sub) continue;
      if (payload.sid && s.sid !== payload.sid) continue;
      sessions.delete(key);
      removed += 1;
    }

    console.log(
      `[rp] 收到 back-channel logout: sub=${payload.sub} sid=${payload.sid || '(无)'} → 清除 ${removed} 个会话`
    );
    res.status(200).end();
  } catch (e) {
    console.error('[rp] logout token 校验失败:', e.message);
    res.status(400).send('logout token 无效');
  }
});

// ---------- 调试接口 ----------
app.get('/me', (req, res) => {
  const s = currentSession(req);
  if (!s) return res.status(401).json({ error: '未登录' });
  res.json({ sub: s.sub, sid: s.sid, claims: s.claims });
});

app.get('/debug/sessions', (req, res) => {
  res.json({
    count: sessions.size,
    sessions: [...sessions.values()].map((s) => ({ sub: s.sub, sid: s.sid, at: s.at })),
  });
});

app.get('/debug/tokens', (req, res) => {
  const s = currentSession(req);
  if (!s) return res.status(401).json({ error: '未登录' });
  res.json({
    scope: s.scope,
    hasAccessToken: !!s.tokens.access_token,
    hasRefreshToken: !!s.tokens.refresh_token,
    hasIdToken: !!s.tokens.id_token,
    expiresAt: new Date(s.tokens.expires_at).toISOString(),
    expiresInSec: Math.round((s.tokens.expires_at - Date.now()) / 1000),
  });
});

// 测试用：把 access token 剩余时间改成 10 秒，触发静默续期
app.post('/debug/expire', (req, res) => {
  const s = currentSession(req);
  if (!s) return res.status(401).json({ error: '未登录' });
  s.tokens.expires_at = Date.now() + 10_000;
  res.json({ ok: true, expiresInSec: 10 });
});

app.get('/debug/session', (req, res) => {
  const s = currentSession(req);
  if (!s) return res.status(401).json({ error: '未登录' });
  res.json({
    sub: s.sub,
    refreshCount: s.refreshCount || 0,
    expiresInSec: Math.round((s.tokens.expires_at - Date.now()) / 1000),
  });
});

// 模拟 BFF 的静默续期：用 refresh_token 换新 access token
app.post('/debug/refresh', async (req, res) => {
  const s = currentSession(req);
  if (!s) return res.status(401).json({ error: '未登录' });
  if (!s.tokens.refresh_token) return res.status(400).json({ error: '没有 refresh_token' });

  try {
    const oldExpiresAt = s.tokens.expires_at;
    const oldAccessToken = s.tokens.access_token;
    const oldRefresh = s.tokens.refresh_token;
    const tokens = await oidc.refreshTokenGrant(config, s.tokens.refresh_token);

    s.tokens.access_token = tokens.access_token;
    s.tokens.id_token = tokens.id_token;
    // 轮换：IdP 可能返回新的 refresh_token
    if (tokens.refresh_token) s.tokens.refresh_token = tokens.refresh_token;
    s.tokens.expires_at = Date.now() + (tokens.expires_in || 0) * 1000;

    // 新 access token 能否调通 userinfo
    let userinfoOk = false;
    try {
      const r = await fetch(`${ISSUER}/me`, {
        headers: { authorization: `Bearer ${s.tokens.access_token}` },
      });
      userinfoOk = r.ok;
    } catch {
      userinfoOk = false;
    }

    // 旧 refresh token 是否已被轮换作废（重放检测）
    // 注意：IdP 检测到重放会吊销整个 grant，所以默认不测，需显式 ?testReplay=1
    let oldRefreshRejected = null;
    if (req.query.testReplay === '1' && tokens.refresh_token && oldRefresh !== tokens.refresh_token) {
      try {
        await oidc.refreshTokenGrant(config, oldRefresh);
        oldRefreshRejected = false;
      } catch {
        oldRefreshRejected = true;
      }
    }

    res.json({
      ok: true,
      rotatedRefresh: !!tokens.refresh_token,
      accessTokenChanged: oldAccessToken !== tokens.access_token,
      userinfoOk,
      oldRefreshRejected,
      oldRefreshFp: oldRefresh ? crypto.createHash('sha256').update(oldRefresh).digest('hex').slice(0, 8) : null,
      newRefreshFp: s.tokens.refresh_token ? crypto.createHash('sha256').update(s.tokens.refresh_token).digest('hex').slice(0, 8) : null,
      oldExpiresAt: new Date(oldExpiresAt).toISOString(),
      newExpiresAt: new Date(s.tokens.expires_at).toISOString(),
      expiresIn: tokens.expires_in,
    });
  } catch (e) {
    res.status(400).json({ error: `刷新失败: ${e.message}` });
  }
});

async function main() {
  // 本地 PoC 用 http，openid-client v6 默认只允许 HTTPS，需显式放行
  config = await oidc.discovery(
    new URL(ISSUER),
    CLIENT_ID,
    CLIENT_SECRET,
    undefined,
    { execute: [oidc.allowInsecureRequests] }
  );
  const meta = config.serverMetadata();
  JWKS = createRemoteJWKSet(new URL(meta.jwks_uri));

  app.listen(PORT, () => {
    console.log(`[rp] 演示小站 listening on http://localhost:${PORT}`);
    console.log(`[rp] issuer = ${ISSUER}, jwks = ${meta.jwks_uri}`);
  });
}

main().catch((e) => {
  console.error('[rp] startup failed:', e);
  process.exit(1);
});
