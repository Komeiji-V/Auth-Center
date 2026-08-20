require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const { authMiddleware, parseToken } = require('./middleware');

const app = express();
app.set('trust proxy', true);
app.disable('x-powered-by');
app.use(cors({ origin: true, credentials: true })); // 演示站自身不做访问限制；credentials 供 sso 端点跨域 Set-Cookie 被浏览器接受
app.use(express.json({ limit: '32kb' }));

const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 5 });

// 演示站自管存档表（认证中心不负责）
pool.query(`
  CREATE TABLE IF NOT EXISTS demo_saves (
    user_id INTEGER PRIMARY KEY,
    data JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )
`).catch((e) => console.error('[demo-app] init table failed:', e.message));

const AUTH_BASE = process.env.AUTH_BASE || 'http://localhost:8000';
// 认证中心 origin（sso 端点 CSRF 校验白名单）；AUTH_BASE 为 https 时 sso cookie 加 Secure
const AUTH_ORIGIN = (() => {
  try { return new URL(AUTH_BASE).origin; } catch { return ''; }
})();
const SSO_COOKIE_SECURE = AUTH_BASE.startsWith('https://');

// sso 端点轻量内存限流（参考实现演示：30 次/分/IP；生产小站复用其现有 IpRateLimiter 并覆盖此端点）
const ssoHits = new Map();
function ssoRateLimit(ip) {
  const now = Date.now();
  const key = ip || 'unknown';
  const arr = (ssoHits.get(key) || []).filter((t) => now - t < 60 * 1000);
  if (arr.length >= 30) return false;
  arr.push(now);
  ssoHits.set(key, arr);
  return true;
}

app.use(express.static(require('path').join(__dirname, 'public')));

// 前端读取认证中心地址（部署时改 AUTH_BASE 环境变量即可）
app.get('/api/auth-base', (req, res) => res.json({ url: AUTH_BASE }));

// 当前身份：有 token 返回用户，没有返回游客（游客也能玩）
app.get('/api/me', async (req, res) => {
  const token = parseToken(req);
  if (!token) return res.json({ guest: true });
  try {
    const jwt = require('jsonwebtoken');
    const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    const { rows } = await pool.query('SELECT id, username, email, role, status, token_version FROM users WHERE id = $1', [payload.uid]);
    if (rows.length === 0) return res.json({ guest: true });
    if ((payload.ver || 0) !== (rows[0].token_version || 0)) return res.json({ guest: true });
    if (rows[0].status !== 'active') return res.json({ guest: true, reason: rows[0].status });
    res.json({ guest: false, user: rows[0] });
  } catch {
    res.json({ guest: true });
  }
});

// 安全回跳端点（M1 修复）：认证中心登录页将 token POST 到这里（凭证不再进 URL）
// 流程：来源校验（CSRF 防护）→ 验签 → 确认用户 active → 以 60s 短时 cookie 交还前端
// CSRF 防护（双重）：
//   1. Origin/Referer 必须命中认证中心 origin（跨站 <form> 的 Origin 指向攻击者站点，直接 403）
//   2. 必须携带自定义头 X-Requested-With: AuthCenter——跨站 <form> 无法携带自定义头，
//      且自定义头强制浏览器先发 preflight（CORS 白名单只放行认证中心）
app.post('/api/auth/sso', async (req, res) => {
  if (!ssoRateLimit(req.ip)) return res.status(429).json({ error: '请求过于频繁' });
  const origin = req.headers.origin
    || (req.headers.referer ? (() => { try { return new URL(req.headers.referer).origin; } catch { return ''; } })() : '');
  if (!origin || !AUTH_ORIGIN || origin !== AUTH_ORIGIN) {
    return res.status(403).json({ error: '非法来源' });
  }
  if (req.headers['x-requested-with'] !== 'AuthCenter') {
    return res.status(403).json({ error: '非法来源' });
  }
  const token = req.body && req.body.token;
  if (!token || typeof token !== 'string') return res.status(400).json({ error: '缺少 token' });
  try {
    const jwt = require('jsonwebtoken');
    const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    const { rows } = await pool.query('SELECT id FROM users WHERE id = $1 AND status = $2', [payload.uid, 'active']);
    if (rows.length === 0) return res.status(403).json({ error: '用户不存在或未激活' });
    res.cookie('demo_sso_token', token, {
      httpOnly: false, sameSite: 'lax', secure: SSO_COOKIE_SECURE, maxAge: 60 * 1000, path: '/',
    });
    res.json({ ok: true });
  } catch {
    return res.status(401).json({ error: 'token 无效' });
  }
});

// 云端存档（需登录；按账号存储，账号通用性由认证中心保证）
app.get('/api/save', authMiddleware, async (req, res) => {
  const { rows } = await pool.query('SELECT data FROM demo_saves WHERE user_id = $1', [req.user.id]);
  if (rows.length === 0) return res.json({ data: null });
  res.json({ data: rows[0].data });
});

app.post('/api/save', authMiddleware, async (req, res) => {
  const data = req.body && req.body.data;
  if (!data || typeof data !== 'object') return res.status(400).json({ error: '存档格式错误' });
  await pool.query(
    `INSERT INTO demo_saves (user_id, data, updated_at)
     VALUES ($1, $2, now())
     ON CONFLICT (user_id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`,
    [req.user.id, JSON.stringify(data)]
  );
  res.json({ ok: true });
});

const PORT = parseInt(process.env.PORT || '8001', 10);
app.listen(PORT, () => console.log(`[demo-app] listening on :${PORT}, auth base = ${AUTH_BASE}`));
