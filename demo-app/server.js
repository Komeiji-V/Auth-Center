require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const { authMiddleware, parseToken } = require('./middleware');

const app = express();
app.set('trust proxy', true);
app.disable('x-powered-by');
app.use(cors({ origin: true })); // 演示站自身不做访问限制，认证中心才有白名单
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
    const { rows } = await pool.query('SELECT id, username, email, role, status FROM users WHERE id = $1', [payload.uid]);
    if (rows.length === 0) return res.json({ guest: true });
    if (rows[0].status !== 'active') return res.json({ guest: true, reason: rows[0].status });
    res.json({ guest: false, user: rows[0] });
  } catch {
    res.json({ guest: true });
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
