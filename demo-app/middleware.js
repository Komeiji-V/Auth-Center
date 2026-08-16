// =============================================================
// 各小站接入认证中心的 JWT 中间件（复制本文件到你的项目即可）
// 用法：app.use('/api', authMiddleware)
// 通过后 req.user = { id, username, email, role, status }
// =============================================================
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 5 });

function parseToken(req) {
  const h = req.headers.authorization || '';
  if (h.startsWith('Bearer ')) return h.slice(7);
  return null;
}

async function authMiddleware(req, res, next) {
  try {
    const token = parseToken(req);
    if (!token) return res.status(401).json({ error: '未登录' });
    let payload;
    try {
      payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    } catch {
      return res.status(401).json({ error: '登录已过期，请重新登录' });
    }
    const { rows } = await pool.query(
      'SELECT id, username, email, status, role, token_version FROM users WHERE id = $1',
      [payload.uid]
    );
    if (rows.length === 0) return res.status(401).json({ error: '用户不存在' });
    const u = rows[0];
    // token 版本号比对：改密/重置/改邮箱后旧 access token 立即失效
    if ((payload.ver || 0) !== (u.token_version || 0)) {
      return res.status(401).json({ error: '登录已过期，请重新登录' });
    }
    if (u.status !== 'active') {
      return res.status(403).json({ error: u.status === 'banned' ? '账号已被封禁' : '账号未通过审核' });
    }
    req.user = u;
    next();
  } catch (e) {
    console.error('[auth middleware] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
}

module.exports = { authMiddleware, parseToken };
