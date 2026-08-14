const jwt = require('jsonwebtoken');

function parseToken(req) {
  const h = req.headers.authorization || '';
  if (h.startsWith('Bearer ')) return h.slice(7);
  return null;
}

function createAuthMiddleware(secret, db) {
  return async function authMiddleware(req, res, next) {
    try {
      const token = parseToken(req);
      if (!token) return res.status(401).json({ error: '未登录' });
      let payload;
      try {
        payload = jwt.verify(token, secret, { algorithms: ['HS256'] });
      } catch {
        return res.status(401).json({ error: '登录已过期，请重新登录' });
      }
      const { rows } = await db.query(
        'SELECT id, username, email, status, role, totp_enabled, is_owner FROM users WHERE id = $1',
        [payload.uid]
      );
      if (rows.length === 0) return res.status(401).json({ error: '用户不存在' });
      const u = rows[0];
      if (u.status !== 'active') {
        return res.status(403).json({ error: u.status === 'banned' ? '账号已被封禁' : '账号未通过审核' });
      }
      req.user = u;
      next();
    } catch (e) {
      console.error('[middleware] error:', e);
      res.status(500).json({ error: '服务器内部错误' });
    }
  };
}

function createAdminMiddleware(secret, db, requireTotp) {
  const auth = createAuthMiddleware(secret, db);
  return [
    auth,
    (req, res, next) => {
      if (req.user.role !== 'admin') return res.status(403).json({ error: '无权限' });
      if (requireTotp && !req.user.totp_enabled) {
        return res.status(403).json({ error: '请先绑定 TOTP 再使用管理功能' });
      }
      next();
    },
  ];
}

module.exports = { createAuthMiddleware, createAdminMiddleware, parseToken };
