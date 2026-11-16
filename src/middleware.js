const session = require('./session');

/**
 * 会话认证中间件（替代原来的 JWT 校验）
 *
 * req.user 字段与原 JWT 版本保持一致：id / username / email / role / status / totp_enabled / is_owner
 * 每次请求都会查 sessions + users，所以封禁、删号是立即生效的。
 */
function createSessionAuth() {
  return async function sessionAuth(req, res, next) {
    try {
      const s = await session.getSession(req);
      if (!s) return res.status(401).json({ error: '未登录' });

      if (s.status !== 'active') {
        return res.status(403).json({
          error: s.status === 'banned' ? '账号已被封禁' : '账号未通过审核',
        });
      }

      req.user = s;
      next();
    } catch (e) {
      console.error('[middleware] error:', e);
      res.status(500).json({ error: '服务器内部错误' });
    }
  };
}

function createAdminMiddleware(requireTotp) {
  const auth = createSessionAuth();
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

module.exports = { createSessionAuth, createAdminMiddleware };
