const crypto = require('crypto');
const db = require('./db');

/**
 * 服务端会话（替代原来的 JWT + refresh token）
 *
 * - 浏览器只持有 HttpOnly cookie（ac_sid），JS 读不到
 * - 会话存在 sessions 表，封禁 / 改密时可直接删除，立即失效
 * - 不需要 token_version：会话本身就是撤销单位
 */

const TTL_DAYS = parseInt(process.env.SESSION_TTL_DAYS, 10) || 7;
const SECURE =
  process.env.COOKIE_SECURE === 'true' ||
  (process.env.SITE_ORIGIN || '').startsWith('https://');

// __Host- 前缀强制要求 Secure + Path=/ + 无 Domain，浏览器会拒绝同域小站
// 塞进来的同名 Domain cookie（cookie tossing）。本地 http 不满足条件，退回普通名字。
const COOKIE_NAME = SECURE ? '__Host-ac_sid' : 'ac_sid';

function cookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: SECURE,
    path: '/',
    maxAge: TTL_DAYS * 24 * 60 * 60 * 1000,
  };
}

/** 创建会话并写入 cookie */
async function createSession(res, userId) {
  const id = crypto.randomBytes(32).toString('hex');
  await db.query(
    `INSERT INTO sessions (id, user_id, expires_at)
     VALUES ($1, $2, now() + ($3 || ' days')::interval)`,
    [id, userId, String(TTL_DAYS)]
  );
  res.cookie(COOKIE_NAME, id, cookieOptions());
  return id;
}

/** 从请求 cookie 解析会话（连带查出用户状态） */
async function getSession(req) {
  const id = req.cookies && req.cookies[COOKIE_NAME];
  if (!id) return null;

  const { rows } = await db.query(
    `SELECT s.id AS sid, s.expires_at,
            u.id, u.username, u.email, u.role, u.status, u.totp_enabled, u.is_owner
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.id = $1 AND s.expires_at > now()`,
    [id]
  );
  return rows[0] || null;
}

/** 销毁当前会话（登出） */
async function destroySession(req, res) {
  const id = req.cookies && req.cookies[COOKIE_NAME];
  if (id) await db.query('DELETE FROM sessions WHERE id = $1', [id]);
  res.clearCookie(COOKIE_NAME, { path: '/' });
}

/** 销毁某用户全部会话（改密 / 封禁 / 删号） */
async function destroyUserSessions(userId) {
  const r = await db.query('DELETE FROM sessions WHERE user_id = $1', [userId]);
  return r.rowCount;
}

module.exports = {
  COOKIE_NAME,
  createSession,
  getSession,
  destroySession,
  destroyUserSessions,
};
