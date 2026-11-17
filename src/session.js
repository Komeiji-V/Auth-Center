const crypto = require('crypto');
const db = require('./db');

/**
 * 服务端会话（替代原来的 JWT + refresh token）
 *
 * - 浏览器只持有 HttpOnly cookie，JS 读不到
 * - 会话存在 sessions 表，封禁 / 改密时可直接删除，立即失效
 * - 不需要 token_version：会话本身就是撤销单位
 * - 空闲超时：last_seen 超过 SESSION_IDLE_HOURS 未更新则视为失效（绝对上限仍是 TTL_DAYS）
 */

const TTL_DAYS = parseInt(process.env.SESSION_TTL_DAYS, 10) || 7;
const IDLE_HOURS = parseInt(process.env.SESSION_IDLE_HOURS, 10) || 24;
const { SECURE, SESSION_COOKIE: COOKIE_NAME } = require('./cookie-config');

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
async function createSession(res, userId, meta = {}) {
  const id = crypto.randomBytes(32).toString('hex');
  await db.query(
    `INSERT INTO sessions (id, user_id, expires_at, last_seen, ip, user_agent)
     VALUES ($1, $2, now() + ($3 || ' days')::interval, now(), $4, $5)`,
    [id, userId, String(TTL_DAYS), meta.ip || null, (meta.userAgent || '').slice(0, 300) || null]
  );
  res.cookie(COOKIE_NAME, id, cookieOptions());
  // 迁移残留：从 ac_sid 切到 __Host-ac_sid 后，老用户浏览器里可能还留着旧 cookie，
  // 不清掉会在关闭 Secure 时让旧会话“复活”，也会在设备列表里显示成一台未知设备
  if (COOKIE_NAME !== 'ac_sid') {
    res.clearCookie('ac_sid', { path: '/', secure: SECURE, sameSite: 'lax' });
  }
  return id;
}

/**
 * 从请求 cookie 解析会话（连带查出用户状态）
 *
 * 每次请求都会 join users 判断 status，所以封禁是立即生效的。
 * 命中后顺手把 last_seen 推进（60 秒内不重复写，避免每个静态资源都打一次库）。
 */
async function getSession(req) {
  const id = req.cookies && req.cookies[COOKIE_NAME];
  if (!id) return null;

  const { rows } = await db.query(
    `SELECT s.id AS sid, s.expires_at, s.last_seen,
            u.id, u.username, u.email, u.role, u.status, u.totp_enabled, u.is_owner
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.id = $1
       AND s.expires_at > now()
       AND s.last_seen > now() - ($2 || ' hours')::interval`,
    [id, String(IDLE_HOURS)]
  );
  if (!rows.length) return null;

  const s = rows[0];
  if (Date.now() - new Date(s.last_seen).getTime() > 60_000) {
    // fire-and-forget：推进活跃时间，不阻塞请求
    db.query('UPDATE sessions SET last_seen = now() WHERE id = $1', [s.sid]).catch(() => {});
  }
  return s;
}

/** 销毁当前会话（登出） */
async function destroySession(req, res) {
  const id = req.cookies && req.cookies[COOKIE_NAME];
  if (id) await db.query('DELETE FROM sessions WHERE id = $1', [id]);
  // __Host- 前缀 cookie 的 Set-Cookie 必须带 Secure，否则浏览器整条忽略、删不掉
  res.clearCookie(COOKIE_NAME, { path: '/', secure: SECURE, sameSite: 'lax' });
}

/** 销毁某用户全部会话（改密 / 封禁 / 删号） */
async function destroyUserSessions(userId) {
  const r = await db.query('DELETE FROM sessions WHERE user_id = $1', [userId]);
  return r.rowCount;
}

/** 销毁该用户除当前会话外的其他会话（「退出其他设备」） */
async function destroyOtherSessions(userId, currentSid) {
  const r = await db.query(
    'DELETE FROM sessions WHERE user_id = $1 AND id <> $2',
    [userId, currentSid]
  );
  return r.rowCount;
}

/** 列出该用户所有有效会话（设备管理用） */
async function listSessions(userId) {
  const { rows } = await db.query(
    `SELECT id, created_at, last_seen, expires_at, ip, user_agent
     FROM sessions
     WHERE user_id = $1
       AND expires_at > now()
       AND last_seen > now() - ($2 || ' hours')::interval
     ORDER BY last_seen DESC
     LIMIT 50`,
    [userId, String(IDLE_HOURS)]
  );
  return rows;
}

module.exports = {
  COOKIE_NAME,
  TTL_DAYS,
  IDLE_HOURS,
  createSession,
  getSession,
  destroySession,
  destroyUserSessions,
  destroyOtherSessions,
  listSessions,
};
