const crypto = require('crypto');
const db = require('./db');
const { SECURE, SESSION_COOKIE: COOKIE_NAME } = require('./cookie-config');

/**
 * 服务端会话（替代原来的 JWT + refresh token）
 *
 * - 浏览器只持有 HttpOnly cookie，JS 读不到
 * - 会话存在 sessions 表，封禁 / 改密时可直接删除，立即失效
 * - 不需要 token_version：会话本身就是撤销单位
 * - 空闲超时：last_seen 超过 SESSION_IDLE_HOURS 未更新则视为失效（绝对上限仍是 TTL_DAYS）
 *
 * 同时供 Express（res.cookie）与 Koa（oidc-provider 的 ctx.cookies）使用，
 * 所以 cookie 的拼装逻辑单独拆出来。
 */

const TTL_DAYS = parseInt(process.env.SESSION_TTL_DAYS, 10) || 7;
const IDLE_HOURS = parseInt(process.env.SESSION_IDLE_HOURS, 10) || 24;

const COOKIE_OPTIONS = {
  httpOnly: true,
  sameSite: 'lax',
  secure: SECURE,
  path: '/',
  maxAge: TTL_DAYS * 24 * 60 * 60 * 1000,
};

/** 从 Cookie 头里取某个 cookie 的值（Koa 的 req.cookies 不经过 cookie-parser） */
function parseCookie(header, name) {
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) {
      return decodeURIComponent(part.slice(i + 1).trim());
    }
  }
  return null;
}

/** 按会话 ID 查（会话 ID = cookie 值），命中后顺手推进 last_seen */
async function findSession(sessionId) {
  if (!sessionId) return null;

  const { rows } = await db.query(
    `SELECT s.id AS sid, s.expires_at, s.last_seen, s.created_at,
            u.id, u.username, u.email, u.role, u.status, u.totp_enabled, u.is_owner
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.id = $1
       AND s.expires_at > now()
       AND s.last_seen > now() - ($2 || ' hours')::interval`,
    [sessionId, String(IDLE_HOURS)]
  );
  if (!rows.length) return null;

  const s = rows[0];
  if (Date.now() - new Date(s.last_seen).getTime() > 60_000) {
    // fire-and-forget：推进活跃时间，不阻塞请求
    db.query('UPDATE sessions SET last_seen = now() WHERE id = $1', [s.sid]).catch(() => {});
  }
  return s;
}

/** 只写会话记录，返回 id（不碰任何 res/ctx，调用方自己写 cookie） */
async function createSessionRecord(userId, meta = {}) {
  const id = crypto.randomBytes(32).toString('hex');
  await db.query(
    `INSERT INTO sessions (id, user_id, expires_at, last_seen, ip, user_agent)
     VALUES ($1, $2, now() + ($3 || ' days')::interval, now(), $4, $5)`,
    [id, userId, String(TTL_DAYS), meta.ip || null, (meta.userAgent || '').slice(0, 300) || null]
  );
  return id;
}

/** Express 用：建会话并下发 cookie */
async function createSession(res, userId, meta = {}) {
  const id = await createSessionRecord(userId, meta);
  res.cookie(COOKIE_NAME, id, COOKIE_OPTIONS);
  // 迁移残留：从 ac_sid 切到 __Host-ac_sid 后，老用户浏览器里可能还留着旧 cookie
  if (COOKIE_NAME !== 'ac_sid') {
    res.clearCookie('ac_sid', { path: '/', secure: SECURE, sameSite: 'lax' });
  }
  return id;
}

/** Express 用：从 req.cookies 解析会话 */
async function getSession(req) {
  return findSession(req.cookies && req.cookies[COOKIE_NAME]);
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
  SECURE,
  TTL_DAYS,
  IDLE_HOURS,
  COOKIE_OPTIONS,
  parseCookie,
  findSession,
  createSessionRecord,
  createSession,
  getSession,
  destroySession,
  destroyUserSessions,
  destroyOtherSessions,
  listSessions,
};
