import crypto from 'node:crypto';
import { authenticator } from 'otplib';
import db from '../db.js';
import auth from '../auth.js';
import session from '../session.js';
import rateLimit from '../rateLimit.js';

/**
 * 自定义登录交互（替代官方 devInteractions）
 *
 *   GET  /interaction/:uid  → 渲染登录页
 *   POST /interaction/:uid  → 校验账号 / 密码 / TOTP / 状态 → interactionFinished
 *
 * 密码校验直接复用 auth.js 的 verifyPassword（scrypt 格式一致），
 * 登录成功/失败同样写 audit_log，保持与旧登录路径一致的审计口径。
 */

const SITE_TITLE = process.env.SITE_TITLE || '认证中心';
// 登录失败锁定复用 auth.js 同一套 store：两条登录入口（/api/login 与 OIDC interaction）
// 共享计数，否则可以从另一条路径绕过 5 次锁定。
const { loginAttempt, loginSuccess } = rateLimit;

// 上限 8KB：登录表单只有三个短字段，超出直接 413。
// 不设限时一次 300KB 的 login 会写一条 300KB 的审计、占一个 300KB 的限流 key、返回 300KB 的响应。
const MAX_BODY = 8 * 1024;

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) {
      const err = new Error('BODY_TOO_LARGE');
      err.status = 413;
      throw err;
    }
    chunks.push(chunk);
  }
  return new URLSearchParams(Buffer.concat(chunks).toString());
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[c]));
}

function renderLogin(uid, { error = '', username = '', needTotp = false } = {}) {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>登录 - ${escapeHtml(SITE_TITLE)}</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: grid; place-items: center;
    font-family: system-ui, -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif;
    background: linear-gradient(135deg, #1e293b, #0f172a);
  }
  .card {
    width: 360px; padding: 32px; border-radius: 12px; background: #fff;
    box-shadow: 0 10px 40px rgba(0,0,0,.3);
  }
  h1 { margin: 0 0 4px; font-size: 20px; }
  .sub { margin: 0 0 24px; color: #64748b; font-size: 13px; }
  label { display: block; margin-bottom: 6px; font-size: 13px; color: #334155; }
  input {
    width: 100%; padding: 10px 12px; margin-bottom: 16px; font-size: 14px;
    border: 1px solid #cbd5e1; border-radius: 6px;
  }
  input:focus { outline: 2px solid #3b82f6; border-color: transparent; }
  button {
    width: 100%; padding: 11px; font-size: 15px; color: #fff; background: #2563eb;
    border: 0; border-radius: 6px; cursor: pointer;
  }
  button:hover { background: #1d4ed8; }
  .err {
    padding: 10px 12px; margin-bottom: 16px; font-size: 13px;
    color: #b91c1c; background: #fef2f2; border-radius: 6px;
  }
  .hint { margin-top: 14px; font-size: 12px; color: #94a3b8; text-align: center; }
</style>
</head>
<body>
  <form class="card" method="post" action="/interaction/${escapeHtml(uid)}">
    <h1>${escapeHtml(SITE_TITLE)}</h1>
    <p class="sub">登录后返回应用</p>
    ${error ? `<div class="err">${escapeHtml(error)}</div>` : ''}
    <label for="login">账号</label>
    <input id="login" name="login" value="${escapeHtml(username)}" autocomplete="username" required autofocus>
    <label for="password">密码</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    <label for="totp">TOTP 验证码${needTotp ? '' : '（未开启可留空）'}</label>
    <input id="totp" name="totp" inputmode="numeric" autocomplete="one-time-code" placeholder="6 位数字">
    <button type="submit">登录</button>
    <p class="hint">
      使用认证中心账号登录 ·
      <a href="/forgot" style="color:#2563eb;">忘记密码</a>
    </p>
  </form>
</body>
</html>`;
}

async function handleLogin(provider, ctx, uid, body) {
  const username = (body.get('login') || '').trim().slice(0, 64);   // 截断，防超长输入进审计与限流 key
  const password = body.get('password') || '';
  const totpCode = (body.get('totp') || '').trim();
  // oidc-provider 不读 XFF，用 server.js 注入的真实 IP，否则锁定 key 的 IP 维度会是反代地址
  const ip = (ctx.req && ctx.req.realIp) || ctx.ip || 'unknown';

  const fail = (msg, needTotp = false) => {
    ctx.type = 'html';
    ctx.body = renderLogin(uid, { error: msg, username, needTotp });
  };

  if (!username || !password) return fail('请输入账号和密码');

  const lockKey = `login:${ip}:${username.toLowerCase()}`;
  const check = loginAttempt(lockKey);
  if (check.locked) return fail(`尝试次数过多，请 ${check.remainSec} 秒后再试`);

  const GENERIC = '账号或密码错误';

  const { rows } = await db.query(
    'SELECT * FROM users WHERE LOWER(username) = $1 OR LOWER(email) = $1',
    [username.toLowerCase()]
  );
  const u = rows[0];

  if (!u || !(await auth.verifyPassword(password, u.password_hash))) {
    db.audit(username, 'oidc_login_fail', ip, 'bad_credentials').catch(() => {});
    return fail(GENERIC);
  }

  if (u.status === 'pending') return fail('账号待审核，请等待管理员通过');
  if (u.status === 'banned') return fail('账号已被封禁');

  const amr = ['pwd'];
  if (u.totp_enabled) {
    if (!totpCode) return fail('请输入 TOTP 验证码', true);
    let ok = false;
    try {
      authenticator.options = { window: 1 };
      ok = authenticator.check(totpCode, u.totp_secret);
    } catch {
      ok = false;
    }
    if (!ok) {
      db.audit(u.username, 'oidc_login_fail', ip, 'bad_totp').catch(() => {});
      return fail(GENERIC, true);
    }
    amr.push('otp');
  }

  loginSuccess(lockKey);
  db.audit(u.username, 'oidc_login_success', ip, '').catch(() => {});

  // 反向桥接：在小站登录成功后顺手建一个本站会话，
  // 这样用户回到 /profile、/admin 时不用再登录一次
  const curSid = session.parseCookie(ctx.req.headers.cookie, session.COOKIE_NAME);
  const curSession = curSid ? await session.findSession(curSid) : null;
  if (!curSession) {
    const newSid = await session.createSessionRecord(u.id, {
      ip,
      userAgent: ctx.req.headers['user-agent'],
    });
    // signed: false —— provider 的 Koa app 配了 keys，默认会给 cookie 加签名后缀；
    // 本站用 cookie-parser 读，不需要 .sig，留着只会多一个 cookie
    ctx.cookies.set(session.COOKIE_NAME, newSid, { ...session.COOKIE_OPTIONS, signed: false });
  }

  await provider.interactionFinished(
    ctx.req,
    ctx.res,
    {
      login: {
        accountId: String(u.id),
        acr: amr.length > 1 ? 'urn:mace:incommon:iap:silver' : 'urn:mace:incommon:iap:bronze',
        amr,
      },
    },
    { mergeWithLastSubmission: false }
  );
  ctx.respond = false;
}

export function interactionMiddleware(provider) {
  return async (ctx, next) => {
    if (!ctx.path.startsWith('/interaction/')) return next();

    const uid = ctx.path.slice('/interaction/'.length);
    if (!uid || uid.includes('/')) return next();

    try {
      const details = await provider.interactionDetails(ctx.req, ctx.res);

      if (ctx.method === 'GET') {
        // 本方应用：consent 自动通过，不打断用户
        if (details.prompt.name === 'consent') {
          const grant = new provider.Grant({
            accountId: details.session.accountId,
            clientId: details.params.client_id,
          });
          grant.addOIDCScope(details.params.scope);
          const grantId = await grant.save();
          await provider.interactionFinished(
            ctx.req,
            ctx.res,
            { consent: { grantId } },
            { mergeWithLastSubmission: true }
          );
          ctx.respond = false;
          return;
        }

        if (details.prompt.name !== 'login') {
          ctx.status = 400;
          ctx.body = `未预期的交互步骤: ${details.prompt.name}`;
          return;
        }

        // 完整 SSO：本站会话仍有效时不再要求重复输密码。
        // 这是「在 /login 登录过之后，进小站不用再登」的实现点。
        const existingSid = session.parseCookie(ctx.req.headers.cookie, session.COOKIE_NAME);
        const existing = await session.findSession(existingSid);
        if (existing && existing.status === 'active') {
          await provider.interactionFinished(
            ctx.req,
            ctx.res,
            {
              login: {
                accountId: String(existing.id),
                // 用会话创建时间作为 auth_time，避免把很久以前登录的会话标成「刚刚认证」
                ts: Math.floor(new Date(existing.created_at).getTime() / 1000),
                acr: 'urn:mace:incommon:iap:bronze',
                amr: ['pwd'],
              },
            },
            { mergeWithLastSubmission: false }
          );
          ctx.respond = false;
          return;
        }

        ctx.type = 'html';
        ctx.body = renderLogin(details.uid);
        return;
      }

      if (ctx.method === 'POST') {
        const body = await readBody(ctx.req);
        await handleLogin(provider, ctx, details.uid, body);
        return;
      }

      ctx.status = 405;
    } catch (e) {
      if (e.status === 413) {
        ctx.status = 413;
        ctx.type = 'text/plain';
        ctx.body = '请求体过大';
        return;
      }
      console.error('[oidc interaction] error:', e);
      ctx.status = 500;
      ctx.type = 'text/plain';
      ctx.body = '登录处理失败，请返回重试';
    }
  };
}
