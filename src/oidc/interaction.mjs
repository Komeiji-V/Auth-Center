import crypto from 'node:crypto';
import { authenticator } from 'otplib';
import db from '../db.js';
import auth from '../auth.js';

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
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 5;

// 进程内失败计数（与旧登录路径的 rateLimit 相互独立）
const attempts = new Map();

function hitCounter(key) {
  const now = Date.now();
  const rec = attempts.get(key);
  if (!rec || now - rec.first > LOGIN_WINDOW_MS) {
    attempts.set(key, { count: 1, first: now });
    return { count: 1, locked: false };
  }
  rec.count += 1;
  return { count: rec.count, locked: rec.count > LOGIN_MAX_ATTEMPTS };
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
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
    <p class="hint">使用认证中心账号登录</p>
  </form>
</body>
</html>`;
}

async function handleLogin(provider, ctx, uid, body) {
  const username = (body.get('login') || '').trim();
  const password = body.get('password') || '';
  const totpCode = (body.get('totp') || '').trim();
  const ip = ctx.ip || 'unknown';

  const fail = (msg, needTotp = false) => {
    ctx.type = 'html';
    ctx.body = renderLogin(uid, { error: msg, username, needTotp });
  };

  if (!username || !password) return fail('请输入账号和密码');

  const lockKey = `login:${ip}:${username.toLowerCase()}`;
  if (hitCounter(lockKey).locked) return fail('尝试次数过多，请 15 分钟后再试');

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

  attempts.delete(lockKey);
  db.audit(u.username, 'oidc_login_success', ip, '').catch(() => {});

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
      console.error('[oidc interaction] error:', e);
      ctx.status = 500;
      ctx.type = 'text/plain';
      ctx.body = '登录处理失败，请返回重试';
    }
  };
}
