const express = require('express');
const crypto = require('crypto');
const QRCode = require('qrcode');
const { authenticator } = require('otplib');

const db = require('./db');
const mail = require('./mail');
const session = require('./session');
const { loginAttempt, loginSuccess, ipRateLimit } = require('./rateLimit');
const { createSessionAuth } = require('./middleware');

const router = express.Router();

const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 32 };
const CODE_MAX_ATTEMPTS = 5;
const REFRESH_TTL_DAYS = 30;
const REG_CODE_PER_HOUR = parseInt(process.env.REG_CODE_PER_HOUR, 10) || 3;
const PROFILE_CODE_PER_HOUR = parseInt(process.env.PROFILE_CODE_PER_HOUR, 10) || 5;

const EMAIL_RE = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const USERNAME_RE = /^[\u4e00-\u9fa5a-zA-Z0-9_]{2,20}$/;
// HTML 特殊字符（XSS 防护：用户名/邮箱/申请说明等一律禁止）
const HTML_SPECIAL_RE = /[<>&"'\\]/;

const { promisify } = require('util');
const scryptAsync = promisify(crypto.scrypt);

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16);
    scryptAsync(password, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p })
      .then((hash) => resolve(`scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('hex')}$${hash.toString('hex')}`))
      .catch(reject);
  });
}

function verifyPassword(password, stored) {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return Promise.resolve(false);
  const [, n, r, p, saltHex, hashHex] = parts;
  return scryptAsync(password, Buffer.from(saltHex, 'hex'), hashHex.length / 2, {
    N: parseInt(n, 10), r: parseInt(r, 10), p: parseInt(p, 10),
  }).then((hash) => {
    if (hash.length !== Buffer.from(hashHex, 'hex').length) return false;
    return crypto.timingSafeEqual(hash, Buffer.from(hashHex, 'hex'));
  }).catch(() => false);
}

function emailBlocked(email) {
  const domain = email.split('@')[1].toLowerCase();
  const blocked = (process.env.BLOCKED_EMAIL_DOMAINS || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  return blocked.includes(domain);
}

function normalizeAccount(account) {
  return account.trim().toLowerCase();
}

async function issueCode(email, purpose, ip) {
  await db.query('DELETE FROM codes WHERE LOWER(email) = $1 AND purpose = $2 AND used = FALSE', [email, purpose]);
  const code = mail.genCode();
  await db.query(
    `INSERT INTO codes (email, code, purpose, expires_at)
     VALUES ($1, $2, $3, now() + interval '10 minutes')`,
    [email, code, purpose]
  );
  return code;
}

// 通用验证码校验：成功则置 used，返回 { ok }；失败返回 { error }
async function consumeCode(email, code, purpose) {
  const { rows } = await db.query(
    `SELECT * FROM codes
     WHERE LOWER(email) = $1 AND purpose = $2 AND used = FALSE AND expires_at > now()
     ORDER BY id DESC LIMIT 1`,
    [email, purpose]
  );
  if (rows.length === 0) return { error: '验证码不存在或已过期，请重新获取' };
  const c = rows[0];
  if (c.attempts >= CODE_MAX_ATTEMPTS) {
    return { error: '尝试次数过多，验证码已作废，请重新获取' };
  }
  const input = code.trim();
  const ok = input.length === c.code.length && crypto.timingSafeEqual(Buffer.from(input), Buffer.from(c.code));
  if (!ok) {
    await db.query('UPDATE codes SET attempts = attempts + 1 WHERE id = $1', [c.id]);
    const remain = CODE_MAX_ATTEMPTS - c.attempts - 1;
    return { error: remain > 0 ? `验证码错误，剩余 ${remain} 次机会` : '验证码已作废，请重新获取' };
  }
  // 原子占用：并发请求仅一个成功（验证码真正一次性）
  const up = await db.query(
    'UPDATE codes SET used = TRUE WHERE id = $1 AND used = FALSE RETURNING id',
    [c.id]
  );
  if (up.rowCount === 0) return { error: '验证码已被使用' };
  return { ok: true };
}

// ---- 注册：三开关组合（邀请码/邮箱验证/人工审核，任意组合）----
router.post('/register', async (req, res) => {
  try {
    const { username, email, password, invite_code, apply_info } = req.body || {};
    const ip = req.ip;

    if (!username || !USERNAME_RE.test(username)) {
      return res.status(400).json({ error: '用户名需为 2-20 位中文、字母、数字或下划线' });
    }
    if (!email || !EMAIL_RE.test(email)) {
      return res.status(400).json({ error: '邮箱格式不正确' });
    }
    if (!password || password.length < 8 || password.length > 72) {
      return res.status(400).json({ error: '密码长度需为 8-72 位' });
    }
    if (emailBlocked(email)) {
      return res.status(400).json({ error: '该邮箱域名不允许注册' });
    }

    const normEmail = normalizeAccount(email);
    const flags = await db.getRegistrationFlags();

    if (flags.review_required && (!apply_info || String(apply_info).trim().length < 5)) {
      return res.status(400).json({ error: '当前为人工审核注册，请填写申请说明（至少 5 字）' });
    }
    if (apply_info && String(apply_info).trim().length > 500) {
      return res.status(400).json({ error: '申请说明不能超过 500 字' });
    }
    if (apply_info && HTML_SPECIAL_RE.test(String(apply_info))) {
      return res.status(400).json({ error: '申请说明包含不允许的字符' });
    }

    let usedInvite = null;
    if (flags.invite_required) {
      if (!invite_code) return res.status(400).json({ error: '当前为邀请制注册，请输入邀请码' });
      const { rows } = await db.query('SELECT * FROM invite_codes WHERE code = $1', [invite_code.trim()]);
      if (rows.length === 0) return res.status(400).json({ error: '邀请码不存在' });
      const ic = rows[0];
      if (ic.expires_at && new Date(ic.expires_at) < new Date()) {
        return res.status(400).json({ error: '邀请码已过期' });
      }
      if (ic.max_uses !== 0 && ic.used_count >= ic.max_uses) {
        return res.status(400).json({ error: '邀请码已被使用' });
      }
      usedInvite = ic.code;
    }

    const { rows: dup } = await db.query(
      'SELECT id, username, email, password_hash, status, email_verified FROM users WHERE LOWER(username) = $1 OR LOWER(email) = $2',
      [username.trim().toLowerCase(), normEmail]
    );
    if (dup.length > 0) {
      const e = dup[0];
      // 未完成的注册（pending + 邮箱未验证）：允许用原密码续期重发验证码，避免用户被永久卡死
      // 仅当邮箱完全一致时允许续期，防止用他人用户名探测接口
      if (e.email.toLowerCase() === normEmail && e.status === 'pending' && !e.email_verified) {
        if (!(await verifyPassword(password, e.password_hash))) {
          return res.status(400).json({ error: '该邮箱有未完成的注册，请使用原密码继续' });
        }
        // 用户名必须与原记录一致：否则用户会误以为改名成功，实际沿用旧名
        if (e.username.toLowerCase() !== username.trim().toLowerCase()) {
          return res.status(400).json({ error: `该邮箱有未完成的注册（用户名 ${e.username}），请使用原用户名继续` });
        }
        // 与首次注册共用同一发码限流桶，防止绕过限流
        if (!ipRateLimit(`reg-code:${ip}`, 60 * 60 * 1000, REG_CODE_PER_HOUR)) {
          return res.status(429).json({ error: '发送太频繁，请 1 小时后再试' });
        }
        const code = await issueCode(normEmail, 'register', ip);
        try {
          const sent = await mail.sendCode(normEmail, code, 'register');
          db.audit(e.username, 'register_resume', ip, '');
          return res.json({
            ok: true,
            needs_verify: true,
            message: '检测到未完成的注册，验证码已重新发送',
            ...(sent.debug ? { debug_code: sent.code } : {}),
          });
        } catch (err) {
          await db.query('DELETE FROM codes WHERE LOWER(email) = $1 AND purpose = $2', [normEmail, 'register']);
          console.error('[register] resume send failed, rollback codes:', err.message);
          return res.status(502).json({ error: '邮件发送失败，请稍后再试或联系管理员' });
        }
      }
      return res.status(400).json({ error: '用户名或邮箱已被注册' });
    }

    if (flags.email_verify_required && !ipRateLimit(`reg-code:${ip}`, 60 * 60 * 1000, REG_CODE_PER_HOUR)) {
      return res.status(429).json({ error: '发送太频繁，请 1 小时后再试' });
    }

    // 首个用户判定 + 用户插入 + 邀请码占用原子化（advisory lock 串行化并发注册）
    const OWNER_LOCK_KEY = 8128;
    let isFirst = false;
    try {
      isFirst = await db.withTransaction(async (client) => {
        await client.query('SELECT pg_advisory_xact_lock($1)', [OWNER_LOCK_KEY]);
        const { rows: cnt } = await client.query('SELECT COUNT(*)::int AS c FROM users');
        const first = cnt[0].c === 0;
        // 首个用户会成为 owner：配置了 OWNER_EMAIL 时只允许该邮箱注册，防止部署窗口被抢注
        if (first) {
          const ownerEmail = (process.env.OWNER_EMAIL || '').trim().toLowerCase();
          if (ownerEmail && normEmail !== ownerEmail) throw new Error('OWNER_EMAIL_MISMATCH');
        }
        const pwdHash = await hashPassword(password);
        await client.query(
          `INSERT INTO users (username, email, password_hash, status, role, invite_code_used, apply_info, is_owner, email_verified)
           VALUES ($1, $2, $3, 'pending', $4, $5, $6, $7, $8)`,
          [username.trim(), normEmail, pwdHash, first ? 'admin' : 'user', usedInvite,
            apply_info ? String(apply_info).trim() : null, first,
            // 不需要邮箱验证时直接视为「邮箱环节已通过」，否则僵尸清理会误删真·待审用户
            !flags.email_verify_required]
        );
        if (usedInvite) {
          // 原子条件占用：防止并发超用（max_uses=0 表示不限次）
          const up = await client.query(
            `UPDATE invite_codes SET used_count = used_count + 1, used_by = $1, used_at = now()
             WHERE code = $2 AND (max_uses = 0 OR used_count < max_uses)`,
            [normEmail, usedInvite]
          );
          if (up.rowCount === 0) throw new Error('INVITE_EXHAUSTED');
          await client.query('INSERT INTO invite_usage_log (code, email) VALUES ($1, $2)', [usedInvite, normEmail]);
        }
        return first;
      });
    } catch (e) {
      if (e.message === 'INVITE_EXHAUSTED') {
        return res.status(400).json({ error: '邀请码已被使用' });
      }
      if (e.message === 'OWNER_EMAIL_MISMATCH') {
        return res.status(403).json({ error: '系统尚未初始化，请使用 OWNER_EMAIL 指定的邮箱注册首个管理员' });
      }
      throw e;
    }

    // 免邮箱验证直接进入 pending 时：通知管理员审核
    const notifyPending = async (uName, uEmail, applyText) => {
      try {
        const { rows: admins } = await db.query('SELECT email FROM users WHERE role = $1 AND status = $2', ['admin', 'active']);
        for (const a of admins) {
          mail.sendNotify(a.email, 'new_pending', { username: uName, email: uEmail, apply_info: applyText || '（无）' })
            .catch((e) => console.error('[notify] new_pending failed:', e.message));
        }
      } catch (e) {
        console.error('[notify] admins query failed:', e.message);
      }
    };

    if (flags.email_verify_required) {
      const code = await issueCode(normEmail, 'register', ip);
      try {
        const sent = await mail.sendCode(normEmail, code, 'register');
        db.audit(username, 'register_submit', ip, `flags=${JSON.stringify(flags)}`);
        res.json({
          ok: true,
          needs_verify: true,
          message: '验证码已发送，请查收邮箱',
          ...(sent.debug ? { debug_code: sent.code } : {}),
        });
      } catch (e) {
        // 发信失败：回滚已创建的用户/验证码/邀请码占用
        console.error('[register] send mail failed, rollback:', e.message);
        await db.query('DELETE FROM users WHERE LOWER(email) = $1 AND status = $2', [normEmail, 'pending']);
        await db.query('DELETE FROM codes WHERE LOWER(email) = $1 AND purpose = $2', [normEmail, 'register']);
        if (usedInvite) {
          await db.query(
            'UPDATE invite_codes SET used_count = GREATEST(used_count - 1, 0), used_by = NULL, used_at = NULL WHERE code = $1 AND used_by = $2',
            [usedInvite, normEmail]
          );
          await db.query('DELETE FROM invite_usage_log WHERE code = $1 AND email = $2', [usedInvite, normEmail]);
        }
        res.status(502).json({ error: '邮件发送失败，请稍后再试或联系管理员' });
      }
      return;
    }

    // 无邮箱验证：注册即完成
    const initialStatus = flags.review_required ? 'pending' : 'active';
    await db.query(
      `UPDATE users SET status = $1 WHERE LOWER(email) = $2 AND status = 'pending'`,
      [initialStatus, normEmail]
    );
    db.audit(username, 'register_done', ip, `status=${initialStatus}`);
    if (initialStatus === 'pending') {
      notifyPending(username, normEmail, apply_info ? String(apply_info).trim() : '');
    }
    res.json({
      ok: true,
      status: initialStatus,
      message: initialStatus === 'active' ? '注册成功，可以登录了' : '注册成功，等待管理员审核通过后即可登录',
    });
  } catch (e) {
    console.error('[register] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- 邮箱验证码校验（注册用）----
router.post('/verify-email', async (req, res) => {
  try {
    const { email, code } = req.body || {};
    if (!email || !code) return res.status(400).json({ error: '参数缺失' });

    const normEmail = normalizeAccount(email);
    const r = await consumeCode(normEmail, code, 'register');
    if (r.error) return res.status(400).json({ error: r.error });

    const flags = await db.getRegistrationFlags();
    const { rows: uRows } = await db.query(
      'SELECT role FROM users WHERE LOWER(email) = $1 AND status = $2',
      [normEmail, 'pending']
    );
    if (uRows.length === 0) return res.status(400).json({ error: '账号不存在或状态异常' });

    // 管理员（首位用户）不参与审核，直接激活
    const status = flags.review_required && uRows[0].role !== 'admin' ? 'pending' : 'active';
    const { rows: updated } = await db.query(
      'UPDATE users SET status = $1, email_verified = TRUE WHERE LOWER(email) = $2 AND status = $3 RETURNING id, username, role',
      [status, normEmail, 'pending']
    );
    if (updated.length === 0) return res.status(400).json({ error: '账号不存在或状态异常' });
    const u = updated[0];

    db.audit(u.username, 'register_verify', req.ip, `status=${status}`);
    if (status === 'pending') {
      try {
        const { rows: admins } = await db.query('SELECT email FROM users WHERE role = $1 AND status = $2', ['admin', 'active']);
        for (const a of admins) {
          mail.sendNotify(a.email, 'new_pending', { username: u.username, email: normEmail, apply_info: '（邮箱验证通过）' })
            .catch((e) => console.error('[notify] new_pending failed:', e.message));
        }
      } catch (e) {
        console.error('[notify] admins query failed:', e.message);
      }
    }
    res.json({
      ok: true,
      status,
      message: status === 'active' ? '注册成功，可以登录了' : '邮箱已验证，等待管理员审核通过后即可登录',
    });
  } catch (e) {
    console.error('[verify-email] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- 登录：签发 access + refresh ----
router.post('/login', async (req, res) => {
  try {
    const { account, password, totp_code } = req.body || {};
    const ip = req.ip;
    if (!account || !password) return res.status(400).json({ error: '请输入账号和密码' });

    const lockKey = `login:${ip}:${normalizeAccount(account)}`;
    const check = loginAttempt(lockKey);
    if (check.locked) {
      return res.status(429).json({ error: `尝试次数过多，请 ${check.remainSec} 秒后再试` });
    }

    // 密码错与 TOTP 错返回完全一致的消息（防密码 oracle）；不含剩余次数（次数差异也是可区分信号）
    const failMsg = () => '密码或 TOTP 验证码错误';

    const { rows } = await db.query(
      'SELECT * FROM users WHERE LOWER(username) = $1 OR LOWER(email) = $1',
      [normalizeAccount(account)]
    );
    if (rows.length === 0 || !(await verifyPassword(password, rows[0].password_hash))) {
      db.audit(account, 'login_fail', ip, 'bad_credentials');
      return res.status(401).json({ error: failMsg() });
    }

    const u = rows[0];
    if (u.status === 'pending') return res.status(403).json({ error: '账号待审核，请等待管理员通过' });
    if (u.status === 'banned') return res.status(403).json({ error: '账号已被封禁' });

    if (u.totp_enabled) {
      // 不带码/错码/校验异常 → 统一计一次并返回与密码错误相同的消息
      let ok = false;
      if (totp_code) {
        try {
          authenticator.options = { window: 1 };
          ok = authenticator.check(totp_code, u.totp_secret);
        } catch { ok = false; }
      }
      if (!ok) {
        db.audit(u.username, 'login_fail', ip, 'bad_totp');
        loginAttempt(lockKey);
        return res.status(401).json({ error: failMsg() });
      }
    }

    loginSuccess(lockKey);
    await session.createSession(res, u.id);
    const needTotpSetup = u.role === 'admin' && !u.totp_enabled && process.env.ADMIN_TOTP_REQUIRED === 'true';
    db.audit(u.username, 'login_success', ip, '');
    res.json({
      ok: true,
      user: {
        id: u.id, username: u.username, email: u.email,
        role: u.role, status: u.status, is_owner: u.is_owner,
      },
      need_totp_setup: needTotpSetup,
    });
  } catch (e) {
    console.error('[login] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- 登出：销毁服务端会话 ----
router.post('/logout', async (req, res) => {
  try {
    const s = await session.getSession(req);
    await session.destroySession(req, res);
    // 同时撤销 OIDC 侧：否则 provider 的 _session cookie 还在，小站会被静默重新登录
    if (s) await revokeOidc(req, s.id);
    const provSession = process.env.OIDC_COOKIE_SECURE === 'true' ? '__Host-_session' : '_session';
    res.clearCookie(provSession, { path: '/' });
    res.clearCookie(`${provSession}.sig`, { path: '/' });
    res.json({ ok: true });
  } catch (e) {
    console.error('[logout] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- 用户信息（当前会话）----
router.get('/userinfo', createSessionAuth(), (req, res) => {
  res.json({
    id: req.user.id,
    username: req.user.username,
    email: req.user.email,
    role: req.user.role,
    totp_enabled: req.user.totp_enabled,
    is_owner: req.user.is_owner,
  });
});

// ---- 注册模式开关 + 站点设置 + 允许回跳的站点白名单（防开放重定向）----
router.get('/config', async (req, res) => {
  try {
    const flags = await db.getRegistrationFlags();
    const redirectOrigins = (process.env.CORS_ORIGINS || '')
      .split(',')
      .map((s) => {
        try { return new URL(s.trim()).origin; } catch { return s.trim(); }
      })
      .filter(Boolean);
    const site = {
      site_title: process.env.SITE_TITLE || '认证中心',
      site_icon: process.env.SITE_ICON || '',
      site_bg: process.env.SITE_BG || '',
      site_bg_register: process.env.SITE_BG_REGISTER || process.env.SITE_BG || '',
    };
    res.json({ flags, redirect_origins: redirectOrigins, site });
  } catch (e) {
    console.error('[config] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ===================== 个人中心 =====================
const profileAuth = createSessionAuth();

/**
 * 收回该账号在小站侧的访问权（OIDC 的 Session / Grant / RefreshToken）
 * 只删本站 sessions 是不够的：小站手里的 refresh token 仍然有效。
 */
async function revokeOidc(req, userId) {
  const oidc = req.app.locals && req.app.locals.oidc;
  if (!oidc) return;
  try {
    await oidc.revokeAccount(userId);
  } catch (e) {
    console.error('[oidc revoke] failed:', e.message);
  }
}

// ---- 修改用户名 ----
router.post('/profile/username', profileAuth, async (req, res) => {
  try {
    const { username } = req.body || {};
    if (!username || !USERNAME_RE.test(username)) {
      return res.status(400).json({ error: '用户名需为 2-20 位中文、字母、数字或下划线' });
    }
    const { rows: dup } = await db.query(
      'SELECT id FROM users WHERE LOWER(username) = $1 AND id <> $2',
      [username.trim().toLowerCase(), req.user.id]
    );
    if (dup.length > 0) return res.status(400).json({ error: '用户名已被使用' });
    await db.query('UPDATE users SET username = $1 WHERE id = $2', [username.trim(), req.user.id]);
    db.audit(req.user.username, 'profile_username_change', req.ip, `to=${username.trim()}`);
    res.json({ ok: true, message: '用户名已更新' });
  } catch (e) {
    console.error('[profile username] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- 修改密码（验证旧密码；改后吊销所有刷新令牌）----
router.post('/profile/password', profileAuth, async (req, res) => {
  try {
    const { old_password, new_password } = req.body || {};
    if (!old_password || !new_password || new_password.length < 8 || new_password.length > 72) {
      return res.status(400).json({ error: '新密码长度需为 8-72 位' });
    }
    const { rows } = await db.query('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
    if (!(await verifyPassword(old_password, rows[0].password_hash))) {
      return res.status(400).json({ error: '旧密码错误' });
    }
    const newHash = await hashPassword(new_password);
    await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, req.user.id]);
    await session.destroyUserSessions(req.user.id);
    await revokeOidc(req, req.user.id);
    db.audit(req.user.username, 'profile_password_change', req.ip, '');
    res.json({ ok: true, message: '密码已修改，其他设备需重新登录' });
  } catch (e) {
    console.error('[profile password] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- 修改邮箱：第一步，发送验证码到新邮箱 ----
router.post('/profile/email', profileAuth, async (req, res) => {
  try {
    const { new_email } = req.body || {};
    if (!new_email || !EMAIL_RE.test(new_email)) return res.status(400).json({ error: '邮箱格式不正确' });
    if (emailBlocked(new_email)) return res.status(400).json({ error: '该邮箱域名不允许使用' });
    const normEmail = normalizeAccount(new_email);
    if (normEmail === req.user.email) return res.status(400).json({ error: '新邮箱与当前邮箱相同' });
    const { rows: dup } = await db.query('SELECT id FROM users WHERE LOWER(email) = $1 AND id <> $2', [normEmail, req.user.id]);
    if (dup.length > 0) return res.status(400).json({ error: '该邮箱已被其他账号使用' });
    if (!ipRateLimit(`profile-code:${req.ip}`, 60 * 60 * 1000, PROFILE_CODE_PER_HOUR)) {
      return res.status(429).json({ error: '发送太频繁，请稍后再试' });
    }
    const code = await issueCode(normEmail, 'change_email', req.ip);
    try {
      const sent = await mail.sendCode(normEmail, code, 'change_email');
      res.json({
        ok: true,
        message: '验证码已发送到新邮箱',
        ...(sent.debug ? { debug_code: sent.code } : {}),
      });
    } catch (e) {
      await db.query('DELETE FROM codes WHERE LOWER(email) = $1 AND purpose = $2', [normEmail, 'change_email']);
      console.error('[profile email] send failed:', e.message);
      res.status(502).json({ error: '邮件发送失败，请稍后再试' });
    }
  } catch (e) {
    console.error('[profile email] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- 修改邮箱：第二步，校验验证码后生效 ----
router.post('/profile/email/verify', profileAuth, async (req, res) => {
  try {
    const { new_email, code } = req.body || {};
    if (!new_email || !code) return res.status(400).json({ error: '参数缺失' });
    const normEmail = normalizeAccount(new_email);
    const r = await consumeCode(normEmail, code, 'change_email');
    if (r.error) return res.status(400).json({ error: r.error });
    await db.query('UPDATE users SET email = $1, email_verified = TRUE WHERE id = $2', [normEmail, req.user.id]);
    await session.destroyUserSessions(req.user.id);
    await revokeOidc(req, req.user.id);
    db.audit(req.user.username, 'profile_email_change', req.ip, `to=${normEmail}`);
    res.json({ ok: true, message: '邮箱已更新' });
  } catch (e) {
    console.error('[profile email verify] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- TOTP：生成绑定密钥（160bit + 二维码），所有用户可用；已绑定需验证当前 TOTP 防劫持 ----
router.post('/profile/totp-setup', profileAuth, async (req, res) => {
  try {
    const { rows } = await db.query('SELECT totp_enabled, totp_secret FROM users WHERE id = $1', [req.user.id]);
    if (rows[0].totp_enabled) {
      const { code } = req.body || {};
      if (!code) return res.status(400).json({ error: '已绑定 TOTP，请输入当前验证码以重新生成' });
      let ok = false;
      try {
        authenticator.options = { window: 1 };
        ok = authenticator.check(code, rows[0].totp_secret);
      } catch { ok = false; }
      if (!ok) {
        // 失败计数锁定，防爆破（5 次锁 15 分钟）；与 confirm/disable 共享同一 key
        const ck = loginAttempt(`totp:${req.user.id}`);
        return res.status(401).json({ error: ck.locked ? '尝试次数过多，请稍后再试' : 'TOTP 验证码错误' });
      }
    }
    const secret = authenticator.generateSecret(20);
    await db.query('UPDATE users SET totp_secret = $1 WHERE id = $2', [secret, req.user.id]);
    const uri = authenticator.keyuri(req.user.username, 'AuthCenter', secret);
    const qr = await QRCode.toDataURL(uri);
    res.json({ ok: true, secret, uri, qr });
  } catch (e) {
    console.error('[totp setup] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- TOTP：确认绑定 ----
router.post('/profile/totp-confirm', profileAuth, async (req, res) => {
  try {
    const { code } = req.body || {};
    if (!code) return res.status(400).json({ error: '请输入验证码' });
    const { rows } = await db.query('SELECT totp_secret FROM users WHERE id = $1', [req.user.id]);
    if (rows.length === 0 || !rows[0].totp_secret) return res.status(400).json({ error: '请先生成绑定密钥' });
    let ok = false;
    try {
      ok = authenticator.check(code, rows[0].totp_secret);
    } catch { ok = false; }
    if (!ok) {
      // 与 setup/disable 共享失败计数
      const ck = loginAttempt(`totp:${req.user.id}`);
      return res.status(401).json({ error: ck.locked ? '尝试次数过多，请稍后再试' : '验证码错误' });
    }
    await db.query('UPDATE users SET totp_enabled = TRUE WHERE id = $1', [req.user.id]);
    db.audit(req.user.username, 'totp_enable', req.ip, '');
    res.json({ ok: true, message: 'TOTP 已绑定' });
  } catch (e) {
    console.error('[totp confirm] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- TOTP：解绑（需当前验证码确认）----
router.post('/profile/totp-disable', profileAuth, async (req, res) => {
  try {
    const { code } = req.body || {};
    if (!req.user.totp_enabled) return res.status(400).json({ error: '当前未绑定 TOTP' });
    if (!code) return res.status(400).json({ error: '请输入当前 TOTP 验证码以确认解绑' });
    const { rows } = await db.query('SELECT totp_secret FROM users WHERE id = $1', [req.user.id]);
    if (rows.length === 0 || !rows[0].totp_secret) return res.status(400).json({ error: 'TOTP 数据异常' });
    let ok = false;
    try {
      ok = authenticator.check(code, rows[0].totp_secret);
    } catch { ok = false; }
    if (!ok) {
      // 与 setup/confirm 共享失败计数
      const ck = loginAttempt(`totp:${req.user.id}`);
      return res.status(401).json({ error: ck.locked ? '尝试次数过多，请稍后再试' : '验证码错误' });
    }
    await db.query('UPDATE users SET totp_enabled = FALSE, totp_secret = NULL WHERE id = $1', [req.user.id]);
    db.audit(req.user.username, 'totp_disable', req.ip, '');
    res.json({ ok: true, message: 'TOTP 已解绑' });
  } catch (e) {
    console.error('[totp disable] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- 找回密码：第一步，账号 +（已绑 TOTP 则需验证 TOTP）→ 发送邮箱重置验证码 ----
// 防枚举：所有分支（不存在/非活跃/无 TOTP/有 TOTP 不带码/TOTP 错）返回同一消息
router.post('/forgot-password', async (req, res) => {
  try {
    const { account, totp_code } = req.body || {};
    if (!account) return res.status(400).json({ error: '请输入账号' });
    const ip = req.ip;

    const GENERIC = { ok: true, message: '如果账号存在，验证码已发送到邮箱' };

    // 限流前置：对所有请求统一计数（429 行为与账号存在性解耦，防枚举）
    if (!ipRateLimit(`profile-code:${ip}`, 60 * 60 * 1000, PROFILE_CODE_PER_HOUR)) {
      return res.status(429).json({ error: '发送太频繁，请稍后再试' });
    }

    const { rows } = await db.query(
      'SELECT id, username, email, totp_enabled, totp_secret, status FROM users WHERE LOWER(username) = $1 OR LOWER(email) = $1',
      [normalizeAccount(account)]
    );
    if (rows.length === 0) return res.json(GENERIC);
    const u = rows[0];
    if (u.status !== 'active') return res.json(GENERIC);

    if (u.totp_enabled) {
      if (!totp_code) return res.json(GENERIC);
      let ok = false;
      try {
        authenticator.options = { window: 1 };
        ok = authenticator.check(totp_code, u.totp_secret);
      } catch { ok = false; }
      if (!ok) return res.json(GENERIC);
    }

    const code = await issueCode(u.email, 'reset_password', ip);
    try {
      const sent = await mail.sendCode(u.email, code, 'reset_password');
      db.audit(u.username, 'forgot_password_code', ip, '');
      res.json({
        ok: true,
        message: GENERIC.message,
        ...(sent.debug ? { debug_code: sent.code } : {}),
      });
    } catch (e) {
      await db.query('DELETE FROM codes WHERE LOWER(email) = $1 AND purpose = $2', [u.email, 'reset_password']);
      console.error('[forgot-password] send failed:', e.message);
      res.status(502).json({ error: '邮件发送失败，请稍后再试' });
    }
  } catch (e) {
    console.error('[forgot-password] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- 找回密码：第二步，邮箱验证码 + 新密码 → 重置并吊销全部会话 ----
router.post('/reset-password', async (req, res) => {
  try {
    const { account, code, new_password } = req.body || {};
    if (!account || !code || !new_password) return res.status(400).json({ error: '参数缺失' });
    if (new_password.length < 8 || new_password.length > 72) {
      return res.status(400).json({ error: '新密码长度需为 8-72 位' });
    }
    const normAccount = normalizeAccount(account);
    const { rows: uRows } = await db.query(
      'SELECT id, username, email, status FROM users WHERE LOWER(username) = $1 OR LOWER(email) = $1',
      [normAccount]
    );
    // 账号不存在/非活跃统一走验证码错误消息（防枚举）
    if (uRows.length === 0 || uRows[0].status !== 'active') {
      return res.status(400).json({ error: '验证码不存在或已过期，请重新获取' });
    }
    const u = uRows[0];

    const r = await consumeCode(u.email, code, 'reset_password');
    if (r.error) return res.status(400).json({ error: r.error });

    const newHash = await hashPassword(new_password);
    await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, u.id]);
    await session.destroyUserSessions(u.id);
    await revokeOidc(req, u.id);
    db.audit(u.username, 'reset_password', req.ip, '');
    res.json({ ok: true, message: '密码已重置，请重新登录' });
  } catch (e) {
    console.error('[reset-password] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

module.exports = { router, hashPassword, verifyPassword, normalizeAccount, emailBlocked, EMAIL_RE, USERNAME_RE };
