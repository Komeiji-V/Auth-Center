const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const QRCode = require('qrcode');
const { authenticator } = require('otplib');

const db = require('./db');
const mail = require('./mail');
const { loginAttempt, loginSuccess, ipRateLimit } = require('./rateLimit');
const { createAuthMiddleware } = require('./middleware');

const router = express.Router();

const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 32 };
const CODE_MAX_ATTEMPTS = 5;
const REFRESH_TTL_DAYS = 30;
const REG_CODE_PER_HOUR = parseInt(process.env.REG_CODE_PER_HOUR, 10) || 3;
const PROFILE_CODE_PER_HOUR = parseInt(process.env.PROFILE_CODE_PER_HOUR, 10) || 5;

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const USERNAME_RE = /^[a-zA-Z0-9_]{3,20}$/;

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('hex')}$${hash.toString('hex')}`;
}

function verifyPassword(password, stored) {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, n, r, p, saltHex, hashHex] = parts;
  const hash = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), hashHex.length / 2, {
    N: parseInt(n, 10), r: parseInt(r, 10), p: parseInt(p, 10),
  });
  if (hash.length !== Buffer.from(hashHex, 'hex').length) return false;
  return crypto.timingSafeEqual(hash, Buffer.from(hashHex, 'hex'));
}

function emailBlocked(email) {
  const domain = email.split('@')[1].toLowerCase();
  const blocked = (process.env.BLOCKED_EMAIL_DOMAINS || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  return blocked.includes(domain);
}

function normalizeAccount(account) {
  return account.trim().toLowerCase();
}

function signToken(user) {
  return jwt.sign({ uid: user.id, role: user.role }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES || '1h',
    algorithm: 'HS256',
  });
}

function tokenExpiresIn(token) {
  const d = jwt.decode(token);
  return d && d.exp ? d.exp - d.iat : 3600;
}

function genRefreshToken() {
  return crypto.randomBytes(48).toString('base64url');
}

function hashRefresh(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

async function issueTokens(user) {
  const token = signToken(user);
  const refreshToken = genRefreshToken();
  await db.query(
    `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
     VALUES ($1, $2, now() + interval '${REFRESH_TTL_DAYS} days')`,
    [user.id, hashRefresh(refreshToken)]
  );
  return { token, refresh_token: refreshToken, expires_in: tokenExpiresIn(token) };
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
  await db.query('UPDATE codes SET used = TRUE WHERE id = $1', [c.id]);
  return { ok: true };
}

// ---- 注册：三开关组合（邀请码/邮箱验证/人工审核，任意组合）----
router.post('/register', async (req, res) => {
  try {
    const { username, email, password, invite_code, apply_info } = req.body || {};
    const ip = req.ip;

    if (!username || !USERNAME_RE.test(username)) {
      return res.status(400).json({ error: '用户名需为 3-20 位字母、数字或下划线' });
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
      'SELECT username, email FROM users WHERE LOWER(username) = $1 OR LOWER(email) = $2',
      [username.trim().toLowerCase(), normEmail]
    );
    if (dup.length > 0) return res.status(400).json({ error: '用户名或邮箱已被注册' });

    if (flags.email_verify_required && !ipRateLimit(`reg-code:${ip}`, 60 * 60 * 1000, REG_CODE_PER_HOUR)) {
      return res.status(429).json({ error: '发送太频繁，请 1 小时后再试' });
    }

    // 首个用户判定 + 插入原子化：advisory lock 串行化并发注册，防止双 owner
    const OWNER_LOCK_KEY = 8128;
    const isFirst = await db.withTransaction(async (client) => {
      await client.query('SELECT pg_advisory_xact_lock($1)', [OWNER_LOCK_KEY]);
      const { rows: cnt } = await client.query('SELECT COUNT(*)::int AS c FROM users');
      const first = cnt[0].c === 0;
      await client.query(
        `INSERT INTO users (username, email, password_hash, status, role, invite_code_used, apply_info, is_owner)
         VALUES ($1, $2, $3, 'pending', $4, $5, $6, $7)`,
        [username.trim(), normEmail, hashPassword(password), first ? 'admin' : 'user', usedInvite,
          apply_info ? String(apply_info).trim() : null, first]
      );
      return first;
    });

    if (usedInvite) {
      await db.query(
        'UPDATE invite_codes SET used_count = used_count + 1, used_by = $1, used_at = now() WHERE code = $2',
        [normEmail, usedInvite]
      );
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
      'UPDATE users SET status = $1 WHERE LOWER(email) = $2 AND status = $3 RETURNING id, username, role',
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

    const { rows } = await db.query(
      'SELECT * FROM users WHERE LOWER(username) = $1 OR LOWER(email) = $1',
      [normalizeAccount(account)]
    );
    if (rows.length === 0 || !verifyPassword(password, rows[0].password_hash)) {
      db.audit(account, 'login_fail', ip, 'bad_credentials');
      const remain = check.remain;
      return res.status(401).json({
        error: remain > 0 ? `用户名或密码错误（剩余 ${remain} 次机会）` : '尝试次数过多，已锁定 15 分钟',
      });
    }

    const u = rows[0];
    if (u.status === 'pending') return res.status(403).json({ error: '账号待审核，请等待管理员通过' });
    if (u.status === 'banned') return res.status(403).json({ error: '账号已被封禁' });

    if (u.totp_enabled) {
      if (!totp_code) return res.status(400).json({ error: '该账号已开启 TOTP，请输入验证码' });
      try {
        authenticator.options = { window: 1 };
        const ok = authenticator.check(totp_code, u.totp_secret);
        if (!ok) return res.status(401).json({ error: 'TOTP 验证码错误' });
      } catch {
        return res.status(401).json({ error: 'TOTP 验证失败' });
      }
    }

    loginSuccess(lockKey);
    const tokens = await issueTokens(u);
    const needTotpSetup = u.role === 'admin' && !u.totp_enabled && process.env.ADMIN_TOTP_REQUIRED === 'true';
    db.audit(u.username, 'login_success', ip, '');
    res.json({
      ok: true,
      token: tokens.token,
      refresh_token: tokens.refresh_token,
      expires_in: tokens.expires_in,
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

// ---- 刷新令牌：轮换制，封禁/审核状态即时失效 ----
router.post('/refresh', async (req, res) => {
  try {
    const { refresh_token } = req.body || {};
    if (!refresh_token) return res.status(400).json({ error: '缺少刷新令牌' });

    const { rows } = await db.query(
      `SELECT rt.id, rt.user_id, u.username, u.role, u.status
       FROM refresh_tokens rt JOIN users u ON u.id = rt.user_id
       WHERE rt.token_hash = $1 AND rt.revoked = FALSE AND rt.expires_at > now()`,
      [hashRefresh(refresh_token)]
    );
    if (rows.length === 0) return res.status(401).json({ error: '刷新令牌无效或已过期，请重新登录' });

    const rt = rows[0];
    if (rt.status === 'pending') return res.status(403).json({ error: '账号待审核，请等待管理员通过' });
    if (rt.status === 'banned') return res.status(403).json({ error: '账号已被封禁' });

    // 轮换：吊销旧 refresh，签发新的一对
    await db.query('UPDATE refresh_tokens SET revoked = TRUE WHERE id = $1', [rt.id]);
    const tokens = await issueTokens({ id: rt.user_id, username: rt.username, role: rt.role });
    res.json({ ok: true, ...tokens });
  } catch (e) {
    console.error('[refresh] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- 用户信息（各小站校验身份用）----
router.get('/userinfo', createAuthMiddleware(process.env.JWT_SECRET, db), (req, res) => {
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
    const redirectHosts = (process.env.CORS_ORIGINS || '')
      .split(',')
      .map((s) => {
        try { return new URL(s.trim()).host; } catch { return s.trim(); }
      })
      .filter(Boolean);
    const site = {
      site_title: process.env.SITE_TITLE || '认证中心',
      site_icon: process.env.SITE_ICON || '',
      site_bg: process.env.SITE_BG || '',
    };
    res.json({ flags, redirect_hosts: redirectHosts, site });
  } catch (e) {
    console.error('[config] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ===================== 个人中心 =====================
const profileAuth = createAuthMiddleware(process.env.JWT_SECRET, db);

// ---- 修改用户名 ----
router.post('/profile/username', profileAuth, async (req, res) => {
  try {
    const { username } = req.body || {};
    if (!username || !USERNAME_RE.test(username)) {
      return res.status(400).json({ error: '用户名需为 3-20 位字母、数字或下划线' });
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
    if (!verifyPassword(old_password, rows[0].password_hash)) {
      return res.status(400).json({ error: '旧密码错误' });
    }
    await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hashPassword(new_password), req.user.id]);
    await db.query('UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1', [req.user.id]);
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
    await db.query('UPDATE users SET email = $1 WHERE id = $2', [normEmail, req.user.id]);
    await db.query('UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1', [req.user.id]);
    db.audit(req.user.username, 'profile_email_change', req.ip, `to=${normEmail}`);
    res.json({ ok: true, message: '邮箱已更新' });
  } catch (e) {
    console.error('[profile email verify] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- TOTP：生成绑定密钥（160bit + 二维码），所有用户可用 ----
router.post('/profile/totp-setup', profileAuth, async (req, res) => {
  try {
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
    const ok = authenticator.check(code, rows[0].totp_secret);
    if (!ok) return res.status(400).json({ error: '验证码错误' });
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
    const ok = authenticator.check(code, rows[0].totp_secret);
    if (!ok) return res.status(400).json({ error: '验证码错误' });
    await db.query('UPDATE users SET totp_enabled = FALSE, totp_secret = NULL WHERE id = $1', [req.user.id]);
    db.audit(req.user.username, 'totp_disable', req.ip, '');
    res.json({ ok: true, message: 'TOTP 已解绑' });
  } catch (e) {
    console.error('[totp disable] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

module.exports = { router, hashPassword, verifyPassword, normalizeAccount, emailBlocked, EMAIL_RE, USERNAME_RE };
