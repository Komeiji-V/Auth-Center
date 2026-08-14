const express = require('express');
const crypto = require('crypto');

const db = require('./db');
const mail = require('./mail');
const { createAdminMiddleware } = require('./middleware');
const { normalizeAccount, emailBlocked, EMAIL_RE, USERNAME_RE } = require('./auth');
const { clearUserLocks } = require('./rateLimit');

const router = express.Router();

const adminGuard = createAdminMiddleware(process.env.JWT_SECRET, db, process.env.ADMIN_TOTP_REQUIRED === 'true');

function validId(v) {
  const id = parseInt(v, 10);
  return Number.isInteger(id) ? id : null;
}

async function loadUser(id) {
  const { rows } = await db.query(
    'SELECT id, username, email, status, role, is_owner, invite_code_used, apply_info FROM users WHERE id = $1',
    [id]
  );
  return rows[0] || null;
}

// 目标为管理员/owner 时，仅 owner 可执行管理操作（封禁/解封/编辑/设取消管理员/拒绝/解锁）
function canManageUser(actor, target) {
  if (target.role === 'admin' || target.is_owner) {
    return actor.is_owner;
  }
  return true;
}

// ---- 用户列表：?status=pending|active|banned|all ----
router.get('/users', ...adminGuard, async (req, res) => {
  try {
    const status = req.query.status || 'pending';
    const params = [];
    let where = '';
    if (status !== 'all') {
      where = 'WHERE status = $1';
      params.push(status);
    }
    const { rows } = await db.query(
      `SELECT id, username, email, status, role, is_owner, invite_code_used, apply_info, created_at, approved_at, banned_at
       FROM users ${where} ORDER BY id DESC LIMIT 200`,
      params
    );
    res.json({ users: rows });
  } catch (e) {
    console.error('[admin users] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- 人工审核：通过（发送通知邮件）----
router.post('/users/:id/approve', ...adminGuard, async (req, res) => {
  try {
    const id = validId(req.params.id);
    if (!id) return res.status(400).json({ error: '参数错误' });
    const { rows } = await db.query(
      `UPDATE users SET status = 'active', approved_at = now(), banned_at = NULL
       WHERE id = $1 AND status <> 'banned'
       RETURNING id, username, email, status`,
      [id]
    );
    if (rows.length === 0) return res.status(400).json({ error: '用户不存在或已被封禁' });
    const u = rows[0];
    db.audit(req.user.username, 'user_approve', req.ip, `target=${u.username}`);
    mail.sendNotify(u.email, 'approved').catch((e) => console.error('[notify] approved failed:', e.message));
    res.json({ ok: true, user: u });
  } catch (e) {
    console.error('[approve] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- 人工审核：拒绝 = 删除记录（释放邮箱/用户名/邀请码），用户可重新注册 ----
router.post('/users/:id/reject', ...adminGuard, async (req, res) => {
  try {
    const id = validId(req.params.id);
    if (!id) return res.status(400).json({ error: '参数错误' });
    const u = await loadUser(id);
    if (!u) return res.status(400).json({ error: '用户不存在' });
    if (!canManageUser(req.user, u)) {
      return res.status(403).json({ error: '仅初始管理员（owner）可对管理员执行此操作' });
    }
    if (u.status === 'banned') return res.status(400).json({ error: '用户已被封禁，请使用封禁/删除流程' });

    const email = u.email;
    await db.query('DELETE FROM users WHERE id = $1', [id]);
    await db.query('DELETE FROM codes WHERE LOWER(email) = $1', [email]);
    if (u.invite_code_used) {
      await db.query(
        'UPDATE invite_codes SET used_count = GREATEST(used_count - 1, 0), used_by = NULL, used_at = NULL WHERE code = $1 AND used_by = $2',
        [u.invite_code_used, email]
      );
    }
    db.audit(req.user.username, 'user_reject', req.ip, `target=${u.username}`);
    mail.sendNotify(email, 'rejected').catch((e) => console.error('[notify] rejected failed:', e.message));
    res.json({ ok: true, message: '已拒绝该申请，用户可重新注册' });
  } catch (e) {
    console.error('[reject] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- 封禁（即时生效；发送通知邮件）----
router.post('/users/:id/ban', ...adminGuard, async (req, res) => {
  try {
    const id = validId(req.params.id);
    if (!id) return res.status(400).json({ error: '参数错误' });
    if (id === req.user.id) return res.status(400).json({ error: '不能封禁自己' });
    const u = await loadUser(id);
    if (!u) return res.status(400).json({ error: '用户不存在' });
    if (!canManageUser(req.user, u)) {
      return res.status(403).json({ error: '仅初始管理员（owner）可对管理员执行此操作' });
    }
    await db.query(
      `UPDATE users SET status = 'banned', banned_at = now()
       WHERE id = $1 RETURNING id, username, email, status`,
      [id]
    );
    await db.query('UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1', [id]);
    db.audit(req.user.username, 'user_ban', req.ip, `target=${u.username}`);
    mail.sendNotify(u.email, 'banned').catch((e) => console.error('[notify] banned failed:', e.message));
    res.json({ ok: true, user: { id: u.id, username: u.username, email: u.email, status: 'banned' } });
  } catch (e) {
    console.error('[ban] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- 解封（发送通知邮件）----
router.post('/users/:id/unban', ...adminGuard, async (req, res) => {
  try {
    const id = validId(req.params.id);
    if (!id) return res.status(400).json({ error: '参数错误' });
    const target = await loadUser(id);
    if (!target || target.status !== 'banned') return res.status(400).json({ error: '用户不存在或未封禁' });
    if (!canManageUser(req.user, target)) {
      return res.status(403).json({ error: '仅初始管理员（owner）可对管理员执行此操作' });
    }
    const { rows } = await db.query(
      `UPDATE users SET status = 'active', banned_at = NULL
       WHERE id = $1 AND status = 'banned'
       RETURNING id, username, email, status`,
      [id]
    );
    const u = rows[0];
    db.audit(req.user.username, 'user_unban', req.ip, `target=${u.username}`);
    mail.sendNotify(u.email, 'unbanned').catch((e) => console.error('[notify] unbanned failed:', e.message));
    res.json({ ok: true, user: u });
  } catch (e) {
    console.error('[unban] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- 登录锁定重置（清除该账号所有 IP 维度的失败计数）----
router.post('/users/:id/unlock', ...adminGuard, async (req, res) => {
  try {
    const id = validId(req.params.id);
    if (!id) return res.status(400).json({ error: '参数错误' });
    const u = await loadUser(id);
    if (!u) return res.status(400).json({ error: '用户不存在' });
    if (!canManageUser(req.user, u)) {
      return res.status(403).json({ error: '仅初始管理员（owner）可对管理员执行此操作' });
    }
    const cleared = clearUserLocks(normalizeAccount(u.username));
    db.audit(req.user.username, 'user_unlock', req.ip, `target=${u.username}`);
    res.json({ ok: true, message: `已清除锁定（${cleared} 条）` });
  } catch (e) {
    console.error('[unlock] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- 设置/取消管理员（初始管理员不可取消）----
router.post('/users/:id/set-admin', ...adminGuard, async (req, res) => {
  try {
    const id = validId(req.params.id);
    if (!id) return res.status(400).json({ error: '参数错误' });
    const { is_admin } = req.body || {};
    const u = await loadUser(id);
    if (!u) return res.status(400).json({ error: '用户不存在' });
    // 提升他人为管理员仅 owner 可执行；降级管理员维持 canManageUser 校验（目标为管理员时仅 owner）
    if (is_admin === true && !req.user.is_owner) {
      return res.status(403).json({ error: '仅初始管理员（owner）可添加管理员' });
    }
    if (!canManageUser(req.user, u)) {
      return res.status(403).json({ error: '仅初始管理员（owner）可对管理员执行此操作' });
    }
    if (u.is_owner && is_admin === false) return res.status(400).json({ error: '不能取消初始管理员的管理员身份' });
    if (u.status !== 'active') return res.status(400).json({ error: '仅激活用户可设为管理员' });
    const role = is_admin ? 'admin' : 'user';
    await db.query('UPDATE users SET role = $1 WHERE id = $2', [role, id]);
    db.audit(req.user.username, 'user_set_admin', req.ip, `target=${u.username}, role=${role}`);
    res.json({ ok: true, user: { id: u.id, username: u.username, role } });
  } catch (e) {
    console.error('[set-admin] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- 编辑用户名/邮箱（查重校验）----
router.post('/users/:id/edit', ...adminGuard, async (req, res) => {
  try {
    const id = validId(req.params.id);
    if (!id) return res.status(400).json({ error: '参数错误' });
    const { username, email } = req.body || {};
    const u = await loadUser(id);
    if (!u) return res.status(400).json({ error: '用户不存在' });
    if (!canManageUser(req.user, u)) {
      return res.status(403).json({ error: '仅初始管理员（owner）可对管理员执行此操作' });
    }

    let newUsername = u.username;
    let newEmail = u.email;
    if (username !== undefined && username !== '') {
      if (!USERNAME_RE.test(username)) return res.status(400).json({ error: '用户名需为 3-20 位字母、数字或下划线' });
      const { rows: dup } = await db.query(
        'SELECT id FROM users WHERE LOWER(username) = $1 AND id <> $2',
        [username.trim().toLowerCase(), id]
      );
      if (dup.length > 0) return res.status(400).json({ error: '用户名已被使用' });
      newUsername = username.trim();
    }
    if (email !== undefined && email !== '') {
      if (!EMAIL_RE.test(email)) return res.status(400).json({ error: '邮箱格式不正确' });
      if (emailBlocked(email)) return res.status(400).json({ error: '该邮箱域名不允许使用' });
      const norm = normalizeAccount(email);
      const { rows: dup } = await db.query(
        'SELECT id FROM users WHERE LOWER(email) = $1 AND id <> $2',
        [norm, id]
      );
      if (dup.length > 0) return res.status(400).json({ error: '该邮箱已被其他账号使用' });
      newEmail = norm;
      if (newEmail !== u.email) {
        await db.query('UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1', [id]);
      }
    }
    if (newUsername !== u.username || newEmail !== u.email) {
      await db.query('UPDATE users SET username = $1, email = $2 WHERE id = $3', [newUsername, newEmail, id]);
      db.audit(req.user.username, 'user_edit', req.ip, `target=${u.username} -> ${newUsername}/${newEmail}`);
    }
    res.json({ ok: true, user: { id: u.id, username: newUsername, email: newEmail } });
  } catch (e) {
    console.error('[edit] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- 注册模式开关（三个独立开关）----
router.post('/config', ...adminGuard, async (req, res) => {
  try {
    const { invite_required, email_verify_required, review_required } = req.body || {};
    const next = {
      invite_required: invite_required ? 'true' : 'false',
      email_verify_required: email_verify_required === false ? 'false' : 'true',
      review_required: review_required ? 'true' : 'false',
    };
    for (const [k, v] of Object.entries(next)) {
      await db.setConfig(k, v);
    }
    db.audit(req.user.username, 'config_change', req.ip, JSON.stringify(next));
    res.json({ ok: true, flags: next });
  } catch (e) {
    console.error('[config change] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- 生成邀请码（支持使用次数/过期时间）----
router.post('/invite-codes', ...adminGuard, async (req, res) => {
  try {
    const count = Math.min(Math.max(parseInt((req.body || {}).count, 10) || 1, 1), 100);
    const note = (req.body || {}).note || null;
    const maxUsesRaw = parseInt((req.body || {}).max_uses, 10);
    const maxUses = Number.isInteger(maxUsesRaw) && maxUsesRaw >= 0 ? maxUsesRaw : 1; // 0 = 不限次
    const daysRaw = parseInt((req.body || {}).expires_days, 10);
    const expiresDays = Number.isInteger(daysRaw) && daysRaw > 0 ? daysRaw : null;
    const codes = [];
    for (let i = 0; i < count; i++) {
      const code = crypto.randomBytes(6).toString('hex').toUpperCase();
      await db.query(
        `INSERT INTO invite_codes (code, note, max_uses, expires_at)
         VALUES ($1, $2, $3, CASE WHEN $4::int IS NULL THEN NULL ELSE now() + ($4::int || ' days')::interval END)`,
        [code, note, maxUses, expiresDays]
      );
      codes.push(code);
    }
    db.audit(req.user.username, 'invite_create', req.ip, `count=${count}, max_uses=${maxUses}, days=${expiresDays || 'permanent'}`);
    res.json({ ok: true, codes });
  } catch (e) {
    console.error('[invite create] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- 邀请码列表及使用状态 ----
router.get('/invite-codes', ...adminGuard, async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT code, note, max_uses, used_count, expires_at, used_by, used_at, created_at
       FROM invite_codes ORDER BY id DESC LIMIT 200`
    );
    res.json({ codes: rows });
  } catch (e) {
    console.error('[invite list] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ---- 管理员 TOTP：绑定接口已迁移至 /api/profile/totp-*（所有用户通用）----

module.exports = { router };
