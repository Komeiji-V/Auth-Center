import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { IDP, assertUp } from './helpers.mjs';

/** 用 /api/login 拿会话 cookie（管理接口不走 OIDC） */
async function login(account, password) {
  const res = await fetch(`${IDP}/api/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ account, password }),
  });
  assert.equal(res.status, 200, `${account} 登录失败: ${res.status}`);
  return res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
}

function api(cookie, path, opts = {}) {
  return fetch(`${IDP}${path}`, {
    ...opts,
    headers: {
      'content-type': 'application/json',
      ...(cookie ? { cookie } : {}),
      ...(opts.headers || {}),
    },
  });
}

const OWNER = { account: 'alice', password: 'Passw0rd!123' };
const ADMIN = { account: 'bob', password: 'Passw0rd!123' };
const USER = { account: 'oidcuser', password: 'Passw0rd!123' };

before(async () => {
  await assertUp(`${IDP}/.well-known/openid-configuration`, 'OIDC Provider');
});

describe('管理接口权限矩阵', () => {
  let owner;
  let admin;
  let user;

  before(async () => {
    owner = await login(OWNER.account, OWNER.password);
    admin = await login(ADMIN.account, ADMIN.password);
    user = await login(USER.account, USER.password);

    // 前置：确保 bob(id=2) 是 admin —— 重复执行也安全
    const r = await api(owner, '/api/admin/users/2/set-admin', {
      method: 'POST',
      body: JSON.stringify({ is_admin: true }),
    });
    assert.equal(r.status, 200, '前置失败：owner 无法把 bob 提为 admin');
  });

  it('未登录访问管理接口 → 401', async () => {
    const r = await api(null, '/api/admin/users?status=all');
    assert.equal(r.status, 401);
  });

  it('普通用户访问管理接口 → 403', async () => {
    const r = await api(user, '/api/admin/users?status=all');
    assert.equal(r.status, 403);
  });

  it('非 owner 的管理员无法提升他人 → 403', async () => {
    const r = await api(admin, `/api/admin/users/${5140001}/set-admin`, {
      method: 'POST',
      body: JSON.stringify({ is_admin: true }),
    });
    assert.equal(r.status, 403);
  });

  it('set-admin 传字符串应 400（类型混淆回归）', async () => {
    const r = await api(owner, '/api/admin/users/2/set-admin', {
      method: 'POST',
      body: JSON.stringify({ is_admin: 'true' }),
    });
    assert.equal(r.status, 400);
  });

  it('非 owner 的管理员无法封禁 owner → 403', async () => {
    const r = await api(admin, '/api/admin/users/1/ban', { method: 'POST' });
    assert.equal(r.status, 403);
  });

  it('owner 无法删除自己 → 403', async () => {
    const r = await api(owner, '/api/admin/users/1/reject', { method: 'POST' });
    assert.equal(r.status, 403);
  });

  it('非 owner 的管理员看不到邀请码 → 403', async () => {
    const r = await api(admin, '/api/admin/invite-codes');
    assert.equal(r.status, 403);
  });

  it('id 带杂字符应 400（parseInt 宽松解析回归）', async () => {
    for (const bad of ['2abc', '2.5', '-2', '1e3']) {
      const r = await api(owner, `/api/admin/users/${bad}/edit`, {
        method: 'POST',
        body: JSON.stringify({}),
      });
      assert.equal(r.status, 400, `id=${bad} 应被拒绝，实际 ${r.status}`);
    }
  });

  it('config 三个开关必须是布尔值', async () => {
    const r = await api(owner, '/api/admin/config', {
      method: 'POST',
      body: JSON.stringify({ invite_required: 'false', email_verify_required: true, review_required: false }),
    });
    assert.equal(r.status, 400);
  });

  it('owner 可以正常读取用户列表', async () => {
    const r = await api(owner, '/api/admin/users?status=all');
    assert.equal(r.status, 200);
    const d = await r.json();
    assert.ok(Array.isArray(d.users));
    assert.ok(!('password_hash' in (d.users[0] || {})), '响应不应包含密码哈希');
  });
});
