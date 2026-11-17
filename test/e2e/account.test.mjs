import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { IDP, assertUp, dbClient } from './helpers.mjs';
import auth from '../../src/auth.js';

// 独立测试账号，避免与其它套件互相干扰
const ACCOUNT = `acct_${Date.now().toString(36)}`;
const EMAIL = `${ACCOUNT}@test.local`;
const PASSWORD = 'InitPass123!';
const NEW_PASSWORD = 'ResetPass456!';

let db;

function post(path, body, cookie) {
  return fetch(`${IDP}${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(cookie ? { cookie } : {}),
    },
    body: JSON.stringify(body),
  });
}

before(async () => {
  await assertUp(`${IDP}/.well-known/openid-configuration`, 'OIDC Provider');
  db = dbClient();
  await db.connect();
  const hash = await auth.hashPassword(PASSWORD);
  await db.query(
    `INSERT INTO users (username, email, password_hash, status, email_verified)
     VALUES ($1, $2, $3, 'active', TRUE)`,
    [ACCOUNT, EMAIL, hash]
  );
});

after(async () => {
  try {
    await db.query('DELETE FROM users WHERE username = $1', [ACCOUNT]);
    await db.query('DELETE FROM codes WHERE LOWER(email) LIKE $1', [`${ACCOUNT}%`]);
  } finally {
    await db.end();
  }
});

describe('找回密码', () => {
  it('不存在的账号返回同一文案（防枚举）', async () => {
    const res = await post('/api/forgot-password', { account: 'no_such_user_xyz' });
    assert.equal(res.status, 200);
    const d = await res.json();
    assert.equal(d.message, '如果账号存在，验证码已发送到邮箱');
    assert.ok(!d.debug_code, '不存在的账号不应真的发码');
  });

  it('存在的账号发码并可重置', async () => {
    const sent = await post('/api/forgot-password', { account: ACCOUNT });
    assert.equal(sent.status, 200);
    const { debug_code: code } = await sent.json();
    assert.match(code, /^\d{6}$/, '调试模式应返回验证码');

    const reset = await post('/api/reset-password', {
      account: ACCOUNT,
      code,
      new_password: NEW_PASSWORD,
    });
    assert.equal(reset.status, 200);
  });

  it('重置后新密码可登录、旧密码失效', async () => {
    const ok = await post('/api/login', { account: ACCOUNT, password: NEW_PASSWORD });
    assert.equal(ok.status, 200);

    const bad = await post('/api/login', { account: ACCOUNT, password: PASSWORD });
    assert.equal(bad.status, 401);
  });

  it('同一验证码不能重复使用', async () => {
    const sent = await post('/api/forgot-password', { account: ACCOUNT });
    const { debug_code: code } = await sent.json();

    const first = await post('/api/reset-password', {
      account: ACCOUNT, code, new_password: NEW_PASSWORD,
    });
    assert.equal(first.status, 200);

    const second = await post('/api/reset-password', {
      account: ACCOUNT, code, new_password: 'Another789!',
    });
    assert.equal(second.status, 400, '验证码应一次性');
  });
});

describe('改邮箱', () => {
  const NEW_EMAIL = `${ACCOUNT}_new@test.local`;
  let cookie;

  before(async () => {
    const res = await post('/api/login', { account: ACCOUNT, password: NEW_PASSWORD });
    assert.equal(res.status, 200);
    cookie = res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
  });

  it('第一步发码到新邮箱', async () => {
    const res = await post('/api/profile/email', { new_email: NEW_EMAIL }, cookie);
    assert.equal(res.status, 200);
    const d = await res.json();
    assert.match(d.debug_code, /^\d{6}$/);
  });

  it('第二步确认后邮箱更新，旧会话失效', async () => {
    const sent = await post('/api/profile/email', { new_email: NEW_EMAIL }, cookie);
    const { debug_code: code } = await sent.json();

    const verify = await post(
      '/api/profile/email/verify',
      { new_email: NEW_EMAIL, code },
      cookie
    );
    assert.equal(verify.status, 200);

    // 改邮箱会删掉该用户全部会话
    const me = await fetch(`${IDP}/api/userinfo`, { headers: { cookie } });
    assert.equal(me.status, 401, '改邮箱后旧会话应失效');
  });

  it('新邮箱可登录，旧邮箱不行', async () => {
    const ok = await post('/api/login', { account: NEW_EMAIL, password: NEW_PASSWORD });
    assert.equal(ok.status, 200);

    const old = await post('/api/login', { account: EMAIL, password: NEW_PASSWORD });
    assert.equal(old.status, 401);
  });

  it('验证码错误不应改变邮箱', async () => {
    const res = await post('/api/login', { account: NEW_EMAIL, password: NEW_PASSWORD });
    const c = res.headers.getSetCookie().map((x) => x.split(';')[0]).join('; ');

    const sent = await post('/api/profile/email', { new_email: `${ACCOUNT}_x@test.local` }, c);
    assert.equal(sent.status, 200);

    const bad = await post(
      '/api/profile/email/verify',
      { new_email: `${ACCOUNT}_x@test.local`, code: '000000' },
      c
    );
    assert.equal(bad.status, 400);

    // 邮箱未变，仍能用当前邮箱登录
    const still = await post('/api/login', { account: NEW_EMAIL, password: NEW_PASSWORD });
    assert.equal(still.status, 200);
  });
});
