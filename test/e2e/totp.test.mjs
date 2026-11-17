import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { authenticator } from 'otplib';
import { IDP, assertUp, dbClient } from './helpers.mjs';
import auth from '../../src/auth.js';

// 每次跑用新用户，避免与 e2e 的固定账号互相干扰
const ACCOUNT = `totptest_${Date.now().toString(36)}`;
const PASSWORD = 'TestPass123!';

let db;

function login(totp) {
  const body = { account: ACCOUNT, password: PASSWORD };
  if (totp) body.totp_code = totp;
  return fetch(`${IDP}/api/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

async function cookieHeader(res) {
  return res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
}

before(async () => {
  await assertUp(`${IDP}/.well-known/openid-configuration`, 'OIDC Provider');
  db = dbClient();
  await db.connect();
  const hash = await auth.hashPassword(PASSWORD);
  await db.query(
    `INSERT INTO users (username, email, password_hash, status, email_verified)
     VALUES ($1, $2, $3, 'active', TRUE)`,
    [ACCOUNT, `${ACCOUNT}@test.local`, hash]
  );
});

after(async () => {
  try {
    await db.query('DELETE FROM users WHERE username = $1', [ACCOUNT]);
  } finally {
    await db.end();
  }
});

describe('TOTP 全状态机', () => {
  let cookie;
  let secret;

  before(async () => {
    const res = await login();
    assert.equal(res.status, 200, '前置：未绑定 TOTP 时应能直接登录');
    cookie = await cookieHeader(res);
  });

  it('未绑定时登录不需要 TOTP', async () => {
    const res = await login();
    assert.equal(res.status, 200);
  });

  it('setup 返回新密钥', async () => {
    const res = await fetch(`${IDP}/api/profile/totp-setup`, {
      method: 'POST',
      headers: { cookie },
    });
    assert.equal(res.status, 200);
    const d = await res.json();
    assert.ok(d.secret, '应返回 secret');
    assert.ok(d.qr, '应返回二维码');
    secret = d.secret;
  });

  it('confirm 之前，登录仍不需要 TOTP（pending 未生效）', async () => {
    const res = await login();
    assert.equal(res.status, 200, 'pending secret 不应影响登录');
  });

  it('confirm 后绑定生效', async () => {
    const code = authenticator.generate(secret);
    const res = await fetch(`${IDP}/api/profile/totp-confirm`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ code }),
    });
    assert.equal(res.status, 200);

    const noTotp = await login();
    assert.equal(noTotp.status, 401, '绑定后不带 TOTP 应被拒');

    const withTotp = await login(authenticator.generate(secret));
    assert.equal(withTotp.status, 200, '绑定后带正确 TOTP 应能登录');
  });

  it('重绑中间态：setup 后旧密钥仍可登录', async () => {
    // 已绑定时 setup 需要当前验证码
    const res = await fetch(`${IDP}/api/profile/totp-setup`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ code: authenticator.generate(secret) }),
    });
    assert.equal(res.status, 200);
    const d = await res.json();
    assert.ok(d.secret && d.secret !== secret, '应返回不同的新密钥');

    // 关键：新密钥还没 confirm，旧密钥必须仍然有效（F7 的回归点）
    const oldStillWorks = await login(authenticator.generate(secret));
    assert.equal(oldStillWorks.status, 200, '重绑中间态不应让旧密钥失效');

    // 新密钥此时还不能登录
    const newNotYet = await login(authenticator.generate(d.secret));
    assert.equal(newNotYet.status, 401, '未 confirm 的新密钥不应生效');

    secret = d.secret;
  });

  it('confirm 新密钥后切换生效', async () => {
    const res = await fetch(`${IDP}/api/profile/totp-confirm`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ code: authenticator.generate(secret) }),
    });
    assert.equal(res.status, 200);
    const ok = await login(authenticator.generate(secret));
    assert.equal(ok.status, 200);
  });

  it('disable 需要当前验证码', async () => {
    const res = await fetch(`${IDP}/api/profile/totp-disable`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ code: '000000' }),
    });
    assert.equal(res.status, 401, '错误验证码不应解绑');
  });

  it('disable 成功后登录不再需要 TOTP', async () => {
    const res = await fetch(`${IDP}/api/profile/totp-disable`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ code: authenticator.generate(secret) }),
    });
    assert.equal(res.status, 200);

    const back = await login();
    assert.equal(back.status, 200, '解绑后应恢复为不需要 TOTP');
  });
});
