import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { authenticator } from 'otplib';
import {
  IDP, RP, ACCOUNT, PASSWORD, CLIENT_ID,
  CookieJar, authorize, rpSession, rawAuthorize, exchangeCode, grantRefresh,
  get, postForm, assertUp, dbClient,
} from './helpers.mjs';

const JWKS = createRemoteJWKSet(new URL(`${IDP}/jwks`));
const newJar = () => new CookieJar();

function decodeJwt(token) {
  const [h, p] = token.split('.');
  return {
    header: JSON.parse(Buffer.from(h, 'base64url')),
    payload: JSON.parse(Buffer.from(p, 'base64url')),
  };
}

before(async () => {
  await assertUp(`${IDP}/.well-known/openid-configuration`, 'OIDC Provider');
  await assertUp(`${RP}/`, '演示小站');
});

// ============================================================
describe('授权码流程（经 RP）', () => {
  it('正确账号密码 → 建立 RP 会话，sub 为 7 位字符串', async () => {
    const jar = newJar();
    const r = await authorize(jar);
    assert.equal(r.ok, true, `登录应成功，实际错误: ${r.error}`);

    const session = await rpSession(jar);
    assert.ok(session, 'RP 应存在会话');
    assert.equal(session.sub, '5140001');
    assert.equal(session.sub.length, 7);
    // 注：preferred_username / email 只在 userinfo 返回，ID Token 默认不含
  });

  it('错误密码 → 统一文案，不泄露账号是否存在', async () => {
    const jar = newJar();
    const r = await authorize(jar, { password: 'definitely-wrong' });
    assert.equal(r.ok, false);
    assert.equal(r.error, '账号或密码错误');
  });

  it('不存在的账号 → 与密码错误同一文案', async () => {
    const jar = newJar();
    const r = await authorize(jar, { account: 'no-such-user-xyz' });
    assert.equal(r.ok, false);
    assert.equal(r.error, '账号或密码错误');
  });

  it('空密码 → 参数提示', async () => {
    const jar = newJar();
    const r = await authorize(jar, { password: '' });
    assert.equal(r.ok, false);
    assert.equal(r.error, '请输入账号和密码');
  });
});

// ============================================================
describe('TOTP 二次验证', () => {
  let db;

  before(async () => {
    db = dbClient();
    await db.connect();
    await db.query(
      `UPDATE users SET totp_enabled = TRUE, totp_secret = 'JBSWY3DPEHPK3PXP' WHERE username = $1`,
      [ACCOUNT]
    );
  });

  it('已绑定但未填 → 提示输入 TOTP', async () => {
    const jar = newJar();
    const r = await authorize(jar, { totp: '' });
    assert.equal(r.ok, false);
    assert.equal(r.error, '请输入 TOTP 验证码');
  });

  it('TOTP 错误 → 与密码错误同一文案', async () => {
    const jar = newJar();
    const r = await authorize(jar, { totp: '000000' });
    assert.equal(r.ok, false);
    assert.equal(r.error, '账号或密码错误');
  });

  it('TOTP 正确 → 登录成功', async () => {
    const jar = newJar();
    const code = authenticator.generate('JBSWY3DPEHPK3PXP');
    const r = await authorize(jar, { totp: code });
    assert.equal(r.ok, true, `应登录成功，实际: ${r.error}`);

    const session = await rpSession(jar);
    assert.ok(session, '应建立会话');
    // ID Token 默认不含 acr/amr，登录成功本身即证明 TOTP 校验通过
  });

  it('清理：解绑 TOTP', async () => {
    await db.query(
      `UPDATE users SET totp_enabled = FALSE, totp_secret = NULL WHERE username = $1`,
      [ACCOUNT]
    );
    await db.end();
    assert.ok(true);
  });
});

// ============================================================
describe('Token 端点与 ID Token', () => {
  let tokens;

  before(async () => {
    const jar = newJar();
    const { code, verifier } = await rawAuthorize(jar);
    assert.ok(code, '应拿到授权码');
    tokens = await exchangeCode(code, verifier);
  });

  it('返回 access / refresh / id token，且 scope 含 offline_access', () => {
    assert.ok(tokens.access_token);
    assert.ok(tokens.id_token);
    assert.ok(tokens.refresh_token, '含 offline_access 时应签发 refresh_token');
    assert.equal(tokens.token_type, 'Bearer');
    assert.match(tokens.scope, /offline_access/);
  });

  it('ID Token 可用 JWKS 独立验签（不依赖 IdP 代码）', async () => {
    const { payload, protectedHeader } = await jwtVerify(tokens.id_token, JWKS, {
      issuer: IDP,
      audience: CLIENT_ID,
    });
    assert.equal(protectedHeader.alg, 'RS256');
    assert.equal(payload.sub, '5140001');
    assert.equal(payload.aud, CLIENT_ID);
    assert.equal(payload.iss, IDP);
    assert.match(payload.sid, /^[\w-]+$/, '应包含 sid 供 back-channel logout 使用');
  });

  it('换 audience 验签必须失败', async () => {
    await assert.rejects(
      () => jwtVerify(tokens.id_token, JWKS, { issuer: IDP, audience: 'other-client' }),
      /unexpected "(aud|iss)" claim value|claim validation failed/i
    );
  });

  it('换 issuer 验签必须失败', async () => {
    await assert.rejects(
      () => jwtVerify(tokens.id_token, JWKS, { issuer: 'http://evil.example', audience: CLIENT_ID }),
      /unexpected "(aud|iss)" claim value|claim validation failed/i
    );
  });

  it('userinfo 的 sub 与 ID Token 一致', async () => {
    const res = await fetch(`${IDP}/me`, {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    assert.equal(res.status, 200);
    const me = await res.json();
    assert.equal(me.sub, '5140001');
    assert.equal(me.email_verified, true);
  });
});

// ============================================================
describe('Refresh Token', () => {
  let refreshToken;

  before(async () => {
    const jar = newJar();
    const { code, verifier } = await rawAuthorize(jar);
    const tokens = await exchangeCode(code, verifier);
    refreshToken = tokens.refresh_token;
  });

  it('刷新成功并轮换', async () => {
    const r = await grantRefresh(refreshToken);
    assert.equal(r.ok, true);
    assert.ok(r.body.access_token);
    assert.ok(r.body.refresh_token);
    assert.notEqual(r.body.refresh_token, refreshToken, 'refresh token 应轮换');
    refreshToken = r.body.refresh_token;
  });

  it('新 access token 可访问 userinfo', async () => {
    const r = await grantRefresh(refreshToken);
    const res = await fetch(`${IDP}/me`, {
      headers: { authorization: `Bearer ${r.body.access_token}` },
    });
    assert.equal(res.status, 200);
    refreshToken = r.body.refresh_token;
  });

  it('旧 refresh token 重放被拒（并吊销 grant）', async () => {
    const old = refreshToken;
    const r1 = await grantRefresh(old);
    assert.equal(r1.ok, true);
    const newToken = r1.body.refresh_token;

    const r2 = await grantRefresh(old); // 重放
    assert.equal(r2.ok, false, '旧 token 应被拒绝');
    assert.equal(r2.body.error, 'invalid_grant');

    // grant 已被吊销，新 token 也应失效
    const r3 = await grantRefresh(newToken);
    assert.equal(r3.ok, false, '重放后整个 grant 应被吊销');
  });
});

// ============================================================
describe('BFF 静默续期', () => {
  let jar;

  before(async () => {
    jar = newJar();
    const r = await authorize(jar);
    assert.equal(r.ok, true, `前置登录失败: ${r.error}`);
  });

  it('剩余时间充足时不续期', async () => {
    const res = await get(jar, `${RP}/debug/session`);
    const s = await res.json();
    assert.ok(s.expiresInSec > 60);
    assert.equal(s.refreshCount, 0);
  });

  it('剩余 <60s 时访问页面自动续期', async () => {
    await postForm(jar, `${RP}/debug/expire`, {});
    const before = await (await get(jar, `${RP}/debug/session`)).json();
    assert.ok(before.expiresInSec <= 10);

    const page = await get(jar, `${RP}/`);
    assert.equal(page.status, 200);

    const after = await (await get(jar, `${RP}/debug/session`)).json();
    assert.equal(after.refreshCount, 1);
    assert.ok(after.expiresInSec > 60);
  });

  it('并发请求只触发一次续期（防轮换竞态）', async () => {
    await postForm(jar, `${RP}/debug/expire`, {});
    const before = await (await get(jar, `${RP}/debug/session`)).json();

    await Promise.all(Array.from({ length: 8 }, () => fetch(`${RP}/`, {
      headers: { cookie: jar.header() },
      redirect: 'manual',
    })));

    const after = await (await get(jar, `${RP}/debug/session`)).json();
    assert.equal(
      after.refreshCount,
      before.refreshCount + 1,
      `8 并发应只续期 1 次，实际 ${after.refreshCount - before.refreshCount} 次`
    );
  });
});

// ============================================================
describe('Back-Channel Logout', () => {
  it('踢人后小站会话立即失效', async () => {
    const jar = newJar();
    const r = await authorize(jar);
    assert.equal(r.ok, true);

    const session = await rpSession(jar);
    assert.ok(session, '踢人前应有会话');

    const res = await fetch(`${IDP}/oidc-debug/kick/${session.sub}`, { method: 'POST' });
    assert.equal(res.status, 200);
    const result = await res.json();
    assert.ok(result.sessions >= 1, '应命中至少一个会话');
    assert.ok(
      result.notified.every((n) => n.ok),
      `所有小站都应收到通知: ${JSON.stringify(result.notified)}`
    );

    const after = await rpSession(jar);
    assert.equal(after, null, '踢人后 RP 会话应被清除');
  });
});
