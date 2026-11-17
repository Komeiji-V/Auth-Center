import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  IDP, ACCOUNT, PASSWORD, CookieJar,
  rawAuthorize, exchangeCode, grantRefresh,
} from './helpers.mjs';

/** 用 /api/login 拿本站会话 cookie（与 OIDC 是两套会话） */
async function loginCookie() {
  const res = await fetch(`${IDP}/api/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ account: ACCOUNT, password: PASSWORD }),
  });
  assert.equal(res.status, 200, '前置登录失败');
  return res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
}

describe('撤销链', () => {
  it('登出后，之前拿到的 refresh token 立即失效', async () => {
    const jar = new CookieJar();
    const { code, verifier } = await rawAuthorize(jar);
    const tokens = await exchangeCode(code, verifier);
    assert.ok(tokens.refresh_token, '前置：应拿到 refresh token');

    // 确认撤销前是可用的
    const beforeLogout = await grantRefresh(tokens.refresh_token);
    assert.equal(beforeLogout.ok, true, '撤销前 refresh 应有效');

    const cookie = await loginCookie();
    const logout = await fetch(`${IDP}/api/logout`, { method: 'POST', headers: { cookie } });
    assert.equal(logout.status, 200);

    // 登出会 revokeAccount → 删除该 accountId 的 Grant/RefreshToken
    const afterLogout = await grantRefresh(beforeLogout.body.refresh_token);
    assert.equal(afterLogout.ok, false, '登出后旧 refresh token 必须失效');
    assert.equal(afterLogout.body.error, 'invalid_grant');
  });

  it('登出后旧 access token 也不能再访问 userinfo', async () => {
    const jar = new CookieJar();
    const { code, verifier } = await rawAuthorize(jar);
    const tokens = await exchangeCode(code, verifier);

    const before = await fetch(`${IDP}/me`, {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    assert.equal(before.status, 200, '撤销前 access token 应可用');

    const cookie = await loginCookie();
    await fetch(`${IDP}/api/logout`, { method: 'POST', headers: { cookie } });

    const after = await fetch(`${IDP}/me`, {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    assert.equal(after.status, 401, '登出后旧 access token 应失效');
  });
});
