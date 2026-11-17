import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { IDP, assertUp } from './helpers.mjs';

const OWNER = { account: 'alice', password: 'Passw0rd!123' };
const stamp = Date.now().toString(36);

let ownerCookie;
let originalFlags;

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

async function login(account, password) {
  const res = await post('/api/login', { account, password });
  assert.equal(res.status, 200, `${account} 登录失败`);
  return res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
}

async function setFlags(flags) {
  const res = await post('/api/admin/config', flags, ownerCookie);
  assert.equal(res.status, 200, `切换注册模式失败: ${await res.text()}`);
}

async function makeInvite(maxUses = 1) {
  const res = await post(
    '/api/admin/invite-codes',
    { count: 1, max_uses: maxUses, note: 'e2e' },
    ownerCookie
  );
  assert.equal(res.status, 200);
  const d = await res.json();
  return d.codes[0];   // 接口返回的是字符串数组
}

before(async () => {
  await assertUp(`${IDP}/.well-known/openid-configuration`, 'OIDC Provider');
  ownerCookie = await login(OWNER.account, OWNER.password);

  const cfg = await fetch(`${IDP}/api/config`).then((r) => r.json());
  originalFlags = cfg.flags;
});

after(async () => {
  // 恢复原始开关，避免影响其它套件
  if (ownerCookie && originalFlags) {
    await post('/api/admin/config', originalFlags, ownerCookie).catch(() => {});
  }
});

describe('邀请码注册', () => {
  it('没有邀请码时注册被拒', async () => {
    await setFlags({ invite_required: true, email_verify_required: false, review_required: false });

    const res = await post('/api/register', {
      username: `noint_${stamp}`,
      email: `noint_${stamp}@test.local`,
      password: 'RegPass123!',
    });
    assert.equal(res.status, 400);
    assert.match((await res.json()).error, /邀请码/);
  });

  it('带有效邀请码可注册并直接激活', async () => {
    const code = await makeInvite(1);
    const res = await post('/api/register', {
      username: `inv_${stamp}`,
      email: `inv_${stamp}@test.local`,
      password: 'RegPass123!',
      invite_code: code,
    });
    assert.equal(res.status, 200);
    const d = await res.json();
    assert.equal(d.status, 'active');

    // 已激活 → 能直接登录
    const ok = await post('/api/login', { account: `inv_${stamp}`, password: 'RegPass123!' });
    assert.equal(ok.status, 200);
  });

  it('邀请码用尽后第二次注册被拒', async () => {
    const code = await makeInvite(1);
    const first = await post('/api/register', {
      username: `once1_${stamp}`,
      email: `once1_${stamp}@test.local`,
      password: 'RegPass123!',
      invite_code: code,
    });
    assert.equal(first.status, 200);

    const second = await post('/api/register', {
      username: `once2_${stamp}`,
      email: `once2_${stamp}@test.local`,
      password: 'RegPass123!',
      invite_code: code,
    });
    assert.equal(second.status, 400);
  });
});

describe('人工审核', () => {
  let pendingId;

  it('开启审核后注册进入 pending，登录被拒', async () => {
    await setFlags({ invite_required: true, email_verify_required: false, review_required: true });
    const code = await makeInvite(1);

    const res = await post('/api/register', {
      username: `rev_${stamp}`,
      email: `rev_${stamp}@test.local`,
      password: 'RegPass123!',
      invite_code: code,
      apply_info: 'e2e 测试申请',
    });
    assert.equal(res.status, 200);
    const d = await res.json();
    assert.equal(d.status, 'pending');

    const loginRes = await post('/api/login', { account: `rev_${stamp}`, password: 'RegPass123!' });
    assert.equal(loginRes.status, 403);
    assert.match((await loginRes.json()).error, /待审核/);

    const list = await fetch(`${IDP}/api/admin/users?status=pending`, {
      headers: { cookie: ownerCookie },
    }).then((r) => r.json());
    pendingId = list.users.find((u) => u.username === `rev_${stamp}`)?.id;
    assert.ok(pendingId, '应在 pending 列表里找到该用户');
  });

  it('审核通过后可以登录', async () => {
    const res = await post(`/api/admin/users/${pendingId}/approve`, {}, ownerCookie);
    assert.equal(res.status, 200);

    const ok = await post('/api/login', { account: `rev_${stamp}`, password: 'RegPass123!' });
    assert.equal(ok.status, 200);
  });

  it('拒绝会删除用户，可重新注册', async () => {
    await setFlags({ invite_required: false, email_verify_required: false, review_required: true });

    const reg = await post('/api/register', {
      username: `rej_${stamp}`,
      email: `rej_${stamp}@test.local`,
      password: 'RegPass123!',
      apply_info: 'e2e 拒绝流程测试',
    });
    assert.equal(reg.status, 200);

    const list = await fetch(`${IDP}/api/admin/users?status=pending`, {
      headers: { cookie: ownerCookie },
    }).then((r) => r.json());
    const target = list.users.find((u) => u.username === `rej_${stamp}`);
    assert.ok(target, '待拒绝用户应在列表里');

    const rej = await post(`/api/admin/users/${target.id}/reject`, {}, ownerCookie);
    assert.equal(rej.status, 200);

    // 记录被删除 → 同一邮箱可以重新注册
    const again = await post('/api/register', {
      username: `rej_${stamp}`,
      email: `rej_${stamp}@test.local`,
      password: 'RegPass123!',
      apply_info: 'e2e 重新提交测试',
    });
    if (again.status !== 200) {
      assert.fail('重注册失败: ' + JSON.stringify(await again.json()));
    }
  });
});
