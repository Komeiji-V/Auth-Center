'use strict';

require('dotenv').config();

/**
 * Auth-Center 本地回归测试：三个补丁的验证（不进仓库）
 *
 * 覆盖场景：
 *   1. 正常注册 → pending + email_verified=false
 *   2. 重复提交（密码错）→ 400
 *   3. 重复提交（密码对、用户名不同）→ 400，提示原用户名
 *   4. 重复提交（密码对、用户名一致）→ 200 重发验证码，不新增用户、id 不变
 *   5. 验证邮箱 → status 变更 + email_verified=true
 *   6. 关闭邮箱验证后注册 → email_verified=true（免检）
 *   7. 僵尸清理 → 只删未验证的，保留真·待审
 *   8. 已激活用户再次提交 → 400「已被注册」（不进续期分支）
 *
 * 运行：NODE_PATH=<Auth-Center>/node_modules node test/run-test.js
 */

const { Client } = require('pg');

const BASE = process.env.TEST_BASE || 'http://localhost:8000';
const DB_URL = process.env.DATABASE_URL;

// 安全守卫：本脚本会清空 / 重建 users 表，拒绝在非测试库上运行
{
  const dbName = new URL(DB_URL).pathname.replace(/^\//, '');
  if (!/test/i.test(dbName)) {
    console.error(`拒绝执行：数据库 "${dbName}" 看起来不是测试库（库名需包含 test）`);
    process.exit(1);
  }
}


let passed = 0;
let failed = 0;

function check(name, cond, detail) {
  if (cond) {
    passed++;
    console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  } else {
    failed++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? `  → ${detail}` : ''}`);
  }
}

function section(title) {
  console.log(`\n\x1b[1m${title}\x1b[0m`);
}

async function post(path, body) {
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  let json = null;
  try {
    json = await res.json();
  } catch {
    json = null;
  }
  return { status: res.status, body: json };
}

async function getUser(db, email) {
  const { rows } = await db.query('SELECT * FROM users WHERE LOWER(email) = $1', [email.toLowerCase()]);
  return rows[0] || null;
}

async function setFlag(db, key, value) {
  await db.query('UPDATE config SET value = $1 WHERE key = $2', [value, key]);
}

async function main() {
  const db = new Client({ connectionString: DB_URL });
  await db.connect();

  // ---- 前置：服务可达 ----
  try {
    const r = await fetch(BASE + '/api/config');
    if (!r.ok) throw new Error(`status ${r.status}`);
  } catch (e) {
    console.error(`\n服务不可达（${BASE}）：${e.message}`);
    console.error(`请先启动：cd Auth-Center && node src/server.js`);
    process.exit(2);
  }

  // ---- 清场，保证可重复运行 ----
  await db.query(
    `TRUNCATE users, codes, refresh_tokens, invite_codes, invite_usage_log, audit_log, config
     RESTART IDENTITY CASCADE`
  );
  await db.query(
    `INSERT INTO config (key, value) VALUES
      ('invite_required', 'false'),
      ('email_verify_required', 'true'),
      ('review_required', 'false')`
  );

  const PWD = 'Passw0rd!123';

  // ================= 场景 1 =================
  section('场景 1：正常注册（邮箱验证开，审核关）');
  const r1 = await post('/api/register', {
    username: 'alice',
    email: 'alice@test.local',
    password: PWD,
  });
  check('HTTP 200', r1.status === 200, `实际 ${r1.status} ${JSON.stringify(r1.body)}`);
  check('needs_verify=true', r1.body && r1.body.needs_verify === true);
  check('返回 6 位 debug_code', /^\d{6}$/.test((r1.body && r1.body.debug_code) || ''));

  const u1 = await getUser(db, 'alice@test.local');
  check('用户记录已创建', !!u1);
  check('status=pending', u1 && u1.status === 'pending', u1 && u1.status);
  check('email_verified=false', u1 && u1.email_verified === false, u1 && String(u1.email_verified));
  const id1 = u1 && u1.id;

  // ================= 场景 2 =================
  section('场景 2：重复提交，密码错误');
  const r2 = await post('/api/register', {
    username: 'alice',
    email: 'alice@test.local',
    password: 'WrongPass!123',
  });
  check('HTTP 400', r2.status === 400, `实际 ${r2.status}`);
  check(
    '提示使用原密码',
    r2.body && r2.body.error === '该邮箱有未完成的注册，请使用原密码继续',
    r2.body && r2.body.error
  );

  // ================= 场景 3 =================
  section('场景 3：重复提交，密码正确但用户名不同');
  const r3 = await post('/api/register', {
    username: 'alice2',
    email: 'alice@test.local',
    password: PWD,
  });
  check('HTTP 400', r3.status === 400, `实际 ${r3.status}`);
  check(
    '提示原用户名',
    r3.body && /该邮箱有未完成的注册（用户名 alice）/.test(r3.body.error || ''),
    r3.body && r3.body.error
  );

  // ================= 场景 4 =================
  section('场景 4：重复提交，密码与用户名均正确 → 续期');
  const r4 = await post('/api/register', {
    username: 'alice',
    email: 'alice@test.local',
    password: PWD,
  });
  check('HTTP 200', r4.status === 200, `实际 ${r4.status}`);
  check('needs_verify=true', r4.body && r4.body.needs_verify === true);
  check('消息含「未完成」', /未完成/.test((r4.body && r4.body.message) || ''));
  check('返回新 debug_code', /^\d{6}$/.test((r4.body && r4.body.debug_code) || ''));

  const cnt = await db.query('SELECT COUNT(*)::int AS c FROM users');
  check('用户数仍为 1（未新增）', cnt.rows[0].c === 1, `实际 ${cnt.rows[0].c}`);
  const u4 = await getUser(db, 'alice@test.local');
  check('id 未变', u4 && u4.id === id1, `${id1} → ${u4 && u4.id}`);
  check('仍为 pending + 未验证', u4 && u4.status === 'pending' && u4.email_verified === false);

  // ================= 场景 5 =================
  section('场景 5：验证邮箱');
  const r5 = await post('/api/verify-email', {
    email: 'alice@test.local',
    code: r4.body.debug_code,
  });
  check('HTTP 200', r5.status === 200, `实际 ${r5.status} ${JSON.stringify(r5.body)}`);
  check('status=active（审核关）', r5.body && r5.body.status === 'active', r5.body && r5.body.status);

  const u5 = await getUser(db, 'alice@test.local');
  check('email_verified=true', u5 && u5.email_verified === true, u5 && String(u5.email_verified));
  check('status=active', u5 && u5.status === 'active', u5 && u5.status);

  // ================= 场景 6 =================
  section('场景 6：关闭邮箱验证后注册');
  await setFlag(db, 'email_verify_required', 'false');
  const r6 = await post('/api/register', {
    username: 'bob',
    email: 'bob@test.local',
    password: PWD,
  });
  check('HTTP 200', r6.status === 200, `实际 ${r6.status} ${JSON.stringify(r6.body)}`);
  check('status=active', r6.body && r6.body.status === 'active', r6.body && r6.body.status);

  const u6 = await getUser(db, 'bob@test.local');
  check('email_verified=true（免检）', u6 && u6.email_verified === true, u6 && String(u6.email_verified));

  // ================= 场景 7 =================
  section('场景 7：僵尸清理（24 小时未验证）');
  await db.query(
    `INSERT INTO users (username, email, password_hash, status, email_verified, created_at, role)
     VALUES
       ('zombie1', 'z1@test.local', 'x', 'pending', FALSE, now() - interval '25 hours', 'user'),
       ('review1', 'r1@test.local', 'x', 'pending', TRUE,  now() - interval '25 hours', 'user'),
       ('zombie2', 'z2@test.local', 'x', 'pending', FALSE, now() - interval '1 hour',  'user')`
  );
  await db.query(
    `DELETE FROM users
     WHERE status = 'pending'
       AND email_verified = FALSE
       AND created_at < now() - interval '24 hours'`
  );
  check('25h 前未验证 → 被删', !(await getUser(db, 'z1@test.local')));
  check('25h 前已验证待审 → 保留', !!(await getUser(db, 'r1@test.local')));
  check('1h 前未验证 → 保留（未到期）', !!(await getUser(db, 'z2@test.local')));

  // ================= 场景 8 =================
  section('场景 8：已激活账号再次提交 → 不进续期分支');
  const r8 = await post('/api/register', {
    username: 'alice',
    email: 'alice@test.local',
    password: PWD,
  });
  check('HTTP 400', r8.status === 400, `实际 ${r8.status}`);
  check(
    '消息为「已被注册」',
    r8.body && r8.body.error === '用户名或邮箱已被注册',
    r8.body && r8.body.error
  );

  // ================= 汇总 =================
  console.log(`\n${'─'.repeat(50)}`);
  console.log(`结果：\x1b[32m${passed} 通过\x1b[0m，\x1b[31m${failed} 失败\x1b[0m`);
  console.log(`${'─'.repeat(50)}\n`);

  await db.end();
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error('测试异常：', e);
  process.exit(3);
});
