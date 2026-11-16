'use strict';

require('dotenv').config();

/**
 * 迁移路径测试：验证「老表（无 email_verified）→ 加列 + 回填」是否正确
 *
 * 生产库是老表，initSchema 走的是 information_schema 检测 → ADD COLUMN → 回填 这条分支，
 * 前面的 run-test.js 从空表开始，覆盖不到这条路径。
 *
 * 运行：NODE_PATH=<Auth-Center>/node_modules node test/test-migration.js
 */

const { Client } = require('pg');
const db = require('../../src/db');

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

// 三个月前的 users 表结构（不含 email_verified）
const LEGACY_USERS_DDL = `
  CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    role TEXT NOT NULL DEFAULT 'user',
    totp_secret TEXT,
    totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    invite_code_used TEXT,
    apply_info TEXT,
    is_owner BOOLEAN NOT NULL DEFAULT FALSE,
    token_version INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at TIMESTAMPTZ,
    banned_at TIMESTAMPTZ
  )`;

async function main() {
  const c = new Client({ connectionString: DB_URL });
  await c.connect();

  console.log('\n\x1b[1m准备：重建「老表」并灌入历史数据\x1b[0m');
  await c.query('DROP TABLE IF EXISTS users CASCADE');
  await c.query(LEGACY_USERS_DDL);
  await c.query(`
    INSERT INTO users (username, email, password_hash, status, role)
    VALUES
      ('old_active',  'a@test.local', 'h', 'active',  'user'),
      ('old_banned',  'b@test.local', 'h', 'banned',  'user'),
      ('old_pending', 'c@test.local', 'h', 'pending', 'user'),
      ('old_owner',   'o@test.local', 'h', 'active',  'admin')
  `);
  const before = await c.query('SELECT COUNT(*)::int AS n FROM users');
  console.log(`  已建 4 条历史用户（active/banned/pending/admin）`);

  console.log('\n\x1b[1m执行 initSchema()（模拟服务启动）\x1b[0m');
  await db.initDb(DB_URL);
  await db.initSchema();

  console.log('\n\x1b[1m断言：列已添加\x1b[0m');
  const col = await c.query(
    `SELECT data_type, is_nullable, column_default
     FROM information_schema.columns
     WHERE table_name = 'users' AND column_name = 'email_verified'`
  );
  check('email_verified 列存在', col.rows.length === 1);
  check('类型为 boolean', col.rows[0] && col.rows[0].data_type === 'boolean', col.rows[0] && col.rows[0].data_type);
  check('NOT NULL', col.rows[0] && col.rows[0].is_nullable === 'NO');
  check('默认 false', col.rows[0] && /false/.test(col.rows[0].column_default || ''), col.rows[0] && col.rows[0].column_default);

  console.log('\n\x1b[1m断言：回填策略\x1b[0m');
  const { rows } = await c.query(
    'SELECT username, status, email_verified FROM users ORDER BY id'
  );
  const byName = Object.fromEntries(rows.map((r) => [r.username, r]));
  check('active → true', byName.old_active.email_verified === true);
  check('banned → true', byName.old_banned.email_verified === true);
  check('pending → false', byName.old_pending.email_verified === false);
  check('admin(active) → true', byName.old_owner.email_verified === true);
  check('用户总数未变（4）', rows.length === 4, String(rows.length));

  console.log('\n\x1b[1m断言：幂等性（再跑一次不会误刷）\x1b[0m');
  // 模拟「管理端直接激活但从未验证邮箱」的账号
  await c.query(
    `INSERT INTO users (username, email, password_hash, status, role, email_verified)
     VALUES ('manual_active', 'm@test.local', 'h', 'active', 'user', FALSE)`
  );
  await db.initSchema(); // 第二次启动
  const again = await c.query('SELECT email_verified FROM users WHERE username = $1', ['manual_active']);
  check(
    '二次启动不把 active+false 刷成 true',
    again.rows[0].email_verified === false,
    String(again.rows[0].email_verified)
  );

  console.log(`\n${'─'.repeat(50)}`);
  console.log(`结果：\x1b[32m${passed} 通过\x1b[0m，\x1b[31m${failed} 失败\x1b[0m`);
  console.log(`${'─'.repeat(50)}\n`);

  await c.end();
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error('测试异常：', e);
  process.exit(3);
});
