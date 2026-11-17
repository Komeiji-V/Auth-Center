const { Pool } = require('pg');

let pool = null;

function initDb(databaseUrl) {
  pool = new Pool({ connectionString: databaseUrl, max: 10 });
  pool.on('error', (err) => {
    console.error('[db] idle client error:', err.message);
  });
}

function query(text, params) {
  return pool.query(text, params);
}

// 事务执行器：BEGIN → fn(client) → COMMIT，异常自动 ROLLBACK
async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}

async function initSchema() {
  await query(`
    CREATE TABLE IF NOT EXISTS users (
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
      email_verified BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      approved_at TIMESTAMPTZ,
      banned_at TIMESTAMPTZ
    )
  `);
  // 兼容升级：已有表补充新列（幂等）
  await query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS apply_info TEXT`);
  await query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_owner BOOLEAN NOT NULL DEFAULT FALSE`);
  await query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0`);
  // email_verified：首次引入该列时补列并回填历史数据
  // 回填策略：active/banned 视为已验证（旧库无此字段，无法追溯真实验证状态）
  // 用 information_schema 判定「列是否存在」，只在首次添加时回填，
  // 避免日后每次启动把「管理端直接激活」的账号也刷成 true
  const { rows: evCol } = await query(
    `SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'email_verified'`
  );
  if (evCol.length === 0) {
    await query(`ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE`);
    await query(`UPDATE users SET email_verified = TRUE WHERE status IN ('active', 'banned')`);
    console.log('[db] migration: users.email_verified 已添加并回填');
  }
  await query(`
    CREATE TABLE IF NOT EXISTS codes (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      code TEXT NOT NULL,
      purpose TEXT NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      used BOOLEAN NOT NULL DEFAULT FALSE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
  await query('CREATE INDEX IF NOT EXISTS idx_codes_email ON codes(email)');
  // ===== 服务端会话（替代 JWT + refresh token）=====
  // 浏览器只持有 HttpOnly cookie，会话本身是撤销单位，不需要 token 版本号
  await query(`
    CREATE TABLE IF NOT EXISTS sessions (
      id         TEXT PRIMARY KEY,
      user_id    INTEGER NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      expires_at TIMESTAMPTZ NOT NULL
    )
  `);
  // 用户名大小写唯一：UNIQUE(username) 大小写敏感，允许 "Bob" 和 "bob" 并存；
  // 而登录用 LOWER(username) 查询，命中两行时结果不确定（其中一个账号永远登不上）
  try {
    await query(`CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_uniq ON users (LOWER(username))`);
  } catch (e) {
    // 已有存量重复时索引建不起来，不能让服务起不来；日志提示人工清理
    console.error('[db] 无法创建 LOWER(username) 唯一索引（可能存在大小写重复的用户名）:', e.message);
  }

  await query('CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id)');
  await query('CREATE INDEX IF NOT EXISTS idx_sessions_exp  ON sessions (expires_at)');
  // 会话卫生：最后活跃时间（空闲超时用）、来源 IP 与 UA（设备列表用）
  await query(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ NOT NULL DEFAULT now()`);
  await query(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip TEXT`);
  await query(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_agent TEXT`);
  await query(`
    CREATE TABLE IF NOT EXISTS invite_codes (
      id SERIAL PRIMARY KEY,
      code TEXT UNIQUE NOT NULL,
      note TEXT,
      max_uses INTEGER NOT NULL DEFAULT 1,
      used_count INTEGER NOT NULL DEFAULT 0,
      expires_at TIMESTAMPTZ,
      used_by TEXT,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
  // 兼容升级：已有邀请码表补充新列（幂等）
  await query(`ALTER TABLE invite_codes ADD COLUMN IF NOT EXISTS max_uses INTEGER NOT NULL DEFAULT 1`);
  await query(`ALTER TABLE invite_codes ADD COLUMN IF NOT EXISTS used_count INTEGER NOT NULL DEFAULT 0`);
  await query(`ALTER TABLE invite_codes ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ`);
  await query(`
    CREATE TABLE IF NOT EXISTS config (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )
  `);
  await query(`
    CREATE TABLE IF NOT EXISTS invite_usage_log (
      id SERIAL PRIMARY KEY,
      code TEXT NOT NULL,
      email TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
  await query('CREATE INDEX IF NOT EXISTS idx_invite_usage_code ON invite_usage_log(code)');
  await query(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id SERIAL PRIMARY KEY,
      actor TEXT,
      action TEXT NOT NULL,
      ip TEXT,
      detail TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);

  // ===== OIDC（oidc-provider）持久化 =====
  // Session / Grant / AccessToken / RefreshToken / AuthorizationCode / Interaction / ReplayDetection
  await query(`
    CREATE TABLE IF NOT EXISTS oidc_payloads (
      id          TEXT PRIMARY KEY,
      type        TEXT NOT NULL,
      payload     JSONB NOT NULL,
      grant_id    TEXT,
      user_code   TEXT,
      uid         TEXT,
      expires_at  TIMESTAMPTZ,
      consumed_at TIMESTAMPTZ
    )
  `);
  await query('CREATE INDEX IF NOT EXISTS idx_oidc_payloads_grant ON oidc_payloads (grant_id)');
  await query('CREATE INDEX IF NOT EXISTS idx_oidc_payloads_uid   ON oidc_payloads (uid)');
  await query('CREATE INDEX IF NOT EXISTS idx_oidc_payloads_exp   ON oidc_payloads (expires_at)');
  await query('CREATE INDEX IF NOT EXISTS idx_oidc_payloads_ucode ON oidc_payloads (user_code)');
  // 撤销链按 accountId 删记录，没有索引会全表扫
  await query(`CREATE INDEX IF NOT EXISTS idx_oidc_payloads_account ON oidc_payloads ((payload->>'accountId'))`);

  // back-channel logout 失败重试队列
  await query(`
    CREATE TABLE IF NOT EXISTS backchannel_retry (
      id         SERIAL PRIMARY KEY,
      client_id  TEXT NOT NULL,
      sub        TEXT NOT NULL,
      sid        TEXT,
      attempts   INTEGER NOT NULL DEFAULT 0,
      next_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
      last_error TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
  await query('CREATE INDEX IF NOT EXISTS idx_backchannel_retry_next ON backchannel_retry (next_at)');

  // 注册模式从旧的单值(registration_mode)迁移为三个独立开关
  const { rows: oldMode } = await query(`SELECT key FROM config WHERE key = 'registration_mode'`);
  if (oldMode.length > 0) {
    const { rows: m } = await query(`SELECT value FROM config WHERE key = 'registration_mode'`);
    const mode = m[0].value;
    const flags = {
      invite_required: mode === 'invite' ? 'true' : 'false',
      email_verify_required: mode === 'invite' ? 'true' : 'true',
      review_required: mode === 'review' ? 'true' : 'false',
    };
    for (const [k, v] of Object.entries(flags)) {
      await query(`INSERT INTO config (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`, [k, v]);
    }
    await query(`DELETE FROM config WHERE key = 'registration_mode'`);
    console.log('[db] migration: registration_mode -> 三个独立开关');
  } else {
    const defaults = {
      invite_required: process.env.REGISTRATION_INVITE_REQUIRED === 'true' ? 'true' : 'false',
      email_verify_required: process.env.REGISTRATION_EMAIL_VERIFY === 'false' ? 'false' : 'true',
      review_required: process.env.REGISTRATION_REVIEW_REQUIRED === 'true' ? 'true' : 'false',
    };
    for (const [k, v] of Object.entries(defaults)) {
      await query(`INSERT INTO config (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`, [k, v]);
    }
    console.log(`[db] registration flags: ${JSON.stringify(defaults)}`);
  }
}

async function getConfig(key) {
  const { rows } = await query('SELECT value FROM config WHERE key = $1', [key]);
  return rows.length ? rows[0].value : null;
}

async function getRegistrationFlags() {
  const { rows } = await query(
    `SELECT key, value FROM config WHERE key IN ('invite_required', 'email_verify_required', 'review_required')`
  );
  const flags = { invite_required: false, email_verify_required: true, review_required: false };
  for (const r of rows) {
    flags[r.key] = r.value === 'true';
  }
  return flags;
}

async function setConfig(key, value) {
  await query(
    `INSERT INTO config (key, value) VALUES ($1, $2)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
    [key, value]
  );
}

async function audit(actor, action, ip, detail) {
  // 截断：审计是「记录发生了什么」，不是「存用户输入」。超长值会撑爆磁盘。
  await query('INSERT INTO audit_log (actor, action, ip, detail) VALUES ($1, $2, $3, $4)', [
    String(actor ?? '').slice(0, 128),
    String(action ?? '').slice(0, 64),
    ip || null,
    String(detail ?? '').slice(0, 512) || null,
  ]);
}

module.exports = { initDb, initSchema, query, withTransaction, getConfig, setConfig, getRegistrationFlags, audit };
