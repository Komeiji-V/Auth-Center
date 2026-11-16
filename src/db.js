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
  await query(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      token_hash TEXT UNIQUE NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      revoked BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
  await query('CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id)');
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
  await query('INSERT INTO audit_log (actor, action, ip, detail) VALUES ($1, $2, $3, $4)', [actor, action, ip || null, detail || null]);
}

module.exports = { initDb, initSchema, query, withTransaction, getConfig, setConfig, getRegistrationFlags, audit };
