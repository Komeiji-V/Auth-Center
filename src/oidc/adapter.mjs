import db from '../db.js';

/**
 * oidc-provider 的 PostgreSQL Adapter
 *
 * 复用 Auth-Center 现有的连接池。数据存在 oidc_payloads 表（见 db.js initSchema）。
 *
 * 关键点：
 *   - ReplayDetection 必须原子插入，否则并发重放无法拦截
 *   - consume 必须原子标记，否则 code / refresh token 可被并发复用
 *   - find 对已消费的记录要返回 payload.consumed，交给 provider 判断
 */
export default class PostgresAdapter {
  constructor(name) {
    this.name = name;
  }

  async upsert(id, payload, expiresIn) {
    const expiresAt = expiresIn ? new Date(Date.now() + expiresIn * 1000) : null;

    if (this.name === 'ReplayDetection') {
      await db.query(
        `DELETE FROM oidc_payloads WHERE id = $1 AND expires_at IS NOT NULL AND expires_at < now()`,
        [id]
      );
      const r = await db.query(
        `INSERT INTO oidc_payloads (id, type, payload, expires_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (id) DO NOTHING`,
        [id, this.name, payload, expiresAt]
      );
      if (r.rowCount === 0) throw new Error('replay detected');
      return;
    }

    await db.query(
      `INSERT INTO oidc_payloads (id, type, payload, grant_id, user_code, uid, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (id) DO UPDATE
         SET payload = EXCLUDED.payload,
             grant_id = EXCLUDED.grant_id,
             user_code = EXCLUDED.user_code,
             uid = EXCLUDED.uid,
             expires_at = EXCLUDED.expires_at`,
      [
        id,
        this.name,
        payload,
        payload.grantId ?? null,
        payload.userCode ?? null,
        payload.uid ?? null,
        expiresAt,
      ]
    );
  }

  async find(id) {
    const { rows } = await db.query(
      `SELECT payload, consumed_at FROM oidc_payloads
       WHERE id = $1 AND (expires_at IS NULL OR expires_at > now())`,
      [id]
    );
    if (!rows.length) return undefined;
    const out = rows[0].payload;
    if (rows[0].consumed_at) out.consumed = rows[0].consumed_at.getTime();
    return out;
  }

  async findByUid(uid) {
    const { rows } = await db.query(
      `SELECT payload FROM oidc_payloads
       WHERE uid = $1 AND (expires_at IS NULL OR expires_at > now())
       ORDER BY id DESC LIMIT 1`,
      [uid]
    );
    return rows.length ? rows[0].payload : undefined;
  }

  async findByUserCode(userCode) {
    const { rows } = await db.query(
      `SELECT payload FROM oidc_payloads
       WHERE user_code = $1 AND (expires_at IS NULL OR expires_at > now())
       ORDER BY id DESC LIMIT 1`,
      [userCode]
    );
    return rows.length ? rows[0].payload : undefined;
  }

  async consume(id) {
    const r = await db.query(
      `UPDATE oidc_payloads SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL`,
      [id]
    );
    if (r.rowCount === 0) throw new Error('already consumed');
  }

  async destroy(id) {
    await db.query('DELETE FROM oidc_payloads WHERE id = $1', [id]);
  }

  async revokeByGrantId(grantId) {
    await db.query('DELETE FROM oidc_payloads WHERE grant_id = $1', [grantId]);
  }
}
