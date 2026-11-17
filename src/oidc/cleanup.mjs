import db from '../db.js';

const CLEAN_INTERVAL_MS = 60 * 60 * 1000;
const RETRY_INTERVAL_MS = 60 * 1000;

/**
 * 后台任务：
 *   1. 清理 oidc_payloads 里已过期的 Session / token / code
 *   2. 重试失败的 back-channel logout（指数退避，最长 1 小时）
 */
export function startCleanup(provider) {
  setInterval(async () => {
    try {
      const r = await db.query(
        `DELETE FROM oidc_payloads WHERE expires_at IS NOT NULL AND expires_at < now()`
      );
      if (r.rowCount) console.log(`[oidc cleanup] 清理过期记录 ${r.rowCount} 条`);
    } catch (e) {
      console.error('[oidc cleanup] 失败:', e.message);
    }
  }, CLEAN_INTERVAL_MS).unref();

  setInterval(async () => {
    let rows;
    try {
      ({ rows } = await db.query(
        `SELECT id, client_id, sub, sid, attempts FROM backchannel_retry
         WHERE next_at <= now() ORDER BY id LIMIT 20`
      ));
    } catch (e) {
      console.error('[oidc retry] 读取队列失败:', e.message);
      return;
    }

    for (const r of rows) {
      try {
      // 重试上限：小站长期离线时不无限堆积
      if (r.attempts >= 10) {
        console.error(`[oidc retry] ${r.client_id} 重试 ${r.attempts} 次仍失败，放弃（sub=${r.sub}）`);
        await db.query('DELETE FROM backchannel_retry WHERE id = $1', [r.id]);
        continue;
      }

      const client = await provider.Client.find(r.client_id).catch(() => undefined);
      if (!client || !client.backchannelLogoutUri) {
        await db.query('DELETE FROM backchannel_retry WHERE id = $1', [r.id]);
        continue;
      }
      try {
        await client.backchannelLogout(r.sub, r.sid);
        await db.query('DELETE FROM backchannel_retry WHERE id = $1', [r.id]);
        console.log(`[oidc retry] ${r.client_id} 第 ${r.attempts + 1} 次重试成功（sub=${r.sub}）`);
      } catch (e) {
        const delaySec = Math.min(3600, 10 * 2 ** Math.min(r.attempts, 8));
        await db.query(
          `UPDATE backchannel_retry
           SET attempts = attempts + 1,
               next_at = now() + ($2 || ' seconds')::interval,
               last_error = $3
           WHERE id = $1`,
          [r.id, String(delaySec), e.message]
        );
      }
      } catch (e) {
        // 单条记录处理失败不能影响整批，更不能让 interval 回调 reject（会按 uncaught 退出进程）
        console.error(`[oidc retry] 处理记录 ${r.id} 失败:`, e.message);
      }
    }
  }, RETRY_INTERVAL_MS).unref();
}
