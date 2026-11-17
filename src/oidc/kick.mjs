import db from '../db.js';

/**
 * 主动踢人：向该用户所有已授权的小站发送 Back-Channel Logout
 *
 * 封禁 / 删除账号时调用。失败的通知写入 backchannel_retry，由 cleanup.mjs 重试。
 *
 * 注意：这里用了 oidc-provider 的内部结构（Session.authorizations / sidFor /
 * Client.backchannelLogout），升级大版本前需要回归验证。
 */
export async function kickAccount(provider, accountId) {
  const id = String(accountId);

  const { rows } = await db.query(
    `SELECT uid FROM oidc_payloads WHERE type = 'Session' AND payload->>'accountId' = $1`,
    [id]
  );

  if (rows.length === 0) {
    return { sessions: 0, notified: [] };
  }

  let sessions = 0;
  const notified = [];

  for (const { uid } of rows) {
    const session = await provider.Session.findByUid(uid);
    if (!session) continue;

    for (const clientId of Object.keys(session.authorizations || {})) {
      const client = await provider.Client.find(clientId);
      if (!client || !client.backchannelLogoutUri) continue;

      const sid = session.sidFor(clientId);
      try {
        await client.backchannelLogout(id, sid);
        notified.push({ clientId, sid, ok: true });
        console.log(`[oidc kick] 已通知 ${clientId} sid=${sid}`);
      } catch (e) {
        notified.push({ clientId, sid, ok: false, error: e.message });
        console.error(`[oidc kick] 通知 ${clientId} 失败: ${e.message}（已入重试队列）`);
        await db.query(
          `INSERT INTO backchannel_retry (client_id, sub, sid, last_error) VALUES ($1, $2, $3, $4)`,
          [clientId, id, sid, e.message]
        );
      }
    }

    await session.destroy();
    sessions += 1;
  }

  return { sessions, notified };
}


/**
 * 彻底撤销某账号的 OIDC 凭据
 *
 * kickAccount 只发 back-channel 通知并销毁 Session，但 Grant / RefreshToken /
 * AccessToken 仍留在库里：登出、改密、重置密码之后，小站手里的 refresh token
 * 还能继续换新 access token（最长 14 天）；封禁解除后旧 token 甚至直接复活。
 *
 * 所以凡是要「收回访问权」的地方（登出 / 改密 / 重置 / 改邮箱 / 封禁 / 删号），
 * 都应该调这个而不是 kickAccount。
 */
export async function revokeAccount(provider, accountId) {
  const id = String(accountId);

  // back-channel 通知是「尽力而为」，删凭据是安全关键步骤。
  // 通知阶段任何一处 DB 抖动都不能让它挡住后面的 DELETE —— 否则密码已改、
  // 本站会话已删，攻击者的 refresh token 却还在。
  let kicked = { sessions: 0, notified: [] };
  let kickError = null;
  try {
    kicked = await kickAccount(provider, id);
  } catch (e) {
    // 通知失败不阻断删凭据，但必须把错误暴露给调用方，
    // 否则管理端会看到 {ok:true} 而小站一个 logout 都没收到
    kickError = e.message;
    console.error('[oidc revoke] back-channel 阶段失败，继续删除凭据:', e.message);
  }

  const r = await db.query(
    `DELETE FROM oidc_payloads
      WHERE type IN ('Session', 'Grant', 'AccessToken', 'RefreshToken', 'AuthorizationCode')
        AND payload->>'accountId' = $1`,
    [id]
  );

  console.log(`[oidc revoke] sub=${id} 会话 ${kicked.sessions} 个，凭据 ${r.rowCount} 条`);
  return { ...kicked, revoked: r.rowCount, kickError };
}
