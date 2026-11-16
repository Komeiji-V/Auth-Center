import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Provider } from 'oidc-provider';
import db from '../db.js';
import PostgresAdapter from './adapter.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));

/** 固定签名密钥（scripts/gen-keys.mjs 生成） */
function loadJwks() {
  const file = path.join(here, '..', '..', 'keys', 'jwks.json');
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

/**
 * 小站（RP）注册表。每新增一个站点，在 OIDC_CLIENTS 里加一项。
 * 每站独立 client_id / secret / redirect_uri，不要共用。
 */
function loadClients() {
  const raw = process.env.OIDC_CLIENTS;
  if (!raw) throw new Error('缺少环境变量 OIDC_CLIENTS（JSON 数组）');
  // 兼容两种加载方式：dotenv 会去掉外层引号，docker --env-file / compose env_file 不会
  const text = raw.trim().replace(/^(['"])([\s\S]*)\1$/, '$2');
  let list;
  try {
    list = JSON.parse(text);
  } catch (e) {
    throw new Error(`OIDC_CLIENTS 不是合法 JSON: ${e.message}`);
  }
  if (!Array.isArray(list) || list.length === 0) {
    throw new Error('OIDC_CLIENTS 至少需要一个客户端');
  }
  return list.map((c) => ({
    client_id: c.client_id,
    // 授权列表里展示给用户看的名字
    client_name: c.client_name || c.client_id,
    client_secret: c.client_secret,
    redirect_uris: c.redirect_uris,
    post_logout_redirect_uris: c.post_logout_redirect_uris || [],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'client_secret_basic',
    backchannel_logout_uri: c.backchannel_logout_uri,
    backchannel_logout_session_required: true,
  }));
}

/**
 * 账号查找：直接读现有 users 表。
 * 密码、TOTP、状态全部留在原地，不做任何用户数据迁移。
 */
async function findAccount(ctx, id) {
  const { rows } = await db.query(
    'SELECT id, username, email, status, email_verified FROM users WHERE id = $1',
    [id]
  );
  if (!rows.length) return undefined;
  const u = rows[0];
  // 封禁 / 待审用户不签发身份
  if (u.status !== 'active') return undefined;

  return {
    accountId: String(u.id),
    async claims() {
      return {
        sub: String(u.id),
        preferred_username: u.username,
        email: u.email,
        email_verified: Boolean(u.email_verified),
      };
    },
  };
}

export function createProvider() {
  const issuer = process.env.OIDC_ISSUER;
  if (!issuer) throw new Error('缺少环境变量 OIDC_ISSUER');

  return new Provider(issuer, {
    adapter: PostgresAdapter,
    clients: loadClients(),
    findAccount,

    claims: {
      openid: ['sub'],
      profile: ['preferred_username'],
      email: ['email', 'email_verified'],
    },

    jwks: loadJwks(),

    interactions: {
      // 保留默认 policy（login + consent）；consent 由 interaction.mjs 自动通过。
      // 注意不能 remove('consent')，否则授权阶段会报 no scope was granted。
      url: (ctx, interaction) => `/interaction/${interaction.uid}`,
    },

    features: {
      devInteractions: { enabled: false },
      backchannelLogout: { enabled: true },
    },

    cookies: {
      keys: [process.env.OIDC_COOKIE_SECRET],
      // session cookie 的 path 是 /，可以吃 __Host- 前缀（防 cookie tossing）；
      // _interaction / _interaction_resume 的 path 是子路径，不能用该前缀，保持原名。
      names: {
        session: process.env.OIDC_COOKIE_SECURE === 'true' ? '__Host-_session' : '_session',
      },
      // 生产必须为 true（HTTPS）；本地 http 调试按 OIDC_COOKIE_SECURE 放行
      short: { secure: process.env.OIDC_COOKIE_SECURE === 'true' },
      long: { secure: process.env.OIDC_COOKIE_SECURE === 'true' },
    },

    pkce: { required: () => true },
    rotateRefreshToken: true,

    ttl: {
      AccessToken: 15 * 60,
      IdToken: 10 * 60,
      RefreshToken: 14 * 24 * 60 * 60,
      AuthorizationCode: 60,
      Session: 24 * 60 * 60,
      Interaction: 60 * 60,
      Grant: 14 * 24 * 60 * 60,
    },
  });
}
