# 小站接入教程（OIDC）

认证中心提供标准 OpenID Connect，小站用任意 OIDC 客户端库接入即可，**不需要共享密钥、不需要读认证中心的数据库**。

> 历史版本（JWT + HS256 共享密钥）已废弃。如果你还持有旧接入代码，请按本文重写。

## 一、在认证中心登记 client

在认证中心 `.env` 的 `OIDC_CLIENTS` 里加一条：

```json
{
  "client_id": "music",
  "client_secret": "用 openssl rand -hex 32 生成",
  "redirect_uris": ["https://music.example.com/auth/callback"],
  "backchannel_logout_uri": "https://music.example.com/auth/backchannel-logout"
}
```

注意事项：

- **每个小站一个 client**，不要共用
- `redirect_uris` 必须精确匹配，不支持通配符
- 改完重启认证中心

## 二、小站侧：BFF 模式（推荐）

浏览器只持有 HttpOnly 会话 cookie，token 全部留在服务端。这样 XSS 偷不到 token，刷新页面也不需要重新登录。

### 依赖

```bash
npm i express openid-client
```

### 核心代码（Express）

```js
import express from 'express';
import crypto from 'node:crypto';
import * as oidc from 'openid-client';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const ISSUER = process.env.AUTH_ISSUER;              // https://auth.example.com
const CLIENT_ID = process.env.OIDC_CLIENT_ID;
const CLIENT_SECRET = process.env.OIDC_CLIENT_SECRET;
const REDIRECT_URI = process.env.OIDC_REDIRECT_URI;  // https://music.example.com/auth/callback

const sessions = new Map();   // 生产换成 Redis / 数据库
const pending = new Map();    // state -> { verifier, nonce }

let config;
let JWKS;

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// 1) 发起登录
app.get('/auth/login', async (req, res) => {
  const verifier = oidc.randomPKCECodeVerifier();
  const challenge = await oidc.calculatePKCECodeChallenge(verifier);
  const state = oidc.randomState();
  const nonce = oidc.randomNonce();
  pending.set(state, { verifier, nonce });

  const url = oidc.buildAuthorizationUrl(config, {
    redirect_uri: REDIRECT_URI,
    // offline_access + prompt=consent 才会签发 refresh token
    scope: 'openid email profile offline_access',
    prompt: 'consent',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
    nonce,
  });
  res.redirect(url.href);
});

// 2) 回调：换 token，建本地会话
app.get('/auth/callback', async (req, res) => {
  const currentUrl = new URL(req.originalUrl, `https://${req.headers.host}`);
  const state = currentUrl.searchParams.get('state');
  const p = pending.get(state);
  if (!p) return res.status(400).send('state 不匹配');

  const tokens = await oidc.authorizationCodeGrant(config, currentUrl, {
    pkceCodeVerifier: p.verifier,
    expectedState: state,
    expectedNonce: p.nonce,
  });
  pending.delete(state);

  const claims = tokens.claims();
  const sid = crypto.randomUUID();
  sessions.set(sid, {
    sub: claims.sub,          // 用户唯一标识，存下来当主键
    idSid: claims.sid,        // 会话标识，back-channel logout 会带回来
    tokens: {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      expires_at: Date.now() + (tokens.expires_in || 0) * 1000,
    },
  });

  res.cookie('app_sid', sid, { httpOnly: true, sameSite: 'lax', secure: true, path: '/', maxAge: 7 * 864e5 });
  res.redirect('/');
});

// 3) 静默续期（每次请求前检查）
async function ensureFreshTokens(req, res, next) {
  const s = sessions.get(req.cookies && req.cookies.app_sid);
  if (!s) return next();
  if (s.tokens.expires_at - Date.now() > 60_000) return next();
  if (!s.tokens.refresh_token) return next();

  // 同一会话的并发请求必须复用同一次刷新：refresh token 是轮换的，
  // 并发刷新会触发 IdP 的重放检测，导致 grant 被吊销、用户被登出。
  if (!s.refreshing) {
    s.refreshing = (async () => {
      const t = await oidc.refreshTokenGrant(config, s.tokens.refresh_token);
      s.tokens.access_token = t.access_token;
      if (t.refresh_token) s.tokens.refresh_token = t.refresh_token;
      s.tokens.expires_at = Date.now() + (t.expires_in || 0) * 1000;
    })().finally(() => { s.refreshing = null; });
  }
  try { await s.refreshing; } catch { sessions.delete(req.cookies.app_sid); }
  next();
}
app.use(ensureFreshTokens);

// 4) Back-Channel Logout：认证中心封禁/删号时推送
app.post('/auth/backchannel-logout', async (req, res) => {
  try {
    const { payload } = await jwtVerify(req.body.logout_token, JWKS, {
      issuer: ISSUER,
      audience: CLIENT_ID,
    });
    if (!payload.events || !payload.events['http://schemas.openid.net/event/backchannel-logout']) {
      return res.status(400).end();
    }
    for (const [key, s] of sessions) {
      if (s.sub === payload.sub && (!payload.sid || s.idSid === payload.sid)) sessions.delete(key);
    }
    res.status(200).end();
  } catch {
    res.status(400).end();
  }
});

// 5) 启动
config = await oidc.discovery(new URL(ISSUER), CLIENT_ID, CLIENT_SECRET);
JWKS = createRemoteJWKSet(new URL(config.serverMetadata().jwks_uri));
app.listen(3000);
```

## 三、用户主键：用 `(issuer, sub)`

`sub` 是字符串形式的认证中心用户 ID（如 `"5140001"`）。建表时：

```sql
CREATE TABLE user_profile (
  issuer  TEXT NOT NULL,
  subject TEXT NOT NULL,
  data    JSONB,
  PRIMARY KEY (issuer, subject)
);
```

带上 `issuer` 是为了将来换认证中心时能平滑迁移——只换 issuer，不丢用户关联。

**不要用 email 或 username 当主键**，它们都可以改。

## 四、封禁 / 删号的行为

| 时机 | 小站侧表现 |
|---|---|
| 管理员点「封禁」 | 认证中心推送 logout token → 小站清会话 → 用户下次访问需重新登录 → 授权时被拒 |
| 管理员点「删除」 | 同上，且 `findAccount` 查不到该用户，永远无法再授权 |
| 通知失败 | 认证中心入重试队列，指数退避重试（最长 1 小时间隔） |

**踢人 ≠ 删数据**：小站里的业务数据（存档等）还在，要不要清是产品决策。

## 五、常见问题

**Q：能不能不用 BFF，纯前端拿 token？**
可以，但不推荐：token 只能放内存或 localStorage，XSS 一偷就失守，而且并发刷新问题更严重。

**Q：access token 能不能当用户凭证用？**
不能。它只用来调资源服务器。用户身份用 ID Token 的 `sub`。

**Q：为什么必须带 `prompt=consent`？**
`offline_access` 需要用户明确同意，否则认证中心会把它从 scope 里移除，导致不签发 refresh token。

**Q：本地 http 调试报 `only requests to HTTPS are allowed`？**
`openid-client` v6 默认只允许 HTTPS，本地开发需显式放行：

```js
oidc.discovery(new URL(ISSUER), CLIENT_ID, CLIENT_SECRET, undefined, {
  execute: [oidc.allowInsecureRequests],
});
```

**Q：`sub` 会变吗？**
不会。但如果你将来换认证中心，`sub` 会变——所以主键要带 `issuer`。
