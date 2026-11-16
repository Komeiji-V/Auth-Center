# OIDC 接入

认证中心是标准的 OpenID Provider（OP）。小站作为 Relying Party（RP）接入，**不需要共享密钥，也不需要读用户库**。

## 端点

| 端点 | 说明 |
|---|---|
| `/.well-known/openid-configuration` | Discovery |
| `/jwks` | 公钥（RS256） |
| `/auth` | 授权（Authorization Code + PKCE） |
| `/token` | 换取 token |
| `/me` | UserInfo |
| `/session/end` | RP-Initiated Logout |
| `/interaction/:uid` | 登录页（自定义） |

## 配置

```bash
OIDC_ENABLED=true
OIDC_ISSUER=https://auth.example.com     # 必须与真实访问地址完全一致
OIDC_COOKIE_SECRET=<openssl rand -hex 32>
OIDC_COOKIE_SECURE=true                  # 生产必须
OIDC_DEBUG_KICK=false                    # 生产的调试踢人端点，必须关

OIDC_CLIENTS='[
  {
    "client_id": "music",
    "client_secret": "<openssl rand -hex 32>",
    "client_name": "听音室",
    "redirect_uris": ["https://music.example.com/auth/callback"],
    "backchannel_logout_uri": "https://music.example.com/auth/backchannel-logout"
  }
]'
```

- **每个小站一个 client**，不要共用
- `redirect_uris` 必须精确匹配，不支持通配符
- `client_name` 可选，会显示在用户的「已授权应用」列表里
- Docker 的 `env_file` 不会去掉外层引号（dotenv 会），代码已兼容，建议保留单引号

首次部署先生成签名密钥：

```bash
node scripts/gen-keys.mjs          # 直接部署
docker compose run --rm auth node scripts/gen-keys.mjs   # 容器部署
```

私钥在 `keys/jwks.json`，已加入 `.gitignore` 与 `.dockerignore`，运行时只读挂载。
**多实例必须共用同一份密钥**，各自生成会互相验签失败。

## 小站接入（BFF 模式）

推荐让浏览器只持有 HttpOnly 会话 cookie，token 全部留在服务端。

```bash
npm i express openid-client
```

```js
import * as oidc from 'openid-client';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const config = await oidc.discovery(new URL(ISSUER), CLIENT_ID, CLIENT_SECRET);
const JWKS = createRemoteJWKSet(new URL(config.serverMetadata().jwks_uri));

// 1) 发起登录
app.get('/auth/login', async (req, res) => {
  const verifier = oidc.randomPKCECodeVerifier();
  const state = oidc.randomState();
  const nonce = oidc.randomNonce();
  pending.set(state, { verifier, nonce });

  const url = oidc.buildAuthorizationUrl(config, {
    redirect_uri: REDIRECT_URI,
    scope: 'openid email profile offline_access',
    prompt: 'consent',                       // 见下方「两个必须注意的点」
    code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
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
    sub: claims.sub,          // 用户唯一标识，见「用户主键」
    idSid: claims.sid,        // 会话标识，back-channel logout 会带回来
    tokens,
  });
  res.cookie('app_sid', sid, { httpOnly: true, sameSite: 'lax', secure: true, path: '/' });
  res.redirect('/');
});

// 3) 静默续期
async function ensureFreshTokens(req, res, next) {
  const s = sessions.get(req.cookies.app_sid);
  if (!s || s.tokens.expires_at - Date.now() > 60_000) return next();

  // 同一会话的并发请求必须复用同一次刷新：refresh token 是轮换的，
  // 并发刷新会触发 IdP 的重放检测，导致整个 grant 被吊销、用户被登出。
  if (!s.refreshing) {
    s.refreshing = (async () => {
      const t = await oidc.refreshTokenGrant(config, s.tokens.refresh_token);
      s.tokens = { ...s.tokens, ...t, expires_at: Date.now() + t.expires_in * 1000 };
    })().finally(() => { s.refreshing = null; });
  }
  try { await s.refreshing; } catch { sessions.delete(req.cookies.app_sid); }
  next();
}

// 4) Back-Channel Logout
app.post('/auth/backchannel-logout', async (req, res) => {
  try {
    const { payload } = await jwtVerify(req.body.logout_token, JWKS, {
      issuer: ISSUER,
      audience: CLIENT_ID,
    });
    if (!payload.events?.['http://schemas.openid.net/event/backchannel-logout']) {
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
```

完整可运行实现见 [`test/e2e/rp.mjs`](../test/e2e/rp.mjs)。

### 两个必须注意的点

**1. `offline_access` 必须配 `prompt=consent`**

不传 `prompt=consent` 时，认证中心会把 `offline_access` 从 scope 里剥掉，**不签发 refresh token**（OIDC 规范要求用户明确同意）。

**2. 并发刷新必须串行化**

refresh token 每次使用都会轮换，两个并发请求同时刷新会触发重放检测，**整个 grant 被吊销**，用户直接被登出。

## 用户主键

`sub` 是字符串形式的用户 ID，如 `"5140001"`。建表：

```sql
CREATE TABLE user_profile (
  issuer  TEXT NOT NULL,
  subject TEXT NOT NULL,
  data    JSONB,
  PRIMARY KEY (issuer, subject)
);
```

带 `issuer` 是为了将来换认证中心时能平滑迁移。

**不要用 email 或 username 当主键**，它们都可以改。`sub` 一旦对外发布就不能变。

## 撤销机制

| 触发 | 效果 |
|---|---|
| 用户在小站点「退出登录」 | 小站清本地会话，认证中心侧不变 |
| 用户在本站「退出登录」 | 删本站会话 + 撤销该用户全部 OIDC 凭据 + 清 provider cookie |
| 改密码 / 重置密码 / 改邮箱 | 同上（所有设备、所有小站一起失效） |
| 管理员封禁 / 解封 / 删号 | 推送 back-channel logout + 删除 Session/Grant/RefreshToken |

「撤销 OIDC 凭据」= 删除 `oidc_payloads` 里该 `accountId` 的 `Session`、`Grant`、`AccessToken`、`RefreshToken`、`AuthorizationCode`。

通知失败会写入 `backchannel_retry`，由 `cleanup.mjs` 指数退避重试（10 次后放弃）。

### 为什么必须一起撤销

只删本站会话是不够的：小站手里的 refresh token 仍然有效，攻击者可以继续换新 access token（最长 14 天）；封禁解除后旧 token 甚至直接复活。

## 已知约束

- access token 寿命 15 分钟。封禁后小站若只验签、不回调认证中心，最多有 15 分钟窗口；主动踢人可以立即失效
- consent 是全自动通过的，用户看不到授权确认页。所有 client 都视为可信，接入第三方站点前需要重新评估
- 用户可在个人中心查看已授权的应用，但暂不支持逐个撤销
