# OIDC 接入说明

认证中心在保留原有 `/api/login`（JWT）的同时，提供标准 OpenID Connect 端点。两者共用同一套 `users` 表，**不需要迁移任何用户数据**。

## 端点

| 端点 | 说明 |
|---|---|
| `/.well-known/openid-configuration` | Discovery |
| `/jwks` | 公钥（RS256） |
| `/auth` | 授权端点（Authorization Code + PKCE） |
| `/token` | 换取 token |
| `/me` | UserInfo |
| `/session/end` | RP-Initiated Logout |
| `/interaction/:uid` | 登录页（自定义） |

## 开启方式

`.env`：

```bash
OIDC_ENABLED=true
OIDC_ISSUER=https://auth.你的域名
OIDC_COOKIE_SECRET=<随机值，留空则复用 JWT_SECRET>
OIDC_COOKIE_SECURE=true          # 生产必须 true
OIDC_CLIENTS='[{"client_id":"music","client_secret":"...","redirect_uris":["https://music.example.com/auth/callback"],"backchannel_logout_uri":"https://music.example.com/auth/backchannel-logout"}]'
```

首次部署先生成签名密钥（**含私钥，已在 .gitignore**）：

```bash
node scripts/gen-keys.mjs
```

## 小站接入

1. 在 `OIDC_CLIENTS` 里为每个小站加一条，`redirect_uris` 必须**精确匹配**
2. 小站使用标准 OIDC 客户端库（如 `openid-client`），不要自己验签
3. 请求 `scope=openid email profile offline_access` 并带 `prompt=consent`，才会签发 refresh token
4. 用 `issuer` + `sub` 作为用户主键（`sub` 是字符串形式的 `users.id`，如 `"5140001"`）

BFF 模式建议：token 只存服务端，浏览器持有 HttpOnly 会话 cookie。

## 封禁 / 删除账号

`src/admin.js` 的 `ban` 与 `reject` 会在改库后调用 `kickAccount`：

1. 查出该用户在所有小站的 Session
2. 向每个 `backchannel_logout_uri` 推送签名的 logout token
3. 销毁本地会话

小站只需实现 `POST /backchannel-logout`：用 JWKS 验签，校验 `iss` / `aud` / `events`，按 `sub`（及 `sid`）清本地会话，返回 200。

通知失败会写入 `backchannel_retry`，由 `src/oidc/cleanup.mjs` 指数退避重试（最长 1 小时）。

## 与旧登录的关系

| 场景 | 走哪条路 |
|---|---|
| 认证中心自己的页面（管理后台、个人中心） | 旧的 `/api/login` + JWT，保持不变 |
| 小站登录 | 新的 OIDC 流程 |

过渡期双轨运行，确认所有小站切换完成后，再考虑下线 `/api/login`。

## 注意事项

- **`sub` 一旦对外发布不能修改**：它是小站关联用户的唯一依据
- access token 寿命 15 分钟；封禁后小站侧最多有 15 分钟窗口，主动踢人可立即失效
- `OIDC_DEBUG_KICK=true` 仅用于调试（暴露 `/oidc-debug/kick/:sub`），生产必须关闭
- `oidc_payloads` 会随使用增长，`cleanup.mjs` 每小时清理过期记录
