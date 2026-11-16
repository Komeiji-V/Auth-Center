# API 契约

Base URL：`https://auth.你的域名`（本地 `http://localhost:8000`）

## 通用约定

- **认证**：登录后服务端下发 `Set-Cookie: __Host-ac_sid=…`（HttpOnly、SameSite=Lax、Secure），后续请求自动携带
- **请求体**：JSON，单请求上限 32KB
- **响应**：成功 `{ ok: true, ... }`，失败 `{ error: string }`
- **CSRF**：所有写请求校验 `Origin`/`Referer` 与 `SITE_ORIGIN` 一致，不一致返回 403

| 状态码 | 含义 |
|---|---|
| 400 | 参数错误 / 业务拒绝 |
| 401 | 未登录 / 会话过期 |
| 403 | 无权限 / 账号 pending 或 banned / 来源非法 |
| 429 | 限流 |
| 502 | 邮件发送失败 |
| 500 | 服务端错误 |

## 会话

- 有效期：绝对 `SESSION_TTL_DAYS`（默认 7 天），闲置 `SESSION_IDLE_HOURS`（默认 24 小时）失效
- 撤销：改密码 / 重置密码 / 改邮箱 / 封禁 / 删号会删除该用户全部会话，**立即失效**
- 小站不走本站 JWT，走标准 OIDC（见 `docs/OIDC.md`）

## 限流阈值（.env 可调）

| 项 | 默认 |
|---|---|
| 登录失败锁定 | 5 次 / 15 分钟（`/api/login` 与 OIDC 登录页共享计数） |
| TOTP 操作锁定 | 5 次 / 15 分钟 |
| 注册验证码发送 | 3 次 / 小时 / IP |
| 个人中心验证码 | 5 次 / 小时 / IP |
| 全局限流 | 60 次 / 分钟 / IP（`/jwks` 与 `/.well-known` 豁免） |

> 限流是进程内存实现，重启清零；多实例下限流阈值需按实例数分摊。

---

# 公共接口

## GET /api/config

站点公开配置（标题、图标、注册开关、回跳白名单）。

```json
{ "flags": { "invite_required": false, "email_verify_required": true, "review_required": false },
  "redirect_origins": [], "site": { "site_title": "…", "site_icon": "", "site_bg": "" } }
```

## POST /api/register

提交注册申请，状态流转取决于三个开关。

| 字段 | 必填 | 校验 |
|---|---|---|
| `username` | 是 | 2-20 位中文/字母/数字/下划线 |
| `email` | 是 | 格式；域名不在 `BLOCKED_EMAIL_DOMAINS` |
| `password` | 是 | 8-72 位 |
| `invite_code` | `invite_required` 时 | 存在、未过期、未用尽 |
| `apply_info` | `review_required` 时 | 5-500 字，不含 `<>&"'\\` |

**响应**
- 需邮箱验证：`{ ok: true, needs_verify: true, message, debug_code?(仅调试) }`
- 免邮箱验证：`{ ok: true, status: 'active'|'pending', message }`

**未完成注册的续期**：同一邮箱已存在「pending 且未验证」的记录时，不报「已被注册」，而是校验密码后重发验证码（不新增用户、不消耗 id）。

| 条件 | 响应 |
|---|---|
| 密码正确 + 用户名一致 | `{ ok: true, needs_verify: true, message: "检测到未完成的注册，验证码已重新发送" }` |
| 密码错误 | 400 `该邮箱有未完成的注册，请使用原密码继续` |
| 用户名不同 | 400 `该邮箱有未完成的注册（用户名 xxx），请使用原用户名继续` |
| 该邮箱已 active/banned | 400 `用户名或邮箱已被注册` |

> 首个注册用户自动成为 owner；配了 `OWNER_EMAIL` 时必须是该邮箱。

## POST /api/verify-email

校验注册验证码。`{ email, code }` → `{ ok: true, status: 'active'|'pending', message }`。

验证码 10 分钟有效、一次性、错 5 次作废。

## POST /api/login

建立服务端会话，下发 HttpOnly cookie。

| 字段 | 必填 |
|---|---|
| `account` | 是（用户名或邮箱） |
| `password` | 是 |
| `totp_code` | 已绑 TOTP 时 |

**成功**：`{ ok: true, user: {...}, need_totp_setup }` + `Set-Cookie`

**错误**
- 401 `密码或 TOTP 验证码错误` —— 密码错 / TOTP 错 / 未提交 TOTP **完全一致的文案**
- 403 `账号待审核` / `账号已被封禁`
- 429 锁定

## POST /api/logout

销毁本站会话、撤销该用户全部 OIDC 凭据、清 provider cookie。→ `{ ok: true }`

## POST /api/forgot-password

`{ account, totp_code? }` → 统一返回 `{ ok: true, message: "如果账号存在，验证码已发送到邮箱" }`。

账号不存在 / 非 active / TOTP 错 全部同一文案（防枚举）；限流前置，429 行为与账号存在性解耦。

## POST /api/reset-password

`{ account, code, new_password }` → 重置并删除全部会话（含 OIDC 凭据）。

---

# 登录态接口

## GET /api/userinfo

当前用户信息：`{ id, username, email, role, totp_enabled, is_owner }`。

## GET /api/sessions

```json
{ "idleHours": 24, "ttlDays": 7,
  "sessions": [{ "current": true, "ip": "…", "userAgent": "…",
                 "createdAt": "…", "lastSeen": "…" }] }
```

## POST /api/sessions/revoke-others

退出除当前设备外的全部本站会话 → `{ ok: true, revoked: n }`。

> 只清本站 `sessions`；小站侧凭据由「退出登录 / 改密」负责。

## GET /api/authorizations

```json
{ "apps": [{ "clientId": "music", "clientName": "听音室",
             "scope": "openid email profile offline_access", "authorizedAt": "…" }] }
```

按 `clientId` 去重取最近一次；`clientName` 来自 `OIDC_CLIENTS` 的 `client_name`。

## POST /api/authorizations/revoke-all

撤销该用户在所有小站的授权（OIDC 的 Session / Grant / RefreshToken）。

- 不影响本站会话（`ac_sid` 不在撤销范围内），用户不会被自己踢下线
- 撤销后所有小站都需要重新授权
- OIDC 未启用时返回 `{ ok: true, revoked: 0 }`

## POST /api/profile/username

`{ username }`（2-20 位，查重）。

## POST /api/profile/password

`{ old_password, new_password }` → 删除该用户全部会话（含 OIDC 凭据），需重新登录。

## POST /api/profile/email → /api/profile/email/verify

两步改邮箱：先发验证码到新邮箱，再 `{ new_email, code }` 确认。成功后同上，全部会话失效。

## TOTP

| 接口 | 说明 |
|---|---|
| `POST /api/profile/totp-setup` | 生成密钥 + 二维码；已绑定时需提交当前 `code` |
| `POST /api/profile/totp-confirm` | `{ code }` 确认绑定 |
| `POST /api/profile/totp-disable` | `{ code }` 解绑 |

setup/confirm/disable 共享失败计数（5 次 / 15 分钟）。

---

# 管理接口

> 需 `role=admin`；`ADMIN_TOTP_REQUIRED=true` 时还需已绑 TOTP。
> 目标为管理员或 owner 的操作仅 **owner** 可执行。

## GET /api/admin/users?status=&q=

| 参数 | 说明 |
|---|---|
| `status` | `pending` / `active` / `banned` / `all`（默认 pending） |
| `q` | 可选。纯数字按 ID 精确匹配；同时按用户名/邮箱模糊匹配（`%` `_` 已转义） |

最多 200 条，按 id 倒序。

## 用户操作

| 接口 | 说明 |
|---|---|
| `POST /api/admin/users/:id/approve` | pending → active；**要求 `email_verified=true`** |
| `POST /api/admin/users/:id/reject` | 删除用户，释放邮箱/用户名/邀请码；**owner 不可删** |
| `POST /api/admin/users/:id/ban` | 封禁 + 撤销该用户全部会话与 OIDC 凭据 |
| `POST /api/admin/users/:id/unban` | 解封 + 再清一次凭据 |
| `POST /api/admin/users/:id/unlock` | 清除登录锁定 |
| `POST /api/admin/users/:id/reset-totp` | 清空 TOTP 绑定 |
| `POST /api/admin/users/:id/set-admin` | `{ is_admin: boolean }`（**必须是布尔值**），提升仅 owner |
| `POST /api/admin/users/:id/edit` | `{ username?, email? }`，改邮箱后该用户全部会话失效 |

## POST /api/admin/config

注册模式热切换（仅 owner）：

```json
{ "invite_required": false, "email_verify_required": true, "review_required": true }
```

## 邀请码（仅 owner）

| 接口 | 说明 |
|---|---|
| `POST /api/admin/invite-codes` | `{ count?, max_uses?, expires_days?, note? }` |
| `GET /api/admin/invite-codes` | 列表（含使用状态） |
| `POST /api/admin/invite-codes/:code/delete` | 删除（不影响已注册用户） |

---

# 注册状态机

三个开关任意组合，最终状态：

| invite | email_verify | review | 流程 |
|---|---|---|---|
| 关 | 关 | 关 | 提交即 active |
| 关 | 关 | 开 | 提交即 pending（等审核） |
| 关 | 开 | 关 | 发码 → 验证 → active |
| 关 | 开 | 开 | 发码 → 验证 → pending |
| 开 | 关 | 关 | 邀请码 → active |
| 开 | 关 | 开 | 邀请码 → pending |
| 开 | 开 | 关 | 邀请码 → 发码 → 验证 → active |
| 开 | 开 | 开 | 邀请码 → 发码 → 验证 → pending |

## email_verified 与两种 pending

| status | email_verified | 含义 | 清理策略 |
|---|---|---|---|
| pending | false | 卡在邮箱验证（僵尸） | 每日任务删除 24h 前的 |
| pending | true | 等人工审核 | 永久保留 |
| active | true | 正常 | — |
| banned | true | 封禁 | — |

- `email_verify_required=false` 时，注册即写入 `email_verified=true`（邮箱环节免检）
- `verify-email`、`profile/email/verify` 成功后置 true
- 历史数据在首次加列时回填：`active`/`banned` 一律 true

## 账号状态

| 状态 | 登录 | 会话 |
|---|---|---|
| pending | 403 待审核 | 403 |
| active | 正常 | 正常 |
| banned | 403 已封禁 | 403（即时） |
