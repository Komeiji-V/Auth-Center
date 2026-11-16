# API 接口契约

认证中心全部 HTTP 接口。适用于 agent 接入、测试与审查。

## 通用约定

- **Base URL**：`https://auth.你的域名`（本地开发 `http://localhost:8000`）
- **认证方式**：会话 cookie（`ac_sid`，登录后由服务端下发）
- **请求体**：JSON（`Content-Type: application/json`），单请求上限 32KB
- **响应格式**：
  - 成功：`{ ok: true, ...字段 }`
  - 失败：`{ error: string }`
- **状态码**：

| 状态码 | 含义 |
|---|---|
| 200 | 成功 |
| 400 | 参数错误 / 业务拒绝（含统一文案的防枚举场景） |
| 401 | 未登录 / 会话已过期或被撤销 |
| 403 | 无权限 / 账号 pending/banned / 管理员未绑 TOTP |
| 404 | 接口不存在 |
| 429 | 限流（登录锁定 / 发码频率 / 全局限流） |
| 502 | 邮件发送失败 |
| 500 | 服务端错误 |

## 会话说明

- **认证方式**：登录成功后服务端下发 `Set-Cookie: ac_sid=<随机值>`（`HttpOnly`、`SameSite=Lax`、`Secure` 按 `COOKIE_SECURE`），浏览器后续请求自动携带
- **有效期**：`SESSION_TTL_DAYS`（默认 7 天）
- **撤销**：会话存在 `sessions` 表，改密码 / 重置密码 / 改邮箱 / 封禁 / 删号会删除该用户全部会话，**立即失效**（不再有 token 版本号机制）
- **CSRF**：写请求会校验 `Origin` / `Referer` 与 `SITE_ORIGIN` 一致，不一致返回 403；`SITE_ORIGIN` 未配置时跳过（仅限本地开发）
- **小站接入**：不再使用本站的 JWT，改走 OIDC（见 `docs/OIDC.md` 与 `docs/GUIDE.md`）

## 限流阈值（默认，.env 可调）

| 限流 | 阈值 |
|---|---|
| 登录失败锁定 | 5 次 / 15 分钟（IP+账号维度；TOTP 失败同样计入） |
| TOTP 操作锁定 | 5 次 / 15 分钟（`totp-setup/confirm/disable` 共享计数） |
| 注册验证码发送 | 3 次 / 小时 / IP（`REG_CODE_PER_HOUR`） |
| 邮箱验证码发送（改邮箱/找回密码） | 5 次 / 小时 / IP（`PROFILE_CODE_PER_HOUR`） |
| 全局限流 | 60 次 / 分钟 / IP（`GLOBAL_REQ_PER_MIN`） |

> 限流为进程内存实现，重启清零。生产通过反代（Caddy/nginx）访问，`TRUST_PROXY_CIDRS` 控制 XFF 信任。

## 调试模式

`.env` 设 `SMTP_DEBUG=true` 时（仅限本地开发）：
- 验证码邮件不真实发送，验证码打印到服务日志
- 发送验证码的接口响应额外返回 `debug_code` 字段

---

# 一、公共接口（无需登录）

## GET /api/config

站点公开配置（前端注入与注册页判断模式用）。

**响应**：

```json
{
  "flags": { "invite_required": false, "email_verify_required": true, "review_required": true },
  "redirect_origins": ["https://game1.example.com"],
  "site": {
    "site_title": "认证中心",
    "site_icon": "",
    "site_bg": "https://...",
    "site_bg_register": "https://..."
  }
}
```

- `flags`：注册三开关（管理后台热切换）
- `redirect_origins`：登录后允许回跳的完整 origin 列表（来自 `CORS_ORIGINS`，**含协议**，回跳白名单；同时也是 CSP `connect-src` 与 CORS 白名单来源）
- `site`：站点外观配置（来自 .env）

## POST /api/register

提交注册申请（实际状态流转取决于三个开关）。

**请求体**：

| 字段 | 必填 | 校验 |
|---|---|---|
| `username` | 是 | 2-20 位中文/字母/数字/下划线 |
| `email` | 是 | 标准邮箱格式；域名不得在 `BLOCKED_EMAIL_DOMAINS` |
| `password` | 是 | 8-72 位 |
| `invite_code` | 开关 `invite_required` 时 | 存在、未过期、未用尽 |
| `apply_info` | 开关 `review_required` 时 | 5-500 字；不含 `<>&"'\\` 等 HTML 特殊字符 |

**响应**：
- 需邮箱验证（`email_verify_required`）：`{ ok: true, needs_verify: true, message, debug_code? }`——验证码已发邮箱
- 免邮箱验证：`{ ok: true, status: 'active'|'pending', message }`——直接激活或进入待审

**错误**：400（格式/邀请码/重复/黑名单/申请说明）；429（发码限流）。

**未完成注册的续期**：

同一邮箱若已存在一条「`pending` 且 `email_verified=false`」的记录，再次提交不会返回「已被注册」，而是校验后重发验证码：

| 条件 | 响应 |
|---|---|
| 密码正确 + 用户名一致 | `{ ok: true, needs_verify: true, message: "检测到未完成的注册，验证码已重新发送" }`——**不新增用户、不消耗新 id** |
| 密码错误 | 400 `该邮箱有未完成的注册，请使用原密码继续` |
| 密码正确但用户名不同 | 400 `该邮箱有未完成的注册（用户名 xxx），请使用原用户名继续` |
| 该邮箱记录已 `active` / `banned` | 400 `用户名或邮箱已被注册` |

- 续期与首次注册**共用同一发码限流桶**（`REG_CODE_PER_HOUR`）
- 仅当邮箱完全一致时才走续期，用户名匹配但邮箱不同不触发

> 首个注册用户自动成为 owner（超级管理员，跳过审核）。并发注册由 advisory lock 串行化，邀请码占用为原子条件更新（防超用）。

## POST /api/verify-email

校验邮箱验证码（注册第二步）。

**请求体**：`{ email, code }`（6 位数字）

**响应**：`{ ok: true, status: 'active'|'pending', message }`

**错误**：400（验证码错误/已作废/过期/不存在）。验证码规则：10 分钟有效、一次性（原子占用，并发仅一成功）、错 5 次作废。

## POST /api/login

登录，建立服务端会话（下发 HttpOnly cookie）。

**请求体**：

| 字段 | 必填 | 说明 |
|---|---|---|
| `account` | 是 | 用户名或邮箱 |
| `password` | 是 | |
| `totp_code` | 账号已绑定 TOTP 时 | 6 位验证码 |

**成功响应**（`Set-Cookie: ac_sid=...; HttpOnly; SameSite=Lax; Max-Age=604800`）：

```json
{
  "ok": true,
  "user": { "id": 1, "username": "...", "email": "...", "role": "admin", "status": "active", "is_owner": true },
  "need_totp_setup": false
}
```

- `need_totp_setup`：管理员未绑 TOTP 时为 true（`ADMIN_TOTP_REQUIRED=true` 时），前端应引导去 `/totp`
- `ADMIN_TOTP_REQUIRED=true` 时，未绑 TOTP 的管理员登录后调用管理接口会返回 403

**错误**：
- 401 `密码或 TOTP 验证码错误`——密码错 / TOTP 错 / 未提交 TOTP 码**返回完全一致消息**（防密码 oracle）
- 403 `账号待审核` / `账号已被封禁`
- 429 登录失败锁定（5 次/15 分钟）

## POST /api/logout

销毁当前会话并清除 cookie。

**响应**：`{ ok: true }`

> 小站不再通过本站 JWT 接入，旧的 `/api/refresh` 与「SSO 回跳协议」已移除。
> 小站请使用标准 OIDC：`docs/GUIDE.md`，端点与配置见 `docs/OIDC.md`。

## POST /api/forgot-password

找回密码第一步：账号 +（已绑 TOTP 需验证）→ 发送重置验证码。

**请求体**：`{ account, totp_code? }`

**响应**（**所有分支返回同一文案**，防枚举）：`{ ok: true, message: "如果账号存在，验证码已发送到邮箱", debug_code? }`

- 账号不存在 / 非 active / 无 TOTP / 有 TOTP 未带码 / TOTP 错误 → 全部同一响应
- 限流前置：所有请求统一计数（429 行为与账号存在性解耦）

## POST /api/reset-password

找回密码第二步：验证码 + 新密码 → 重置并吊销全部会话。

**请求体**：`{ account, code, new_password }`

**响应**：`{ ok: true, message: "密码已重置，请重新登录" }`

**错误**：400（参数/密码长度/验证码错误——账号不存在与非 active 也返回验证码错误文案）；重置后 `token_version` 递增、全部 refresh 吊销。

---

# 二、登录态接口（需 `Authorization: Bearer`）

## GET /api/userinfo

当前会话对应的用户信息（依赖 `ac_sid` cookie）。

**响应**：

```json
{
  "id": 1, "username": "...", "email": "...", "role": "user",
  "totp_enabled": true, "is_owner": false
}
```

**错误**：401（未登录/过期/版本不符）；403（pending/banned）。

## GET /api/sessions

当前用户的所有有效会话（设备管理）。

**响应**：

```json
{
  "idleHours": 24,
  "ttlDays": 7,
  "sessions": [
    {
      "id": "…",
      "current": true,
      "ip": "203.0.113.9",
      "userAgent": "Mozilla/5.0 …",
      "createdAt": "…",
      "lastSeen": "…"
    }
  ]
}
```

- 只返回 `expires_at > now()` 且 `last_seen` 在空闲窗口内的会话
- `current=true` 表示就是发起请求的这一条

## POST /api/sessions/revoke-others

退出除当前设备外的所有会话。

**响应**：`{ ok: true, revoked: <数量> }`

> 只清本站的 `sessions`。小站侧的 OIDC 凭据不受影响（那是「退出登录 / 改密」的职责）。

## GET /api/authorizations

当前用户授权的 OIDC 应用（来自 `oidc_payloads` 的 `Grant`）。

**响应**：

```json
{
  "apps": [
    {
      "clientId": "music",
      "clientName": "听音室",
      "scope": "openid email profile offline_access",
      "authorizedAt": "…"
    }
  ]
}
```

- 按 `clientId` 去重，取最近一次授权
- `clientName` 来自 `OIDC_CLIENTS` 里的 `client_name` 字段，未配置时回退为 `client_id`
- OIDC 未启用时返回空数组

## POST /api/profile/username

改用户名。**请求体**：`{ username }`（2-20 位中文/字母/数字/下划线，查重）。

## POST /api/profile/password

改密码。**请求体**：`{ old_password, new_password }`（8-72 位）。
成功后：`token_version` 递增（**所有旧 access 立即失效**）、全部 refresh 吊销。

## POST /api/profile/email

改邮箱第一步：发验证码到新邮箱。**请求体**：`{ new_email }`（格式/黑名单/查重）。

## POST /api/profile/email/verify

改邮箱第二步。**请求体**：`{ new_email, code }`。
成功后：`token_version` 递增、全部 refresh 吊销。

## POST /api/profile/totp-setup

生成绑定密钥（160bit + 二维码）。**请求体**：`{ code? }`——**已绑定用户必须提交当前 TOTP 码**才能重新生成（防劫持）。

**响应**：`{ ok: true, secret, uri, qr }`（`qr` 为二维码 PNG data URL）。

**错误**：401（已绑定但验证失败，计入锁定 5 次/15 分钟）；429（锁定）。

## POST /api/profile/totp-confirm

确认绑定。**请求体**：`{ code }`。成功后 `totp_enabled = true`。
错误计数与 setup/disable **共享同一锁定**（`totp:<uid>`）。

## POST /api/profile/totp-disable

解绑（需当前验证码确认）。**请求体**：`{ code }`。
错误计数同共享锁定。

---

# 三、管理接口（需管理员 + 已绑定 TOTP）

> 权限模型：所有管理接口需 `role=admin` 且已绑定 TOTP（`ADMIN_TOTP_REQUIRED=true`）。
> 目标为**管理员或 owner** 的操作（ban/unban/unlock/edit/set-admin/reset-totp/reject）**仅 owner** 可执行，非 owner 返回 403。
> owner 不可被封禁、不可被取消管理员。

## GET /api/admin/users?status=pending|active|banned|all&q=<关键词>

用户列表（默认 pending，最多 200 条）。

| 参数 | 说明 |
|---|---|
| `status` | `pending` / `active` / `banned` / `all` |
| `q` | 可选。纯数字时按 ID 精确匹配；同时按用户名 / 邮箱模糊匹配（不区分大小写，最长 50 字） |

`q` 里的 `%` 和 `_` 已做转义，不会被当作 LIKE 通配符。

**响应**：`{ users: [{ id, username, email, status, role, is_owner, invite_code_used, apply_info, created_at, approved_at, banned_at, email_verified }] }`

## POST /api/admin/users/:id/approve

审核通过（pending → active，发通知邮件）。

## POST /api/admin/users/:id/reject

审核拒绝：**删除用户记录**（释放邮箱/用户名/邀请码），可重新注册；发通知邮件。

## POST /api/admin/users/:id/reset-totp

重置 TOTP（清空绑定，静默无通知；目标为管理员时仅 owner）。
**错误**：400（未绑定/不存在）；403（权限）。

## POST /api/admin/users/:id/ban

封禁（即时生效——access 403、refresh 拒绝、登录拒绝；发通知邮件）。
**错误**：400（封禁自己/owner）。

## POST /api/admin/users/:id/unban

解封（发通知邮件）。

## POST /api/admin/users/:id/unlock

清除登录锁定（同时清 username 与 email 两个维度）。

## POST /api/admin/users/:id/set-admin

**请求体**：`{ is_admin: boolean }`。
- `is_admin=true`（提升）→ **仅 owner**
- `is_admin=false`（降级）→ 目标为管理员时仅 owner；owner 不可降级

## POST /api/admin/users/:id/edit

编辑用户名/邮箱（查重校验）。**请求体**：`{ username?, email? }`（留空不修改）。
改邮箱时 `token_version` 递增（旧 access 立即失效）；改用户名不递增。

## POST /api/admin/config

注册模式热切换（**仅 owner**）。

**请求体**：

```json
{ "invite_required": false, "email_verify_required": true, "review_required": true }
```

## POST /api/admin/invite-codes

生成邀请码（**仅 owner**）。

**请求体**：`{ count?, max_uses?, expires_days?, note? }`
- `count`：1-100，默认 1
- `max_uses`：0 = 不限次，默认 1
- `expires_days`：正整数，留空永久
- `note`：≤100 字，不含 `<>&"'\\`

**响应**：`{ ok: true, codes: ["..."] }`

## GET /api/admin/invite-codes

邀请码列表（含使用状态）。

**响应**：`{ codes: [{ code, note, max_uses, used_count, expires_at, used_by, used_at, created_at }] }`

## POST /api/admin/invite-codes/:code/delete

删除邀请码（**仅 owner**，前端须二次确认后调用）。

- 已注册用户不受影响（`users.invite_code_used` / `invite_usage_log` 为文本记录，无外键依赖）
- 操作写入审计日志（含删除时的 `used_count` / `used_by`）

**响应**：`{ ok: true }`

**错误**：403（非 owner）；400（邀请码不存在 / 参数错误）。

---

# 注册模式与状态机

## 状态流转

```
注册提交（pending）
  → 邮箱验证（开关 email_verify_required 时；发码→校验）
  → 终态：review 开关开 → pending（等审核）
           review 开关关 → active（可直接登录）
```

## 三开关对注册流程的影响

| invite_required | email_verify_required | review_required | 流程 |
|---|---|---|---|
| 关 | 关 | 关 | 提交即 active |
| 关 | 关 | 开 | 提交即 pending |
| 关 | 开 | 关 | 发码 → 验证 → active |
| 关 | 开 | 开 | 发码 → 验证 → pending |
| 开 | 关 | 关 | 邀请码 → active |
| 开 | 关 | 开 | 邀请码 → pending |
| 开 | 开 | 关 | 邀请码 → 发码 → 验证 → active |
| 开 | 开 | 开 | 邀请码 → 发码 → 验证 → pending |

## email_verified 与两种 pending

`users.email_verified` 用于区分 pending 的两种含义：

| status | email_verified | 含义 | 清理策略 |
|---|---|---|---|
| pending | `false` | 注册卡在邮箱验证（僵尸） | 定时任务删除 24 小时前的记录 |
| pending | `true` | 邮箱环节已完成，等待人工审核 | 永久保留 |
| active | `true` | 正常账号 | — |
| banned | `true` | 封禁账号 | — |

- `email_verify_required=false` 时，注册在 INSERT 时即写入 `email_verified=true`（邮箱环节视为免检），避免被清理任务误删真·待审用户
- `verify-email` 成功、`profile/email/verify` 改邮箱成功后均置 `true`
- 历史数据在首次添加该列时回填：`active` / `banned` 一律置 `true`

## 账号状态与登录

| 状态 | 登录 | access token | refresh token |
|---|---|---|---|
| pending | 403 待审核 | 403 | 403 |
| active | 正常 | 正常 | 正常 |
| banned | 403 已封禁 | 403（即时） | 403（即时） |
