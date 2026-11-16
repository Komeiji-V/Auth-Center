# 项目状态与交接文档

本文件记录认证中心（Auth Center）的**当前实况**，供开发者/新对话接手时快速对齐。
接口契约见 `docs/API.md`，运维见 `docs/OPS.md`，部署见 `docs/DEPLOY.md`，接入与开发见 `docs/GUIDE.md`。

> 本仓库为公开仓库：**不包含任何敏感信息**（数据库密码、JWT 密钥、TOTP 密钥、SMTP 凭据等均不在仓库内）。

## 一、当前部署实况

| 项 | 状态 |
|---|---|
| 生产域名 | `auth.komeijiv.cn`（HTTPS 已生效） |
| 反代 | openresty（nginx 系），非 Caddy |
| 已接入小站 | `music.komeijiv.cn`（登录回跳已配置） |
| 注册开关（config 表为准） | 邀请码=关 / 邮箱验证=开 / 人工审核=开 |
| 回跳白名单 | `CORS_ORIGINS` 仅含 music 域名（新增小站需扩充） |
| 端口暴露 | 8000/8001/5432 外部均不可达（已核验） |
| 已知配置事项 | HSTS 由应用层与反代层双设（值一致，已决定保留不处理） |

## 二、本地开发环境

| 项 | 状态 |
|---|---|
| 本地服务 | auth=8000（本地调试 SMTP_DEBUG=true，验证码在日志/响应 debug_code） |
| 数据库 | Docker 容器 test-pg（postgres:15，端口 5433，库 auth_db） |
| 测试账号 | 见本地数据库（admin1=owner 等）；密码/TOTP 密钥不记录于仓库，按需从本地数据库读取或重新绑定 |

> 测试脚本存本地（不进仓库），参考 `C:\Users\KomeijiV\AppData\Local\Temp\opencode\test_*.ps1` 的 `Req`/`Test` 写法，原则见 `docs/OPS.md`"测试约定"。

## 三、Git 信息

- 远程：`https://github.com/Komeiji-V/Auth-Center.git`
- 分支：`main`（直接推送，无 PR 流程）
- 提交规范：`feature:` / `fix:` / `security:` / `style:` / `docs:` 前缀
- 数据库连接、环境变量等 `.env` 已被 gitignore，部署时按 `.env.example` 配置

## 四、关键设计决策与演进史

- **服务端会话**（`sessions` 表）：浏览器只持 HttpOnly cookie；改密码/重置密码/改邮箱/封禁/删号都会删除该用户全部会话，立即失效（取代了原 JWT + token_version + refresh_tokens 方案）
- **scrypt 异步化**：`hashPassword`/`verifyPassword` 使用 `crypto.scrypt` 异步版（消除事件循环阻塞，30 并发登录实测 ~123ms）
- **限流体系**：登录锁定（5 次/15 分钟，密码与 TOTP 错误共享计数）、TOTP 操作锁定（setup/confirm/disable 共享 `totp:<uid>`）、发码频率（3~5 次/时/IP）、全局 60 次/分/IP；限流为进程内存实现，重启清零
- **信任代理**：`TRUST_PROXY_CIDRS` 可配置（默认 loopback + Docker 网段），反代须覆写/追加 XFF（openresty 配置已按此部署）
- **注册状态机**：三开关（邀请码/邮箱验证/人工审核）任意组合；首个注册用户自动成为 owner（跳过审核）
- **安全演进**（三轮独立审查累计修复 27+ 项）：XFF 伪造、邀请码并发超用、TOTP 覆写/爆破、找回密码枚举、密码 oracle（统一错误消息）、验证码原子占用、限流内存膨胀等均已修复并复测
- **安全演进（M1，已被 OIDC 取代）**：access token 不再经 URL query 回跳小站（浏览器历史/两端 access log 会留存明文 token）——改为登录页跨域 POST 到小站 `/api/auth/sso`，小站验签后以短时 cookie 交还前端；认证中心 CSP `connect-src` 随 `CORS_ORIGINS` 白名单动态放行（解析经 URL 规范化+格式校验，防指令注入）；sso 端点双重 CSRF 防护（Origin/Referer 白名单 + 自定义头强制 preflight）；旧小站未升级时安全降级（提示且不跳转，绝不回退 URL 带 token）。详见 `docs/API.md`「小站安全回跳协议（SSO）」与 `docs/REPORT-M1-sso-token-redirect.md`
- **SMTP 强制 STARTTLS**：`mail.js` 启用 nodemailer `requireTLS`——587（secure=false）场景服务器必须支持 STARTTLS，否则报错不发信，杜绝"服务器不通告 STARTTLS 就静默降级明文"（STARTTLS 剥离攻击面）；465（secure=true）隐式 TLS 不受影响

## 五、已知事项与待办

- [ ] **人工审核当前为开启状态**——如需关闭，用管理后台"注册模式"或 `POST /api/admin/config`（.env 不生效，以 config 表为准）
- [ ] **回跳白名单扩容**：新增小站时更新 `CORS_ORIGINS`（登录后回跳依赖）
- [ ] **SMTP 授权码定期更换**（曾出现在对话记录中）
- [ ] HSTS 双设（应用层+反代层）：已决定保留，值一致无害
- [ ] 部署后的浏览器人工验收清单未全部执行（注册邮件全链路已由 owner 实测通过）

## 六、给新对话/新开发者的入口指引

1. **先读**：`README.md`（概览）→ 本文件（实况）→ 任务相关文档
2. **写代码前**：先读 `src/` 对应文件——文档可能滞后于代码，以代码为准
3. **接口**：以 `docs/API.md` + `src/auth.js`/`src/admin.js` 路由为准
4. **测试前**：读 `docs/OPS.md`"测试约定"（非破坏性、临时用户、限流注意）
5. **不要**：清库、修改现有生产数据、把 `.env`/密钥/测试脚本推入仓库
6. **验证**：部署相关改动后按 `docs/DEPLOY.md`"部署后验证清单"抽查
