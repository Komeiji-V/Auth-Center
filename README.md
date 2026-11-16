# 认证中心（Auth Center）

面向多个自建小站（听音室、小游戏等）的统一身份认证服务，提供 **标准 OpenID Connect** 与集中式账号管理。
小站无需共享密钥、无需读用户库，接入方式见 [`docs/GUIDE.md`](docs/GUIDE.md)。

## 功能

- **注册**：邀请码 / 邮箱验证码 / 人工审核 三个独立开关，任意组合
- **登录**：服务端会话（HttpOnly cookie，7 天），封禁 / 改密 / 删号即时失效
- **OIDC**：标准 OpenID Connect（Authorization Code + PKCE），多小站 SSO、Refresh Token 轮换、Back-Channel Logout
- **找回密码**：邮箱验证码 + 新密码；已绑 TOTP 的账号需先通过 TOTP 验证
- **TOTP**：任意用户可绑定（160bit + 二维码）；管理员强制；管理员可重置
- **管理后台**：审核 / 封禁 / 解封 / 解锁 / 编辑、邀请码生成（次数/过期）、注册模式切换、重置 TOTP
- **权限模型**：owner 专属（不可封禁/降级）；仅 owner 可管理管理员、生成邀请码、切换模式
- **个人中心**：改用户名 / 密码 / 邮箱（验证码确认）、TOTP 绑定 / 解绑
- **站点外观**：标题 / 图标 / 背景图（.env 配置），登录/注册页随机图背景 + 主题色自动取色
- **通知邮件**：审核 / 封禁 / 解封、新用户待审提醒（SMTP）
- **安全**：scrypt 异步哈希、参数化 SQL、XSS 白名单 + 转义、全链路限流、审计日志、定时清理、CSRF 双防线

## 技术栈

Node.js 22 + Express 4 + PostgreSQL 15 + oidc-provider 9（ESM，经 `.mjs` 与 CJS 主体共存）

## 目录结构

```
├─ docker-compose.yml   # auth + caddy 容器编排
├─ Dockerfile           # node:22-alpine，密钥运行时挂载
├─ Caddyfile            # 反代配置（域名替换后自动 HTTPS）
├─ .env.example         # 全部配置项模板
├─ src/                 # 后端：server/auth/admin/db/mail/rateLimit/middleware/session
├─ src/oidc/            # OIDC：adapter/provider/interaction/kick/cleanup（.mjs）
├─ scripts/             # gen-keys.mjs 生成签名密钥
├─ public/              # 前端：login/register/profile/totp/admin/forgot + site.js
├─ test/                # 测试：patch / e2e / browser（见 test/README.md）
└─ docs/                # 文档（见下方导航）
```

## 快速开始（本地开发）

```bash
# 1. 准备 PostgreSQL 15 空库（建库/建账号方式自选），把连接串填入 .env 的 DATABASE_URL
#    表结构无需手动建，认证服务首次启动自动创建
docker run -d --name auth-pg -e POSTGRES_PASSWORD=test123 -p 5432:5432 postgres:15

# 2. 配置环境（修改 DATABASE_URL / OIDC_COOKIE_SECRET；本地 SMTP_DEBUG=true）
cp .env.example .env

# 3. 生成 OIDC 签名密钥（只需一次，keys/ 已被 gitignore）
npm install && node scripts/gen-keys.mjs

# 4. 启动
node src/server.js     # auth: http://localhost:8000
```

> 第一个注册的用户自动成为 **owner（超级管理员）**。登录后到 `/totp` 绑定 TOTP。

### 本地跑测试

```bash
npm run test:e2e        # OIDC 全链路（需 :8000 + 小站 fixture 在 :8001）
npm run test:patch      # 注册流程回归（会清空测试库）
npm run test:browser    # 无头浏览器 UI（需 CHROME_PATH）
```

详见 [test/README.md](test/README.md)。

## 文档导航

| 文档 | 内容 |
|---|---|
| [docs/STATUS.md](docs/STATUS.md) | **项目实况与交接**：当前部署/本地环境、git 信息、演进史、已知事项、新对话入口指引 |
| [docs/DEPLOY.md](docs/DEPLOY.md) | **部署指南**：VPS 初始化、.env 配置、Caddy/nginx 反代、初始化管理员、验证清单 |
| [docs/GUIDE.md](docs/GUIDE.md) | **小站接入教程**：OIDC + BFF 完整代码 |
| [docs/OIDC.md](docs/OIDC.md) | **OIDC 说明**：端点、配置、封禁踢人机制 |
| [docs/API.md](docs/API.md) | **接口契约**：全部 28 个接口的方法/参数/响应/错误/限流，注册状态机（agent 可读） |
| [docs/OPS.md](docs/OPS.md) | **运维手册**：日志/备份恢复/升级、故障排查、会话与密钥轮换、多实例部署、速查表 |
| [test/README.md](test/README.md) | **测试**：补丁回归 / OIDC 端到端 / 浏览器 UI 的前置条件与运行方式 |

## 安全说明（摘要）

- 密码 scrypt 异步哈希；会话存服务端（HttpOnly cookie），改密 / 封禁即删
- OIDC 走 RS256，私钥文件化；cookie 认证配 Origin 校验防 CSRF
- 全链路限流（登录/TOTP 锁定、发码频率、全局 IP 限流），信任代理网段可配置
- XSS 双防线（输入白名单 + 渲染转义）；全部 SQL 参数化；验证码/邀请码原子占用
- 已知权衡：CSP `script-src 'unsafe-inline'`（页面内联脚本，其余 XSS 防线兜底）
