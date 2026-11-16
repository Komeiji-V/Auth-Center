# 认证中心（Auth Center）

自建的统一身份认证服务：为多个小站提供 **标准 OpenID Connect** 登录与集中式账号管理。
小站不需要共享密钥，也不需要读用户库。

## 特性

| 模块 | 能力 |
|---|---|
| **注册** | 邀请码 / 邮箱验证码 / 人工审核，三个独立开关任意组合 |
| **登录** | 服务端会话（HttpOnly cookie），空闲 24h / 最长 7 天 |
| **OIDC** | Authorization Code + PKCE、RS256、refresh token 轮换、Back-Channel Logout |
| **双因素** | TOTP，可强制管理员绑定 |
| **账号** | 改用户名 / 密码 / 邮箱、找回密码、登录设备管理、已授权应用列表 |
| **管理** | 审核、封禁、邀请码、重置 TOTP、用户搜索、注册模式热切换 |
| **权限** | owner（超级管理员）/ admin / user 三级 |

## 技术栈

Node.js 22 · Express 4 · PostgreSQL 15 · oidc-provider 9

## 快速开始

```bash
# 1. 数据库
docker run -d --name auth-pg -e POSTGRES_PASSWORD=test123 -p 5432:5432 postgres:15

# 2. 配置
cp .env.example .env
# 改 DATABASE_URL / OIDC_COOKIE_SECRET；本地可设 SMTP_DEBUG=true（生产禁止）

# 3. 签名密钥（只需一次，keys/ 已 gitignore）
npm install && node scripts/gen-keys.mjs

# 4. 启动
node src/server.js        # http://localhost:8000
```

首个注册的用户自动成为 **owner**。登录后到 `/totp` 绑定 TOTP。

> 配了 `OWNER_EMAIL` 时，首个注册必须使用该邮箱，防止部署窗口被抢注。

## 目录

```
├─ src/
│  ├─ server.js        入口：中间件顺序 / CSRF / 限流 / 定时清理
│  ├─ auth.js          注册、登录、找回密码、设备与授权列表
│  ├─ admin.js         管理接口
│  ├─ session.js       服务端会话
│  ├─ middleware.js    会话认证与权限守卫
│  ├─ db.js            schema 初始化
│  ├─ mail.js          SMTP（未配置时 fail-closed）
│  └─ oidc/            OIDC：adapter / provider / interaction / kick / cleanup（.mjs）
├─ public/             登录/注册/个人中心/TOTP/管理后台
├─ scripts/gen-keys.mjs
├─ test/               74 项自动化测试
└─ docs/
```

## 文档

| 文档 | 内容 |
|---|---|
| [docs/API.md](docs/API.md) | 接口契约（31 个接口） |
| [docs/OIDC.md](docs/OIDC.md) | OIDC 端点、配置、小站接入、撤销机制 |
| [docs/DEPLOY.md](docs/DEPLOY.md) | 部署：密钥、反代、Docker、验证清单 |
| [docs/OPS.md](docs/OPS.md) | 运维：日志、备份、故障排查、密钥轮换、多实例 |
| [docs/STATUS.md](docs/STATUS.md) | 项目实况与交接 |
| [test/README.md](test/README.md) | 测试前置条件与运行方式 |

## 安全要点

- 密码 scrypt 异步哈希 + `timingSafeEqual`；会话存服务端，改密/封禁即删
- cookie 用 `__Host-` 前缀（HTTPS），配 `SameSite=Lax` + Origin 校验防 CSRF
- OIDC 私钥文件化（`keys/`，不入库不入镜像），启动时挂载
- 全链路限流；登录锁定在 `/api/login` 与 OIDC 登录页之间共享
- 注册/审核/登录的错误消息做了防枚举；SMTP 未配置时直接报错而非降级
- 已知权衡：CSP `script-src 'unsafe-inline'`（页面内联脚本）

## 测试

```bash
npm run test:e2e       # OIDC 全链路 20 项（需 :8000 与 :8001 小站）
npm run test:patch     # 注册流程 29 项（会清空测试库）
npm run test:browser   # UI 15 项（需 CHROME_PATH）
```

详见 [test/README.md](test/README.md)。
