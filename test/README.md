# 测试

三套测试，覆盖协议、补丁与 UI。全部依赖**本地测试库**（`auth_test`），不要指向生产。

## 前置条件

```bash
# 1. 起一个独立的测试数据库（不要用生产库）
docker run -d --name oidc-test-pg \
  -e POSTGRES_PASSWORD=test123 -e POSTGRES_DB=auth_test \
  -p 5433:5432 postgres:15

# 2. .env 指向它，并打开 OIDC
DATABASE_URL=postgres://postgres:test123@127.0.0.1:5433/auth_test
OIDC_ENABLED=true
OIDC_ISSUER=http://localhost:8000
OIDC_COOKIE_SECURE=false
OIDC_DEBUG_KICK=true                 # 踢人测试需要
OIDC_CLIENTS='[{"client_id":"demo-app","client_secret":"demo-secret","redirect_uris":["http://localhost:8001/callback"],"backchannel_logout_uri":"http://localhost:8001/backchannel-logout"}]'

# 3. 生成签名密钥（首次）
node scripts/gen-keys.mjs
```

## 一、补丁回归（`test/patch/`）

注册流程的三个补丁：`email_verified`、未完成注册续期、僵尸清理。

```bash
npm start                 # 终端 1
npm run test:patch        # 终端 2（会 TRUNCATE 用户表，仅测试库可跑）
npm run test:migration    # 老表加列与回填（会重建 users 表）
```

⚠️ 这两个脚本**会清空 users 表**，只能对测试库执行。

## 二、OIDC 端到端（`test/e2e/`）

20 个用例：授权码流程、TOTP、ID Token 验签、refresh 轮换、BFF 续期、Back-Channel Logout。

需要**两个服务同时运行**：

```bash
npm start                       # 终端 1：认证中心 :8000
node test/e2e/rp.mjs            # 终端 2：演示小站 :8001（e2e 的被测对象）
npm run test:e2e                # 终端 3
```

测试账号：`oidcuser` / `Passw0rd!123`（需存在且 id 为 5140001）。
首次准备：

```bash
docker exec oidc-test-pg psql -U postgres -d auth_test -c \
  "ALTER SEQUENCE users_id_seq RESTART WITH 5140001;"
# 然后通过 /register 注册 oidcuser
```

## 三、浏览器 UI（`test/browser/`）

15 项：登录、管理后台、个人中心、刷新保持、退出、无 JS 异常。

```bash
npm start                       # 终端 1
CHROME_PATH=/path/to/chrome npm run test:browser
```

需要本地有 Chrome / Chromium。截图输出到 `test/browser/shots/`（已 gitignore）。

测试账号：`alice` / `Passw0rd!123`（管理员，`ADMIN_TOTP_REQUIRED=false`）。

## 覆盖矩阵

| 套件 | 用例 | 覆盖 |
|---|---|---|
| patch | 29 | 注册续期、email_verified、僵尸清理 |
| migration | 10 | 老表加列、回填、幂等性 |
| e2e | 20 | OIDC 全链路 |
| browser | 15 | 前端交互 |

## 已知的「预期失败」

- `401 /api/userinfo`：页面初始化时探测是否已登录，未登录必然 401，不计入错误
- `404 /favicon.ico`：未配站点图标
