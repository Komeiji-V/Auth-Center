# 认证中心（Auth Center）

自研轻量统一身份认证服务（SSO），为多个自建小站（听音室、小游戏等）提供统一账号体系。
支持游客模式：小站未登录可直接使用基础功能，登录后解锁云端存档等高级服务。

## 功能清单

- **注册**：三个独立开关任意组合——邀请码 / 邮箱验证码 / 人工审核（含申请说明）
- **登录**：JWT（access 1h）+ Refresh Token（30 天轮换），前端静默续期，封禁即时生效
- **找回密码**：两步流程（邮箱验证码 + 新密码），已绑定 TOTP 的账号需先通过 TOTP 验证
- **TOTP 二次验证**：任意用户可绑定（160bit 密钥 + 二维码）；管理员强制；管理员可重置（静默，防劫持）
- **token 版本号**：改密码 / 重置密码 / 改邮箱（自助或管理员操作）后，**所有旧 access token 立即失效**
- **管理后台**：用户审核/封禁/解封/解锁、邀请码生成（次数/过期）、注册模式切换、编辑用户、重置 TOTP
- **权限模型**：初始用户为 owner（不可封禁/不可降级）；仅 owner 可提权管理员/管理管理员/生成邀请码/切换模式
- **个人中心**：改用户名/密码/邮箱（验证码确认）、TOTP 绑定/解绑
- **站点外观**：标题/图标/背景图（.env 配置），登录/注册页背景随机图 + 主题色自动取色
- **通知邮件**：审核通过/拒绝/封禁/解封、新用户待审提醒（SMTP）
- **安全**：scrypt 异步哈希、参数化 SQL、XSS 输入白名单 + 渲染转义、全链路限流、审计日志、定时清理

## 技术栈

Node.js 20 + Express 4 + PostgreSQL 15（限流为进程内存实现）

## 目录结构

```
auth/
├─ docker-compose.yml      # auth + demo-app + caddy 容器编排
├─ Caddyfile               # 反代配置（域名替换后自动 HTTPS）
├─ .env.example            # 全部配置项模板
├─ init.sql                # PG 一次性建库建账号脚本
├─ src/                    # 后端：server/auth/admin/db/mail/rateLimit/middleware
├─ public/                 # 前端：login/register/profile/totp/admin/forgot + site.js
└─ demo-app/               # 演示小站（小站接入范式：游客→登录→云端存档）
```

## 本地快速启动（开发）

```bash
# 1. 准备 PostgreSQL 15（本地或 Docker），执行 init.sql 建库
docker run -d --name auth-pg -e POSTGRES_PASSWORD=test123 -e POSTGRES_DB=auth_db -p 5432:5432 postgres:15

# 2. 配置环境
cp .env.example .env
#   修改 DATABASE_URL / JWT_SECRET；本地调试 SMTP_DEBUG=true（验证码在日志/响应 debug_code）

# 3. 安装依赖并启动
npm install
node src/server.js          # auth: http://localhost:8000

# 4. 演示站（可选）
cd demo-app && npm install && node server.js   # demo: http://localhost:8001
```

> 第一个注册的用户自动成为 **owner（超级管理员）**。登录后到 `/totp` 或个人中心绑定 TOTP。

---

# 部署指南（VPS）

## 一、前置准备

| 项 | 要求 |
|---|---|
| VPS | 2 核 2G 起步 |
| 系统 | Ubuntu 22.04 / Debian 12 或任意 Linux |
| 域名 | 主域名解析 `auth.你的域名` 到 VPS IP（每个小站一个子域） |
| PostgreSQL | 已有 PG 15 实例（本机或 VPS，认证服务网络连接） |
| SMTP | 任意支持 SMTP 的邮箱（QQ/163 需授权码；自建如 smtp.komeijiv.cn:587） |
| Docker | VPS 安装 Docker + Docker Compose |

## 二、VPS 初始化

```bash
# 安装 Docker（Ubuntu）
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker

# 防火墙：只开 80/443（认证服务不对外，由反代访问）
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

## 三、上传项目

```bash
# 本地打包（排除 node_modules/.env/测试残留）
git archive --format=tar.gz -o auth.tar.gz HEAD

# 上传并解压
scp auth.tar.gz root@你的VPS:/opt/
ssh root@你的VPS
mkdir -p /opt/auth && tar -xzf /opt/auth.tar.gz -C /opt/auth
cd /opt/auth
```

## 四、数据库准备（在 PG 15 上执行一次）

```bash
# 用 PG 超级用户执行（把密码改成强密码）
psql -U postgres -h 你的PG地址 -f init.sql
```

> `init.sql` 创建 `auth_db` 库 + `auth_user` 账号 + 授权。**表结构无需手动建**，认证服务首次启动自动创建。

## 五、配置 .env

```bash
cp .env.example .env
nano .env
```

| 配置项 | 填什么 |
|---|---|
| `SITE_TITLE` | 站点名（登录页标题/浏览器标题） |
| `SITE_ICON` / `SITE_BG` / `SITE_BG_REGISTER` | 图标与背景图 URL（可空；背景可填随机图 API） |
| `DATABASE_URL` | PG 连接串，如 `postgres://auth_user:密码@127.0.0.1:5432/auth_db`（不同机用内网 IP） |
| `JWT_SECRET` | **必须生成强随机值**：`openssl rand -hex 32` |
| `SMTP_DEBUG` | **生产必须 `false`** |
| `SMTP_HOST/PORT/SECURE` | 如 `smtp.komeijiv.cn / 587 / false`（587 用 STARTTLS） |
| `SMTP_USER/PASS/FROM` | SMTP 账号（建议更换授权码）与发件人 |
| `BLOCKED_EMAIL_DOMAINS` | 垃圾邮箱黑名单（可空） |
| `REG_CODE_PER_HOUR` / `PROFILE_CODE_PER_HOUR` / `GLOBAL_REQ_PER_MIN` | 限流阈值（默认 3 / 5 / 60） |
| `TRUST_PROXY_CIDRS` | 信任代理网段（默认覆盖 Docker 网段；见反代方案） |
| `CORS_ORIGINS` | **所有小站域名，登录后回跳白名单来源**，逗号分隔 |
| `ADMIN_TOTP_REQUIRED` | `true` |

**注册模式**（.env 仅决定首次启动默认值，之后管理后台可热切换）：

```
REGISTRATION_INVITE_REQUIRED=false
REGISTRATION_EMAIL_VERIFY=true
REGISTRATION_REVIEW_REQUIRED=true
```

## 六、反代方案（二选一）

### 方案 A：Caddy（推荐，docker-compose 自带，自动 HTTPS）

编辑 `Caddyfile`，替换域名：

```
auth.你的域名 {
	encode zstd gzip
	reverse_proxy auth:8000 {
		header_up X-Forwarded-For {http.vars.remote_host}
	}
}
game1.你的域名 {
	encode zstd gzip
	reverse_proxy demo-app:8001
}
```

`TRUST_PROXY_CIDRS` 保持默认即可。

### 方案 B：nginx

auth/demo 端口只绑 127.0.0.1（docker-compose 已配好）。nginx 从宿主访问容器时，默认信任列表含 loopback，无需改配置。示例：

```nginx
server {
    listen 443 ssl;
    server_name auth.你的域名;
    # ssl 配置（certbot 生成）

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;   # 覆写，防伪造混入
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

> nginx 与 auth 不在同一主机/网段时，需把 nginx 的 IP 加入 `TRUST_PROXY_CIDRS`。

## 七、启动

```bash
docker compose up -d --build
docker compose logs -f auth   # 出现 "[server] auth center listening on :8000" 即成功
```

## 八、初始化管理员（关键步骤）

1. 访问 `https://auth.你的域名/register`
2. **第一个注册的用户自动成为 owner（超级管理员）**——请用自己的邮箱注册
3. 登录后到 `/totp` 或个人中心绑定 TOTP（扫码）
4. 进 `/admin`：生成邀请码、切换注册模式（管理后台热切换）

## 九、部署后验证清单

- [ ] `https://auth.你的域名/login` 打开，背景/标题正常
- [ ] HTTPS 有效，响应头含 `Strict-Transport-Security`
- [ ] 注册测试账号 → 收到验证码邮件（SMTP 全链路）→ 审核通过 → 收到通知邮件
- [ ] 找回密码流程（含 TOTP 双因素）
- [ ] TOTP 扫码绑定 → 登录强制输码
- [ ] `CORS_ORIGINS` 内的小站能登录回跳；未配域名回跳被拒
- [ ] 非 owner 后台仅"用户管理"；owner 可生成邀请码/切换模式
- [ ] `ss -tlnp` 确认 8000/8001 只监听 127.0.0.1
- [ ] `nmap -p 8000 你的VPS` 为 filtered/closed（80/443 开放）
- [ ] 错密码 5 次锁定、连发请求 429（限流生效）
- [ ] 改密码后旧 token 立即失效（token 版本号生效）

---

# 小站接入指南

以 `demo-app/` 为完整范式。核心原则：**游客可用、点击登录才跳转认证中心、token 只存小站自己的 localStorage、401 自动回跳静默续期**。

## 一、后端接入（复制中间件）

复制 `demo-app/middleware.js` 到你的项目，配置两个环境变量：

```
JWT_SECRET=与认证中心相同
DATABASE_URL=认证中心的数据库连接串（中间件需要查 users 表校验状态）
```

**中间件完整代码**（`demo-app/middleware.js`，约 40 行）：

```js
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 5 });

function parseToken(req) {
  const h = req.headers.authorization || '';
  if (h.startsWith('Bearer ')) return h.slice(7);
  return null;
}

async function authMiddleware(req, res, next) {
  try {
    const token = parseToken(req);
    if (!token) return res.status(401).json({ error: '未登录' });
    let payload;
    try {
      payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    } catch {
      return res.status(401).json({ error: '登录已过期，请重新登录' });
    }
    const { rows } = await pool.query(
      'SELECT id, username, email, status, role, token_version FROM users WHERE id = $1',
      [payload.uid]
    );
    if (rows.length === 0) return res.status(401).json({ error: '用户不存在' });
    const u = rows[0];
    // token 版本号比对：改密/重置/改邮箱后旧 access 立即失效
    if ((payload.ver || 0) !== (u.token_version || 0)) {
      return res.status(401).json({ error: '登录已过期，请重新登录' });
    }
    if (u.status !== 'active') {
      return res.status(403).json({ error: u.status === 'banned' ? '账号已被封禁' : '账号未通过审核' });
    }
    req.user = u;
    next();
  } catch (e) {
    console.error('[auth middleware] error:', e);
    res.status(500).json({ error: '服务器内部错误' });
  }
}

module.exports = { authMiddleware, parseToken };
```

用法：

```js
const { authMiddleware } = require('./middleware');
app.get('/api/save', authMiddleware, handler);      // 需要登录的接口
```

通过后 `req.user = { id, username, email, role }`。

**其他语言**（Python/PHP/Go 等）：不需要中间件文件，用你的语言做两件事：
1. 用 `JWT_SECRET` 以 HS256 验签 JWT，读取 `payload.uid`、`payload.ver`
2. 查认证库 users 表该 uid 的 `status='active'` 且 `token_version = payload.ver`，否则拒绝

## 二、前端接入（SDK 范式）

**1. 认证中心地址**：后端提供接口（demo-app 的 `/api/auth-base`），或直接写死在页面配置。

**2. 登录回跳：URL 带 token 时收入 localStorage 并清掉 URL**

```js
const TOKEN_KEY = 'myapp_token';
(function () {
  const q = new URLSearchParams(location.search);
  const t = q.get('token');
  if (t) {
    localStorage.setItem(TOKEN_KEY, t);
    q.delete('token');
    const clean = location.pathname + (q.toString() ? '?' + q.toString() : '');
    history.replaceState(null, '', clean);   // 清掉地址栏的 token，防止被复制分享
    console.log('登录成功');
  }
})();
```

**3. API 请求封装（核心：401 自动回跳静默续期）**

```js
function apiRequest(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  const t = localStorage.getItem(TOKEN_KEY);
  if (t) headers['Authorization'] = 'Bearer ' + t;
  return fetch(path, { ...options, headers }).then(async (r) => {
    if (r.status === 401) {
      // access 过期：跳认证中心，登录页检测到 refresh token 会自动续期并回跳
      const cur = location.href.split('?')[0];
      location.href = AUTH + '/login?redirect=' + encodeURIComponent(cur);
      return { status: r.status, data: null };
    }
    const data = await r.json().catch(() => ({}));
    return { status: r.status, data };
  });
}
```

**4. 游客态与登录态**

```js
const me = await apiRequest('/api/me');     // 小站自己实现：带 token 返回用户，否则 guest
if (me.guest) {
  // 游客：正常游玩，云端功能提示"登录后可同步"
} else {
  // 已登录：解锁云端存档/同步等高级功能
}
```

**5. "登录"按钮**

```js
document.getElementById('loginBtn').addEventListener('click', () => {
  location.href = AUTH + '/login?redirect=' + encodeURIComponent(location.href);
});
```

完整可运行示例见 `demo-app/public/index.html`。

## 三、多小站管理

- **每个小站**：独立部署，复制中间件 + 前端 SDK，配置相同的 `JWT_SECRET`（也可用独立数据库？**不行**——中间件必须查认证中心的 users 表，所以 `DATABASE_URL` 指向认证库；小站自己的业务数据存自己的库）
- **认证中心侧**：把所有小站域名加入 `CORS_ORIGINS`（这是登录后回跳白名单，漏配则登录后不自动回跳）

```
CORS_ORIGINS=https://game1.你的域名,https://radio.你的域名,https://xxx.你的域名
```

- **新增小站流程**：写代码（照 demo-app 范式）→ 部署 → 认证中心 `CORS_ORIGINS` 加域名 → 重启认证中心 → 验证登录回跳

## 四、常见坑

| 坑 | 原因与解决 |
|---|---|
| 登录后停在认证中心不回跳 | 小站域名不在 `CORS_ORIGINS`（回跳白名单）；或 redirect 参数丢失 |
| 请求一直 401、跳转后仍 401 | refresh token 也被吊销（改过密码/邮箱）；或 `JWT_SECRET` 两边不一致 |
| token 在地址栏可见 | 正常现象（回跳传递），页面加载后 `history.replaceState` 清除即可 |
| 游客数据与登录数据合并 | 小站自己处理：登录成功后把 localStorage 本地数据合并上传到云端 |

---

# 后续开发指南

## 一、新增接口

1. **位置约定**：
   - 用户侧接口 → `src/auth.js`（路由前缀 `/api`）
   - 管理接口 → `src/admin.js`（路由前缀 `/api/admin`，自动带 `adminGuard` 权限 + TOTP 检查）
   - 挂载点：`src/server.js` 的 `app.use('/api', authRouter)` / `app.use('/api/admin', adminRouter)`

2. **权限约定**：
   - 需登录：`router.get('/xxx', createAuthMiddleware(process.env.JWT_SECRET, db), handler)`
   - 仅管理员：`adminGuard`（已定义）；目标为管理员/owner 时用 `canManageUser(req.user, target)` 二次校验
   - 用户数据操作前查 `req.user.id`，不信任前端传的用户 id

3. **审计与限流**：重要操作 `db.audit(...)`；限流用 `ipRateLimit` / `loginAttempt`（注意 key 命名约定：`login:ip:account`、`totp:uid`、`profile-code:ip`）

4. **错误消息**：区分账号状态的提示会构成枚举面，涉账号存在性的错误统一文案（参考 `forgot-password` 的 `GENERIC` 消息）

5. **异步**：所有 scrypt 调用已异步化；新代码不要用 `scryptSync`（同步版会阻塞事件循环）

## 二、新增页面

1. 在 `public/` 下新建 `xxx.html`，`src/server.js` 加一行路由（或自动被 `express.static` 服务）
2. 引入 `<script src="/site.js"></script>`（自动注入站点标题/图标/背景）
3. 需要主题色跟随背景的页面：复制 `login.html` 的 `adaptBgColor` 取色逻辑（变量驱动样式：`--accent`/`--card-bg`/`--site-bg`）
4. 登录态判断：参考 `profile.html` 的 `ensureToken()` 多路径逻辑（localStorage → sessionStorage → refresh 静默续期）

## 三、数据库变更

**约定：幂等升级**（新列/新表都写成可重复执行）：

```js
// 新表（CREATE TABLE IF NOT EXISTS）
await query(`CREATE TABLE IF NOT EXISTS xxx (...)`)
// 已有表加列（ADD COLUMN IF NOT EXISTS）
await query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS xxx TEXT`)
```

在 `src/db.js` 的 `initSchema()` 里追加，服务启动自动执行，无需手工迁移脚本。

## 四、配置新增

1. 新环境变量 → `.env.example` 加说明 + 默认值（注释写清用途）
2. `src/server.js` 或对应模块读取 `process.env`
3. 部署指南（README）同步更新配置表

## 五、测试约定

- **非破坏性**：测试用临时用户（用户名加时间戳后缀），测完删除；**禁止清库/动现有用户**
- **PowerShell 中文请求体**：用 UTF-8 字节发送（`[System.Text.Encoding]::UTF8.GetBytes(...)` + `charset=utf-8`）
- **TOTP 生成**：项目目录内 `node -e "const {authenticator}=require('otplib');process.stdout.write(authenticator.generate('SECRET'))"`
- **限流注意**：本地测试可用环境变量调大阈值（`REG_CODE_PER_HOUR=100` 等）或重启清内存；别在默认阈值下连发
- **PowerShell 变量名大小写不敏感**：不要用 `$fail`/`$pass` 之类可能与测试框架冲突的变量名
- 测试脚本参考：`C:\Users\KomeijiV\AppData\Local\Temp\opencode\test_fixes*.ps1` 的 `Req`/`Test` 函数写法

## 六、发布流程

```bash
# 1. 提交（前缀约定：feature/fix/security/style/docs）
git add -A && git commit -m "feature: xxx"

# 2. 本地验证
node --check src/*.js
npm audit --omit=dev
docker build -t auth-center:test .

# 3. 部署
git push   # 如有远程
docker compose up -d --build
docker compose logs -f auth

# 4. 部署后验证（README"九、部署后验证清单"逐项过）
```

---

# 备份与维护

```bash
# 数据库备份（建议 cron 每日）：
# 0 2 * * * pg_dump -U postgres auth_db | gzip > /backup/auth_$(date +%F).sql.gz

# 更新：
git pull && docker compose up -d --build

# 日志：
docker compose logs -f auth
```

# 常见问题

| 问题 | 处理 |
|---|---|
| 登录后不回跳小站 | `CORS_ORIGINS` 未包含该小站域名 |
| 收不到验证码邮件 | `docker compose logs auth` 查 SMTP 报错；确认 587 出站端口未被云厂商封 |
| 注册提示"邮箱域名不允许" | `BLOCKED_EMAIL_DOMAINS` 误配 |
| 修改站点标题/背景 | 改 `.env` → `docker compose restart auth` |
| 遗忘管理员 TOTP | owner 可在管理后台重置自己的 TOTP（登录后自助恢复）；普通用户由管理员重置 |
| 刷新后 token 失效（改过密码/邮箱） | 预期行为（token 版本号机制）：重新登录即可 |

# 安全说明

- 密码 scrypt（N=16384，异步化不阻塞事件循环）；JWT HS256 显式算法
- refresh token 哈希存储 + 轮换 + 重放检测（已吊销 token 再次使用仅拒绝，不做全家吊销防 DoS）
- **token 版本号**：改密/重置/改邮箱（自助与管理路径一致）后旧 access 立即失效
- 全链路限流（登录锁定 5 次/15 分钟、TOTP 操作共享锁定、发码 3~5 次/时、全局 60 次/分/IP），信任代理网段可配置（`TRUST_PROXY_CIDRS`）
- XSS 双防线：输入白名单（邮箱/用户名/申请说明/邀请码备注）+ 前端渲染转义
- 所有 SQL 参数化；验证码一次性（原子占用）；邀请码并发原子占用（防超用）
- 定时清理：过期验证码 / 过期 refresh token / 90 天前审计日志与邀请码使用记录
- 已知权衡：CSP `script-src 'unsafe-inline'`（页面内联脚本，XSS 已有输入白名单 + 转义双防线兜底）
