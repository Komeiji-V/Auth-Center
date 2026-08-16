# 认证中心（Auth Center）

自研轻量统一身份认证服务（SSO），为多个自建小站（听音室、小游戏等）提供统一账号体系。
支持游客模式：小站未登录可直接使用基础功能，登录后解锁云端存档等高级服务。

## 功能清单

- **注册**：三个独立开关任意组合——邀请码 / 邮箱验证码 / 人工审核（含申请说明）
- **登录**：JWT（access 1h）+ Refresh Token（30 天轮换），前端静默续期，封禁即时生效
- **找回密码**：两步流程（邮箱验证码 + 新密码），已绑定 TOTP 的账号需先通过 TOTP 验证
- **TOTP 二次验证**：任意用户可绑定（160bit 密钥 + 二维码）；管理员强制；管理员可重置（静默，防劫持）
- **管理后台**：用户审核/封禁/解封/解锁、邀请码生成（次数/过期）、注册模式切换、编辑用户
- **权限模型**：初始用户为 owner（不可封禁/不可降级）；仅 owner 可提权管理员/管理管理员/生成邀请码/切换模式
- **个人中心**：改用户名/密码/邮箱（验证码确认）、TOTP 绑定/解绑
- **站点外观**：标题/图标/背景图（.env 配置），登录/注册页背景随机图 + 主题色自动取色
- **通知邮件**：审核通过/拒绝/封禁/解封、新用户待审提醒（SMTP）
- **安全**：scrypt 密码哈希、参数化 SQL、XSS 输入白名单 + 渲染转义、全链路限流、审计日志、定时清理

## 技术栈

Node.js 20 + Express 4 + PostgreSQL 15 + Redis 无（限流为内存实现）

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

## 十、小站接入指南（以 demo-app 为范式）

1. 复制 `demo-app/middleware.js` 到你的小站，配置相同的 `JWT_SECRET` 与 `DATABASE_URL`
2. 前端：未登录显示游客态；点"登录"跳 `https://auth.你的域名/login?redirect=当前页URL`
3. 登录成功自动回跳并携带 `token` 参数 → 小站存入 localStorage → 清除 URL 参数
4. 请求携带 `Authorization: Bearer <token>`；收到 401 → 跳回登录页（登录页检测到 refresh token 会自动静默续期并回跳）
5. 小站域名必须加入认证中心的 `CORS_ORIGINS`（回跳白名单）

## 十一、备份与维护

```bash
# 数据库备份（建议 cron 每日）：
# 0 2 * * * pg_dump -U postgres auth_db | gzip > /backup/auth_$(date +%F).sql.gz

# 更新：
git pull && docker compose up -d --build

# 日志：
docker compose logs -f auth
```

## 十二、常见问题

| 问题 | 处理 |
|---|---|
| 登录后不回跳小站 | `CORS_ORIGINS` 未包含该小站域名 |
| 收不到验证码邮件 | `docker compose logs auth` 查 SMTP 报错；确认 587 出站端口未被云厂商封 |
| 注册提示"邮箱域名不允许" | `BLOCKED_EMAIL_DOMAINS` 误配 |
| 修改站点标题/背景 | 改 `.env` → `docker compose restart auth` |
| 遗忘管理员 TOTP | owner 可在管理后台重置自己的 TOTP（登录后自助恢复）；普通用户由管理员重置 |

## 安全说明

- 密码 scrypt（N=16384）哈希；JWT HS256 显式算法；refresh token 哈希存储 + 轮换
- 全链路限流（登录锁定 5 次/15 分钟、发码 3~5 次/时、全局 60 次/分/IP），信任代理网段可配置
- XSS 双防线：输入白名单（邮箱/用户名/申请说明）+ 前端渲染转义
- 所有 SQL 参数化；验证码一次性（原子占用）；定时清理过期数据与审计日志
- 已知权衡：CSP `script-src 'unsafe-inline'`（页面内联脚本，XSS 已有其他防线兜底）
