# 部署指南

适用于 VPS 生产部署。本地开发见根目录 `README.md` 的"本地快速启动"。

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

## 四、数据库准备

准备一个空的 PostgreSQL 15 数据库（库名、账号、权限**自行管理**，建库方式自选）。
只需满足：

- 连接串可访问（填入 `.env` 的 `DATABASE_URL`）
- 账号对该库有建表权限（服务首次启动自动创建全部表结构，无需手动执行任何 SQL）

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
| `SMTP_HOST/PORT/SECURE` | 如 `smtp.komeijiv.cn / 587 / false`（587 用 STARTTLS）。应用层强制 `requireTLS`：587 场景服务器不支持 STARTTLS 将报错不发信（绝不降级明文） |
| `SMTP_USER/PASS/FROM` | SMTP 账号（建议更换授权码）与发件人 |
| `BLOCKED_EMAIL_DOMAINS` | 垃圾邮箱黑名单（可空） |
| `REG_CODE_PER_HOUR` / `PROFILE_CODE_PER_HOUR` / `GLOBAL_REQ_PER_MIN` | 限流阈值（默认 3 / 5 / 60） |
| `TRUST_PROXY_CIDRS` | 信任代理网段（默认覆盖 Docker 网段；见反代方案） |
| `CORS_ORIGINS` | **所有小站域名，登录后回跳白名单来源**，逗号分隔；同时是 CORS 白名单与 CSP `connect-src`（登录页跨域 POST `/api/auth/sso` 依赖） |
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

    location ^~ / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;          # 覆写为真实客户端 IP（防伪造混入）
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        # 以下两行仅小站有 WebSocket 功能时才需要，认证中心本身无 WS：
        # proxy_set_header Upgrade $http_upgrade;
        # proxy_set_header Connection $http_connection;
    }
}
```

> 配置要点：
> - `X-Forwarded-For` 用 `$remote_addr` **覆写**（攻击者伪造的 XFF 被直接丢弃）；若用 `$proxy_add_x_forwarded_for`（追加）也可——认证中心取末尾值，追加后末尾是真实 IP，同样安全，但需注意不要与覆写写法同时出现（后者覆盖前者）
> - `X-Forwarded-Proto` 只需设置一次
> - nginx 与 auth 不在同一主机/网段时，需把 nginx 的 IP 加入 `TRUST_PROXY_CIDRS`

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
- [ ] SMTP 加密链路：`openssl s_client -starttls smtp -connect <smtp_host>:587` 确认服务器支持 STARTTLS（应用已强制 requireTLS，不支持则发信会报错）
- [ ] 找回密码流程（含 TOTP 双因素）
- [ ] TOTP 扫码绑定 → 登录强制输码
- [ ] `CORS_ORIGINS` 内的小站能登录回跳（小站已实现 `POST /api/auth/sso` 时：登录页跨域 POST 成功、回跳 URL **不含 token**、小站前端从 cookie 收到 token）；未配域名回跳被拒
- [ ] 登录页响应头 CSP `connect-src` 含全部白名单小站（`CORS_ORIGINS` 动态注入）
- [ ] 非 owner 后台仅"用户管理"；owner 可生成邀请码/切换模式
- [ ] `ss -tlnp` 确认 8000/8001 只监听 127.0.0.1
- [ ] `nmap -p 8000 你的VPS` 为 filtered/closed（80/443 开放）
- [ ] 错密码 5 次锁定、连发请求 429（限流生效）
- [ ] 改密码后旧 token 立即失效（token 版本号生效）

## 十、常见部署问题

| 问题 | 处理 |
|---|---|
| 登录后不回跳小站 | `CORS_ORIGINS` 未包含该小站域名 |
| 登录后提示"目标站暂不支持安全回跳" | 小站未实现 `POST /api/auth/sso`（安全降级，token 不再走 URL，需升级小站） |
| 收不到验证码邮件 | `docker compose logs auth` 查 SMTP 报错；确认 587 出站端口未被云厂商封 |
| 注册提示"邮箱域名不允许" | `BLOCKED_EMAIL_DOMAINS` 误配 |
| 修改站点标题/背景 | 改 `.env` → `docker compose restart auth` |

> 备份、升级、故障排查与安全维护详见 `docs/OPS.md`。
