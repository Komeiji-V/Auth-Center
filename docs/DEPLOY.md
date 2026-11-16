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
| `OIDC_COOKIE_SECRET` | **必须生成强随机值**：`openssl rand -hex 32`（OIDC 会话 cookie 签名） |
| `SMTP_DEBUG` | **生产必须 `false`** |
| `SMTP_HOST/PORT/SECURE` | 如 `smtp.komeijiv.cn / 587 / false`（587 用 STARTTLS）。应用层强制 `requireTLS`：587 场景服务器不支持 STARTTLS 将报错不发信（绝不降级明文） |
| `SMTP_USER/PASS/FROM` | SMTP 账号（建议更换授权码）与发件人 |
| `BLOCKED_EMAIL_DOMAINS` | 垃圾邮箱黑名单（可空） |
| `REG_CODE_PER_HOUR` / `PROFILE_CODE_PER_HOUR` / `GLOBAL_REQ_PER_MIN` | 限流阈值（默认 3 / 5 / 60） |
| `TRUST_PROXY_CIDRS` | 信任代理网段（默认覆盖 Docker 网段；见反代方案） |
| `SITE_ORIGIN` | **本站完整地址**，如 `https://auth.example.com`。用于 CSRF 的 Origin 校验，**不配会导致校验被跳过** |
| `COOKIE_SECURE` | 生产 **必须 `true`**（HTTPS 下 cookie 才加 Secure） |
| `SESSION_TTL_DAYS` | 会话有效期，默认 `7` |
| `OIDC_ENABLED` | `true` 开启 OIDC；关闭则只有会话登录，小站无法接入 |
| `OIDC_ISSUER` | **与真实访问地址完全一致**，如 `https://auth.example.com`（不一致会导致 token 校验失败） |
| `OIDC_COOKIE_SECURE` | 生产 `true` |
| `OIDC_CLIENTS` | 小站注册表（JSON 数组），见下方 |
| `OIDC_DEBUG_KICK` | 生产 **必须 `false`**（开启会暴露 `/oidc-debug/kick/:sub`） |
| `CORS_ORIGINS` | 需要跨域访问本站 API 的来源（多数情况下可留空，小站走 OIDC 不需要） |
| `ADMIN_TOTP_REQUIRED` | `true`（管理员必须绑 TOTP 才能用管理接口） |

**小站注册表**（每个小站一个 client，不要共用）：

```bash
OIDC_CLIENTS='[{"client_id":"music","client_secret":"openssl rand -hex 32","redirect_uris":["https://music.example.com/auth/callback"],"backchannel_logout_uri":"https://music.example.com/auth/backchannel-logout"}]'
```

> `redirect_uris` 必须精确匹配，不支持通配符。注意 Docker 的 `--env-file` / compose `env_file`
> **不会去掉外层引号**（dotenv 会），代码已兼容两种方式，但建议保持单引号包裹。

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
	# 小站独立部署，接入方式见 docs/GUIDE.md
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

## 六点五、生成签名密钥（OIDC 必需）

OIDC 用 RS256 签名，私钥**不能打进镜像**，运行时挂载。

```bash
mkdir -p keys
docker compose run --rm auth node scripts/gen-keys.mjs
```

输出会打印 `kid`。`keys/` 已在 `.gitignore` 和 `.dockerignore` 中忽略。

> 多实例部署时多个容器共用同一份密钥；**不要**各自生成，否则互相验签失败。

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
- [ ] 非 owner 后台仅"用户管理"；owner 可生成邀请码/切换模式
- [ ] `ss -tlnp` 确认 8000 只监听 127.0.0.1
- [ ] `nmap -p 8000 你的VPS` 为 filtered/closed（80/443 开放）
- [ ] 错密码 5 次锁定、连发请求 429（限流生效）
- [ ] 改密码后**所有设备会话立即失效**（服务端会话删除）

**OIDC 相关**：

- [ ] `curl https://auth.你的域名/.well-known/openid-configuration` 的 `issuer` 与 `OIDC_ISSUER` 完全一致
- [ ] `curl https://auth.你的域名/jwks` 返回 `kid` 与生成时一致
- [ ] 小站登录走通：授权码 → token → ID Token 的 `sub` 为 7 位数字
- [ ] 管理后台封禁该用户 → 小站会话**立即失效**
- [ ] `COOKIE_SECURE=true` 时响应头 `Set-Cookie` 含 `Secure; HttpOnly; SameSite=Lax`
- [ ] 跨站 POST 被拒（CSRF Origin 校验生效）：从其他域提交登录请求返回 403

## 十、常见部署问题

| 问题 | 处理 |
|---|---|
| 小站报 `issuer mismatch` | `OIDC_ISSUER` 与实际访问地址不一致（含协议、端口） |
| 小站报 `invalid_client` | `OIDC_CLIENTS` 里没有该 client，或 secret 不一致 |
| 小站报 `redirect_uri_mismatch` | `redirect_uris` 必须与请求里的完全一致（含结尾斜杠） |
| 登录成功但小站拿不到 refresh token | 请求未带 `scope=offline_access` 或 `prompt=consent` |
| 封禁后小站仍能访问 | 小站未实现 `/backchannel-logout`；最坏等 access token 过期（15 分钟） |
| 所有 POST 返回 403 | `SITE_ORIGIN` 配错（与实际访问的 origin 不一致） |
| 容器启动报 `OIDC_CLIENTS 不是合法 JSON` | 环境变量引号问题，见第二节说明 |
| 收不到验证码邮件 | `docker compose logs auth` 查 SMTP 报错；确认 587 出站端口未被云厂商封 |
| 注册提示"邮箱域名不允许" | `BLOCKED_EMAIL_DOMAINS` 误配 |
| 修改站点标题/背景 | 改 `.env` → `docker compose restart auth` |

> 备份、升级、故障排查与安全维护详见 `docs/OPS.md`。
