# 部署

## 前置

- 一台有公网 IP 的 Linux（Docker + Docker Compose）
- 一个解析到该 IP 的域名（HTTPS 由 Caddy 自动签发）
- Node.js **22+**（`oidc-provider` v9 的硬要求；用 Docker 则无需在宿主装）

## 1. 生成签名密钥

OIDC 用 RS256，私钥**不能进镜像**，运行时挂载。

```bash
mkdir -p keys
docker compose run --rm auth node scripts/gen-keys.mjs   # 会打印 kid
```

- `keys/` 已加入 `.gitignore` 与 `.dockerignore`
- 多实例必须共用同一份，各自生成会导致互相验签失败
- 轮换：把新 key 追加进 `keys/jwks.json` 的 `keys` 数组 → 重启 → 等旧 token 过期后再移除旧 key

## 2. 配置 `.env`

```bash
cp .env.example .env
```

必改项：

| 变量 | 说明 |
|---|---|
| `NODE_ENV` | **必须 `production`**（Dockerfile 已设；非 Docker 部署如 systemd/pm2 必须自己加） |
| `DATABASE_URL` | PostgreSQL 15 连接串（首次启动自动建表） |
| `SITE_ORIGIN` | **本站完整地址**，如 `https://auth.example.com`；用于 CSRF，缺失会打印 `[security]` 警告 |
| `COOKIE_SECURE` | 生产 `true` |
| `SMTP_DEBUG` | 生产 `false`（设为 true 会把验证码回显在响应里） |
| `SMTP_HOST/PORT/USER/PASS/FROM` | 587 用 STARTTLS，465 用隐式 TLS |
| `OIDC_ENABLED` | `true` |
| `OIDC_ISSUER` | 与真实访问地址**完全一致** |
| `OIDC_COOKIE_SECRET` | `openssl rand -hex 32` |
| `OIDC_COOKIE_SECURE` | 生产 `true` |
| `OIDC_CLIENTS` | 小站注册表（JSON 数组，见 `docs/OIDC.md`） |
| `OIDC_DEBUG_KICK` | 生产 `false`（开启会暴露 `/oidc-debug/kick/:sub`） |
| `ADMIN_TOTP_REQUIRED` | 建议 `true` |
| `SESSION_TTL_DAYS` / `SESSION_IDLE_HOURS` | 7 / 24 |

可选：`OWNER_EMAIL`（限制首个 owner 的邮箱，防部署窗口被抢注）、`BLOCKED_EMAIL_DOMAINS`、限流阈值。

## 3. 反代

Caddy 已在 `docker-compose.yml` 里，改 `Caddyfile` 的域名即可：

```
auth.example.com {
	encode zstd gzip
	reverse_proxy auth:8000 {
		header_up X-Forwarded-For {http.vars.remote_host}
	}
}
```

用 nginx 时，除常规反代外必须设：

```nginx
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
```

并把 nginx 所在网段加进 `TRUST_PROXY_CIDRS`，否则真实 IP 取不到（限流会把所有人算成一个 IP）。

## 4. 启动

```bash
docker compose up -d --build
docker compose logs -f auth
```

看到 `[server] auth center listening on :8000` 即成功。

## 5. 初始化管理员

1. 打开 `https://auth.你的域名/register`
2. **第一个注册的用户自动成为 owner**（跳过审核）
3. 登录后到 `/totp` 绑定 TOTP
4. 进 `/admin` 生成邀请码、切换注册模式

> 若配了 `OWNER_EMAIL`，首个注册必须用该邮箱。

## 6. 验证清单

**基础**

- [ ] `/login` 正常打开，HTTPS 有效，响应头含 `Strict-Transport-Security`
- [ ] 注册 → 收到验证码邮件 → 审核通过 → 收到通知邮件
- [ ] `SMTP_DEBUG=false`（日志里不应出现 `[mail:debug]`）
- [ ] 找回密码（含 TOTP 双因素）全流程
- [ ] TOTP 扫码绑定 → 登录强制输码
- [ ] `ss -tlnp` 确认 8000 只监听 `127.0.0.1`
- [ ] 错密码 5 次锁定、连发请求 429

**OIDC**

- [ ] `curl https://auth.你的域名/.well-known/openid-configuration` 的 `issuer` 与 `OIDC_ISSUER` 一致
- [ ] `/jwks` 的 `kid` 与生成时一致
- [ ] 小站登录走通，ID Token 的 `sub` 为 7 位数字
- [ ] 管理员封禁该用户 → 小站会话**立即失效**
- [ ] `Set-Cookie` 含 `__Host-` 前缀、`Secure`、`HttpOnly`、`SameSite=Lax`
- [ ] 从其他域 POST 本 API 返回 403（CSRF 生效）

**会话**

- [ ] 个人中心「登录设备」能看到多个设备
- [ ] 「退出其他设备」后，被退出的浏览器立即 401
- [ ] 刷新页面保持登录

## 7. 常见问题

| 现象 | 原因 |
|---|---|
| 所有 POST 返回 403 | `SITE_ORIGIN` 与实际访问地址不一致 |
| 小站报 `issuer mismatch` | `OIDC_ISSUER` 与实际地址不一致（含协议/端口） |
| 小站报 `invalid_client` | `OIDC_CLIENTS` 里没有该 client 或 secret 不一致 |
| 小站报 `redirect_uri_mismatch` | `redirect_uris` 必须与请求完全一致（含结尾斜杠） |
| 小站拿不到 refresh token | 请求缺 `scope=offline_access` 或 `prompt=consent` |
| 封禁后小站仍能访问 | 小站未实现 `/backchannel-logout`；最坏等 access token 过期（15 分钟） |
| 容器报 `OIDC_CLIENTS 不是合法 JSON` | Docker 的 `env_file` 不去引号（dotenv 会），代码已兼容，检查是否有多余字符 |
| 启动报 `EACCES` 读写文件 | 非 root 运行（`USER node`），宿主文件权限需对 uid 1000 可读 |
| 登录后回不到原页面 | `redirect` 只接受本站路径（`//evil.com` 会被拒绝） |

备份、升级、密钥轮换见 `docs/OPS.md`。
