# 运维

## 日志

```bash
docker compose logs -f auth          # 实时
docker compose logs auth --tail 200  # 最近 200 行
```

关注：

| 关键字 | 含义 |
|---|---|
| `[server] auth center listening` | 启动成功 |
| `[security] SITE_ORIGIN 未配置` | CSRF 校验被关闭，生产必须修 |
| `[oidc kick]` / `[oidc revoke]` | 撤销通知 |
| `[oidc retry]` | back-channel 重试 |
| `[cleanup]` | 定时清理 |
| `[mail:debug]` | **生产不该出现**（说明 SMTP_DEBUG 开着或 SMTP 未配置） |

## 备份与恢复

```bash
# 备份（建议 cron 每日）
pg_dump -U postgres auth_db | gzip > /backup/auth_$(date +%F).sql.gz

# 恢复
gunzip -c /backup/auth_YYYY-MM-DD.sql.gz | psql -U postgres auth_db
```

`keys/jwks.json` 也要备份：丢了会导致所有已签发的 token 无法验签（用户需重新登录，小站需重新拉 JWKS）。

## 升级

```bash
git pull
docker compose up -d --build
docker compose logs -f auth
```

升级前先备份。数据库结构由 `initSchema()` 自动迁移（幂等，只加不删）。

## 故障排查

### 收不到验证码邮件

1. `docker compose logs auth` 查 SMTP 报错
2. 确认 `SMTP_DEBUG=false`
3. `nc -vz smtp.你的域名 587` 测出站连通性（云厂商常封 25，587 一般可用）
4. 检查 `SMTP_FROM` 域名的 SPF/DKIM

> SMTP 未配置时接口会返回 **502**（fail-closed），不会降级成「验证码回显」。

### 用户被锁定

`尝试次数过多，请 XXX 秒后再试`。管理后台用户行的「解锁」按钮，或等 15 分钟。

锁定是进程内存实现，**重启即全部清除**。

> `/api/login` 与 OIDC 登录页共享同一套计数，不能靠切换入口绕过。

### 会话反复失效

1. 用户近期改过密码 / 邮箱 / 被重置 —— 预期行为（全部会话已删）
2. `SITE_ORIGIN` 配错导致写请求 403
3. 闲置超过 `SESSION_IDLE_HOURS`（默认 24h）
4. OIDC 场景报 `issuer mismatch` —— `OIDC_ISSUER` 与实际地址不一致

### 数据库连接失败

`ECONNREFUSED` / `[db] idle client error`：检查 PG 是否运行、`DATABASE_URL`、`pg_hba.conf`、防火墙。

## 安全维护

### 强制所有人重新登录

```sql
DELETE FROM sessions;
```

### 只让某个用户下线

```sql
DELETE FROM sessions WHERE user_id = <id>;
```

> 这只会清本站会话。要连小站一起踢，用管理后台的「封禁 → 解封」，或改该用户密码。

### 轮换 OIDC 签名密钥

1. 生成新 key，追加进 `keys/jwks.json` 的 `keys` 数组（旧 key 保留）
2. 重启服务（新旧并存，验签不受影响）
3. 等最长 token 寿命过去（refresh 14 天）后移除旧 key

> 改 `OIDC_COOKIE_SECRET` 会让所有 OIDC 会话 cookie 失效，小站用户需重新授权。

### 依赖更新

```bash
npm audit --omit=dev
npm outdated
```

## 数据管理

### 审计日志

```sql
SELECT * FROM audit_log ORDER BY id DESC LIMIT 50;
SELECT * FROM audit_log WHERE actor = 'xxx' ORDER BY id DESC;
SELECT ip, COUNT(*) FROM audit_log WHERE action = 'login_fail' GROUP BY ip ORDER BY 2 DESC;
```

### 定时清理（每日，多实例下带 advisory lock 只跑一次）

- 过期验证码（1 天前）
- 过期会话（1 天前）
- 24 小时仍未验证邮箱的 pending 用户
- 90 天前审计日志与邀请码使用记录

OIDC 的过期记录由 `src/oidc/cleanup.mjs` 每小时清理。

### 会话卫生

| 配置 | 作用 |
|---|---|
| `SESSION_TTL_DAYS`（7） | 绝对上限 |
| `SESSION_IDLE_HOURS`（24） | 闲置超时，`last_seen` 超过即失效 |

`last_seen` 在请求命中会话时推进（60 秒内不重复写库）。用户在个人中心可查看设备列表并「退出其他设备」。

### 手动治理

```sql
-- 删除测试用户（先备份）
DELETE FROM users WHERE username LIKE 'test%';
-- 清理过期 OIDC 记录
DELETE FROM oidc_payloads WHERE expires_at IS NOT NULL AND expires_at < now();
```

## 多实例

个人项目单实例足够。多副本时：

| 项 | 说明 |
|---|---|
| 会话 / OIDC 状态 | 都在 PG，天然共享，**不需要 sticky session** |
| 签名密钥 | 必须共用同一份 `keys/jwks.json` |
| 清理任务 | 已加 advisory lock，只跑一次 |
| 限流计数 | 进程内存，总阈值 = 配置 × 实例数（记得按比例调小） |
| back-channel 重试 | 可能重复推送，幂等无副作用 |

## 速查命令

```bash
# 登录（拿 cookie）
curl -c jar -X POST https://auth.你的域名/api/login \
  -H 'Content-Type: application/json' \
  -d '{"account":"admin1","password":"***","totp_code":"***"}'

# 解锁用户 / 重置 TOTP
curl -b jar -X POST https://auth.你的域名/api/admin/users/<id>/unlock
curl -b jar -X POST https://auth.你的域名/api/admin/users/<id>/reset-totp

# 切换注册模式（仅 owner）
curl -b jar -X POST https://auth.你的域名/api/admin/config \
  -H 'Content-Type: application/json' \
  -d '{"invite_required":true,"email_verify_required":true,"review_required":true}'

# 生成邀请码
curl -b jar -X POST https://auth.你的域名/api/admin/invite-codes \
  -H 'Content-Type: application/json' \
  -d '{"count":5,"max_uses":1,"expires_days":7,"note":"朋友"}'
```
