# 运维维护手册

日常运维、故障排查、安全维护与数据管理。接口细节见 `docs/API.md`。

## 一、日常运维

### 日志

```bash
docker compose logs -f auth        # 实时跟踪
docker compose logs auth --tail 100  # 最近 100 行
```

关注点：
- 启动成功标志：`[server] auth center listening on :8000`
- `[mail:debug]`：SMTP_DEBUG 模式下的验证码输出（生产应无）
- `[cleanup]`：每日清理任务结果
- `[db]` / `[server] unhandled error`：异常

### 备份

```bash
# 建议 cron 每日：
# 0 2 * * * pg_dump -U postgres auth_db | gzip > /backup/auth_$(date +%F).sql.gz
```

### 恢复

```bash
gunzip -c /backup/auth_YYYY-MM-DD.sql.gz | psql -U postgres auth_db
```

### 升级

```bash
git pull
docker compose up -d --build
docker compose logs -f auth   # 确认正常后按部署验证清单抽查
```

升级前建议先备份数据库。

## 二、故障排查

### 收不到验证码邮件

1. `docker compose logs auth` 查 SMTP 报错（认证失败/连接超时/550 拒收）
2. 确认 `SMTP_DEBUG=false`（调试模式不发真实邮件）
3. 服务器出站连通性：`nc -vz smtp.你的域名 587`；云厂商可能封 25，587 一般可用
4. 邮箱进垃圾箱；`SMTP_FROM` 域名 SPF/DKIM 建议配置

### 用户登录被锁定

- 现象：`尝试次数过多，请 XXX 秒后再试`
- 处理：管理后台用户行"解锁"按钮（同时清 username/email 两维度）；或等 15 分钟自动解除
- 说明：锁定是进程内存实现，重启服务即全部清除

### token 反复失效（401 登录已过期）

可能原因：
1. 用户最近改过密码/邮箱/被重置密码（token 版本号机制）——预期行为，重新登录
2. `JWT_SECRET` 与小站不一致——两边统一
3. access 过期但 refresh 也被吊销（改密）——需重新登录（无法静默续期）

### 限流误触发

- 现象：正常操作被 429
- 检查：`GLOBAL_REQ_PER_MIN`（默认 60/分/IP）是否过小；抓包工具/脚本在短时间内发起大量请求
- 调整：改 `.env` → `docker compose restart auth`

### 数据库连接失败

- `[db] idle client error` / `ECONNREFUSED`
- 检查：PG 是否运行、`DATABASE_URL` 正确性、PG 的 `pg_hba.conf` 是否允许来源 IP、防火墙 5432

## 三、安全维护

### JWT_SECRET 轮换（全端登出）

```bash
# 1. 生成新密钥
openssl rand -hex 32

# 2. 改 .env 的 JWT_SECRET

# 3. 吊销全部 refresh token（防止旧 refresh 换新 access）
docker exec <pg容器> psql -U postgres -d auth_db -c "UPDATE refresh_tokens SET revoked = TRUE;"

# 4. 重启（token_version 不变，仅 access 需等过期；如需立即全端登出，可全局 +1：
#    UPDATE users SET token_version = token_version + 1;）
docker compose restart auth
```

> 注意：改 JWT_SECRET 后，**所有小站必须同步更新**（它们校验 access 用同一密钥）。

### SMTP 授权码更换

改 `.env` 的 `SMTP_PASS` → `docker compose restart auth`。建议定期更换（授权码曾出现在聊天/日志中）。

### 依赖更新

```bash
cd /opt/auth
npm audit --omit=dev
npm outdated
# 升级：改 package.json 后
docker compose up -d --build
```

### 信任代理网段调整

nginx 与 auth 不在同一主机/网段时，把 nginx IP 加入 `TRUST_PROXY_CIDRS`：

```
TRUST_PROXY_CIDRS=loopback,172.16.0.0/12,10.0.0.0/8,你的nginxIP
```

> 错误配置影响：网段外的 XFF 被忽略 → 所有用户显示为代理 IP → 限流按单 IP 聚合（互相耗尽）。

## 四、数据管理

### 审计日志

```sql
-- 最近 50 条操作
SELECT * FROM audit_log ORDER BY id DESC LIMIT 50;
-- 某用户所有操作
SELECT * FROM audit_log WHERE actor = 'xxx' ORDER BY id DESC;
-- 登录失败统计
SELECT ip, COUNT(*) FROM audit_log WHERE action = 'login_fail' GROUP BY ip ORDER BY COUNT(*) DESC;
```

### 定时清理（自动）

每日自动执行（服务启动后 24h 间隔）：
- 过期验证码（1 天前）
- 所有过期 refresh token（1 天前，含未吊销）
- **24 小时仍未完成邮箱验证的 pending 用户**（`email_verified = FALSE`；已通过邮箱验证、等待人工审核的用户不受影响）
- 90 天前审计日志
- 90 天前邀请码使用记录

### 用户 id 分配与释放规则

`users.id` 由 PostgreSQL 序列 `users_id_seq` 分配。理解以下三点可避免误操作。

**增加 id 的唯一入口**

只有 `POST /api/register` 执行到 `INSERT INTO users` 时才会消耗一个 id。以下情况**都会**消耗，即使记录最终不存在：

| 场景 | 记录去向 | id 回收 |
|---|---|---|
| 注册成功（active / pending） | 保留 | 否 |
| 邀请码并发超用（事务回滚） | 不存在 | 否 |
| 发邮件失败（提交后删除） | 不存在 | 否 |
| 用户长期不验证邮箱（被清理任务删） | 不存在 | 否 |
| 管理员审核拒绝（删除记录） | 不存在 | 否 |

**不消耗 id 的操作**

登录、刷新 token、改密码 / 邮箱、TOTP 操作、封禁 / 解封、审核通过、生成邀请码，以及注册查重命中后的「续期重发验证码」——均不产生新用户。

**id 永不释放**

- `DELETE` 只删行，序列不动
- 事务 `ROLLBACK` 不退号（`nextval` 非事务性）
- `TRUNCATE` 默认不重置序列

实测行为：

```text
① 连续注册 3 人       → 1,2,3
② 删除 id=2 后再注册  → 4（不是 2）
③ 事务回滚后再注册    → 6（5 被消耗）
④ TRUNCATE 后再注册   → 7（序列未重置）
```

**唯一的重置方式**

```sql
ALTER SEQUENCE users_id_seq RESTART WITH 5140001;   -- 切换 id 起点（一次性）
TRUNCATE users RESTART IDENTITY;                     -- ⚠️ 见下方警告
```

> ⚠️ **生产环境禁止 `TRUNCATE users RESTART IDENTITY`**。
> id 一旦被复用，`sub` 会跟着复用（`sub = String(id)`），小站按 `sub` 存的用户数据会串号——新用户可能直接看到旧用户的数据。
> 日常清理一律用 `DELETE`，绝不加 `RESTART IDENTITY`。

**序列表不保证严格连续**

数据库崩溃恢复、`setval`、极高并发都可能跳号。`id` 仅作标识，不要假设连续。

### 邀请码使用记录

```sql
SELECT * FROM invite_usage_log WHERE code = 'XXXX' ORDER BY id;
```

### 手动治理

- 清理已吊销的 refresh：`DELETE FROM refresh_tokens WHERE revoked = TRUE AND expires_at < now();`
- 删除测试用户：`DELETE FROM users WHERE username LIKE 'test%';`（谨慎，先备份）

## 五、速查表（API 方式运维）

以下操作均可用 curl 完成（管理员需 TOTP，先登录拿 token）：

```bash
# 登录（owner，带 TOTP）
curl -X POST https://auth.你的域名/api/login \
  -H 'Content-Type: application/json' \
  -d '{"account":"admin1","password":"***","totp_code":"***"}'
# → 取 token

# 解锁用户
curl -X POST https://auth.你的域名/api/admin/users/<id>/unlock \
  -H "Authorization: Bearer <token>"

# 重置用户 TOTP
curl -X POST https://auth.你的域名/api/admin/users/<id>/reset-totp \
  -H "Authorization: Bearer <token>"

# 切换注册模式（仅 owner）
curl -X POST https://auth.你的域名/api/admin/config \
  -H "Authorization: Bearer <token>" -H 'Content-Type: application/json' \
  -d '{"invite_required":true,"email_verify_required":true,"review_required":true}'

# 生成邀请码
curl -X POST https://auth.你的域名/api/admin/invite-codes \
  -H "Authorization: Bearer <token>" -H 'Content-Type: application/json' \
  -d '{"count":5,"max_uses":1,"expires_days":7,"note":"测试"}'
```

## 六、测试约定（本地）

- 测试脚本**存本地**（不进 GitHub，避免暴露测试密钥/本地环境依赖）
- 参考写法：`C:\Users\KomeijiV\AppData\Local\Temp\opencode\test_fixes*.ps1`（`Req`/`Test` 函数）
- 安全跑测试的原则：
  - 非破坏性：临时用户（时间戳后缀），测完删除；禁止清库
  - 本地限流阈值可调大（`REG_CODE_PER_HOUR=100` 等环境变量）或重启清内存
  - TOTP 生成：项目目录 `node -e "const {authenticator}=require('otplib');process.stdout.write(authenticator.generate('SECRET'))"`
  - PowerShell 中文 body 用 UTF-8 字节；避免 `$fail`/`$pass` 等可能与框架冲突的变量名（大小写不敏感）
