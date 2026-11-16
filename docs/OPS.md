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
1. 用户最近改过密码 / 邮箱 / 被重置密码 —— 预期行为（该用户全部会话已被删除），重新登录即可
2. 浏览器禁用了 cookie，或 `SITE_ORIGIN` 配错导致请求被 CSRF 校验拒绝（403）
3. 会话超过 `SESSION_TTL_DAYS`（默认 7 天）
4. OIDC 场景下小站报 `issuer mismatch` —— `OIDC_ISSUER` 与实际访问地址不一致

### 限流误触发

- 现象：正常操作被 429
- 检查：`GLOBAL_REQ_PER_MIN`（默认 60/分/IP）是否过小；抓包工具/脚本在短时间内发起大量请求
- 调整：改 `.env` → `docker compose restart auth`

### 数据库连接失败

- `[db] idle client error` / `ECONNREFUSED`
- 检查：PG 是否运行、`DATABASE_URL` 正确性、PG 的 `pg_hba.conf` 是否允许来源 IP、防火墙 5432

## 三、安全维护

### 会话与密钥轮换

**强制所有人重新登录**：

```sql
DELETE FROM sessions;
```

**只让某个用户下线**：

```sql
DELETE FROM sessions WHERE user_id = <id>;
```

**轮换 OIDC 签名密钥**（会让已签发的 ID Token 失效）：

1. 保留旧 key，把新 key 追加进 `keys/jwks.json` 的 `keys` 数组
2. 重启服务（新旧 key 都在，验签不受影响）
3. 等最长 token 寿命（15 分钟 ~ 14 天）过去后，再移除旧 key

> 改 `OIDC_COOKIE_SECRET` 会让所有 OIDC 会话 cookie 失效，小站用户需重新授权。
> `.env` 里没有 `JWT_SECRET` 了——JWT 已完全移除。

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

### 会话卫生

| 配置 | 作用 |
|---|---|
| `SESSION_TTL_DAYS`（默认 7） | 会话绝对上限 |
| `SESSION_IDLE_HOURS`（默认 24） | 闲置超时：`last_seen` 超过该窗口即失效 |

- `last_seen` 在每次请求命中会话时推进（60 秒内不重复写库）
- 个人中心「登录设备」可查看所有会话与最近活跃时间
- 「退出其他设备」删除除当前之外的全部会话；改密 / 重置密码 / 封禁 / 删号会删全部会话
- 会话表含 `ip` / `user_agent`，便于用户识别设备，也便于事后排查

### 手动治理

- 清理已吊销的 refresh：`DELETE FROM refresh_tokens WHERE revoked = TRUE AND expires_at < now();`
- 删除测试用户：`DELETE FROM users WHERE username LIKE 'test%';`（谨慎，先备份）

## 五、多实例部署

个人项目**单实例就够**。确实需要多副本（负载均衡 / 滚动更新）时，注意以下几点。

### 天然共享的部分

| 数据 | 位置 | 说明 |
|---|---|---|
| 登录会话 | `sessions` 表 | 任意实例都能验，**不需要 sticky session** |
| OIDC 会话 / token / 授权码 | `oidc_payloads` 表 | 同上 |
| 用户、邀请码、验证码 | 各自的表 | 同上 |

### 不共享、需要留意的部分

| 项 | 影响 | 处理 |
|---|---|---|
| 登录失败计数、发码限流、全局限流 | 每个实例独立计数，总阈值 = 配置值 × 实例数 | 单机可接受；严格限流需换 Redis |
| 每日清理任务 | 加了事务级 advisory lock，同一时刻只有一个实例执行 | 已处理 |
| back-channel 失败重试 | 可能重复推送（幂等操作，无副作用） | 可接受 |
| 进程内 interaction 失败计数 | 同限流 | 可接受 |

### 必须满足

1. **所有实例连同一个 PostgreSQL**（会话与 OIDC 状态都在库里）
2. **共用同一份 `keys/jwks.json`** —— 各自生成会导致互相验签失败
3. `OIDC_ISSUER` 配成对外统一域名，不要写各实例的地址
4. 反代层开启会话保持不是必需的，但能减少重复验库

### 限流的近似换算

```bash
# 3 个实例，希望全局 60 次/分 → 每个实例配 20
GLOBAL_REQ_PER_MIN=20
```

幂等性说明：限流只是「更宽松」，不会误伤正常用户。

## 六、速查表（API 方式运维）

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

## 七、测试约定（本地）

- 测试脚本**存本地**（不进 GitHub，避免暴露测试密钥/本地环境依赖）
- 参考写法：`C:\Users\KomeijiV\AppData\Local\Temp\opencode\test_fixes*.ps1`（`Req`/`Test` 函数）
- 安全跑测试的原则：
  - 非破坏性：临时用户（时间戳后缀），测完删除；禁止清库
  - 本地限流阈值可调大（`REG_CODE_PER_HOUR=100` 等环境变量）或重启清内存
  - TOTP 生成：项目目录 `node -e "const {authenticator}=require('otplib');process.stdout.write(authenticator.generate('SECRET'))"`
  - PowerShell 中文 body 用 UTF-8 字节；避免 `$fail`/`$pass` 等可能与框架冲突的变量名（大小写不敏感）
