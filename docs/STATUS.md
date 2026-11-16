# 项目状态与交接

## 一、当前部署

| 项 | 状态 |
|---|---|
| 生产域名 | `auth.komeijiv.cn`（HTTPS） |
| 反代 | openresty（nginx 系） |
| 已接入小站 | `music.komeijiv.cn` |
| 注册开关 | 以 `config` 表为准（管理后台可热切换） |
| 小站注册表 | `OIDC_CLIENTS` |
| 端口暴露 | 8000 / 5432 外部不可达 |

## 二、本地开发

| 项 | 值 |
|---|---|
| 认证中心 | `http://localhost:8000` |
| 测试库 | Docker `postgres:15`，端口 5433，库名需含 `test` |
| 演示小站 | `test/e2e/rp.mjs`（端口 8001） |
| 测试 | 见 `test/README.md` |

## 三、关键设计

- **会话**：服务端 `sessions` 表 + HttpOnly cookie；改密/封禁/删号即删会话，取代了 JWT + token_version + refresh_tokens
- **OIDC**：`oidc-provider` v9（ESM，`.mjs` 与 CJS 主体共存）；`findAccount` 直连 `users` 表，零用户数据迁移
- **撤销链**：登出/改密/封禁会同时清 OIDC 的 Session/Grant/RefreshToken（见 `docs/OIDC.md`）
- **注册状态机**：三开关任意组合；首个用户自动成 owner（可配 `OWNER_EMAIL` 限制）
- **限流**：进程内存；`/api/login` 与 OIDC 登录页共享登录失败计数
- **CSRF**：cookie 认证 + `SITE_ORIGIN` 的 Origin 校验 + `SameSite=Lax`
- **邮件**：SMTP 未配置或异常时 **fail-closed**（返回 502），绝不降级为回显验证码

## 四、安全审查结论（2026-11）

第三方审查 380 行，结论「中上」，问题集中在迁移接缝：

- 严重 1 项（SMTP 降级）、高 4 项（OIDC 撤销链、set-admin 类型混淆、全局 CORS、限流绕过）
- 上述已全部修复并验证
- 保留的设计取舍：`admin` 可改任意用户邮箱（产品需求：用户邮箱丢失时管理员可改），**等价于 admin 能接管任意普通账号**——目前只有 owner 一个 admin
- 未修：账号枚举（注册提示是必要的用户体验）、`offline_access` 无 client 级限制（小站均自建）

## 五、待办

- [ ] 生产部署新版本（含 OIDC、会话改造、安全修复）
- [ ] 按 `docs/DEPLOY.md` 的验证清单走一遍
- [ ] `music.komeijiv.cn` 切换到 OIDC 接入
- [ ] SMTP 授权码定期更换

## 六、给接手者

1. 先读 `README.md` → 本文件 → 任务相关文档
2. 写代码前先读 `src/`，文档可能滞后
3. 接口以 `docs/API.md` + `src/auth.js` / `src/admin.js` 的路由为准
4. 改动了认证/会话/OIDC 后，跑 `npm run test:e2e` 与 `npm run test:browser`
5. **不要**：清生产库、提交 `.env` 或 `keys/`、在非测试库上跑 `test/patch/*`
