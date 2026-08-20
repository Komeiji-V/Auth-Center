# M1 安全修复报告：登录凭证不再经 URL 回跳（SSO 协议）

> 状态：已实施并本地测试通过（11/11）
> 范围：认证中心（auth-center）已改完；**MusicParty 侧需按本文档第三节配合改动**
> 关联文档：`docs/API.md`「小站安全回跳协议（SSO）」、`docs/GUIDE.md` 前端接入范式

---

## 一、问题（M1，中危）

登录/静默刷新后，access token 通过 URL query 回跳小站：

- 位置：`public/login.html` 的 `goBackWithToken()`（登录成功、静默续期两条路径共用）
- 危害：
  1. **浏览器历史**：token 明文进入历史条目（小站侧 `replaceState` 只能清当前地址，清不掉历史与跳转瞬间）
  2. **两端 access log**：认证中心与小站的反代层默认记录完整 query，日志平台/备份泄露即可 `grep "token="` 批量收割 1 小时内的有效登录态
  3. 浏览器扩展/代理可见
- 回跳白名单校验本身正确（防开放重定向），问题在**凭证传输通道**

## 二、修复方案与实施（认证中心侧，已完成）

采用「方案一」：**token 不再进 URL**，登录页将 token 跨域 POST 到小站 `POST /api/auth/sso`，小站后端验签后以短时 cookie 交还小站前端。

### 修改文件

| 文件 | 改动 |
|---|---|
| `public/login.html` | `goBackWithToken()`：`location.href = target + '&token=' + token` → `fetch(target + '/api/auth/sso', { method: 'POST', body: { token } })`，成功后跳转 `target`（无 token）；失败**安全降级**：提示"目标站暂不支持安全回跳"且**绝不回退 URL 带 token** |
| `src/server.js` | CSP `connect-src` 由静态 `'self'` 改为 `'self' + CORS_ORIGINS` 动态注入（否则登录页跨域 POST 被 CSP 拦截） |
| `demo-app/server.js` | 新增 `POST /api/auth/sso` 参考实现（见下） |
| `demo-app/public/index.html` | 前端改为从 sso cookie 收 token 入 localStorage 并清 cookie（原 URL token 逻辑删除） |
| `docs/API.md` / `docs/GUIDE.md` / `docs/STATUS.md` / `docs/DEPLOY.md` | 协议、接入范式、演进记录、部署清单同步更新 |

### 新流程

```
小站未登录 → 跳 /login?redirect=<小站URL>
  → 登录/静默续期成功
  → 登录页 fetch POST <小站>/api/auth/sso { token }   （跨域，CORS + CSP 已放行）
  → 小站后端验签（同 JWT_SECRET, HS256）→ 确认用户 active
  → 种 60s 短时 cookie（httpOnly:false, SameSite:Lax）
  → 登录页跳回小站 URL（不含 token）
  → 小站前端从 cookie 收入 localStorage 并清除 cookie
  → 后续请求照常 Authorization: Bearer <token>
```

### 测试结果（本地 11/11 通过）

- 登录 → sso POST 200 + `Set-Cookie: demo_sso_token`；token 调小站 `/api/me` 正常
- 边界：无 token→400；伪造 token→401；pending 用户登录被拒（403 场景由登录层拦截）
- CSP 头含白名单小站（`connect-src self http://localhost:8011`）；demo-app 对认证中心 origin 的 preflight 返回 204 + 允许头
- 登录页/小站前端已无 `token=` URL 拼接逻辑；全部 JS 语法检查通过

---

## 三、MusicParty 需要做的改动（必读）

### 1. 后端新增 `POST /api/auth/sso`（参考 demo-app/server.js）

```js
app.post('/api/auth/sso', async (req, res) => {
  const token = req.body && req.body.token;
  if (!token || typeof token !== 'string') return res.status(400).json({ error: '缺少 token' });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    // 校验用户存在且 active（查认证中心 users 表，与现有中间件同库）
    const { rows } = await pool.query('SELECT id FROM users WHERE id = $1 AND status = $2', [payload.uid, 'active']);
    if (rows.length === 0) return res.status(403).json({ error: '用户不存在或未激活' });
    res.cookie('music_sso_token', token, { httpOnly: false, sameSite: 'lax', maxAge: 60 * 1000, path: '/' });
    res.json({ ok: true });
  } catch {
    return res.status(401).json({ error: 'token 无效' });
  }
});
```

要点：
- `JWT_SECRET` 与认证中心一致；算法白名单 `HS256`（必须显式指定，防算法混淆）
- **必须查库校验 `status='active'`**（封禁即时生效；只验签不查库会被封禁用户绕过）
- cookie 命名可自定义，`SameSite=Lax`（认证中心与小站同为 `komeijiv.cn` 子域，属 same-site，正常生效）

### 2. CORS：允许认证中心 origin 的跨域 POST

- 需允许 `https://auth.komeijiv.cn`（含 OPTIONS preflight，`Content-Type: application/json` 触发预检）
- 若 MusicParty 用 `cors` 包：`cors({ origin: ['https://auth.komeijiv.cn', ...自身], methods: ['GET','POST','OPTIONS'] })`；若自有反代：在反代层加 `Access-Control-Allow-Origin` 与 `Access-Control-Allow-Headers: content-type` 响应头并处理 OPTIONS

### 3. 前端：从 cookie 收 token（替换现有"URL 带 token"逻辑）

```js
const TOKEN_KEY = 'music_token';  // 按现状命名
(function () {
  const m = document.cookie.match(/(?:^|;\s*)music_sso_token=([^;]*)/);
  if (m) {
    localStorage.setItem(TOKEN_KEY, decodeURIComponent(m[1]));
    document.cookie = 'music_sso_token=; Max-Age=0; path=/';
  }
})();
```

删除原 `q.get('token')` 收 token 逻辑（不再有 URL token 可收）。

### 4. 日志脱敏（建议一并做，纵深防御）

反代层 access log 不记录 query（或对 `token=` 值脱敏），即使未来再有凭证进 URL 也不落日志。

---

## 四、安全边界与注意点

1. **降级策略**：认证中心对未实现 `/api/auth/sso` 的旧小站**不跳转并提示升级**——这是有意的安全降级（token 宁可不到达也不进 URL），升级 MusicParty 前登录回跳会暂时不可用，请与业务排期协调
2. **跨注册域边界**：若未来小站与认证中心**不同注册域**（如 `xxx.com` vs `komeijiv.cn`），`SameSite=Lax` cookie 在第三方上下文可能被浏览器阻止，需改 `SameSite=None; Secure` 或升级为一次性票据模式（`docs/API.md` 有说明）
3. **cookie 为短时一次性**（60s）：仅作为"登录页 → 小站前端"的搬运通道，过期自动失效；token 最终仍存小站自己的 localStorage（现有模型不变）
4. 认证中心 CSP `connect-src` 已随 `CORS_ORIGINS` 白名单动态放行，**新增小站域名时只需加 `CORS_ORIGINS`，无需改代码**

## 五、回归确认

- 认证中心内部页面（登录/注册/个人中心/管理后台/TOTP）不受影响——改动仅涉及回跳小站的路径
- 登录锁定、限流、token 版本号等既有安全机制未触碰
- 本仓库代码改动未提交，等待与其它安全审查项合并后统一提交
