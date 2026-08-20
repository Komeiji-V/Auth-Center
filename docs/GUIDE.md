# 内部教程：小站接入与后续开发

面向：新小站接入认证中心、认证中心功能扩展。接口契约见 `docs/API.md`，部署见 `docs/DEPLOY.md`。

---

# 第一部分：小站接入指南

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

**2. 登录回跳（安全版）：token 不走 URL，从 sso cookie 收入 localStorage**

```js
const TOKEN_KEY = 'myapp_token';
// 认证中心登录页已将 token POST 到本站 /api/auth/sso（后端验签后种 60s 短时 cookie），
// 此处从 cookie 收入 localStorage 并立即清除（凭证不经过浏览器历史/日志）
(function () {
  const m = document.cookie.match(/(?:^|;\s*)demo_sso_token=([^;]*)/);
  if (m) {
    localStorage.setItem(TOKEN_KEY, decodeURIComponent(m[1]));
    document.cookie = 'demo_sso_token=; Max-Age=0; path=/';
    console.log('登录成功');
  }
})();
```

配套后端端点（参考 `demo-app/server.js` 的 `POST /api/auth/sso`）：验签 → 确认用户 active → 种 cookie。

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

- **每个小站**：独立部署，复制中间件 + 前端 SDK，配置相同的 `JWT_SECRET`。中间件必须查认证中心的 users 表，所以 `DATABASE_URL` 指向认证库；小站自己的业务数据存自己的库
- **认证中心侧**：把所有小站域名加入 `CORS_ORIGINS`（登录后回跳白名单 + CSP `connect-src` + CORS 白名单，漏配则登录后不自动回跳）
- **小站侧**：必须实现 `POST /api/auth/sso`（凭证安全回跳端点，参考 demo-app），否则登录页会提示"目标站不支持安全回跳"且不跳转

```
CORS_ORIGINS=https://game1.你的域名,https://radio.你的域名,https://xxx.你的域名
```

- **新增小站流程**：写代码（照 demo-app 范式，含 `/api/auth/sso`）→ 部署 → 认证中心 `CORS_ORIGINS` 加域名 → 重启认证中心 → 验证登录回跳

## 四、常见坑

| 坑 | 原因与解决 |
|---|---|
| 登录后停在认证中心不回跳 | 小站域名不在 `CORS_ORIGINS`（回跳白名单）；或 redirect 参数丢失 |
| 登录后提示"目标站暂不支持安全回跳" | 小站未实现 `POST /api/auth/sso` 端点（安全降级：token 不再走 URL，须升级小站） |
| 请求一直 401、跳转后仍 401 | refresh token 也被吊销（改过密码/邮箱）；或 `JWT_SECRET` 两边不一致 |
| sso 回跳后未登录 | 小站 `/api/auth/sso` 未验签/未种 cookie；或前端未从 cookie 收 token；或 cookie 跨域被拦（跨注册域需 `SameSite=None; Secure`） |
| 游客数据与登录数据合并 | 小站自己处理：登录成功后把 localStorage 本地数据合并上传到云端 |

---

# 第二部分：后续开发指南

## 一、新增接口

1. **位置约定**：
   - 用户侧接口 → `src/auth.js`（路由前缀 `/api`）
   - 管理接口 → `src/admin.js`（路由前缀 `/api/admin`，自动带 `adminGuard` 权限 + TOTP 检查）
   - 挂载点：`src/server.js` 的 `app.use('/api', authRouter)` / `app.use('/api/admin', adminRouter)`

2. **权限约定**：
   - 需登录：`router.get('/xxx', createAuthMiddleware(process.env.JWT_SECRET, db), handler)`
   - 仅管理员：`adminGuard`（已定义）；目标为管理员/owner 时用 `canManageUser(req.user, target)` 二次校验
   - 用户数据操作前查 `req.user.id`，不信任前端传的用户 id

3. **审计与限流**：重要操作 `db.audit(...)`；限流用 `ipRateLimit` / `loginAttempt`（key 命名约定：`login:ip:account`、`totp:uid`、`profile-code:ip`）

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
3. 部署文档（docs/DEPLOY.md 配置表）同步更新

## 五、测试约定

- **非破坏性**：测试用临时用户（用户名加时间戳后缀），测完删除；**禁止清库/动现有用户**
- **PowerShell 中文请求体**：用 UTF-8 字节发送（`[System.Text.Encoding]::UTF8.GetBytes(...)` + `charset=utf-8`）
- **TOTP 生成**：项目目录内 `node -e "const {authenticator}=require('otplib');process.stdout.write(authenticator.generate('SECRET'))"`
- **限流注意**：本地测试可用环境变量调大阈值（`REG_CODE_PER_HOUR=100` 等）或重启清内存；别在默认阈值下连发
- **PowerShell 变量名大小写不敏感**：不要用 `$fail`/`$pass` 之类可能与测试框架冲突的变量名
- 测试脚本建议存本地（不进仓库，避免暴露测试密钥/本地环境依赖），写法参考 `C:\Users\KomeijiV\AppData\Local\Temp\opencode\test_fixes*.ps1` 的 `Req`/`Test` 函数

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

# 4. 部署后验证（docs/DEPLOY.md"九、部署后验证清单"逐项过）
```
