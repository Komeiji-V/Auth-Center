require('dotenv').config();

const express = require('express');
const cors = require('cors');

const cookieParser = require('cookie-parser');

const db = require('./db');
const mail = require('./mail');
const session = require('./session');
const { ipRateLimit } = require('./rateLimit');
const { router: authRouter } = require('./auth');
const { router: adminRouter } = require('./admin');

const app = express();
const trustedProxy = (process.env.TRUST_PROXY_CIDRS || 'loopback,172.16.0.0/12,10.0.0.0/8')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
app.set('trust proxy', trustedProxy);

// CORS_ORIGINS 解析：new URL 规范化 + 严格格式校验（仅 http(s)://host[:port]，防 CSP 指令注入）
// 非法/无法解析的条目直接丢弃，保证拼进 CSP connect-src 的值必然安全
const origins = Array.from(new Set(
  (process.env.CORS_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      try {
        const u = new URL(s);
        return /^https?:\/\/[a-zA-Z0-9.\-:[\]]+$/.test(u.origin) ? u.origin : null;
      } catch {
        return null;
      }
    })
    .filter(Boolean)
));
// CSP connect-src：默认仅 'self'；白名单小站需被登录页跨域 POST 凭证（/api/auth/sso），动态加入
// 注意：CSP 关键字必须带单引号（'self'），否则会被解析为主机名导致同源请求全部被拦
const connectSrc = ["'self'", ...origins].join(' ');

app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader(
    'Content-Security-Policy',
    `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https: http:; connect-src ${connectSrc}`
  );
  next();
});

// 未配置白名单时不发 CORS 头（浏览器跨域默认拦截），显式收紧
app.use(cors({ origin: origins.length ? origins : false, credentials: true }));

// ===== OIDC =====
// 必须在 express.json 之前挂载：oidc-provider 需要读取原始请求体，
// 一旦被 body parser 消费，token / interaction 等端点会拿不到表单数据。
let oidc = null;
const OIDC_PATHS = ['/auth', '/token', '/jwks', '/me', '/session', '/interaction', '/.well-known', '/oidc-debug'];
app.use((req, res, next) => {
  if (!oidc) return next();
  const p = req.path;
  const hit = OIDC_PATHS.some((prefix) => p === prefix || p.startsWith(`${prefix}/`));
  if (hit) return oidc.callback(req, res);
  next();
});

app.use(cookieParser());

// CSRF 防护：改用 cookie 认证后，写操作必须来自本站。
// Bearer token 时代天然免疫 CSRF（跨站表单带不上 Authorization 头），换成 cookie 后必须补上。
// SameSite=Lax 已挡掉大部分跨站 POST，这里再加一层 Origin 校验。
const SITE_ORIGIN = (process.env.SITE_ORIGIN || '').replace(/\/+$/, '');
app.use((req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (!SITE_ORIGIN) return next();
  let origin = req.headers.origin;
  if (!origin && req.headers.referer) {
    try {
      origin = new URL(req.headers.referer).origin;
    } catch {
      origin = '';
    }
  }
  if (origin && origin !== SITE_ORIGIN) {
    return res.status(403).json({ error: '非法来源' });
  }
  next();
});

app.use(express.json({ limit: '32kb' }));

const GLOBAL_REQ_PER_MIN = parseInt(process.env.GLOBAL_REQ_PER_MIN, 10) || 60;
app.use((req, res, next) => {
  if (!ipRateLimit(req.ip, 60 * 1000, GLOBAL_REQ_PER_MIN)) {
    return res.status(429).json({ error: '请求过于频繁' });
  }
  next();
});

app.use('/api', authRouter);
app.use('/api/admin', adminRouter);

app.get('/login', (req, res) => res.sendFile(require('path').join(__dirname, '../public/login.html')));
app.get('/register', (req, res) => res.sendFile(require('path').join(__dirname, '../public/register.html')));
app.get('/forgot', (req, res) => res.sendFile(require('path').join(__dirname, '../public/forgot.html')));
app.get('/admin', (req, res) => res.sendFile(require('path').join(__dirname, '../public/admin.html')));
app.get('/profile', (req, res) => res.sendFile(require('path').join(__dirname, '../public/profile.html')));
app.get('/totp', (req, res) => res.sendFile(require('path').join(__dirname, '../public/totp.html')));
app.get('/', (req, res) => res.redirect('/login'));
app.use(express.static(require('path').join(__dirname, '../public')));

app.use((req, res) => res.status(404).json({ error: '接口不存在' }));

app.use((err, req, res, next) => {
  console.error('[server] unhandled error:', err);
  res.status(500).json({ error: '服务器内部错误' });
});

const PORT = parseInt(process.env.PORT || '8000', 10);

// 每日清理：过期验证码 / 过期会话 / 僵尸注册 / 90 天前审计与邀请码记录
// 多实例部署时用事务级 advisory lock 保证同一时刻只有一个实例执行（事务结束自动释放）
setInterval(async () => {
  try {
    const result = await db.withTransaction(async (client) => {
      const { rows } = await client.query('SELECT pg_try_advisory_xact_lock(9527) AS ok');
      if (!rows[0].ok) return null;   // 别的实例正在清理

      await client.query(`DELETE FROM codes WHERE expires_at < now() - interval '1 day'`);

      const s = await client.query(
        `DELETE FROM sessions WHERE expires_at < now() - interval '1 day'`
      );

      // 清理 24 小时仍未完成邮箱验证的 pending 用户（僵尸注册）
      // email_verified=TRUE 的真·待审用户不在删除范围；无邮箱验证的注册在 INSERT 时即置 true，同样不受影响
      await client.query(`
        DELETE FROM users
        WHERE status = 'pending'
          AND email_verified = FALSE
          AND created_at < now() - interval '24 hours'
      `);

      await client.query(`DELETE FROM audit_log WHERE created_at < now() - interval '90 days'`);
      await client.query(`DELETE FROM invite_usage_log WHERE created_at < now() - interval '90 days'`);

      return { sessions: s.rowCount };
    });

    if (result === null) {
      console.log('[cleanup] 其他实例正在清理，跳过');
    } else {
      console.log(`[cleanup] 定时清理完成（过期会话 ${result.sessions} 个）`);
    }
  } catch (e) {
    console.error('[cleanup] 失败:', e.message);
  }
}, 24 * 60 * 60 * 1000).unref();

async function main() {
  if (!process.env.DATABASE_URL) throw new Error('缺少 DATABASE_URL 环境变量');
  if (!process.env.OIDC_COOKIE_SECRET || process.env.OIDC_COOKIE_SECRET.startsWith('CHANGE_ME')) {
    throw new Error('请设置 OIDC_COOKIE_SECRET（openssl rand -hex 32）');
  }
  await db.initDb(process.env.DATABASE_URL);
  await db.initSchema();
  mail.initMail();

  // OIDC：复用现有 users 表；旧的 /api/login 保留，过渡期双轨运行
  if (process.env.OIDC_ENABLED === 'true') {
    const { createOidc } = await import('./oidc/bootstrap.mjs');
    oidc = await createOidc();
    app.locals.oidc = oidc;
    console.log(`[oidc] issuer    = ${oidc.issuer}`);
    console.log(`[oidc] discovery = ${oidc.issuer}/.well-known/openid-configuration`);
  } else {
    console.log('[oidc] 未启用（设置 OIDC_ENABLED=true 开启）');
  }

  app.listen(PORT, () => {
    console.log(`[server] auth center listening on :${PORT}`);
  });
}

main().catch((e) => {
  console.error('[server] startup failed:', e.message);
  process.exit(1);
});
