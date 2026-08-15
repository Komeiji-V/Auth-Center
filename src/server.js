require('dotenv').config();

const express = require('express');
const cors = require('cors');

const db = require('./db');
const mail = require('./mail');
const { ipRateLimit } = require('./rateLimit');
const { router: authRouter } = require('./auth');
const { router: adminRouter } = require('./admin');

const app = express();
app.set('trust proxy', true);

app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https: http:; connect-src 'self'"
  );
  next();
});

const origins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
// 未配置白名单时不发 CORS 头（浏览器跨域默认拦截），显式收紧
app.use(cors({ origin: origins.length ? origins : false, credentials: true }));

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

async function main() {
  if (!process.env.DATABASE_URL) throw new Error('缺少 DATABASE_URL 环境变量');
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.startsWith('CHANGE_ME')) {
    throw new Error('请先设置 JWT_SECRET（可用 openssl rand -hex 32 生成）');
  }
  await db.initDb(process.env.DATABASE_URL);
  await db.initSchema();
  mail.initMail();
  app.listen(PORT, () => {
    console.log(`[server] auth center listening on :${PORT}`);
  });
}

main().catch((e) => {
  console.error('[server] startup failed:', e.message);
  process.exit(1);
});
