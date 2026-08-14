const crypto = require('crypto');
const nodemailer = require('nodemailer');

let transporter = null;

function initMail() {
  if (process.env.SMTP_DEBUG === 'true') {
    console.log('[mail] SMTP_DEBUG=true：验证码将打印到日志，不会真实发信');
    return;
  }
  if (!process.env.SMTP_HOST) {
    console.log('[mail] 未配置 SMTP_HOST，降级为调试模式');
    return;
  }
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '465', 10),
    secure: process.env.SMTP_SECURE === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
}

function genCode() {
  return crypto.randomInt(100000, 1000000).toString();
}

function isDebug() {
  return process.env.SMTP_DEBUG === 'true' || !transporter;
}

async function sendCode(email, code, purpose) {
  if (isDebug()) {
    console.log(`[mail:debug] ${purpose} code -> ${email}: ${code}`);
    return { debug: true, code };
  }
  const subject = purpose === 'register' ? '【注册验证码】' : '【验证码】';
  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to: email,
    subject: `${subject} ${code}`,
    text: `你的验证码是 ${code}，10 分钟内有效。如非本人操作请忽略此邮件。`,
  });
  return { debug: false };
}

// 通知模板：type + 动态内容（extra 为对象，模板内以 {{key}} 占位）
// 类型：approved=审核通过 | rejected=审核拒绝 | banned=封禁 | unbanned=解封 | new_pending=新用户待审核
function notifyTemplates(type) {
  const t = {
    approved: { subject: '【通知】注册审核已通过', text: '你的注册申请已通过审核，现在可以登录使用了。' },
    rejected: { subject: '【通知】注册申请未通过', text: '你的注册申请未通过审核。如有疑问请联系管理员。' },
    banned: { subject: '【通知】账号已被封禁', text: '你的账号已被封禁，如有疑问请联系管理员。' },
    unbanned: { subject: '【通知】账号已解封', text: '你的账号已解封，可以正常登录使用了。' },
    new_pending: {
      subject: '【审核提醒】有新的注册申请待审核',
      text: '新用户 {{username}}（{{email}}）已提交注册申请，等待审核。\n申请说明：{{apply_info}}\n请登录管理后台处理：',
    },
  };
  return t[type] || null;
}

function renderTemplate(text, extra) {
  if (!extra) return text;
  return text.replace(/\{\{(\w+)\}\}/g, (m, k) => (extra[k] !== undefined ? String(extra[k]) : m));
}

async function sendNotify(email, type, extra) {
  const t = notifyTemplates(type);
  if (!t) return;
  const text = renderTemplate(t.text, extra);
  if (isDebug()) {
    console.log(`[mail:debug] notify ${type} -> ${email}${extra && extra.username ? ' (' + extra.username + ')' : ''}`);
    return { debug: true };
  }
  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to: email,
    subject: t.subject,
    text,
  });
  return { debug: false };
}

module.exports = { initMail, genCode, sendCode, sendNotify, isDebug };
