/**
 * cookie 的 Secure 判断与命名，统一从这里取
 *
 * 之前 session.js / provider.mjs / auth.js 各自判断一次环境变量：
 *   session.js   → COOKIE_SECURE || SITE_ORIGIN 是 https
 *   provider.mjs → 只看 OIDC_COOKIE_SECURE
 * 配置不统一时会出现「本站 cookie 带 __Host- 前缀、但 provider 会话 cookie 不带」
 * 的半安全状态。这里合并成一个来源，任一项为 https 即整体开启 Secure。
 */

const SECURE =
  process.env.COOKIE_SECURE === 'true' ||
  process.env.OIDC_COOKIE_SECURE === 'true' ||
  (process.env.SITE_ORIGIN || '').startsWith('https://');

// __Host- 前缀要求 Secure + Path=/ + 无 Domain，能挡住同域小站的 cookie tossing
const SESSION_COOKIE = SECURE ? '__Host-ac_sid' : 'ac_sid';
// provider 的 session cookie（path 为 /，可以用前缀；_interaction 系列 path 是子路径，不能用）
const PROVIDER_SESSION_COOKIE = SECURE ? '__Host-_session' : '_session';

module.exports = { SECURE, SESSION_COOKIE, PROVIDER_SESSION_COOKIE };
