const store = new Map();

const MAX_STORE = 100000;
const IDLE_CLEANUP_MS = 30 * 60 * 1000;

function touch(s) {
  s.lastAccess = Date.now();
}

// 定时清理：过期锁/过期窗口/长时间不活跃对象；超过上限时清最旧
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of store) {
    const dead = (v.lockedUntil && v.lockedUntil < now)
      || (v.windowStart && v.windowStart + v.windowMs < now)
      || !v.lastAccess
      || (v.lastAccess + IDLE_CLEANUP_MS < now);
    if (dead) store.delete(k);
  }
  if (store.size > MAX_STORE) {
    const sorted = [...store.entries()].sort((a, b) => (a[1].lastAccess || 0) - (b[1].lastAccess || 0));
    const overflow = store.size - MAX_STORE;
    for (let i = 0; i < overflow; i++) store.delete(sorted[i][0]);
  }
}, 10 * 60 * 1000).unref();

function loginAttempt(key, { max = 5, lockMs = 15 * 60 * 1000 } = {}) {
  const now = Date.now();
  let s = store.get(key);
  if (!s || (s.lockedUntil && s.lockedUntil < now)) {
    s = { fails: 0, lastAccess: now };
    store.set(key, s);
  }
  touch(s);
  if (s.lockedUntil && s.lockedUntil > now) {
    return { locked: true, remainSec: Math.ceil((s.lockedUntil - now) / 1000) };
  }
  s.fails += 1;
  if (s.fails >= max) {
    s.lockedUntil = now + lockMs;
    s.fails = 0;
    return { locked: true, remainSec: Math.ceil(lockMs / 1000) };
  }
  return { locked: false, remain: max - s.fails };
}

function loginSuccess(key) {
  store.delete(key);
}

function windowHit(key, windowMs, max) {
  const now = Date.now();
  let s = store.get(key);
  if (!s || s.windowStart + s.windowMs < now) {
    s = { windowStart: now, windowMs, hits: 0, lastAccess: now };
    store.set(key, s);
  }
  touch(s);
  s.hits += 1;
  return s.hits <= max;
}

function ipRateLimit(ip, windowMs, max) {
  return windowHit('ip:' + ip, windowMs, max);
}

// 清除某个账号的所有登录锁定（管理员"解锁"用）
// 登录锁 key 格式：login:<ip>:<account>
function clearUserLocks(account) {
  const prefix = 'login:';
  const suffix = ':' + account;
  let cleared = 0;
  for (const [k] of store) {
    if (k.startsWith(prefix) && k.endsWith(suffix)) {
      store.delete(k);
      cleared += 1;
    }
  }
  return cleared;
}

module.exports = { loginAttempt, loginSuccess, windowHit, ipRateLimit, clearUserLocks };
