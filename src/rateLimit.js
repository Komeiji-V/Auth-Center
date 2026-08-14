const store = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of store) {
    const dead = v.lockedUntil && v.lockedUntil < now
      || v.windowStart && v.windowStart + v.windowMs < now;
    if (dead) store.delete(k);
  }
}, 10 * 60 * 1000).unref();

function loginAttempt(key, { max = 5, lockMs = 15 * 60 * 1000 } = {}) {
  const now = Date.now();
  let s = store.get(key);
  if (!s || (s.lockedUntil && s.lockedUntil < now)) {
    s = { fails: 0 };
    store.set(key, s);
  }
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
    s = { windowStart: now, windowMs, hits: 0 };
    store.set(key, s);
  }
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
