// 无头浏览器手测：登录 → 管理后台 → 个人中心 → 刷新保持 → 退出
const puppeteer = require('puppeteer-core');
const path = require('path');
const fs = require('fs');

const BASE = 'http://localhost:8000';
const ACCOUNT = 'alice';
const PASSWORD = 'Passw0rd!123';
const SHOT_DIR = path.join(__dirname, 'shots');

let pass = 0;
let fail = 0;
const check = (name, cond, detail) => {
  if (cond) {
    pass += 1;
    console.log(`  ✓ ${name}`);
  } else {
    fail += 1;
    console.log(`  ✗ ${name}${detail ? `  → ${detail}` : ''}`);
  }
};

(async () => {
  fs.mkdirSync(SHOT_DIR, { recursive: true });
  // 沙箱只允许写工作区：临时目录与 Chrome profile 都放这里
  const TMP = path.join(__dirname, 'tmp');
  fs.mkdirSync(TMP, { recursive: true });
  process.env.TMPDIR = TMP;

  const browser = await puppeteer.launch({
    executablePath: process.env.CHROME_PATH || '/home/ubuntu-chen/tools/bin/google-chrome',
    headless: true,
    userDataDir: path.join(__dirname, 'chrome-profile'),
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
  });

  const page = await browser.newPage();
  await page.setCacheEnabled(false);
  await page.setViewport({ width: 1280, height: 900 });

  // 只统计真正的 JS 异常与网络失败；
  // 401（未登录探测）和 favicon 404 属于预期行为，不计入
  const jsErrors = [];
  const netErrors = [];
  page.on('pageerror', (e) => jsErrors.push(e.message));
  page.on('requestfailed', (r) => {
    const url = r.url();
    if (url.includes('favicon')) return;
    netErrors.push(`${url} ${r.failure()?.errorText || ''}`);
  });

  try {
    // 1. 登录页
    console.log('\n[1] 打开登录页');
    await page.goto(`${BASE}/login`, { waitUntil: 'networkidle2', timeout: 15000 });
    const title = await page.title();
    check('页面加载', title.length > 0, title);
    check('有账号输入框', (await page.$('#account')) !== null);
    await page.screenshot({ path: path.join(SHOT_DIR, '1-login.png') });

    // 2. 登录
    console.log('\n[2] 填账号密码并登录');
    await page.type('#account', ACCOUNT);
    await page.type('#password', PASSWORD);
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15000 }).catch(() => null),
      page.click('#btn'),
    ]);
    await new Promise((r) => setTimeout(r, 1200));

    const urlAfterLogin = page.url();
    check('跳转到后台或绑定页', /\/(admin|totp|profile)/.test(urlAfterLogin), urlAfterLogin);
    await page.screenshot({ path: path.join(SHOT_DIR, '2-after-login.png') });

    // 3. 管理后台
    console.log('\n[3] 管理后台');
    await page.goto(`${BASE}/admin`, { waitUntil: 'networkidle2', timeout: 15000 });
    await new Promise((r) => setTimeout(r, 1000));
    check('未跳回登录页', !page.url().includes('/login'), page.url());
    const hasApp = (await page.$('#app')) !== null;
    check('管理面板存在', hasApp);
    const appVisible = hasApp
      ? await page.$eval('#app', (el) => getComputedStyle(el).display !== 'none')
      : false;
    check('管理面板已显示（说明会话有效）', appVisible);
    await page.screenshot({ path: path.join(SHOT_DIR, '3-admin.png') });

    // 4. 用户列表是否有数据
    console.log('\n[4] 用户列表');
    const rows = await page.$$eval('#userList tr, #users tr, table tbody tr', (trs) => trs.length).catch(() => 0);
    check('用户表格有行', rows > 0, `行数 ${rows}`);

    // 5. 个人中心
    console.log('\n[5] 个人中心');
    await page.goto(`${BASE}/profile`, { waitUntil: 'networkidle2', timeout: 15000 });
    await new Promise((r) => setTimeout(r, 800));
    check('未跳回登录页', !page.url().includes('/login'), page.url());
    const mainShown = await page.$eval('#main', (el) => el.classList.contains('show')).catch(() => false);
    check('个人中心内容已显示', mainShown);
    const userInfo = await page.$eval('#userInfo', (el) => el.textContent).catch(() => '');
    check('显示用户名', userInfo.includes(ACCOUNT), userInfo.slice(0, 40));
    await page.screenshot({ path: path.join(SHOT_DIR, '4-profile.png') });

    // 6. 刷新保持登录
    console.log('\n[6] 刷新页面');
    await page.reload({ waitUntil: 'networkidle2' });
    await new Promise((r) => setTimeout(r, 800));
    check('刷新后仍登录', !page.url().includes('/login'), page.url());

    // 7. 退出
    console.log('\n[7] 退出登录');
    await page.goto(`${BASE}/profile`, { waitUntil: 'networkidle2' });
    await page.click('#logout').catch(() => null);
    await new Promise((r) => setTimeout(r, 1200));
    check('退出后回到登录页', page.url().includes('/login'), page.url());

    // 8. 退出后无法访问后台
    console.log('\n[8] 退出后访问后台');
    await page.goto(`${BASE}/admin`, { waitUntil: 'networkidle2' });
    await new Promise((r) => setTimeout(r, 800));
    const loginCard = await page.$('#loginCard');
    const loginCardVisible = loginCard
      ? await page.$eval('#loginCard', (el) => getComputedStyle(el).display !== 'none')
      : false;
    check('后台显示登录卡片（未进入应用）', loginCardVisible, page.url());
    await page.screenshot({ path: path.join(SHOT_DIR, '5-after-logout.png') });

    // 9. JS 错误
    console.log('\n[9] 运行时错误');
    check('无未捕获 JS 异常', jsErrors.length === 0, jsErrors.join(' | ').slice(0, 200));
    check('无网络请求失败', netErrors.length === 0, netErrors.join(' | ').slice(0, 200));
  } finally {
    await browser.close();
  }

  console.log(`\n${'─'.repeat(50)}`);
  console.log(`结果：${pass} 通过，${fail} 失败`);
  console.log(`截图：${SHOT_DIR}`);
  console.log(`${'─'.repeat(50)}\n`);
  process.exit(fail > 0 ? 1 : 0);
})().catch((e) => {
  console.error('测试异常：', e);
  process.exit(2);
});
