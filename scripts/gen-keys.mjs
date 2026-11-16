import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPair, exportJWK } from 'jose';

/**
 * 生成固定的 OIDC 签名密钥（RS256），写入 keys/jwks.json
 *
 * 只在首次部署时执行一次。文件含私钥，已在 .gitignore 中忽略，切勿提交。
 * 轮换时：保留旧 key 一段时间（jwks.keys 数组里放多个），让已签发的 token 仍可验签。
 *
 * 用法：node scripts/gen-keys.mjs
 */
const here = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.join(here, '..', 'keys');
const outFile = path.join(outDir, 'jwks.json');

if (fs.existsSync(outFile)) {
  console.error(`已存在 ${outFile}；如确需重新生成，请先手动删除（会导致已签发 token 全部失效）`);
  process.exit(1);
}

const { privateKey } = await generateKeyPair('RS256', {
  modulusLength: 2048,
  extractable: true,
});

const jwk = await exportJWK(privateKey);
jwk.kid = `auth-center-${Date.now()}`;
jwk.alg = 'RS256';
jwk.use = 'sig';

fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(outFile, JSON.stringify({ keys: [jwk] }, null, 2), { mode: 0o600 });

console.log(`已生成 ${outFile}`);
console.log(`kid = ${jwk.kid}`);
