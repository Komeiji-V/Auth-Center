import { createProvider } from './provider.mjs';
import { interactionMiddleware } from './interaction.mjs';
import { kickAccount } from './kick.mjs';
import { startCleanup } from './cleanup.mjs';

/**
 * 组装 OIDC 能力，返回给 server.js 挂载
 *
 * 注意：provider.callback() 必须在 Express 的 body parser 之前调用，
 * 否则请求体已被消费，oidc-provider 读不到表单数据。
 */
export async function createOidc() {
  const provider = createProvider();

  provider.use(interactionMiddleware(provider));

  // 仅调试用：模拟「封禁时踢人」，生产不要开启 OIDC_DEBUG_KICK
  if (process.env.OIDC_DEBUG_KICK === 'true') {
    provider.use(async (ctx, next) => {
      if (ctx.method === 'POST' && ctx.path.startsWith('/oidc-debug/kick/')) {
        const sub = decodeURIComponent(ctx.path.slice('/oidc-debug/kick/'.length));
        ctx.body = await kickAccount(provider, sub);
        return;
      }
      await next();
    });
    console.warn('[oidc] 调试端点 /oidc-debug/kick 已启用（生产请关闭 OIDC_DEBUG_KICK）');
  }

  startCleanup(provider);

  provider.on('server_error', (ctx, err) => {
    console.error('[oidc] server_error:', err);
  });
  provider.on('authorization.error', (ctx, err) => {
    console.error('[oidc] authorization.error:', err.error || '', err.error_description || err.message);
  });
  provider.on('grant.error', (ctx, err) => {
    console.error('[oidc] grant.error:', err.error || '', err.error_description || err.message);
  });
  provider.on('backchannel.error', (ctx, err, client) => {
    console.error('[oidc] backchannel.error:', client && client.clientId, err.message);
  });

  return {
    provider,
    callback: provider.callback(),
    issuer: provider.issuer,
    kickAccount: (sub) => kickAccount(provider, sub),
  };
}
