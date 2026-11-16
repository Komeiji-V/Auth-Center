FROM node:22-alpine

WORKDIR /app

# 依赖层单独缓存；--omit=dev 跳过 openid-client / puppeteer-core 等测试依赖
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --chown=node:node . .

# 签名密钥不打进镜像，运行时挂载：./keys:/app/keys:ro
# 首次部署前在宿主机执行 node scripts/gen-keys.mjs
#
# 以非 root 运行：官方 node 镜像的 node 用户是 uid/gid 1000，
# 与多数 Linux 发行版的首个普通用户一致，能读取宿主 600 权限的 keys/jwks.json。
# 若宿主的 uid 不是 1000，需 chown 或改用 --user 覆盖。
USER node

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD wget -q -O /dev/null "http://127.0.0.1:${PORT:-8000}/api/config" || exit 1

CMD ["node", "src/server.js"]
