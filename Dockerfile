FROM node:22-alpine

WORKDIR /app

# 依赖层单独缓存；--omit=dev 跳过 openid-client / puppeteer-core 等测试依赖
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY . .

# 签名密钥不打进镜像，运行时挂载：./keys:/app/keys:ro
# 首次部署前在宿主机执行 node scripts/gen-keys.mjs

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD-SHELL wget -q -O /dev/null http://127.0.0.1:8000/api/config || exit 1

CMD ["node", "src/server.js"]
