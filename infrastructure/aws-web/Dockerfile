FROM node:22-bookworm-slim

ENV NODE_ENV=production \
    WRANGLER_WRITE_LOGS=false \
    WRANGLER_LOG_PATH=/tmp/wrangler.log

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --include=dev --no-audit --no-fund

COPY . .
RUN npm run build

RUN mkdir -p /data && chown -R node:node /app /data

USER node
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/').then(r=>process.exit(r.status < 500 ? 0 : 1)).catch(()=>process.exit(1))"

CMD ["bash", "-lc", "node infrastructure/aws-web/prepare-runtime.mjs && exec npx wrangler dev --config dist/server/wrangler.aws.json --ip 0.0.0.0 --port 3000 --inspector-ip 127.0.0.1 --inspector-port 9230 --persist-to /data --local --show-interactive-dev-session false --log-level error"]
