ARG NODE_RUNTIME_IMAGE
FROM ${NODE_RUNTIME_IMAGE} AS build

ENV NODE_ENV=production \
    WRANGLER_WRITE_LOGS=false \
    WRANGLER_LOG_PATH=/tmp/wrangler.log

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --include=dev --no-audit --no-fund

COPY . .
RUN npm run build

FROM ${NODE_RUNTIME_IMAGE} AS runtime

ENV NODE_ENV=production \
    WRANGLER_WRITE_LOGS=false \
    WRANGLER_LOG_PATH=/tmp/wrangler.log

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund \
    && npm cache clean --force

COPY --from=build /app/dist ./dist
COPY infrastructure/aws-web/prepare-runtime.mjs infrastructure/aws-web/aws-bridge.mjs ./infrastructure/aws-web/

RUN mkdir -p /data \
    && chown -R node:node /app /data

USER node
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/').then(r=>process.exit(r.status < 500 ? 0 : 1)).catch(()=>process.exit(1))"

CMD ["bash", "-lc", "node infrastructure/aws-web/prepare-runtime.mjs && exec ./node_modules/.bin/wrangler dev --config dist/server/wrangler.aws.json --ip 0.0.0.0 --port 3000 --persist-to /data --local --show-interactive-dev-session false --log-level error"]
