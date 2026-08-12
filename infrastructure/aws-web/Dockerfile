ARG NODE_RUNTIME_IMAGE
FROM ${NODE_RUNTIME_IMAGE} AS build

ENV NODE_ENV=production \
    WRANGLER_WRITE_LOGS=false \
    WRANGLER_LOG_PATH=/tmp/wrangler.log

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --include=dev --no-audit --no-fund

COPY . .
RUN npm run build:aws \
    && mkdir -p /runtime-deps \
    && cp package.json package-lock.json /runtime-deps/ \
    && cd /runtime-deps \
    && npm ci --omit=dev --no-audit --no-fund

FROM ${NODE_RUNTIME_IMAGE} AS runtime-root

RUN rm -rf /usr/local/lib/node_modules/npm \
    /usr/local/bin/npm \
    /usr/local/bin/npx

FROM scratch AS runtime

COPY --from=runtime-root / /

ENV NODE_ENV=production \
    WRANGLER_WRITE_LOGS=false \
    WRANGLER_LOG_PATH=/tmp/wrangler.log

WORKDIR /app

COPY --from=build --chown=node:node /app/.next/standalone ./
COPY --from=build --chown=node:node /runtime-deps/node_modules ./node_modules
COPY --from=build --chown=node:node /app/.next/static ./.next/static
COPY --from=build --chown=node:node /app/public ./public
COPY --chown=node:node infrastructure/aws-web/aws-bridge.mjs ./infrastructure/aws-web/

RUN mkdir -p /data \
    && chown -R node:node /app /data

USER node
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/').then(r=>process.exit(r.status < 500 ? 0 : 1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
