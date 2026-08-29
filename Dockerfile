# Shared build: pnpm workspace
FROM node:22-slim AS base
RUN corepack enable && corepack prepare pnpm@11.23.0 --activate
WORKDIR /app

FROM base AS build
COPY pnpm-workspace.yaml package.json tsconfig.base.json turbo.json ./
COPY packages/shared/package.json packages/shared/
COPY packages/tokens-core/package.json packages/tokens-core/
COPY apps/api/package.json apps/api/
COPY apps/gateway/package.json apps/gateway/
COPY apps/web/package.json apps/web/
RUN pnpm install --frozen-lockfile || pnpm install
COPY packages/shared/ packages/shared/
COPY packages/tokens-core/ packages/tokens-core/
COPY apps/api/ apps/api/
COPY apps/gateway/ apps/gateway/
COPY apps/web/ apps/web/
RUN pnpm build

# --- API ---
FROM node:22-slim AS api
# Code signing runs on the API host: openssl for key/cert handling and the
# Ed25519 release manifests, osslsigncode for Authenticode. Shipping them
# here means the console's signing features work on a fresh install instead
# of failing with "spawn openssl ENOENT" the first time an operator tries.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl osslsigncode \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/packages ./packages
COPY --from=build /app/apps/api ./apps/api
EXPOSE 8443
CMD ["node", "apps/api/dist/server.js"]

# --- Gateway ---
FROM node:22-slim AS gateway
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/packages ./packages
COPY --from=build /app/apps/gateway ./apps/gateway
EXPOSE 80 53/udp 2525
CMD ["node", "apps/gateway/dist/server.js"]

# --- Web (static, served by Caddy in production) ---
FROM node:22-slim AS web-build
WORKDIR /app
COPY --from=build /app/apps/web/dist ./dist
FROM caddy:2-alpine AS web
COPY deploy/Caddyfile /etc/caddy/Caddyfile
COPY --from=web-build /app/dist /srv/www
