# One image for every service; Compose picks the command and the access each gets.
FROM node:24-bookworm-slim AS base
ENV PNPM_HOME=/pnpm PATH=/pnpm:$PATH COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/core/package.json packages/core/
COPY packages/privacy/package.json packages/privacy/
COPY apps/server/package.json apps/server/
COPY apps/worker/package.json apps/worker/
COPY apps/web/package.json apps/web/
COPY apps/intake/package.json apps/intake/
COPY apps/gateway/package.json apps/gateway/
COPY apps/agent-runtime/package.json apps/agent-runtime/

FROM base AS build
RUN pnpm install --frozen-lockfile
COPY tsconfig.base.json ./
COPY packages packages
COPY apps apps
RUN pnpm build

FROM base AS prod-deps
RUN pnpm install --frozen-lockfile --prod

FROM node:24-bookworm-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY --from=prod-deps /app /app
COPY --from=build /app/packages/core/dist packages/core/dist
COPY --from=build /app/packages/core/migrations packages/core/migrations
COPY --from=build /app/packages/privacy/dist packages/privacy/dist
COPY --from=build /app/apps/server/dist apps/server/dist
COPY --from=build /app/apps/worker/dist apps/worker/dist
COPY --from=build /app/apps/web/dist apps/web/dist
COPY --from=build /app/apps/intake/dist apps/intake/dist
COPY --from=build /app/apps/gateway/dist apps/gateway/dist
COPY --from=build /app/apps/agent-runtime/dist apps/agent-runtime/dist
# Mount point for the sanitized source snapshot volume (owned by the app user).
RUN mkdir -p /snapshots && chown node:node /snapshots
USER node
CMD ["node", "apps/server/dist/main.js"]
