# syntax=docker/dockerfile:1.7
# Build context: repo root (dockerfile: services/user-service/Dockerfile)

FROM node:24-slim AS build
WORKDIR /app
RUN npm i -g pnpm@9.15.0
COPY services/user-service/package.json services/user-service/pnpm-lock.yaml ./
RUN --mount=type=cache,id=pnpm-user,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile
COPY services/user-service/tsconfig.json services/user-service/tsconfig.spec.json services/user-service/nest-cli.json ./
COPY services/user-service/mikro-orm.config.ts ./
COPY services/user-service/test ./test
COPY services/user-service/src ./src
RUN pnpm test && pnpm build && pnpm prune --prod

FROM node:24-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/package.json ./package.json
USER node
EXPOSE 8080
# exec form — SIGTERM reaches Node so enableShutdownHooks drains cleanly
CMD ["node", "dist/src/main.js"]
