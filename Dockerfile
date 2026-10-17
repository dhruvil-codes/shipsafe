# Multi-stage Bun build for ShipSafe production container
FROM oven/bun:1.1.26 AS base
WORKDIR /app

# Step 1: Install dependencies
FROM base AS dependencies
COPY package.json bun.lock ./
COPY packages/ ./packages/
COPY apps/ ./apps/
RUN bun install --frozen-lockfile

# Step 2: Build the production bundle
FROM base AS builder
COPY --from=dependencies /app /app
ENV NODE_ENV=production
RUN bun run build

# Step 3: Production runner
FROM base AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV SHIPSAFE_RUNTIME=local
ENV SHIPSAFE_LAB_ENABLED=1
ENV SHIPSAFE_PORT=3000
ENV HOSTNAME="0.0.0.0"

COPY --from=builder /app /app

VOLUME ["/app/.artifacts/local-scans"]
EXPOSE 3000

CMD ["sh", "-c", "bun ./apps/web/node_modules/next/dist/bin/next start -H 0.0.0.0 -p ${SHIPSAFE_PORT:-3000}"]
