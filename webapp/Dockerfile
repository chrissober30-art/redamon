# ============================================
# RedAmon Web Application - Production Dockerfile
# Multi-stage build for optimized production image
# ============================================

# Stage 1: Dependencies
FROM node:22-slim AS deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app

COPY package.json package-lock.json* ./
COPY prisma ./prisma
RUN npm ci --no-audit --no-fund && npm cache clean --force

# Stage 2: Builder
FROM node:22-slim AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . ./

ARG REDAMON_VERSION=0.0.0
ENV NEXT_PUBLIC_REDAMON_VERSION=$REDAMON_VERSION
ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_ENV=production
# Dummy DATABASE_URL for Prisma client generation at build time (not used at runtime)
ENV DATABASE_URL="postgresql://build:build@localhost:5432/build"
ENV NODE_OPTIONS=--max-old-space-size=4096

RUN npm run build

# Stage 3: Runner (Production)
FROM node:22-slim AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 1001 nodejs
RUN useradd --system --uid 1001 --gid nodejs --no-create-home nextjs

COPY --from=builder /app/public ./public

RUN mkdir .next
RUN chown nextjs:nodejs .next

# Pre-create data dirs so named volumes inherit correct ownership
RUN mkdir -p /data/reports && chown nextjs:nodejs /data/reports
RUN mkdir -p /data/js-recon-uploads && chown nextjs:nodejs /data/js-recon-uploads
RUN mkdir -p /data/js-recon-custom && chown nextjs:nodejs /data/js-recon-custom

# Leverage output traces to reduce image size
# https://nextjs.org/docs/advanced-features/output-file-tracing
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

# CLI utility scripts (admin setup, password reset)
COPY --from=builder --chown=nextjs:nodejs /app/scripts ./scripts

# Prisma schema + CLI for automatic migration on startup
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/node_modules/prisma/package.json /tmp/prisma-pkg.json
RUN PRISMA_VER=$(node -p "require('/tmp/prisma-pkg.json').version") && \
    npm install --no-save "prisma@${PRISMA_VER}" bcryptjs && \
    npm cache clean --force && rm /tmp/prisma-pkg.json

# Entrypoint: sync schema to PostgreSQL, then start server
RUN printf '#!/bin/sh\necho "Syncing Prisma schema..."\nnode node_modules/prisma/build/index.js db push --skip-generate --accept-data-loss --schema ./prisma/schema.prisma 2>&1\nexec node server.js\n' > /app/entrypoint.sh \
    && chmod +x /app/entrypoint.sh

USER nextjs

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

CMD ["/app/entrypoint.sh"]
