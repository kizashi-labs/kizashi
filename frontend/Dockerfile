# syntax=docker/dockerfile:1
# EDR Platform — Frontend Next.js build

FROM node:26-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --legacy-peer-deps && \
    npm install --no-save @next/swc-linux-x64-musl 2>/dev/null || true

FROM node:26-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

ARG NEXT_PUBLIC_API_URL=http://localhost:8080
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL

ARG API_URL=http://localhost:8080
ENV API_URL=$API_URL

# 開発・デモフェーズ中はモックデータを有効にする
# 本番リリース時は NEXT_PUBLIC_USE_MOCK=false に変更すること
ENV NEXT_PUBLIC_USE_MOCK=true
ENV NEXT_TELEMETRY_DISABLED=1

RUN npm run build

FROM node:26-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

CMD ["node", "server.js"]

# ── Production target (alias for runner) ─────────
# Used by docker-compose.prod.yml (target: production)
FROM runner AS production
