# ─────────────────────────────────────────────────────────────────────────────
# ThreatAtlas — Multi-Stage Dockerfile
#
# Stage 1 (build):  Install deps + compile TypeScript + build Vite bundle
# Stage 2 (runtime): Copy built assets, run Express server or BullMQ worker
#
# Build: docker build -t threatatlas .
# Run:   docker-compose up --build  (recommended — includes Redis)
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM node:20-alpine AS build

WORKDIR /app

# Install all deps (including devDependencies needed for tsc + vite)
COPY package*.json ./
RUN npm ci

# Copy source and compile
COPY . .
RUN npm run build

# Prune devDependencies — only keep production deps for runtime image
RUN npm prune --omit=dev

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM node:20-alpine AS runtime

WORKDIR /app

# Non-root user for security
RUN addgroup -S atlas && adduser -S atlas -G atlas

# Copy compiled frontend bundle
COPY --from=build /app/dist ./dist

# Copy server-side files and production node_modules
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/server.js ./server.js
COPY --from=build /app/worker.js ./worker.js
COPY --from=build /app/package.json ./package.json

# Environment defaults (override via docker-compose.yml or -e flags)
ENV NODE_ENV=production \
    PORT=3000 \
    REDIS_URL=redis://redis:6379

# The CMD is overridden per service in docker-compose.yml:
#   api    → node server.js
#   worker → node worker.js
CMD ["node", "server.js"]

EXPOSE 3000

# Health check — confirms the Express API is responding
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/api/scan/queue-health || exit 1

USER atlas
