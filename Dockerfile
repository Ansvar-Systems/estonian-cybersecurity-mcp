# ─────────────────────────────────────────────────────────────────────────────
# estonian-cybersecurity-mcp — multi-stage Dockerfile
# ─────────────────────────────────────────────────────────────────────────────
# Build:  docker build -t estonian-cybersecurity-mcp .
# Run:    docker run --rm -p 3000:3000 estonian-cybersecurity-mcp
#
# Multi-stage: builder stage compiles native better-sqlite3 binding via
# `npm rebuild`; runtime stage copies the prebuilt node_modules tree so the
# binding ships in the final image. The DB is baked at /app/data/ria.db.
# Override with RIA_DB_PATH for a custom location.
# ─────────────────────────────────────────────────────────────────────────────

# --- Stage 1: Build ---
FROM node:20-alpine AS builder

# better-sqlite3 native build needs python3 + build toolchain on Alpine
RUN apk add --no-cache python3 make g++ libc6-compat

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci && npm rebuild better-sqlite3
COPY tsconfig.json tsconfig.build.json ./
COPY src/ src/
RUN npm run build

# --- Stage 2: Production ---
FROM node:20-alpine AS production

# Runtime needs libstdc++ for the prebuilt better-sqlite3 binding
RUN apk add --no-cache libstdc++ libc6-compat

WORKDIR /app
ENV NODE_ENV=production
ENV RIA_DB_PATH=/app/data/ria.db

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY package.json ./
COPY data/database.db data/ria.db

# Non-root user for security
RUN addgroup -S -g 1001 mcp && \
    adduser -S -u 1001 -G mcp mcp && \
    chown -R mcp:mcp /app
USER mcp

# Health check: verify HTTP server responds
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health',r=>{process.exit(r.statusCode===200?0:1)}).on('error',()=>process.exit(1))"

CMD ["node", "dist/src/http-server.js"]
