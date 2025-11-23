# Frontend/Dockerfile

# --- Stage 1: Deps ---
FROM node:18-alpine AS deps
WORKDIR /app

# Copy package files (path relative to root)
COPY Frontend/package.json Frontend/package-lock.json* ./
RUN npm ci

# --- Stage 2: Builder ---
FROM node:18-alpine AS builder
WORKDIR /app

# Copy node_modules from deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy Frontend source code (path relative to root)
COPY Frontend/ .

# Disable Next.js telemetry for privacy
ENV NEXT_TELEMETRY_DISABLED 1
RUN npm run build

# --- Stage 3: Runner (Production) ---
FROM node:18-alpine AS runner
WORKDIR /app
ENV NODE_ENV production
ENV NEXT_TELEMETRY_DISABLED 1

# Create a non-root user for security
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# Copy only the standalone build output
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000
ENV PORT 3000
# Listen on all interfaces
ENV HOSTNAME "0.0.0.0"

CMD ["node", "server.js"]
