# GIAI ĐOẠN 1: BUILD và Install dependencies (Cài đặt môi trường)
FROM node:20-alpine AS builder
WORKDIR /app

# Cài đặt công cụ cần thiết để build thư viện native (sqlite3)
RUN apk add --no-cache python3 make g++

# Copy package.json và cài đặt dependencies
COPY package*.json ./
RUN npm ci

# Copy toàn bộ source code
COPY . .

# ==========================================
# GIAI ĐOẠN 2:Production Runtime (Chạy thật)
# ==========================================
FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production

# Run tạo User thường (Non-root)
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Chỉ copy file cần thiết từ Giai đoạn 1
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/server.js ./

# Phân quyền cho user appuser
RUN chown -R appuser:appgroup /app

# Chuyển sang user thường
USER appuser

EXPOSE 3000
CMD ["node", "server.js"]