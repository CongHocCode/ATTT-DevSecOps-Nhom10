# Build native production dependencies in a disposable stage.
FROM node:20-alpine AS dependencies
WORKDIR /app

RUN apk add --no-cache python3 make g++
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Keep the runtime small and run the application without root privileges.
FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY --from=dependencies --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --chown=appuser:appgroup package.json server.js ./

USER appuser
EXPOSE 3000
CMD ["node", "server.js"]
