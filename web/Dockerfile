# ============================================================
# RAGFlow Web Frontend Dockerfile
# ============================================================

FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json* ./

RUN npm ci

COPY . .

RUN npm run build

# ---- Production ----
FROM nginx:alpine

COPY --from=builder /app/dist /usr/share/nginx/html

COPY ../docker/nginx/ragflow-web.conf /etc/nginx/conf.d/default.conf 2>/dev/null || true

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;"]
