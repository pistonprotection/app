FROM node:22-alpine AS builder

RUN npm install -g pnpm

WORKDIR /app

COPY frontend/package.json frontend/pnpm-lock.yaml ./

RUN pnpm install --frozen-lockfile

COPY frontend/ .

RUN pnpm build

# Runtime image
FROM node:22-alpine

RUN npm install -g pnpm

WORKDIR /app

COPY --from=builder /app/.output ./.output
COPY --from=builder /app/package.json ./

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

USER 1000:1000

CMD ["node", ".output/server/index.mjs"]
