FROM node:22.12-alpine3.21 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

FROM node:22.12-alpine3.21
LABEL org.opencontainers.image.source="https://github.com/example/app" \
      org.opencontainers.image.version="1.2.3" \
      org.opencontainers.image.description="Example application"
WORKDIR /app
COPY --from=build --chown=app:app /app /app
RUN addgroup -S app && adduser -S app -G app
USER app
EXPOSE 8080
HEALTHCHECK --interval=30s CMD wget -qO- http://localhost:8080/health || exit 1
CMD ["node", "server.js"]
