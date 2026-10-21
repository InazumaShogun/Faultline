FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
COPY scripts ./scripts
COPY public ./public
COPY examples ./examples
RUN npm run build

FROM node:24-bookworm-slim
ENV NODE_ENV=production PORT=4317 FAULTLINE_CONTAINER=1
WORKDIR /app
COPY --from=build --chown=node:node /app/dist ./dist
COPY package.json ./
USER node
EXPOSE 4317
HEALTHCHECK --interval=30s --timeout=5s CMD node -e "fetch('http://127.0.0.1:4317/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/src/server.js"]
