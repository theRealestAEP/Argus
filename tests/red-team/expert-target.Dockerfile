FROM node:24-bookworm-slim AS build

WORKDIR /build

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build

FROM node:24-bookworm-slim

RUN apt-get update \
    && apt-get install --yes --no-install-recommends nftables procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY package.json ./
COPY --from=build /build/node_modules ./node_modules
COPY --from=build /build/dist ./dist
COPY tests/e2e/expert-target.mjs ./host-runtime.mjs
COPY tests/e2e/workload/expert-http.mjs ./services/expert-http.mjs
COPY tests/e2e/workload/expert-jwt.mjs ./services/identity.mjs
COPY tests/e2e/workload/expert-ssrf.mjs ./services/renderer.mjs
COPY tests/e2e/workload/expert-double-decode.mjs ./services/router.mjs

CMD ["node", "host-runtime.mjs"]
