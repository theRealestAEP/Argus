FROM node:24-bookworm-slim

RUN apt-get update \
    && apt-get install --yes --no-install-recommends nftables procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN install -d -m 0755 /opt/operations /var/lib/operations /var/log/operations \
    && install -m 0644 tests/e2e/workload/operations-api.mjs /opt/operations/operations-api.mjs \
    && install -m 0644 tests/e2e/workload/local-assistant.mjs /opt/operations/local-assistant.mjs
RUN npm run build

CMD ["./tests/e2e/linux-container.sh"]
