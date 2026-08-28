FROM node:24-bookworm-slim

WORKDIR /workspace

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

CMD ["./tests/e2e/linux-container.sh"]
