FROM node:24-bookworm-slim

RUN apt-get update \
    && apt-get install --yes --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && npm install --global @earendil-works/pi-coding-agent@0.84.3

WORKDIR /work

ENTRYPOINT ["pi"]

