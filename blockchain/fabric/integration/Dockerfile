FROM node:24-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /work/fabric/integration
COPY integration/package.json integration/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY . /work/fabric/
ENV NODE_PATH=/work/fabric/integration/node_modules
