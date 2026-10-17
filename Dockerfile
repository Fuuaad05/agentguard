FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/* && ln -s /usr/bin/python3 /usr/local/bin/python
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY server.js verifier.py ./
ENV NODE_ENV=production
EXPOSE 3001
CMD ["node", "server.js"]
