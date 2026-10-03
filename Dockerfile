FROM node:22-bookworm-slim
ENV NODE_ENV=production
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY src ./src
COPY sql ./sql
COPY scripts ./scripts
COPY public ./public
EXPOSE 8787
CMD ["npm", "start"]
