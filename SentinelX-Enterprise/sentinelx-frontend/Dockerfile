FROM node:24-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY index.html tsconfig.json vite.config.ts postcss.config.cjs tailwind.config.cjs ./
COPY src src

