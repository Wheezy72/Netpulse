# Build stage
FROM node:20-alpine AS build

WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json* ./ 2>/dev/null || true
RUN npm install

COPY frontend ./
RUN npm run build

# Runtime stage
FROM nginx:1.27-alpine

COPY --from=build /frontend/dist /usr/share/nginx/html

EXPOSE 80