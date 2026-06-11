# Harbor console frontend (Next.js). Static-first; proxies /api to the backend service.
FROM node:20-slim AS build

WORKDIR /app
COPY console/frontend/package.json console/frontend/package-lock.json* ./
RUN npm install --no-audit --no-fund

COPY console/frontend ./
# API base points at the backend service on the compose network.
ENV HARBOR_API=http://backend:8000
RUN npm run build

FROM node:20-slim AS run
WORKDIR /app
ENV NODE_ENV=production \
    HARBOR_API=http://backend:8000
COPY --from=build /app ./
EXPOSE 8080
CMD ["npm", "run", "start"]
