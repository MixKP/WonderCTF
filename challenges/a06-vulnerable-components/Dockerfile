# syntax=docker/dockerfile:1
#
# This image intentionally ships a known-vulnerable dependency (lodash
# 4.17.4, CVE-2018-3721) — that's the point of this challenge. The Trivy
# scan is expected to flag it; see the repo-root .trivyignore for the
# documented, deliberate exception that keeps CI green while the finding
# stays visible.
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev
COPY server.js ./
RUN addgroup -g 1001 -S app && adduser -u 1001 -S app -G app
USER app
EXPOSE 8080
CMD ["node", "server.js"]
