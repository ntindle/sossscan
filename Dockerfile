# The Secure Open Source guide as one small container: the Next.js server and the page.
# /data, which the host mounts as a persistent volume, holds caches only (scan results, the OSS-Fuzz list, AI fix
# usage). Every secret comes from the environment. Build from the repo root: docker build -t sosf-guide .
# As the guide recommends, the base image is pinned by digest (a release at least 7 days old), and dependencies
# install exactly as locked, with no install scripts (.npmrc).
FROM node:24.22.1-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c AS build
ENV NEXT_TELEMETRY_DISABLED=1
WORKDIR /srv/site
COPY package.json package-lock.json .npmrc ./
RUN npm ci
COPY . .
RUN npm run build && npm prune --omit=dev

FROM node:24.22.1-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    SOSF_DATA_DIR=/data \
    TRUST_PROXY_HEADERS=1
RUN mkdir -p /data && chown node:node /data
WORKDIR /srv/site
COPY --from=build /srv/site/package.json /srv/site/next.config.ts ./
COPY --from=build /srv/site/node_modules ./node_modules
COPY --from=build /srv/site/.next ./.next
COPY --from=build /srv/site/public ./public
# The text pages' Markdown: they're prerendered, so only a page that renders per request would read it.
COPY --from=build /srv/site/content ./content
EXPOSE 8080
# Start as root only to hand the mounted volume to the node user, then drop to that user for good.
CMD ["sh", "-c", "chown -R node:node /data && exec setpriv --reuid=node --regid=node --init-groups node_modules/.bin/next start --hostname 0.0.0.0 --port 8080"]
