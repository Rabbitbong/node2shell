# node2shell vulnerable fixture.
#
# Default build pins the exact official node 24.22.0 x86-64 binary the PoC's ROP
# profile was calibrated against (binary sha256 67ca5783...). Override NODE_IMAGE
# to node:24.22.1-bookworm-slim for the patched (fixed) A/B counterpart.
ARG NODE_IMAGE=node@sha256:925de64a85319052d6971ae81ef2417da956e8a3a2c4a0fac732327970f017f5
FROM ${NODE_IMAGE}
WORKDIR /app
COPY app/package*.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY app/server.js ./
COPY app/public ./public
EXPOSE 3000
USER node
# In-container supervisor: restart the worker immediately on crash (the PoC
# crashes it repeatedly to re-roll ASLR). This avoids Docker's restart backoff,
# which otherwise grows past the client's health-wait after a few crashes.
CMD ["sh", "-c", "while true; do node /app/server.js; echo '[supervisor] worker exited, restarting' >&2; done"]
