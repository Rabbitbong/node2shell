#!/bin/bash
# Build and run the A/B lab with plain docker (no compose required).
# vuln node 24.22.0 on :3000, patched 24.22.1 on :3002. `--restart on-failure`
# is the crash-restart supervisor the PoC relies on.
set -e
cd "$(dirname "$0")"

VULN_IMAGE="node@sha256:925de64a85319052d6971ae81ef2417da956e8a3a2c4a0fac732327970f017f5"
FIXED_IMAGE="node:24.22.1-bookworm-slim"

docker build --platform linux/amd64 --build-arg NODE_IMAGE="$VULN_IMAGE"  -t node2shell:vuln  .
docker build --platform linux/amd64 --build-arg NODE_IMAGE="$FIXED_IMAGE" -t node2shell:fixed .

docker rm -f node2shell-vuln node2shell-fixed 2>/dev/null || true
docker run -d --name node2shell-vuln  --restart on-failure \
  -e PORT=3000 -e UV_THREADPOOL_SIZE=1 -p 127.0.0.1:3000:3000 node2shell:vuln
docker run -d --name node2shell-fixed --restart on-failure \
  -e PORT=3000 -p 127.0.0.1:3002:3000 node2shell:fixed

echo "vuln :3000   fixed :3002"
