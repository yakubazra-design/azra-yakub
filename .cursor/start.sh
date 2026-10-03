#!/usr/bin/env bash
set -euo pipefail

cd /workspace

if ! tmux has-session -t realitycheck_api 2>/dev/null; then
  tmux new-session -d -s realitycheck_api \
    "python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 2>&1 | tee /tmp/realitycheck-api.log"
fi

if ! tmux has-session -t realitycheck_frontend 2>/dev/null; then
  tmux new-session -d -s realitycheck_frontend \
    "cd frontend && python3 -m http.server 8080 --bind 0.0.0.0 2>&1 | tee /tmp/realitycheck-frontend.log"
fi

for _ in $(seq 1 45); do
  if curl -sf http://127.0.0.1:8000/api/health >/dev/null; then
    exit 0
  fi
  sleep 1
done

echo "API health check timed out" >&2
exit 1
