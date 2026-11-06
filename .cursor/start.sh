#!/usr/bin/env bash
# Per-boot dev servers: FastAPI backend + static frontend (plain ES5 app).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TMUX_CMD=(tmux)
if [[ -f /exec-daemon/tmux.portal.conf ]]; then
  TMUX_CMD+=( -f /exec-daemon/tmux.portal.conf )
fi

export PATH="$ROOT/.venv/bin:${PATH:-}"

if ! "${TMUX_CMD[@]}" has-session -t rc_api 2>/dev/null; then
  "${TMUX_CMD[@]}" new-session -d -s rc_api -c "$ROOT" \
    "exec env PYTHONPATH=backend uvicorn app.main:app --host 127.0.0.1 --port 8000 2>&1 | tee /tmp/rc-api.log"
fi

if ! "${TMUX_CMD[@]}" has-session -t rc_frontend 2>/dev/null; then
  "${TMUX_CMD[@]}" new-session -d -s rc_frontend -c "$ROOT/frontend" \
    "exec python3 -m http.server 5500 --bind 127.0.0.1 2>&1 | tee /tmp/rc-frontend.log"
fi

for _ in $(seq 1 45); do
  if curl -fsS "http://127.0.0.1:8000/api/health" >/dev/null 2>&1; then
    exit 0
  fi
  sleep 1
done

echo "rc_api: backend did not respond on http://127.0.0.1:8000/api/health" >&2
exit 1
