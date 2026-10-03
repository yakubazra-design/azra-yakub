#!/usr/bin/env bash
set -euo pipefail

cd /workspace

python3 -m pip install --user -r backend/requirements.txt

if [[ ! -f .env ]]; then
  cp .env.example .env
fi
