#!/bin/sh
set -eu

REMOTE_HOST="${1:?Usage: deploy/push_to_server.sh user@host [/remote/path]}"
REMOTE_DIR="${2:-/opt/nfc_app_stats}"

ssh "$REMOTE_HOST" "mkdir -p '$REMOTE_DIR'"

rsync -az --delete \
    --exclude '.git/' \
    --exclude '.venv/' \
    --exclude '__pycache__/' \
    --exclude '*.pyc' \
    --exclude 'data/' \
    --exclude '.env.production' \
    --exclude 'caddy_data/' \
    --exclude 'caddy_config/' \
    ./ "$REMOTE_HOST:$REMOTE_DIR/"

printf "Project copied to %s:%s\n" "$REMOTE_HOST" "$REMOTE_DIR"
