#!/bin/sh
set -eu

APP_DIR="${1:-$(pwd)}"

cd "$APP_DIR"

if [ ! -f ".env.production" ]; then
    echo ".env.production not found in $APP_DIR"
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is not installed on the server"
    exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
    echo "docker compose is not available on the server"
    exit 1
fi

mkdir -p data caddy_data caddy_config

docker compose -f compose.production.yaml --env-file .env.production up -d --build

if command -v tailscale >/dev/null 2>&1; then
    tailscale serve --bg 8001 >/dev/null 2>&1 || true
    TS_HOSTNAME="$(tailscale status --json 2>/dev/null | awk -F'\"' '/"DNSName":/ {print $4; exit}' | sed 's/\.$//')"
    if [ -n "$TS_HOSTNAME" ]; then
        echo "Tailscale admin URL: https://$TS_HOSTNAME/admin/login"
    fi
fi

PUBLIC_URL="$(awk -F= '/^PUBLIC_BASE_URL=/{print $2}' .env.production)"
if [ -n "$PUBLIC_URL" ]; then
    echo "Public site URL: $PUBLIC_URL"
fi
