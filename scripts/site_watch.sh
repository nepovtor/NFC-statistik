#!/bin/sh
set -eu

PATH="/Users/nepovtor/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
REPO_DIR="/Users/nepovtor/Downloads/nfc_app_stats"
LOCAL_URL="http://127.0.0.1:8001/"
TAILSCALE_TARGET="http://127.0.0.1:8001"
LOG_FILE="${HOME}/Library/Logs/nfc_app_stats-site-watch.log"
LOCK_DIR="${TMPDIR:-/tmp}/nfc_app_stats-site-watch.lock"
DOCKER_APP="/Applications/Docker.app"
TAILSCALE_APP="/Applications/Tailscale.app"

mkdir -p "$(dirname "$LOG_FILE")"

log() {
    printf "%s %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$LOG_FILE"
}

check_url() {
    curl -fsS --max-time 8 "$1" >/dev/null 2>&1
}

docker_ready() {
    docker info >/dev/null 2>&1
}

wait_for_docker() {
    attempt=0
    while [ "$attempt" -lt 45 ]; do
        if docker_ready; then
            return 0
        fi
        sleep 2
        attempt=$((attempt + 1))
    done
    return 1
}

ensure_docker() {
    if docker_ready; then
        return 0
    fi

    log "Docker daemon is not ready. Opening Docker.app."
    open -g -a "$DOCKER_APP" >/dev/null 2>&1 || true

    if wait_for_docker; then
        log "Docker daemon is ready."
        return 0
    fi

    log "Docker daemon did not become ready in time."
    return 1
}

wait_for_tailscale() {
    attempt=0
    while [ "$attempt" -lt 20 ]; do
        if tailscale status >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
        attempt=$((attempt + 1))
    done
    return 1
}

ensure_tailscale() {
    if ! command -v tailscale >/dev/null 2>&1; then
        log "tailscale command is not available in PATH."
        return 1
    fi

    if tailscale status >/dev/null 2>&1; then
        return 0
    fi

    log "Tailscale is not running. Opening Tailscale.app."
    open -g -a "$TAILSCALE_APP" >/dev/null 2>&1 || true

    if wait_for_tailscale; then
        log "Tailscale is running again."
        return 0
    fi

    log "Tailscale did not become ready in time."
    return 1
}

compose_up() {
    cd "$REPO_DIR"
    docker compose up -d >/dev/null 2>&1
}

compose_restart() {
    cd "$REPO_DIR"
    docker compose restart nfc_app >/dev/null 2>&1
}

ensure_local_site() {
    if ! ensure_docker; then
        return 1
    fi

    if check_url "$LOCAL_URL"; then
        return 0
    fi

    log "Local site is down. Running docker compose up -d."
    if ! compose_up; then
        log "Failed to run docker compose up -d."
        return 1
    fi

    sleep 4
    if check_url "$LOCAL_URL"; then
        log "Local site recovered after docker compose up -d."
        return 0
    fi

    log "Site is still unavailable. Restarting nfc_app."
    if ! compose_restart; then
        log "Failed to restart nfc_app."
        return 1
    fi

    sleep 4
    if check_url "$LOCAL_URL"; then
        log "Local site recovered after restart."
        return 0
    fi

    log "Local site is still unavailable after restart."
    return 1
}

ensure_tailscale_serve() {
    if ! ensure_tailscale; then
        return 1
    fi

    serve_status="$(tailscale serve status 2>/dev/null || true)"
    case "$serve_status" in
        *"proxy ${TAILSCALE_TARGET}"*)
            return 0
            ;;
    esac

    log "Tailscale Serve is missing. Restoring proxy to ${TAILSCALE_TARGET}."
    if tailscale serve --bg 8001 >/dev/null 2>&1; then
        log "Tailscale Serve restored."
        return 0
    fi

    log "Failed to restore Tailscale Serve."
    return 1
}

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    exit 0
fi
trap 'rmdir "$LOCK_DIR"' EXIT INT TERM

ensure_local_site || true
ensure_tailscale_serve || true
