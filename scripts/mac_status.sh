#!/bin/sh
set -eu

PATH="/Users/nepovtor/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
REPO_DIR="/Users/nepovtor/Downloads/nfc_app_stats"

printf "Site:\n"
curl -fsS http://127.0.0.1:8001/
printf "\n---\nDocker:\n"
(cd "$REPO_DIR" && docker compose ps)
printf "\n---\nTailscale Serve:\n"
tailscale serve status
printf "\n---\nTailscale:\n"
tailscale status
printf "\n---\nLaunchAgent:\n"
launchctl print "gui/$(id -u)/com.nepovtor.nfc-site-watch" | sed -n '1,40p'
