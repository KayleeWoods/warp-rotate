#!/usr/bin/env bash
# Start the WARP rotation sidecar in the foreground (rotate-ctl wraps this).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
export PORT="${PORT:-40100}"
# Seconds without a request before the process shuts itself down (0 disables).
export IDLE_SHUTDOWN_S="${IDLE_SHUTDOWN_S:-1800}"
# Rotation tunables (see README.md).
export WARP_FAST_SETTLE_S="${WARP_FAST_SETTLE_S:-3.0}"
export WARP_FULL_SETTLE_S="${WARP_FULL_SETTLE_S:-4.0}"
export WARP_CMD_TIMEOUT_S="${WARP_CMD_TIMEOUT_S:-30}"
export WARP_CONNECT_TIMEOUT_S="${WARP_CONNECT_TIMEOUT_S:-60}"
export WARP_PROXY_PORT="${WARP_PROXY_PORT:-40000}"
export WARP_ROTATE_LOG="${WARP_ROTATE_LOG:-/tmp/warp_rotate.log}"
source .venv/bin/activate
exec python3 server.py
