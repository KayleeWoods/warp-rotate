# WARP Rotator

Local HTTP sidecar that rotates the Cloudflare WARP **exit IP** on demand and reports the
result, so a caller can detect a 403/429 block and then rotate away from it.

FastAPI on `127.0.0.1:40100`. Exit-IP reads go through the local WARP proxy on
`127.0.0.1:40000` (SOCKS5 + HTTP, mode `WarpProxy`).

## Commands

```bash
./rotate-ctl start            # start in the background (writes the PID file)
./rotate-ctl status           # port, PID, RAM, /health, /current
./rotate-ctl rotate           # POST /rotate          (fast path)
./rotate-ctl rotate --full    # POST /rotate?full=true (re-registration)
./rotate-ctl test             # live self-test: health, current, check, rotate
./rotate-ctl logs             # tail -f the log file
./rotate-ctl stop             # stop and release the port
./rotate-ctl restart
```

## Endpoints

| Method | Path             | Purpose |
|--------|------------------|---------|
| GET    | `/health`        | `ok`, `warp_connected`, `proxy_up`, `uptime_s`, `idle_s`, `endpoint_override` |
| GET    | `/current`       | `ip`, `colo`, `family`, `rotated_at` (ISO), `age_s` |
| POST   | `/rotate`        | Fast rotation; `?full=true` forces re-registration |
| GET    | `/trace`         | Raw Cloudflare trace body through the proxy (text/plain) |
| POST   | `/check`         | `{url, method, timeout_s}` -> `{status_code, elapsed_s, ok, body}` |

`attempts` counts rotation commands issued (each `rotate-keys` run and each re-registration
run counts as one). `ok` in `/check` means `200 <= status_code < 400`; a request that never
completes reports `status_code` 0 with the error text in `body`.

## Conventions

- English only: identifiers, comments, logs, docs.
- Every `warp-cli` call is `warp-cli --accept-tos <subcommand>` and runs in a thread
  executor with a hard timeout - the event loop is never blocked by subprocess work.
- All rotations are serialized behind one `asyncio.Lock`; concurrent calls queue instead
  of interleaving commands.
- Exit IP is read through the proxy, never from the daemon's registration file.
- Timestamped logs; secrets are never logged (the registration file is never opened).

## Boundaries

- Do not stop, restart, or rebind the captcha-solver on `:8877`.
- Do not touch systemd units `hermes` or `9router`.
- Never `pkill -f server.py` - kill by listening port or by the PID file instead.
- One rotation at a time is a hard invariant; do not add a parallel path around the lock.
- Not a public service: binds `0.0.0.0:40100` on the host only, no auth layer, no TLS.

## Dependencies

- `/usr/bin/warp-cli` (2026.6.880.0) and the `warp-svc` daemon, connected in `WarpProxy`
  mode on port 40000.
- Python 3 with `fastapi`, `uvicorn`, `httpx` in `./.venv` (`requirements.txt`).
- `warp_client.py` is stdlib-only, so callers do not need the venv.

## Config

Environment variables (defaults in parentheses); no secrets are involved.

```bash
PORT=40100                     # listen port
IDLE_SHUTDOWN_S=1800           # idle seconds before self-shutdown (0 disables)
WARP_PROXY_URL=http://127.0.0.1:40000
WARP_PROXY_HOST=127.0.0.1
WARP_PROXY_PORT=40000
WARP_TRACE_URL=https://cloudflare.com/cdn-cgi/trace
WARP_CLI=/usr/bin/warp-cli
WARP_ROTATE_LOG=/tmp/warp_rotate.log
WARP_FAST_SETTLE_S=3.0         # wait after rotate-keys before reading the IP
WARP_FULL_SETTLE_S=4.0         # wait after connect in the re-registration path
WARP_CMD_TIMEOUT_S=30          # per warp-cli timeout
WARP_CONNECT_TIMEOUT_S=60      # timeout for registration new / connect
WARP_MAX_FAST_ATTEMPTS=3       # fast attempts before escalating
WARP_MAX_FULL_ATTEMPTS=2       # re-registration runs before giving up
WARP_ROTATE_URL=http://127.0.0.1:40100   # used by warp_client.py
```

## Error Handling

- Any failure path calls the recovery routine (mode proxy, proxy port, connect, verify)
  before the error response is returned, so WARP is never left disconnected.
- Fast path: `rotate-keys` is retried up to `WARP_MAX_FAST_ATTEMPTS`; if the exit IP still
  matches the previous one, the call escalates to re-registration automatically.
- `502` - the IP never changed; `503` - the exit IP could not be read through the proxy;
  `502` from `/trace` - the trace fetch failed.
- `/check` never raises for upstream failures; it reports `status_code: 0`.

## Troubleshooting

- `rotate-ctl status` shows `Health: UNREACHABLE` -> check `./rotate-ctl logs`; the
  process may have idle-shut down.
- `warp_connected: false` -> `warp-cli --accept-tos connect`, then re-check `/health`.
- `proxy_up: false` -> confirm `ss -lntp 'sport = :40000'`; re-apply with
  `warp-cli --accept-tos mode proxy` and `warp-cli --accept-tos proxy port 40000`.
- Rotation succeeds but the IP is identical -> another client is pinned to the same edge;
  check `endpoint_override` in `/health` and clear it with
  `warp-cli --accept-tos tunnel endpoint reset`.
- Port 40100 busy -> `fuser -k 40100/tcp`, then start again.
