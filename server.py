"""WARP exit-IP rotation sidecar - FastAPI on 127.0.0.1:40100.

Rotates the Cloudflare WARP exit IP on demand through the local WARP proxy
(127.0.0.1:40000, SOCKS5 + HTTP) and exposes the result over HTTP so callers
can detect a 403/429 block and then rotate.

Two rotation paths:

* FAST (default) - ``warp-cli --accept-tos tunnel rotate-keys``: generates a new
  tunnel key pair while keeping the current account registration. Cheap and fast.
* FULL (``?full=true``) - re-registration sequence: disconnect, registration
  delete, registration new, mode proxy, proxy port, connect. Slower, used as the
  automatic escalation when the fast path cannot change the exit IP.

Every warp-cli invocation runs in a thread executor with a hard timeout, and all
rotation work is serialized behind a single asyncio lock so two concurrent
rotate calls can never interleave warp-cli commands. Any error path attempts to
leave WARP connected before returning.

No secret is ever logged. The daemon's registration file (which holds the
account license) is never read; only the single ``override_warp_endpoint`` key of
the settings file is inspected.
"""

import asyncio
import json
import logging
import os
import re
import signal
import socket
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

# ── Configuration (env-overridable) ──────────────────────────────────
WARP_CLI = os.getenv("WARP_CLI", "/usr/bin/warp-cli")
PROXY_HOST = os.getenv("WARP_PROXY_HOST", "127.0.0.1")
PROXY_PORT = int(os.getenv("WARP_PROXY_PORT", "40000"))
PROXY_URL = os.getenv("WARP_PROXY_URL", f"http://{PROXY_HOST}:{PROXY_PORT}")
TRACE_URL = os.getenv("WARP_TRACE_URL", "https://cloudflare.com/cdn-cgi/trace")
PORT = int(os.getenv("PORT", "40100"))
LOG_FILE = os.getenv("WARP_ROTATE_LOG", "/tmp/warp_rotate.log")
# Idle auto-shutdown: seconds without any request before the process exits. 0 disables.
IDLE_SHUTDOWN_S = int(os.getenv("IDLE_SHUTDOWN_S", "1800"))
# Hard timeouts for warp-cli calls (seconds).
CMD_TIMEOUT_S = float(os.getenv("WARP_CMD_TIMEOUT_S", "30"))
CONNECT_TIMEOUT_S = float(os.getenv("WARP_CONNECT_TIMEOUT_S", "60"))
# Settlement waits after a rotation command before reading the exit IP.
FAST_SETTLE_S = float(os.getenv("WARP_FAST_SETTLE_S", "3.0"))
FULL_SETTLE_S = float(os.getenv("WARP_FULL_SETTLE_S", "4.0"))
# How many times the fast path may retry before escalating to re-registration.
MAX_FAST_ATTEMPTS = int(os.getenv("WARP_MAX_FAST_ATTEMPTS", "3"))
# How many re-registration runs the full path may spend chasing a new IP.
MAX_FULL_ATTEMPTS = int(os.getenv("WARP_MAX_FULL_ATTEMPTS", "2"))
# Daemon settings file holding the optional edge endpoint override.
WARP_SETTINGS_PATH = os.getenv("WARP_SETTINGS_PATH", "/var/lib/cloudflare-warp/settings.json")

# ── Logging (timestamped; never logs secrets) ────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stderr)],
)
log = logging.getLogger("warp-rotate")

_DESCRIPTION = """
Local WARP exit-IP rotation sidecar.

Rotates the Cloudflare WARP exit IP on demand and reports the result so a caller
can detect a **403/429** block (via `POST /check`) and then rotate (via
`POST /rotate`). Traffic is read through the local WARP proxy on
`127.0.0.1:40000`.

* `POST /rotate` - **fast** path (`tunnel rotate-keys`), retried up to 3 times and
  escalated automatically to **full** re-registration when the exit IP refuses to
  change. `?full=true` forces re-registration directly.
* Rotations are serialized behind one lock; a failed rotation reconnects WARP
  before the error response is returned.
* The process shuts itself down after `IDLE_SHUTDOWN_S` seconds without a request.
"""

_TAGS = [
    {"name": "rotation", "description": "Rotate the WARP exit IP."},
    {"name": "probe", "description": "Read the current exit IP and probe through the proxy."},
    {"name": "monitoring", "description": "Liveness and proxy state."},
]

# ── Runtime state ────────────────────────────────────────────────────
_STARTED_AT = time.monotonic()
_last_activity = time.monotonic()
_rotate_lock = asyncio.Lock()
_state: dict[str, Any] = {
    "ip": None,
    "colo": None,
    "family": None,
    "rotated_at": time.time(),
}


def _touch() -> None:
    """Record that a request arrived (feeds the idle watchdog)."""
    global _last_activity
    _last_activity = time.monotonic()


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _family(ip: str) -> str:
    return "IPv6" if ":" in ip else "IPv4"


# ── warp-cli wrapper ─────────────────────────────────────────────────
async def _run_warp(*args: str, timeout: float = CMD_TIMEOUT_S) -> tuple[int, str]:
    """Run ``warp-cli --accept-tos <args...>`` off the event loop.

    Blocking subprocess work runs in a thread executor and is hard-bounded by
    ``timeout``. Never raises: a timeout returns rc 124, a missing binary rc 127.
    """
    cmd = [WARP_CLI, "--accept-tos", *args]

    def _run() -> tuple[int, str]:
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False
            )
            return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
        except subprocess.TimeoutExpired:
            return 124, f"warp-cli {' '.join(args)} timed out after {timeout}s"
        except OSError as exc:
            return 127, f"warp-cli could not be executed: {exc}"

    rc, out = await asyncio.to_thread(_run)
    log.info("warp-cli %s -> rc=%s (%s)", " ".join(args), rc, out.strip()[:200])
    return rc, out


async def _warp_connected() -> bool:
    """True when ``warp-cli status`` reports Connected (not Disconnected)."""
    _rc, out = await _run_warp("status")
    return re.search(r"\bConnected\b", out) is not None


async def _proxy_up() -> bool:
    """True when something is listening on the WARP proxy port."""

    def _try() -> bool:
        try:
            with socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=1.5):
                return True
        except OSError:
            return False

    return await asyncio.to_thread(_try)


async def _endpoint_override() -> Optional[str]:
    """The pinned Cloudflare edge endpoint, or None when no override is active.

    ``warp-cli`` has no getter for this; the daemon persists it as
    ``override_warp_endpoint`` in its settings file (root-owned, mode 0600), so
    the file is read directly and falls back to a non-interactive ``sudo -n``.
    Only that single key is touched - never the registration file.
    """

    def _read() -> Optional[str]:
        raw: Optional[str] = None
        try:
            with open(WARP_SETTINGS_PATH, encoding="utf-8") as fh:
                raw = fh.read()
        except OSError:
            try:
                proc = subprocess.run(
                    ["sudo", "-n", "cat", WARP_SETTINGS_PATH],
                    capture_output=True, text=True, timeout=5, check=False,
                )
                if proc.returncode == 0:
                    raw = proc.stdout
            except (OSError, subprocess.SubprocessError):
                return None
        if not raw:
            return None
        try:
            value = json.loads(raw).get("override_warp_endpoint")
        except (ValueError, AttributeError):
            return None
        return value if isinstance(value, str) and value else None

    return await asyncio.to_thread(_read)


# ── Exit-IP probe ────────────────────────────────────────────────────
def _parse_trace(text: str) -> dict[str, Any]:
    """Parse the plain-text Cloudflare trace body into {ip, colo, family, loc, warp}."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            fields[key.strip()] = value.strip()
    ip = fields.get("ip") or ""
    return {
        "ip": ip,
        "colo": fields.get("colo") or None,
        "family": _family(ip) if ip else None,
        "loc": fields.get("loc") or None,
        "warp": fields.get("warp") or None,
    }


async def _fetch_trace(timeout_s: float = 20.0) -> str:
    """Fetch the Cloudflare trace body through the WARP proxy."""
    async with httpx.AsyncClient(proxy=PROXY_URL, timeout=timeout_s) as client:
        resp = await client.get(TRACE_URL)
        resp.raise_for_status()
        return resp.text


async def _read_exit(timeout_s: float = 20.0) -> Optional[dict[str, Any]]:
    """Current exit info as seen through the proxy, or None when unreadable."""
    try:
        return _parse_trace(await _fetch_trace(timeout_s))
    except Exception as exc:  # noqa: BLE001 - any transport error means "unknown"
        log.warning("Could not read exit IP through the proxy: %s", exc)
        return None


def _store(info: dict[str, Any]) -> dict[str, Any]:
    """Record the exit info as the current state and stamp rotated_at."""
    _state.update(ip=info.get("ip"), colo=info.get("colo"), family=info.get("family"))
    _state["rotated_at"] = time.time()
    return info


async def _restore_connected() -> bool:
    """Best effort recovery: ensure proxy mode + port, connect, verify.

    Called on every error path so the sidecar never leaves WARP down.
    """
    log.warning("Restoring WARP to a known-good connected state")
    await _run_warp("mode", "proxy")
    await _run_warp("proxy", "port", str(PROXY_PORT))
    await _run_warp("connect", timeout=CONNECT_TIMEOUT_S)
    await asyncio.sleep(3)
    connected = await _warp_connected()
    proxy_up = await _proxy_up()
    log.info("Recovery result: connected=%s proxy_up=%s", connected, proxy_up)
    return connected and proxy_up


async def _reregister() -> Optional[dict[str, Any]]:
    """FULL rotation: tear the registration down and create a new one."""
    sequence: list[tuple[tuple[str, ...], float]] = [
        (("disconnect",), CMD_TIMEOUT_S),
        (("registration", "delete"), CMD_TIMEOUT_S),
        (("registration", "new"), CONNECT_TIMEOUT_S),
        (("mode", "proxy"), CMD_TIMEOUT_S),
        (("proxy", "port", str(PROXY_PORT)), CMD_TIMEOUT_S),
        (("connect",), CONNECT_TIMEOUT_S),
    ]
    for args, timeout in sequence:
        rc, out = await _run_warp(*args, timeout=timeout)
        if rc != 0:
            raise RuntimeError(f"re-registration step '{' '.join(args)}' failed (rc={rc}): {out.strip()[:160]}")
    await asyncio.sleep(FULL_SETTLE_S)
    return await _read_exit()


# ── App ──────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(_app: FastAPI):
    info = await _read_exit()
    if info and info.get("ip"):
        _store(info)
        log.info("Initial exit IP %s (colo=%s, family=%s)", info["ip"], info["colo"], info["family"])
    else:
        log.warning("Could not determine the initial exit IP through the proxy")

    async def _idle_watchdog() -> None:
        if IDLE_SHUTDOWN_S <= 0:
            log.info("Idle auto-shutdown disabled (IDLE_SHUTDOWN_S=%s)", IDLE_SHUTDOWN_S)
            return
        log.info("Idle auto-shutdown enabled: exit after %ss without a request", IDLE_SHUTDOWN_S)
        while True:
            await asyncio.sleep(10)
            idle = time.monotonic() - _last_activity
            if idle >= IDLE_SHUTDOWN_S and not _rotate_lock.locked():
                log.info("Idle for %.1fs (limit %ss) - shutting down", idle, IDLE_SHUTDOWN_S)
                os.kill(os.getpid(), signal.SIGTERM)
                return

    task = asyncio.create_task(_idle_watchdog())
    try:
        yield
    finally:
        task.cancel()
        log.info("WARP rotation sidecar stopping")


app = FastAPI(
    title="WARP Rotator",
    description=_DESCRIPTION,
    version="1.0.0",
    openapi_tags=_TAGS,
    lifespan=lifespan,
    servers=[{"url": f"http://127.0.0.1:{PORT}", "description": "Local (no auth)"}],
    swagger_ui_parameters={
        "docExpansion": "list",
        "tryItOutEnabled": True,
        "displayRequestDuration": True,
        "filter": True,
    },
)


@app.middleware("http")
async def _activity_middleware(request, call_next):
    _touch()
    return await call_next(request)


# ── Models ───────────────────────────────────────────────────────────
class HealthResponse(BaseModel):
    ok: bool = Field(..., description="warp_connected and proxy_up")
    warp_connected: bool = Field(..., description="warp-cli status reports Connected")
    proxy_up: bool = Field(..., description=f"something listens on {PROXY_HOST}:{PROXY_PORT}")
    uptime_s: float = Field(..., description="Seconds since process start")
    idle_s: float = Field(..., description="Seconds since the last request")
    endpoint_override: Optional[str] = Field(None, description="Pinned edge endpoint (ip:port), or null")


class CurrentResponse(BaseModel):
    ip: str = Field(..., description="Exit IP as seen by Cloudflare")
    colo: Optional[str] = Field(None, description="Cloudflare colo (IATA) serving the exit")
    family: str = Field(..., description="IPv4 or IPv6")
    rotated_at: str = Field(..., description="ISO-8601 UTC timestamp of the last rotation")
    age_s: float = Field(..., description="Seconds since rotated_at")


class RotateResponse(BaseModel):
    ip: str = Field(..., description="New exit IP")
    colo: Optional[str] = Field(None, description="Cloudflare colo serving the new exit")
    elapsed_s: float = Field(..., description="Wall-clock seconds for the whole call")
    method: str = Field(..., description="rotate-keys (fast) or reregister (full)")
    attempts: int = Field(..., description="Rotation commands issued (each rotate-keys run and each re-registration run counts as one)")


class CheckRequest(BaseModel):
    url: str = Field(..., description="URL to fetch through the WARP proxy", examples=["https://cloudflare.com/cdn-cgi/trace"])
    method: str = Field("GET", description="HTTP method")
    timeout_s: float = Field(30.0, description="Per-request timeout in seconds")


class CheckResponse(BaseModel):
    status_code: int = Field(..., description="Upstream status; 0 when the request never completed")
    elapsed_s: float = Field(..., description="Wall-clock seconds")
    ok: bool = Field(..., description="True when 200 <= status_code < 400")
    body: str = Field(..., description="Response body truncated to 200 characters (or the error text)")


# ── Endpoints ────────────────────────────────────────────────────────
@app.get("/health", response_model=HealthResponse, tags=["monitoring"], operation_id="health",
         summary="Liveness, WARP connection and proxy state")
async def health() -> HealthResponse:
    """Report whether WARP is connected and the local proxy port is accepting."""
    connected, proxy_up, override = await asyncio.gather(
        _warp_connected(), _proxy_up(), _endpoint_override()
    )
    return HealthResponse(
        ok=bool(connected and proxy_up),
        warp_connected=connected,
        proxy_up=proxy_up,
        uptime_s=round(time.monotonic() - _STARTED_AT, 1),
        idle_s=round(time.monotonic() - _last_activity, 1),
        endpoint_override=override,
    )


@app.get("/current", response_model=CurrentResponse, tags=["probe"], operation_id="current",
         summary="Current exit IP, colo and rotation age")
async def current() -> CurrentResponse:
    """The exit IP last observed through the proxy, with its rotation age."""
    info = await _read_exit()
    if info and info.get("ip"):
        if info["ip"] != _state.get("ip"):
            # The IP changed outside this service (e.g. a reconnect) - re-stamp it.
            log.info("Exit IP moved outside this service: %s -> %s", _state.get("ip"), info["ip"])
            _store(info)
        else:
            _state.update(colo=info.get("colo"), family=info.get("family"))
    if not _state.get("ip"):
        raise HTTPException(503, "exit IP unavailable - WARP proxy not answering")
    return CurrentResponse(
        ip=_state["ip"],
        colo=_state.get("colo"),
        family=_state.get("family") or _family(_state["ip"]),
        rotated_at=_iso(_state["rotated_at"]),
        age_s=round(time.time() - _state["rotated_at"], 1),
    )


async def _rotate_locked(force_full: bool) -> RotateResponse:
    """Run one rotation end to end. Caller must hold ``_rotate_lock``."""
    started = time.monotonic()
    before = await _read_exit()
    if before is None or not before.get("ip"):
        await _restore_connected()
        raise HTTPException(503, "cannot read the current exit IP through the WARP proxy")
    previous_ip = before["ip"]
    attempts = 0
    last_error: Optional[str] = None

    if not force_full:
        for _ in range(MAX_FAST_ATTEMPTS):
            attempts += 1
            rc, out = await _run_warp("tunnel", "rotate-keys")
            if rc != 0:
                last_error = f"rotate-keys rc={rc}: {out.strip()[:160]}"
                log.warning("Fast rotation attempt %s failed: %s", attempts, last_error)
                continue
            await asyncio.sleep(FAST_SETTLE_S)
            info = await _read_exit()
            if info and info.get("ip") and info["ip"] != previous_ip:
                _store(info)
                elapsed = round(time.monotonic() - started, 2)
                log.info("Fast rotation ok: %s -> %s in %ss (%s attempt(s))",
                         previous_ip, info["ip"], elapsed, attempts)
                return RotateResponse(ip=info["ip"], colo=info.get("colo"), elapsed_s=elapsed,
                                      method="rotate-keys", attempts=attempts)
            log.info("Fast rotation attempt %s left the exit IP unchanged (%s)",
                     attempts, previous_ip)
        log.warning("Fast path exhausted after %s attempts - escalating to re-registration",
                    MAX_FAST_ATTEMPTS)

    for _ in range(MAX_FULL_ATTEMPTS):
        attempts += 1
        try:
            info = await _reregister()
        except RuntimeError as exc:
            last_error = str(exc)
            log.error("Re-registration attempt %s failed: %s", attempts, last_error)
            await _restore_connected()
            continue
        if info and info.get("ip") and info["ip"] != previous_ip:
            _store(info)
            elapsed = round(time.monotonic() - started, 2)
            log.info("Full rotation ok: %s -> %s in %ss (%s attempt(s))",
                     previous_ip, info["ip"], elapsed, attempts)
            return RotateResponse(ip=info["ip"], colo=info.get("colo"), elapsed_s=elapsed,
                                  method="reregister", attempts=attempts)
        log.warning("Re-registration attempt %s left the exit IP unchanged (%s)", attempts, previous_ip)

    # Nothing worked: make sure WARP is left connected, then report the failure.
    await _restore_connected()
    info = await _read_exit()
    if info and info.get("ip"):
        _store(info)
    detail = f"exit IP did not change after {attempts} attempt(s); last IP {previous_ip}"
    if last_error:
        detail += f"; last error: {last_error}"
    raise HTTPException(502, detail)


@app.post("/rotate", response_model=RotateResponse, tags=["rotation"], operation_id="rotate",
          summary="Rotate the WARP exit IP (fast by default, ?full=true forces re-registration)")
async def rotate(full: bool = Query(False, description="Force the full re-registration path")):
    """Rotate the exit IP.

    Fast path: ``tunnel rotate-keys``, ~3s settle, verify the IP actually changed,
    retry up to 3 times, then escalate to the full re-registration path.
    """
    async with _rotate_lock:
        return await _rotate_locked(full)


@app.get("/trace", response_class=PlainTextResponse, tags=["probe"], operation_id="trace",
         summary="Raw Cloudflare trace body fetched through the proxy")
async def trace() -> PlainTextResponse:
    """Return the untouched plain-text trace body (``ip=``, ``colo=``, ``warp=``, ...)."""
    try:
        body = await _fetch_trace()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(502, f"trace fetch through the proxy failed: {exc}")
    return PlainTextResponse(body, media_type="text/plain")


@app.post("/check", response_model=CheckResponse, tags=["probe"], operation_id="check",
          summary="Probe any URL through the proxy (detect 403/429 blocks)")
async def check(req: CheckRequest) -> CheckResponse:
    """Fetch ``url`` through the WARP proxy and report the status.

    Exists so a caller can spot a 403/429 block and then decide to rotate.
    Redirects are not followed, so the reported status is the upstream one.
    A request that never completes reports ``status_code`` 0 with the error text.
    """
    started = time.monotonic()
    try:
        async with httpx.AsyncClient(proxy=PROXY_URL, timeout=req.timeout_s,
                                     follow_redirects=False) as client:
            resp = await client.request(req.method.upper(), req.url)
        return CheckResponse(
            status_code=resp.status_code,
            elapsed_s=round(time.monotonic() - started, 2),
            ok=200 <= resp.status_code < 400,
            body=resp.text[:200],
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("check %s %s failed: %s", req.method, req.url, exc)
        return CheckResponse(
            status_code=0,
            elapsed_s=round(time.monotonic() - started, 2),
            ok=False,
            body=f"{type(exc).__name__}: {exc}"[:200],
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")
