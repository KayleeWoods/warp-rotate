"""Client helper for the local WARP rotation sidecar (127.0.0.1:40100).

Standard library only, so it can be imported from any Python 3 on this host.

    from warp_client import rotate, current, request_with_rotate

    print(current())
    print(rotate())                       # fast path
    print(rotate(full=True))              # force re-registration

    # Retry a blocked request after rotating the exit IP:
    def fetch():
        return requests.get("https://target.example.com/api", timeout=30)

    resp = request_with_rotate(fetch, blocked_statuses=(403, 429), max_attempts=4)
"""

import json
import os
import urllib.error
import urllib.request
from typing import Any, Callable, Iterable, Optional

DEFAULT_BASE_URL = os.getenv("WARP_ROTATE_URL", "http://127.0.0.1:40100")
DEFAULT_BLOCKED_STATUSES = (403, 429)


def _request(path: str, method: str = "GET", payload: Optional[dict] = None,
             base_url: Optional[str] = None, timeout_s: float = 60.0) -> Any:
    """Call one sidecar endpoint and return the decoded JSON body."""
    url = (base_url or DEFAULT_BASE_URL).rstrip("/") + path
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")[:300]
        raise RuntimeError(f"{method} {path} failed: HTTP {exc.code} {body}") from exc


def health(base_url: Optional[str] = None, timeout_s: float = 10.0) -> dict:
    """Service + WARP state: {ok, warp_connected, proxy_up, uptime_s, idle_s, endpoint_override}."""
    return _request("/health", base_url=base_url, timeout_s=timeout_s)


def current(base_url: Optional[str] = None, timeout_s: float = 15.0) -> dict:
    """Current exit: {ip, colo, family, rotated_at, age_s}."""
    return _request("/current", base_url=base_url, timeout_s=timeout_s)


def rotate(full: bool = False, base_url: Optional[str] = None,
           timeout_s: float = 300.0) -> dict:
    """Rotate the WARP exit IP. Returns {ip, colo, elapsed_s, method, attempts}.

    ``full=True`` forces the slow re-registration path; the default uses
    ``tunnel rotate-keys`` and escalates automatically when the IP will not change.
    """
    path = "/rotate?full=true" if full else "/rotate"
    return _request(path, method="POST", base_url=base_url, timeout_s=timeout_s)


def check(url: str, method: str = "GET", timeout_s: float = 30.0,
          base_url: Optional[str] = None) -> dict:
    """Fetch ``url`` through the WARP proxy: {status_code, elapsed_s, ok, body}."""
    return _request("/check", method="POST", base_url=base_url, timeout_s=timeout_s + 10,
                    payload={"url": url, "method": method, "timeout_s": timeout_s})


def _status_of(response: Any) -> Optional[int]:
    """Read the status code off a response object or a mapping."""
    if response is None:
        return None
    status = getattr(response, "status_code", None)
    if status is None and isinstance(response, dict):
        status = response.get("status_code")
    try:
        return int(status) if status is not None else None
    except (TypeError, ValueError):
        return None


def request_with_rotate(request_fn: Callable[[], Any],
                        blocked_statuses: Iterable[int] = DEFAULT_BLOCKED_STATUSES,
                        max_attempts: int = 3,
                        rotate_fn: Optional[Callable[..., dict]] = None,
                        on_rotate: Optional[Callable[[dict], None]] = None) -> Any:
    """Call ``request_fn`` and rotate the exit IP whenever it is blocked.

    ``request_fn`` takes no arguments and returns either a response object with a
    ``status_code`` attribute or a mapping with a ``status_code`` key. While the
    status is in ``blocked_statuses`` (default 403 and 429) the exit IP is
    rotated and the callable is retried, up to ``max_attempts`` calls in total.

    Returns the last response. ``on_rotate`` receives each rotation result dict.
    Raises ``RuntimeError`` when the status stays blocked after the last attempt.
    """
    blocked = set(blocked_statuses or ())
    do_rotate = rotate_fn or rotate
    response = None
    status: Optional[int] = None

    for attempt in range(1, max(1, int(max_attempts)) + 1):
        response = request_fn()
        status = _status_of(response)
        if status not in blocked:
            return response
        if attempt >= max_attempts:
            break
        info = do_rotate()
        if on_rotate is not None:
            on_rotate(info)

    raise RuntimeError(
        f"still blocked after {max_attempts} attempt(s): last status {status} in {sorted(blocked)}"
    )
