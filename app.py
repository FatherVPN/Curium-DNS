from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
UPSTREAM_DOH = os.getenv("UPSTREAM_DOH", "https://cloudflare-dns.com/dns-query")
TURNSTILE_SITE_KEY = os.getenv("TURNSTILE_SITE_KEY", "").strip()
TURNSTILE_SECRET_KEY = os.getenv("TURNSTILE_SECRET_KEY", "").strip()
TURNSTILE_ALLOWED_HOSTS = {
    host.strip().lower()
    for host in os.getenv("TURNSTILE_ALLOWED_HOSTS", "").split(",")
    if host.strip()
}
ACCESS_GATE_SECRET = os.getenv("ACCESS_GATE_SECRET", "")
ACCESS_COOKIE_NAME = "curium_verified"
ACCESS_COOKIE_MAX_AGE = 12 * 60 * 60
MAX_DNS_MESSAGE_SIZE = 4096
RATE_LIMIT = int(os.getenv("RATE_LIMIT_PER_MINUTE", "90"))
WINDOW_SECONDS = 60

# Lightweight per-process abuse protection. It is intentionally memory-only:
# use a shared store if the service is later scaled to multiple instances.
_request_windows: dict[str, deque[float]] = defaultdict(deque)


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.http = httpx.AsyncClient(
        timeout=httpx.Timeout(6.0, connect=3.0),
        follow_redirects=False,
        headers={"User-Agent": "Curium-DNS/1.0"},
    )
    yield
    await app.state.http.aclose()


app = FastAPI(
    title="Curium DNS",
    description="A small DNS-over-HTTPS forwarding gateway.",
    version="1.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Accept", "Content-Type"],
    max_age=600,
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; "
        "frame-src https://challenges.cloudflare.com; "
        "connect-src 'self' https://challenges.cloudflare.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'"
    )
    return response


def client_key(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return request.client.host if request.client else "unknown"


def enforce_rate_limit(request: Request) -> None:
    now = time.monotonic()
    key = client_key(request)
    window = _request_windows[key]

    while window and now - window[0] >= WINDOW_SECONDS:
        window.popleft()

    if len(window) >= RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail="Rate limit reached. Please retry in a moment.",
            headers={"Retry-After": "60"},
        )

    window.append(now)

    if len(_request_windows) > 5000:
        stale_before = now - WINDOW_SECONDS
        stale_keys = [
            ip for ip, timestamps in _request_windows.items()
            if not timestamps or timestamps[-1] < stale_before
        ]
        for ip in stale_keys:
            _request_windows.pop(ip, None)


def turnstile_is_configured() -> bool:
    return bool(TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY and ACCESS_GATE_SECRET)


def make_access_cookie() -> str:
    timestamp = str(int(time.time()))
    signature = hmac.new(
        ACCESS_GATE_SECRET.encode("utf-8"),
        timestamp.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return f"{timestamp}.{signature}"


def has_valid_access_cookie(value: str | None) -> bool:
    if not value or not ACCESS_GATE_SECRET:
        return False
    try:
        timestamp, supplied_signature = value.split(".", 1)
        issued_at = int(timestamp)
    except (ValueError, TypeError):
        return False

    age = int(time.time()) - issued_at
    if age < 0 or age > ACCESS_COOKIE_MAX_AGE:
        return False

    expected_signature = hmac.new(
        ACCESS_GATE_SECRET.encode("utf-8"),
        timestamp.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(supplied_signature, expected_signature)


def validate_dns_query(packet: bytes) -> None:
    if len(packet) < 12 or len(packet) > MAX_DNS_MESSAGE_SIZE:
        raise HTTPException(status_code=400, detail="Invalid DNS message size.")

    flags = packet[2]
    opcode = (flags >> 3) & 0x0F
    question_count = int.from_bytes(packet[4:6], "big")

    if flags & 0x80:
        raise HTTPException(status_code=400, detail="A DNS query was expected.")
    if opcode != 0 or question_count != 1:
        raise HTTPException(status_code=400, detail="Only standard single-question queries are supported.")


async def forward_dns(request: Request, packet: bytes) -> Response:
    validate_dns_query(packet)

    try:
        upstream = await request.app.state.http.post(
            UPSTREAM_DOH,
            content=packet,
            headers={
                "Accept": "application/dns-message",
                "Content-Type": "application/dns-message",
            },
        )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="DNS upstream timed out.")
    except httpx.HTTPError:
        raise HTTPException(status_code=502, detail="Could not reach the DNS upstream.")

    if upstream.status_code != 200:
        raise HTTPException(status_code=502, detail="DNS upstream returned an error.")
    if len(upstream.content) < 12 or len(upstream.content) > MAX_DNS_MESSAGE_SIZE:
        raise HTTPException(status_code=502, detail="DNS upstream returned an invalid response.")
    if not (upstream.content[2] & 0x80):
        raise HTTPException(status_code=502, detail="DNS upstream response was malformed.")

    return Response(
        content=upstream.content,
        media_type="application/dns-message",
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/")
async def home(request: Request):
    no_cache = {"Cache-Control": "no-store"}
    if not turnstile_is_configured():
        return FileResponse(STATIC_DIR / "security-setup.html", headers=no_cache)
    if not has_valid_access_cookie(request.cookies.get(ACCESS_COOKIE_NAME)):
        return FileResponse(STATIC_DIR / "challenge.html", headers=no_cache)
    return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-cache"})


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "curium-dns"}


@app.get("/api/config")
async def api_config():
    return {
        "turnstile_enabled": turnstile_is_configured(),
        "site_key": TURNSTILE_SITE_KEY if turnstile_is_configured() else None,
    }


@app.post("/api/turnstile/verify")
async def verify_turnstile(request: Request):
    enforce_rate_limit(request)

    if not turnstile_is_configured():
        raise HTTPException(status_code=503, detail="Turnstile is not configured.")

    try:
        body = await request.json()
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="A JSON body is required.")

    token = body.get("token") if isinstance(body, dict) else None
    if not isinstance(token, str) or not token or len(token) > 2048:
        raise HTTPException(status_code=400, detail="A valid Turnstile token is required.")

    try:
        siteverify = await request.app.state.http.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            json={
                "secret": TURNSTILE_SECRET_KEY,
                "response": token,
                "idempotency_key": str(uuid.uuid4()),
            },
        )
        siteverify.raise_for_status()
        result = siteverify.json()
    except (httpx.HTTPError, ValueError):
        raise HTTPException(status_code=502, detail="Could not validate the security check.")

    if not result.get("success"):
        raise HTTPException(status_code=403, detail="Security check failed. Please try again.")

    verified_hostname = str(result.get("hostname", "")).lower()
    request_hostname = (request.url.hostname or "").lower()
    allowed_hosts = TURNSTILE_ALLOWED_HOSTS or {request_hostname}
    if not verified_hostname or verified_hostname not in allowed_hosts:
        raise HTTPException(status_code=403, detail="Security check hostname did not match.")

    response = JSONResponse({"verified": True})
    response.set_cookie(
        key=ACCESS_COOKIE_NAME,
        value=make_access_cookie(),
        max_age=ACCESS_COOKIE_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/status")
async def api_status(request: Request):
    return {
        "status": "online",
        "service": "Curium DNS",
        "protocol": "DNS-over-HTTPS",
        "endpoint": str(request.base_url).rstrip("/") + "/dns-query",
        "upstream": "Cloudflare DNS",
        "rate_limit_per_minute": RATE_LIMIT,
    }


@app.get("/dns-query")
async def dns_query_get(request: Request, dns: str):
    enforce_rate_limit(request)
    try:
        padded = dns + ("=" * (-len(dns) % 4))
        packet = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, UnicodeEncodeError, binascii.Error):
        raise HTTPException(status_code=400, detail="The dns parameter must be base64url-encoded.")
    return await forward_dns(request, packet)


@app.post("/dns-query")
async def dns_query_post(request: Request):
    enforce_rate_limit(request)
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/dns-message":
        raise HTTPException(status_code=415, detail="Content-Type must be application/dns-message.")

    packet = await request.body()
    return await forward_dns(request, packet)


@app.exception_handler(HTTPException)
async def http_error_response(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail},
        headers=exc.headers,
    )
