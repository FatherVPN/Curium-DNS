# Curium DNS

Curium DNS is a small DNS-over-HTTPS (DoH) forwarding gateway with a Material You 3-inspired landing page.

## What is included

- Responsive landing page with light/dark theme and endpoint copy button.
- DNS-over-HTTPS endpoint at `/dns-query` using standard `application/dns-message` wire format (GET and POST).
- Forwarding to Cloudflare DNS by default.
- Basic input validation, request size limits, upstream timeout handling, and a per-process per-IP rate limit.
- Health endpoints at `/healthz` and `/api/status`.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000.

## Render

- Runtime: Python
- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn app:app --host 0.0.0.0 --port $PORT --no-access-log`
- Health check path: `/healthz`
- Optional environment variables:
  - `UPSTREAM_DOH`: upstream DoH URL (default: `https://cloudflare-dns.com/dns-query`)
  - `RATE_LIMIT_PER_MINUTE`: per-IP request limit (default: `90`)

## Important deployment notes

The free Render web-service plan may spin down after inactivity. The first request after an idle period can therefore be delayed. Do not use artificial four-minute pings as an uptime mechanism; choose an always-on paid instance for dependable DNS service.

The rate limiter is in memory and is intended as a lightweight safeguard for a single instance, not a complete abuse-prevention system for a large public resolver. Keep one instance unless you add a shared rate-limit store. Monitor usage before offering this endpoint publicly at scale.

The application does not intentionally persist DNS query history. The hosting platform may retain operational logs under its own policies.

## Scope and limitations

This is a DNS-over-HTTPS forwarding gateway, not a VPN or general-purpose traffic proxy. It encrypts DNS transport to this endpoint, but does not change a client's public IP or bypass IP/SNI/DPI filtering. It also cannot override a website's own regional availability rules.

Android Private DNS expects DNS-over-TLS, while manual iOS Wi-Fi DNS settings expect IP addresses. A DoH URL must be used by a compatible browser or a separate client profile/application.
