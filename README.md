# Curium DNS

Curium DNS is a small DNS-over-HTTPS (DoH) forwarding gateway with a Material You 3-inspired landing page.

## What is included

- Responsive landing page with light/dark theme and endpoint copy button.
- Official Cloudflare Turnstile browser verification gate.
- Server-side Turnstile token verification through Cloudflare Siteverify.
- Signed, HTTP-only browser verification cookie (12-hour lifetime).
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

## Cloudflare Turnstile setup

Create a Turnstile widget in the Cloudflare dashboard and allow the hostname used by your deployment.

Set these environment variables in Render:

- `TURNSTILE_SITE_KEY`: public widget site key.
- `TURNSTILE_SECRET_KEY`: private widget secret key. Store it only in Render, never in Git.
- `ACCESS_GATE_SECRET`: long random secret used to sign the browser verification cookie. A production value is generated in the Render environment.
- `TURNSTILE_ALLOWED_HOSTS`: comma-separated allowed hostnames, e.g. `curium-dns-app.onrender.com`.

If Turnstile keys are missing, the site shows a setup page rather than pretending that bot protection is active. Once configured, visitors must pass Turnstile before opening the landing page. The browser verification cookie expires after 12 hours.

## Render

- Runtime: Python
- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn app:app --host 0.0.0.0 --port $PORT --no-access-log`
- Health check path: `/healthz`
- Optional environment variables:
  - `UPSTREAM_DOH`: upstream DoH URL (default: `https://cloudflare-dns.com/dns-query`)
  - `RATE_LIMIT_PER_MINUTE`: per-IP request limit (default: `90`)

## Important deployment notes

The free Render web-service plan spins down after 15 minutes without incoming traffic. The next request wakes it and may incur a cold-start delay. Artificial periodic page visits are not configured as an uptime mechanism; use a paid always-on compute plan for dependable DNS service.

The rate limiter is in memory and is intended as a lightweight safeguard for a single instance, not a complete abuse-prevention system for a large public resolver. Keep one instance unless you add a shared rate-limit store. Monitor usage before offering this endpoint publicly at scale.

The application does not intentionally persist DNS query history. The hosting platform may retain operational logs under its own policies.

## Scope and limitations

Turnstile protects access to the website interface. The DNS-over-HTTPS endpoint deliberately does not require an interactive CAPTCHA because standard DoH clients cannot complete browser challenges; it is protected by DNS query validation, request-size limits, upstream timeouts, and per-IP rate limiting.

This is a DNS-over-HTTPS forwarding gateway, not a VPN or general-purpose traffic proxy. It encrypts DNS transport to this endpoint, but does not change a client's public IP or bypass IP/SNI/DPI filtering. It also cannot override a website's own regional availability rules.

Android Private DNS expects DNS-over-TLS, while manual iOS Wi-Fi DNS settings expect IP addresses. A DoH URL must be used by a compatible browser or a separate client profile/application.
