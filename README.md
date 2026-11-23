# Curium DNS

Curium DNS is a small DNS-over-HTTPS (DoH) forwarding gateway with a Material You 3-inspired landing page and lightweight 3D network visualizations.

## What is included

- Responsive landing page with light/dark theme and endpoint copy buttons.
- Local Canvas-based 3D network scenes, animated resolver topology, orbital diagrams, scroll reveals, and subtle pointer tilt effects.
- Windows setup guide for Edge, Chrome, and Firefox browser-level Secure DNS.
- Official Cloudflare Turnstile browser verification gate with server-side Siteverify validation.
- Signed, HTTP-only browser verification cookie (12-hour lifetime).
- DNS-over-HTTPS endpoint at `/dns-query` using standard `application/dns-message` wire format (GET and POST).
- Forwarding to Cloudflare DNS by default.
- Input validation, request size limits, upstream timeouts, and a per-process per-IP rate limit.
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
- `ACCESS_GATE_SECRET`: long random secret used to sign the browser verification cookie.
- `TURNSTILE_ALLOWED_HOSTS`: comma-separated allowed hostnames, e.g. `curium-dns-app.onrender.com`.

If Turnstile keys are missing, the site shows a setup page rather than pretending bot protection is active. Once configured, visitors must pass Turnstile before opening the landing page. The browser verification cookie expires after 12 hours.

## Windows setup

For Microsoft Edge, open `edge://settings/privacy`, find **Security**, enable **Use secure DNS**, choose a custom provider, and paste:

`https://curium-dns-app.onrender.com/dns-query`

For Google Chrome, open `chrome://settings/security`, enable **Use secure DNS**, choose a custom provider, and paste the same URL.

For Firefox, open `about:preferences#privacy`, find **DNS over HTTPS**, choose increased protection and set a custom provider to the same URL.

### Windows system-wide DNS limitation

Windows 11's built-in DoH client is configured with a DNS server IP address and a DoH URI template. The current Render deployment is an HTTP(S) web service exposed through a Render URL; it does not provide Curium with a dedicated static DNS-server IP address or a standard UDP/TCP port 53 listener. Therefore, the endpoint is suitable for supported browsers, but should not be entered as an ordinary Preferred DNS IP address for all Windows applications.

To support system-wide Windows DNS, deploy a dedicated DNS front end on infrastructure with a stable public IP and configure a matching HTTPS certificate and DoH URI template. Do not use a guessed or temporary IP address for the Render hostname.

## Render

- Runtime: Python
- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn app:app --host 0.0.0.0 --port $PORT --no-access-log`
- Health check path: `/healthz`
- Optional environment variables:
  - `UPSTREAM_DOH`: upstream DoH URL (default: `https://cloudflare-dns.com/dns-query`)
  - `RATE_LIMIT_PER_MINUTE`: per-IP request limit (default: `90`)

The free Render web-service plan spins down after inactivity. The next request wakes it and may incur a cold-start delay. Artificial periodic page visits are not configured as an uptime mechanism; use an always-on plan for dependable service.

The rate limiter is in memory and is intended as a lightweight safeguard for a single instance, not a complete abuse-prevention system for a large public resolver. Keep one instance unless you add a shared rate-limit store. Monitor usage before offering this endpoint publicly at scale.

The application does not intentionally persist DNS query history. The hosting platform may retain operational logs under its own policies.

## Scope and limitations

Turnstile protects access to the website interface. The DNS-over-HTTPS endpoint deliberately does not require an interactive CAPTCHA because standard DoH clients cannot complete browser challenges; it is protected by DNS query validation, request-size limits, upstream timeouts, and per-IP rate limiting.

This is a DNS-over-HTTPS forwarding gateway, not a VPN or general-purpose traffic proxy. It encrypts DNS transport to this endpoint, but does not change a client's public IP or bypass IP/SNI/DPI filtering. It also cannot override a website's own regional availability rules.

Android Private DNS expects DNS-over-TLS, while manual iOS Wi-Fi DNS settings expect IP addresses. A DoH URL must be used by a compatible browser or a separate client profile/application.
