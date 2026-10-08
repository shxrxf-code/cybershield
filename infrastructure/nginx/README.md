# CyberShield reverse proxy (nginx)

`nginx.conf` is a complete, self-contained nginx configuration mounted at
`/etc/nginx/nginx.conf` by the `nginx` service in
[`../docker-compose.yml`](../docker-compose.yml) (profile `proxy`).

## Posture

- Serves the API on `api:8000` (the compose service name is the upstream host).
- `client_max_body_size 110m` — the app's upload ceiling is 100 MiB
  (`MAX_UPLOAD_BYTES` in `backend/.env.example`); 110 MiB leaves room for
  multipart encoding overhead.
- `proxy_request_buffering off` streams uploads straight to uvicorn.
- Forwards `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto`, and an
  end-to-end `X-Request-ID` (nginx `$request_id`). The API echoes the first
  `X-Request-ID` it sees.
- Sets security headers (`X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `X-XSS-Protection`) on every response.
- gzip for JSON/OpenAPI responses, `server_tokens off`, sane timeouts.

**Because this config overwrites `X-Forwarded-*`, the API must run with
`TRUST_PROXY_HEADERS=true`** — already set for the `api` service in
`docker-compose.yml`. Never enable that variable on an API that is directly
reachable by clients (any client could then spoof its source IP for rate
limiting and audit).

## Quick start (HTTP, no TLS)

```bash
cd infrastructure
docker compose --profile proxy up -d --build
curl http://127.0.0.1/api/v1/health
```

## TLS with certbot

The bundled config ships an active HTTP server (works immediately) and a fully
written, commented-out HTTPS server block.

1. Point a DNS record (e.g. `scan.example.com`) at the host.
2. Start the stack so the webroot path exists:
   ```bash
   docker compose --profile proxy up -d
   ```
3. Obtain a certificate. **Container one-shot** (uses the same volumes the
   nginx service mounts):
   ```bash
   docker run --rm \
     -v cybershield_certbot-conf:/etc/letsencrypt \
     -v cybershield_certbot-www:/var/www/certbot \
     certbot/certbot certonly --webroot -w /var/www/certbot \
       -d scan.example.com --email you@example.com --agree-tos --no-eff-email
   ```
   (Volume names are `cybershield_certbot-conf` / `cybershield_certbot-www`
   because compose prefixes named volumes with the project name `cybershield`.)
   **On the host** alternatively:
   ```bash
   sudo certbot certonly --webroot -w /path/to/certbot-www -d scan.example.com
   ```
4. In `nginx.conf`, uncomment the 443 `server` block, set `server_name` to your
   hostname and fix the certificate paths
   (`/etc/letsencrypt/live/<your-hostname>/{fullchain,privkey}.pem`), then swap
   the HTTP server for the commented redirect variant.
5. Reload:
   ```bash
   docker compose --profile proxy exec nginx nginx -s reload
   ```
6. Renewal — the standard mechanism is a cron job or a systemd timer running:
   ```bash
   certbot renew --webroot -w /var/www/certbot --post-hook "nginx -s reload"
   ```
   For the containerised setup, a small `certbot renew` job invokes
   `docker compose --profile proxy exec nginx nginx -s reload` after renewal.

## Operational notes

- Logs: `docker compose --profile proxy logs -f nginx`.
- `docker compose --profile proxy config --services` lists what the profile starts.
- If you edit `nginx.conf`, validate with
  `docker compose --profile proxy exec nginx nginx -t` before reloading.
- The `X-Request-ID` header the proxy sets also appears in the nginx access
  log (last field, from `$http_x_request_id`), so you can correlate a request
  from edge to the `request_id` column in `audit_events`.