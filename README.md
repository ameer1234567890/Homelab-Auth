# Homelab Auth: login gate + reverse proxy

One container, one SQLite file. Visitors see a login page; once signed in, **every request
is proxied to the internal app you configure** (`UPSTREAM_URL`). The app itself is not
published to the host network, so the only way in is through the login.
Includes a user-management UI with a light/dark switch.

```
browser ──► auth :8080 ──(after login)──► app:80   (internal docker network only)
```

## Run
```bash
docker compose up -d --build
```
Open `http://<host>:8080`. Sign in with **admin / password123**, and you land in the app.
(The bundled `traefik/whoami` example just prints the headers it received.
Replace the `app` service with your own and set `UPSTREAM_URL`.)

Using your own compose file? Copy the `auth` service (+ `Dockerfile`, `app.py`, `static/`),
make sure the app has **no `ports:`** mapping, and point `UPSTREAM_URL` at its service name and
container port, e.g. `http://jellyfin:8096`.

## Managing users / signing out
Everything of this service lives under **`/_auth/`** (that path is reserved, all other paths go to your app):
- `http://<host>:8080/_auth/` → user management (admins), change password, dark-mode switch, "Open app", sign out
- `http://<host>:8080/_auth/logout` → quick sign-out link

## What the app receives
Your app sees normal requests plus headers identifying the user (client-supplied copies are always stripped,
so they can't be spoofed): `Remote-User`, `Remote-Name`, `Remote-Email`, `Remote-Groups`
(also `X-Forwarded-User/-Email/-Groups`), and `X-Forwarded-For/-Proto/-Host`.
The session cookie is never forwarded to the app. Apps that support "trusted header / proxy auth"
(Grafana, Paperless, Navidrome, Gitea…) can log users in automatically with these.

Supported through the proxy: all HTTP methods, streaming/SSE, large uploads, WebSockets,
multiple `Set-Cookie`, and rewriting of absolute redirects that point at the upstream.

## Settings
| Var | Default | Purpose |
|---|---|---|
| `UPSTREAM_URL` | `http://app:80` | Internal app to proxy to (may include a path prefix; https allowed) |
| `PRESERVE_HOST` | `true` | Forward the browser's `Host` header (set `false` if the app needs its own hostname) |
| `UPSTREAM_INSECURE_TLS` | `false` | Accept self-signed certs on an https upstream |
| `UPSTREAM_TIMEOUT` | `600` | Seconds of upstream silence before giving up |
| `ADMIN_USER` / `ADMIN_PASSWORD` | `admin` / `password123` | First-run admin only (empty DB) |
| `COOKIE_SECURE` | `false` | `true` when served over HTTPS |
| `TRUST_PROXY` | `false` | `true` if another proxy (Caddy/Traefik/NPM) is in front of this container |
| `SESSION_HOURS` | `168` | Session lifetime |
| `PUBLIC_URL`, `COOKIE_DOMAIN` | empty | Only for forward-auth mode below |

If you put TLS termination in front (recommended for anything beyond your LAN), point it at
this container's port 8080, set `COOKIE_SECURE=true` and `TRUST_PROXY=true`.

## Dark mode
The theme switch is remembered in the browser (localStorage + a 1-year cookie, so the login
page uses it too) **and** saved to your user account, so it follows you across devices.

## Optional: forward-auth mode (no `UPSTREAM_URL`)
Leave `UPSTREAM_URL` empty and use this as an auth endpoint for Caddy/Traefik/nginx instead:
`/_auth/verify` returns `200` + `Remote-*` headers when signed in, otherwise redirects to
`PUBLIC_URL/_auth/?rd=…` (or `401` with `?mode=401`). Add `?group=media` to require a group.
Set `PUBLIC_URL` (e.g. `https://auth.home.example.com`) and `COOKIE_DOMAIN` (`home.example.com`).
```
# Caddy
forward_auth homelab-auth:8080 {
    uri /_auth/verify
    copy_headers Remote-User Remote-Name Remote-Email Remote-Groups
}
```

## Security notes
- scrypt password hashes; random session tokens (only hashes stored); HttpOnly + SameSite=Lax cookie.
- Login throttling (5 failures → 1 min), CSRF header on API writes, strict CSP on the admin UI,
  redirects limited to your own domain. Disabling/deleting a user, or changing their password, signs them out.
- Everything unauthenticated gets only the login page (browsers) or `401` (API calls, WebSockets).
- Not included: OIDC/SAML/LDAP, MFA, email password reset.
- Don't expose on the internet over plain HTTP, and change `password123`.

## Backup
```bash
docker compose cp auth:/data/auth.db ./auth-backup.db
```
Never run `docker compose down -v` unless you want to wipe all users.
