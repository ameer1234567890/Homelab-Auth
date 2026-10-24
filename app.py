#!/usr/bin/env python3
"""Homelab Auth: a tiny single-container auth portal.
SQLite + forward-auth + user management UI. Python standard library only."""
import hashlib, hmac, http.client, json, os, re, secrets, select, socket, sqlite3, ssl, threading, time
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse


def env(name, default=""):
    return os.environ.get(name, default)


DB_PATH = env("DB_PATH", "/data/auth.db")
PORT = int(env("PORT", "8080"))
ADMIN_USER = env("ADMIN_USER", "admin").strip().lower()
ADMIN_PASSWORD = env("ADMIN_PASSWORD", "password123")
PUBLIC_URL = env("PUBLIC_URL").strip().rstrip("/")
COOKIE_DOMAIN = env("COOKIE_DOMAIN").strip().lstrip(".").lower()
COOKIE_SECURE = env("COOKIE_SECURE", "false").lower() == "true"
SESSION_SECONDS = int(float(env("SESSION_HOURS", "168")) * 3600)
TRUST_PROXY = env("TRUST_PROXY", "false").lower() == "true"

UPSTREAM_URL = env("UPSTREAM_URL").strip().rstrip("/")
UPSTREAM_TIMEOUT = float(env("UPSTREAM_TIMEOUT", "600"))
UPSTREAM_INSECURE_TLS = env("UPSTREAM_INSECURE_TLS", "false").lower() == "true"
PRESERVE_HOST = env("PRESERVE_HOST", "true").lower() == "true"
UP = urlparse(UPSTREAM_URL) if UPSTREAM_URL else None
if UP and (UP.scheme not in ("http", "https") or not UP.hostname):
    raise SystemExit("UPSTREAM_URL must look like http://service:port")
UP_TLS = bool(UP and UP.scheme == "https")
UP_HOST = UP.hostname if UP else ""
UP_PORT = (UP.port or (443 if UP_TLS else 80)) if UP else 0
UP_BASE = UP.path.rstrip("/") if UP else ""
UP_ORIGIN = f"{UP.scheme}://{UP.netloc}" if UP else ""
UP_CTX = None
if UP_TLS:
    UP_CTX = ssl.create_default_context()
    if UPSTREAM_INSECURE_TLS:
        UP_CTX.check_hostname = False
        UP_CTX.verify_mode = ssl.CERT_NONE

AUDIT_MAX_ROWS = int(env("AUDIT_MAX_ROWS", "50000"))  # oldest entries are pruned beyond this

COOKIE = "hl_session"
STRIP_COOKIES = {"hl_session", "hl_theme"}
HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "trailers",
       "transfer-encoding", "upgrade", "expect"}
SPOOFABLE = {"x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-forwarded-user",
             "x-forwarded-email", "x-forwarded-groups", "x-real-ip"}
STATIC = Path(__file__).parent / "static"
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")
GROUP_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+$")
MIN_PW = 8
SCRYPT = dict(n=2**14, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32)


# ---------- passwords ----------
def hash_pw(pw):
    salt = secrets.token_bytes(16)
    return f"scrypt${salt.hex()}${hashlib.scrypt(pw.encode(), salt=salt, **SCRYPT).hex()}"


def check_pw(pw, stored):
    try:
        _, salt, digest = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), **SCRYPT).hex()
        return hmac.compare_digest(calc, digest)
    except Exception:
        return False


DUMMY_HASH = hash_pw(secrets.token_hex(8))  # equalises timing for unknown users


# ---------- database ----------
def db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


RUN_UID = RUN_GID = 10001


def drop_privileges():
    """If started as root: make the data dir writable for the app user, then drop to it.
    This makes bind mounts and old root-owned volumes just work."""
    if os.geteuid() != 0:
        return
    d = Path(DB_PATH).parent
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chown(d, RUN_UID, RUN_GID)
        for p in d.iterdir():
            os.chown(p, RUN_UID, RUN_GID)
    except OSError as e:
        print(f"WARNING: could not chown {d}: {e}", flush=True)
    os.setgroups([])
    os.setgid(RUN_GID)
    os.setuid(RUN_UID)


def init_db():
    try:
        Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
        with closing(db()) as con:
            con.execute("PRAGMA schema_version")
    except (OSError, sqlite3.OperationalError) as e:
        raise SystemExit(f"Cannot open database at {DB_PATH}: {e}\n"
                         f"The directory {Path(DB_PATH).parent} must be writable by uid {os.geteuid()}. "
                         f"Run the container as root (default) so it can fix permissions, or chown the mount yourself.")
    with closing(db()) as con:
        con.execute("PRAGMA journal_mode=WAL")
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL UNIQUE,
          display_name TEXT NOT NULL DEFAULT '',
          email TEXT NOT NULL DEFAULT '',
          password_hash TEXT NOT NULL,
          is_admin INTEGER NOT NULL DEFAULT 0,
          disabled INTEGER NOT NULL DEFAULT 0,
          groups TEXT NOT NULL DEFAULT '',
          pw_default INTEGER NOT NULL DEFAULT 0,
          theme TEXT NOT NULL DEFAULT '',
          created_at INTEGER NOT NULL,
          last_login INTEGER);
        CREATE TABLE IF NOT EXISTS sessions(
          token_hash TEXT PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
        CREATE TABLE IF NOT EXISTS audit_log(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts INTEGER NOT NULL,
          action TEXT NOT NULL,
          actor TEXT NOT NULL DEFAULT '',
          target TEXT NOT NULL DEFAULT '',
          ip TEXT NOT NULL DEFAULT '',
          detail TEXT NOT NULL DEFAULT '');
        CREATE INDEX IF NOT EXISTS audit_ts ON audit_log(ts);
        """)
        cols = [r["name"] for r in con.execute("PRAGMA table_info(users)")]
        if "theme" not in cols:  # migrate databases created by earlier versions
            con.execute("ALTER TABLE users ADD COLUMN theme TEXT NOT NULL DEFAULT ''")
        if con.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            con.execute(
                "INSERT INTO users(username,display_name,password_hash,is_admin,pw_default,created_at)"
                " VALUES(?,?,?,1,1,?)",
                (ADMIN_USER, "Administrator", hash_pw(ADMIN_PASSWORD), int(time.time())))
            print(f"Created initial admin user '{ADMIN_USER}'", flush=True)
        con.commit()


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def user_out(r):
    return {"id": r["id"], "username": r["username"], "display_name": r["display_name"],
            "email": r["email"], "is_admin": bool(r["is_admin"]), "disabled": bool(r["disabled"]),
            "groups": [g for g in r["groups"].split(",") if g], "pw_default": bool(r["pw_default"]), "theme": r["theme"],
            "created_at": r["created_at"], "last_login": r["last_login"]}


# ---------- login throttling ----------
FAILS, FAILS_LOCK = {}, threading.Lock()


def throttled(key):
    with FAILS_LOCK:
        rec = FAILS.get(key)
        return bool(rec and rec[1] > time.time())


def note_fail(key):
    with FAILS_LOCK:
        if len(FAILS) > 10000:
            FAILS.clear()
        count, _ = FAILS.get(key, (0, 0))
        count += 1
        FAILS[key] = (0, time.time() + 60) if count >= 5 else (count, 0)


def clear_fail(key):
    with FAILS_LOCK:
        FAILS.pop(key, None)


# ---------- helpers ----------
def hv(s):  # safe HTTP header value
    return re.sub(r"[\x00-\x1f\x7f]", "", s or "").encode("utf-8").decode("latin-1")


def clean(s, limit):
    return re.sub(r"[\x00-\x1f\x7f]", "", str(s or "")).strip()[:limit]


def safe_redirect(url):
    """Only allow redirects to our own auth host or hosts under COOKIE_DOMAIN."""
    try:
        p = urlparse(url or "")
        if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
            return None
        host = p.hostname.lower()
        own = (urlparse(PUBLIC_URL).hostname or "").lower() if PUBLIC_URL else ""
        if own and host == own:
            return url
        if COOKIE_DOMAIN and (host == COOKIE_DOMAIN or host.endswith("." + COOKIE_DOMAIN)):
            return url
    except Exception:
        pass
    return None


def parse_groups(v):
    items = v.split(",") if isinstance(v, str) else v
    if not isinstance(items, list):
        raise ValueError("Groups must be a list")
    out = []
    for g in items:
        g = str(g).strip().lower()
        if not g:
            continue
        if not GROUP_RE.match(g):
            raise ValueError(f"Invalid group name '{g}' (use a-z, 0-9, _ or -)")
        if g not in out:
            out.append(g)
    if len(out) > 20:
        raise ValueError("Too many groups (max 20)")
    return ",".join(out)


class ApiError(Exception):
    def __init__(self, code, msg):
        self.code, self.msg = code, msg


CT = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
      ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml"}
FILES = {"/_auth/": "index.html", "/_auth/app.js": "app.js", "/_auth/theme.js": "theme.js",
         "/_auth/style.css": "style.css", "/_auth/favicon.svg": "favicon.svg"}


class Handler(BaseHTTPRequestHandler):
    server_version = "HomelabAuth"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # --- plumbing ---
    def log_message(self, fmt, *args):
        print(f"{self.client_ip()} {fmt % args}".split("?")[0], flush=True)

    def client_ip(self):
        if TRUST_PROXY:
            xff = self.headers.get("X-Forwarded-For", "")
            if xff:
                return xff.split(",")[0].strip()
        return self.client_address[0]

    def respond(self, code, body=b"", ctype="text/plain; charset=utf-8", headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.sent = True
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                         "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        for k, v in (headers or {}):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def json(self, code, obj, headers=None):
        self.respond(code, json.dumps(obj), "application/json", headers)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 65536:
            raise ApiError(413, "Request too large")
        if not n:
            return {}
        try:
            data = json.loads(self.rfile.read(n))
        except ValueError:
            raise ApiError(400, "Invalid JSON")
        if not isinstance(data, dict):
            raise ApiError(400, "Invalid JSON")
        return data

    def cookie_hdr(self, value, max_age):
        parts = [f"{COOKIE}={value}", "Path=/", "HttpOnly", "SameSite=Lax", f"Max-Age={max_age}"]
        if COOKIE_DOMAIN:
            parts.append(f"Domain={COOKIE_DOMAIN}")
        if COOKIE_SECURE:
            parts.append("Secure")
        return ("Set-Cookie", "; ".join(parts))

    def session(self):
        """Returns (user_row, token_hash) or (None, None)."""
        token = None
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == COOKIE:
                token = v
        if not token or len(token) > 128:
            return None, None
        th = sha(token)
        with closing(db()) as con:
            row = con.execute(
                "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id "
                "WHERE s.token_hash=? AND s.expires_at>? AND u.disabled=0", (th, int(time.time()))).fetchone()
        return (row, th) if row else (None, None)

    def audit(self, action, actor="", target="", detail="", con=None):
        """Append to the audit log. With `con`, joins the caller's transaction (caller commits)."""
        own = con is None
        if own:
            con = db()
        try:
            cur = con.execute("INSERT INTO audit_log(ts,action,actor,target,ip,detail) VALUES(?,?,?,?,?,?)",
                              (int(time.time()), action, clean(actor, 64), clean(target, 64),
                               clean(self.client_ip(), 64), clean(detail, 300)))
            if cur.lastrowid % 200 == 0:
                con.execute("DELETE FROM audit_log WHERE id<=?", (cur.lastrowid - AUDIT_MAX_ROWS,))
            if own:
                con.commit()
        finally:
            if own:
                con.close()

    def end_session(self):
        user, th = self.session()
        if th:
            with closing(db()) as con:
                con.execute("DELETE FROM sessions WHERE token_hash=?", (th,))
                self.audit("logout", user["username"], con=con)
                con.commit()

    # --- dispatch ---
    def do_GET(self): self.route()
    def do_HEAD(self): self.route()
    def do_POST(self): self.route()
    def do_PATCH(self): self.route()
    def do_DELETE(self): self.route()
    def do_PUT(self): self.route()
    def do_OPTIONS(self): self.route()

    def route(self):
        self.sent = False
        raw = self.path.split("?", 1)[0]  # don't urlparse(): "//x" would be read as a host
        q = parse_qs(self.path.partition("?")[2])
        try:
            if raw == "/_auth":
                return self.respond(302, headers=[("Location", "/_auth/")])
            if raw.startswith("/_auth/"):
                return self.own(raw, q)
            if UP:
                return self.gate()
            if raw == "/":
                qs = self.path.partition("?")[2]
                return self.respond(302, headers=[("Location", "/_auth/" + ("?" + qs if qs else ""))])
            self.respond(404, "Not found")
        except ApiError as e:
            if self.sent:
                self.close_connection = True
                return
            self.json(e.code, {"error": e.msg})
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            self.close_connection = True
        except Exception as e:  # never leak internals
            print("ERROR", repr(e), flush=True)
            if self.sent:
                self.close_connection = True
            else:
                self.json(500, {"error": "Internal error"})

    def own(self, raw, q):
        """Everything under /_auth/ belongs to this app, never to the upstream."""
        get = self.command in ("GET", "HEAD")
        if raw == "/_auth/healthz":
            return self.respond(200, "ok")
        if raw == "/_auth/verify" and get:
            return self.verify(q)
        if raw == "/_auth/logout" and get:
            self.end_session()
            return self.respond(302, headers=[("Location", "/_auth/"), self.cookie_hdr("", 0)])
        if raw.startswith("/_auth/api/"):
            if not get and self.headers.get("X-Requested-With") != "fetch":
                raise ApiError(403, "Missing CSRF header")
            return self.api(raw[len("/_auth/api/"):].strip("/").split("/"), q)
        if get and raw in FILES:
            f = STATIC / FILES[raw]
            return self.respond(200, f.read_bytes(), CT[f.suffix])
        self.respond(404, "Not found")

    # --- gateway (reverse proxy) ---
    def gate(self):
        user, _ = self.session()
        if not user:
            wants_page = (self.command == "GET" and "text/html" in self.headers.get("Accept", "")
                          and not self.headers.get("Upgrade"))
            if wants_page:  # the login page is shown at whatever URL was requested
                return self.respond(200, (STATIC / "index.html").read_bytes(), CT[".html"])
            return self.respond(401, "Unauthorized")
        self.proxy(user)

    def upstream_headers(self, user):
        out = []
        for k, v in self.headers.items():
            lk = k.lower()
            if lk in HOP or lk in ("host", "content-length") or lk in SPOOFABLE or lk.startswith("remote-"):
                continue
            if lk == "cookie":
                v = "; ".join(p.strip() for p in v.split(";")
                              if p.strip() and p.strip().split("=", 1)[0] not in STRIP_COOKIES)
                if not v:
                    continue
            out.append((k, v))
        trusted = TRUST_PROXY
        prior = self.headers.get("X-Forwarded-For", "") if trusted else ""
        ip = self.client_address[0]
        host = self.headers.get("Host", "")
        proto = (self.headers.get("X-Forwarded-Proto") if trusted else None) or ("https" if COOKIE_SECURE else "http")
        fhost = (self.headers.get("X-Forwarded-Host") if trusted else None) or host
        groups = ",".join(g for g in user["groups"].split(",") if g)
        extra = [("Host", host if PRESERVE_HOST else UP.netloc),
                 ("X-Forwarded-For", f"{prior}, {ip}" if prior else ip),
                 ("X-Forwarded-Proto", proto), ("X-Forwarded-Host", fhost),
                 ("Remote-User", hv(user["username"])), ("Remote-Name", hv(user["display_name"])),
                 ("Remote-Email", hv(user["email"])), ("Remote-Groups", hv(groups)),
                 ("X-Forwarded-User", hv(user["username"])), ("X-Forwarded-Email", hv(user["email"])),
                 ("X-Forwarded-Groups", hv(groups))]
        return extra + out

    def read_body_chunked(self):
        buf = b""
        while True:
            size = int(self.rfile.readline(1024).split(b";")[0].strip() or b"0", 16)
            if size == 0:
                while self.rfile.readline(8192).strip():  # trailers
                    pass
                return buf
            buf += self.rfile.read(size)
            self.rfile.readline(4)

    def proxy(self, user):
        if not self.path.startswith("/"):
            raise ApiError(400, "Bad request")
        target = UP_BASE + self.path
        headers = self.upstream_headers(user)
        conn_hdr = self.headers.get("Connection", "").lower()
        if "upgrade" in conn_hdr and self.headers.get("Upgrade", "").lower() == "websocket":
            return self.tunnel(headers, target)

        body, length = None, int(self.headers.get("Content-Length") or 0)
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            body = self.read_body_chunked(); length = len(body)
        try:
            if UP_TLS:
                conn = http.client.HTTPSConnection(UP_HOST, UP_PORT, timeout=UPSTREAM_TIMEOUT, context=UP_CTX)
            else:
                conn = http.client.HTTPConnection(UP_HOST, UP_PORT, timeout=UPSTREAM_TIMEOUT)
            conn.putrequest(self.command, target, skip_host=True, skip_accept_encoding=True)
            for k, v in headers:
                conn.putheader(k, v)
            if length or self.command in ("POST", "PUT", "PATCH"):
                conn.putheader("Content-Length", str(length))
            conn.endheaders()
            if body is not None:
                conn.send(body)
            else:
                left = length
                while left > 0:
                    chunk = self.rfile.read(min(65536, left))
                    if not chunk:
                        raise ConnectionError("client went away")
                    conn.send(chunk); left -= len(chunk)
            resp = conn.getresponse()
        except (OSError, http.client.HTTPException) as e:
            print("UPSTREAM ERROR", repr(e), flush=True)
            self.close_connection = True
            return self.respond(502, "Bad gateway: upstream unavailable", headers=[("Connection", "close")])

        hdrs = [(k, v) for k, v in resp.getheaders() if k.lower() not in HOP]
        nobody = self.command == "HEAD" or resp.status in (204, 304) or 100 <= resp.status < 200
        keep = nobody or any(k.lower() == "content-length" for k, _ in hdrs)
        self.sent = True
        self.send_response_only(resp.status, resp.reason)
        for k, v in hdrs:
            if k.lower() == "location" and UP_ORIGIN and v.startswith(UP_ORIGIN):
                v = v[len(UP_ORIGIN):]
                if UP_BASE and v.startswith(UP_BASE):
                    v = v[len(UP_BASE):]
                v = v or "/"
            self.send_header(k, v)
        self.send_header("Connection", "keep-alive" if keep else "close")
        if not keep:
            self.close_connection = True
        self.end_headers()
        try:
            while not nobody:
                chunk = resp.read1(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
        except (OSError, http.client.HTTPException):
            self.close_connection = True
        finally:
            conn.close()

    def tunnel(self, headers, target):
        """WebSocket (or any Upgrade) passthrough: relay raw bytes both ways."""
        try:
            up = socket.create_connection((UP_HOST, UP_PORT), timeout=10)
            if UP_TLS:
                up = UP_CTX.wrap_socket(up, server_hostname=UP_HOST)
        except OSError as e:
            print("UPSTREAM ERROR", repr(e), flush=True)
            self.close_connection = True
            return self.respond(502, "Bad gateway: upstream unavailable", headers=[("Connection", "close")])
        lines = [f"{self.command} {target} HTTP/1.1"] + [f"{k}: {v}" for k, v in headers]
        lines += ["Connection: Upgrade", "Upgrade: " + self.headers.get("Upgrade", "websocket"), "", ""]
        self.close_connection = True
        self.sent = True
        cli = self.connection
        try:
            up.sendall("\r\n".join(lines).encode("latin-1", "replace"))
            up.settimeout(None)
            while True:
                ready, _, _ = select.select([cli, up], [], [], 3600)
                if not ready:
                    break
                for sock in ready:
                    data = sock.recv(65536)
                    if not data:
                        return
                    while isinstance(sock, ssl.SSLSocket) and sock.pending():
                        data += sock.recv(sock.pending())
                    (up if sock is cli else cli).sendall(data)
        except OSError:
            pass
        finally:
            up.close()

    # --- forward auth ---
    def verify(self, q):
        user, _ = self.session()
        if user:
            need = (q.get("group") or [""])[0]
            groups = [g for g in user["groups"].split(",") if g]
            if need and not (user["is_admin"] or need in groups):
                return self.respond(403, "Forbidden: you are not in the required group")
            return self.respond(200, "OK", headers=[
                ("Remote-User", hv(user["username"])), ("Remote-Name", hv(user["display_name"])),
                ("Remote-Email", hv(user["email"])), ("Remote-Groups", hv(",".join(groups)))])
        if PUBLIC_URL and (q.get("mode") or [""])[0] != "401":
            proto = self.headers.get("X-Forwarded-Proto", "http")
            host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host", "")
            uri = self.headers.get("X-Forwarded-Uri", "/")
            target = hv(f"{PUBLIC_URL}/_auth/?rd={quote(f'{proto}://{host}{uri}', safe='')}")
            return self.respond(302, "Login required", headers=[("Location", target)])
        self.respond(401, "Unauthorized")

    # --- JSON API ---
    def need_user(self):
        user, th = self.session()
        if not user:
            raise ApiError(401, "Not signed in")
        return user, th

    def need_admin(self):
        user, th = self.need_user()
        if not user["is_admin"]:
            raise ApiError(403, "Admin only")
        return user

    def api(self, p, q):
        m = self.command
        if p == ["login"] and m == "POST":
            return self.login()
        if p == ["logout"] and m == "POST":
            self.end_session()
            return self.json(200, {"ok": True}, [self.cookie_hdr("", 0)])
        if p == ["me"] and m in ("GET", "HEAD"):
            user, _ = self.need_user()
            return self.json(200, {"user": user_out(user), "gateway": bool(UP),
                                   "redirect": safe_redirect((q.get("rd") or [""])[0])})
        if p == ["me", "theme"] and m == "POST":
            user, _ = self.need_user()
            theme = clean(self.body().get("theme"), 8)
            if theme not in ("light", "dark"):
                raise ApiError(400, "Theme must be light or dark")
            with closing(db()) as con:
                con.execute("UPDATE users SET theme=? WHERE id=?", (theme, user["id"])); con.commit()
            return self.json(200, {"ok": True})
        if p == ["me", "password"] and m == "POST":
            return self.change_own_password()
        if p[0] == "users":
            return self.users_api(p[1:])
        if p[0] == "audit" and len(p) == 1:
            return self.audit_api(q)
        raise ApiError(404, "Not found")

    def login(self):
        d = self.body()
        username, password = clean(d.get("username"), 64).lower(), str(d.get("password") or "")[:256]
        key = f"{self.client_ip()}|{username}"
        if throttled(key):
            print(f"Login blocked from {self.client_ip()} for user {username} (too many failed attempts)", flush=True)
            self.audit("login.blocked", username, detail="too many failed attempts")
            raise ApiError(429, "Too many attempts. Try again in a minute.")
        with closing(db()) as con:
            row = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            ok = check_pw(password, row["password_hash"] if row else DUMMY_HASH)
            if not (row and ok and not row["disabled"]):
                note_fail(key)
                print(f"Login failed from {self.client_ip()} for user {username}", flush=True)
                reason = "unknown user" if not row else ("account disabled" if ok and row["disabled"] else "wrong password")
                self.audit("login.failed", username, detail=reason, con=con)
                con.commit()
                raise ApiError(401, "Invalid username or password")
            clear_fail(key)
            token, now = secrets.token_urlsafe(32), int(time.time())
            con.execute("DELETE FROM sessions WHERE expires_at<?", (now,))
            con.execute("INSERT INTO sessions VALUES(?,?,?,?)", (sha(token), row["id"], now, now + SESSION_SECONDS))
            con.execute("UPDATE users SET last_login=? WHERE id=?", (now, row["id"]))
            self.audit("login.success", row["username"], con=con)
            con.commit()
            row = con.execute("SELECT * FROM users WHERE id=?", (row["id"],)).fetchone()
        self.json(200, {"user": user_out(row), "gateway": bool(UP),
                        "redirect": safe_redirect(clean(d.get("rd"), 2000))},
                  [self.cookie_hdr(token, SESSION_SECONDS)])

    def change_own_password(self):
        user, th = self.need_user()
        d = self.body()
        if not check_pw(str(d.get("current") or ""), user["password_hash"]):
            raise ApiError(400, "Current password is incorrect")
        new = str(d.get("new") or "")
        if len(new) < MIN_PW or len(new) > 256:
            raise ApiError(400, f"New password must be at least {MIN_PW} characters")
        with closing(db()) as con:
            con.execute("UPDATE users SET password_hash=?, pw_default=0 WHERE id=?", (hash_pw(new), user["id"]))
            con.execute("DELETE FROM sessions WHERE user_id=? AND token_hash!=?", (user["id"], th))
            self.audit("password.change", user["username"], user["username"], "own password", con=con)
            con.commit()
        self.json(200, {"ok": True})

    def audit_api(self, q):
        admin = self.need_admin()

        def num(name, default, lo, hi):
            try:
                return min(max(int((q.get(name) or [default])[0]), lo), hi)
            except ValueError:
                return default

        if self.command == "DELETE":
            with closing(db()) as con:
                n = con.execute("DELETE FROM audit_log").rowcount
                self.audit("audit.clear", admin["username"], detail=f"{n} entries removed", con=con)
                con.commit()
            return self.json(200, {"ok": True, "removed": n})
        if self.command not in ("GET", "HEAD"):
            raise ApiError(405, "Method not allowed")
        limit, offset = num("limit", 25, 1, 200), num("offset", 0, 0, 10**9)
        flt, search = (q.get("filter") or [""])[0], (q.get("q") or [""])[0].strip()[:100]
        where, args = [], []
        if flt == "failed":
            where.append("action IN ('login.failed','login.blocked')")
        elif flt == "login":
            where.append("(action LIKE 'login.%' OR action='logout')")
        elif flt == "user":
            where.append("(action LIKE 'user.%' OR action LIKE 'password.%')")
        if search:
            like = "%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            cols = ("action", "actor", "target", "ip", "detail")
            where.append("(" + " OR ".join(f"{c} LIKE ? ESCAPE '\\'" for c in cols) + ")")
            args += [like] * len(cols)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with closing(db()) as con:
            total = con.execute(f"SELECT COUNT(*) FROM audit_log {clause}", args).fetchone()[0]
            rows = con.execute(f"SELECT * FROM audit_log {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                               (*args, limit, offset)).fetchall()
        return self.json(200, {"total": total, "limit": limit, "offset": offset,
                               "entries": [dict(r) for r in rows]})

    def users_api(self, p):
        admin = self.need_admin()
        m = self.command
        with closing(db()) as con:
            if not p and m in ("GET", "HEAD"):
                rows = con.execute("SELECT * FROM users ORDER BY username").fetchall()
                return self.json(200, {"users": [user_out(r) for r in rows]})
            if not p and m == "POST":
                d = self.body()
                username = clean(d.get("username"), 32).lower()
                pw = str(d.get("password") or "")
                if not USERNAME_RE.match(username):
                    raise ApiError(400, "Username: 2-32 chars, a-z 0-9 . _ - (start with letter or digit)")
                if len(pw) < MIN_PW or len(pw) > 256:
                    raise ApiError(400, f"Password must be at least {MIN_PW} characters")
                email = clean(d.get("email"), 254)
                if email and not EMAIL_RE.match(email):
                    raise ApiError(400, "Invalid email address")
                try:
                    groups = parse_groups(d.get("groups") or [])
                except ValueError as e:
                    raise ApiError(400, str(e))
                try:
                    con.execute("INSERT INTO users(username,display_name,email,password_hash,is_admin,disabled,groups,created_at)"
                                " VALUES(?,?,?,?,?,0,?,?)",
                                (username, clean(d.get("display_name"), 64), email, hash_pw(pw),
                                 1 if d.get("is_admin") else 0, groups, int(time.time())))
                    con.commit()
                except sqlite3.IntegrityError:
                    raise ApiError(409, "That username is already taken")
                self.audit("user.create", admin["username"], username,
                           f"admin={'yes' if d.get('is_admin') else 'no'}, groups={groups or '-'}", con=con)
                con.commit()
                return self.json(201, {"ok": True})
            if len(p) == 1 and p[0].isdigit() and m in ("PATCH", "DELETE"):
                uid = int(p[0])
                target = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
                if not target:
                    raise ApiError(404, "User not found")
                me = uid == admin["id"]
                if m == "DELETE":
                    if me:
                        raise ApiError(400, "You can't delete your own account")
                    con.execute("DELETE FROM users WHERE id=?", (uid,))
                    self.audit("user.delete", admin["username"], target["username"], con=con)
                    con.commit()
                    return self.json(200, {"ok": True})
                d = self.body()
                sets, vals, kill_sessions, changed = [], [], False, []
                if "display_name" in d:
                    v = clean(d["display_name"], 64)
                    sets.append("display_name=?"); vals.append(v)
                    if v != target["display_name"]:
                        changed.append("display_name")
                if "email" in d:
                    email = clean(d["email"], 254)
                    if email and not EMAIL_RE.match(email):
                        raise ApiError(400, "Invalid email address")
                    sets.append("email=?"); vals.append(email)
                    if email != target["email"]:
                        changed.append("email")
                if "groups" in d:
                    try:
                        g = parse_groups(d["groups"])
                        sets.append("groups=?"); vals.append(g)
                        if g != target["groups"]:
                            changed.append("groups")
                    except ValueError as e:
                        raise ApiError(400, str(e))
                if "is_admin" in d:
                    if me and not d["is_admin"]:
                        raise ApiError(400, "You can't remove your own admin rights")
                    sets.append("is_admin=?"); vals.append(1 if d["is_admin"] else 0)
                    if bool(d["is_admin"]) != bool(target["is_admin"]):
                        changed.append("is_admin=" + ("yes" if d["is_admin"] else "no"))
                if "disabled" in d:
                    if me and d["disabled"]:
                        raise ApiError(400, "You can't disable your own account")
                    sets.append("disabled=?"); vals.append(1 if d["disabled"] else 0)
                    if bool(d["disabled"]) != bool(target["disabled"]):
                        changed.append("disabled=" + ("yes" if d["disabled"] else "no"))
                    kill_sessions = kill_sessions or bool(d["disabled"])
                if d.get("password"):
                    pw = str(d["password"])
                    if len(pw) < MIN_PW or len(pw) > 256:
                        raise ApiError(400, f"Password must be at least {MIN_PW} characters")
                    sets += ["password_hash=?", "pw_default=0"]; vals.append(hash_pw(pw))
                    changed.append("password")
                    kill_sessions = kill_sessions or not me
                if sets:
                    con.execute(f"UPDATE users SET {', '.join(sets)} WHERE id=?", (*vals, uid))
                if kill_sessions:
                    con.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
                if changed:
                    self.audit("user.update", admin["username"], target["username"], "changed: " + ", ".join(changed), con=con)
                con.commit()
                return self.json(200, {"ok": True})
        raise ApiError(404, "Not found")


if __name__ == "__main__":
    drop_privileges()
    init_db()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    srv.daemon_threads = True
    print(f"Homelab Auth listening on :{PORT}" + (f", proxying to {UPSTREAM_URL}" if UP else " (no UPSTREAM_URL set)"), flush=True)
    srv.serve_forever()
