"""
backend/auth.py
===============
Authentication for BioPredict (login / sign-up / logout + route guard).

* Users are stored in SQLite (backend/data/users.db) with PBKDF2-SHA256 hashes.
* Sessions are stateless, HMAC-signed cookies (``bp_session``).
* ``install(app)`` wires everything into the existing FastAPI app, so the
  compiled ``_compiled_main`` module does not need to change.

Environment variables
---------------------
BIOPREDICT_SECRET   Signing key for session cookies. If unset, a random key is
                    generated once and kept in backend/data/.secret.
BIOPREDICT_DB       Override path for the SQLite user database.
"""
import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(CURRENT_DIR, "data")
FRONTEND_DIR = os.path.join(os.path.dirname(CURRENT_DIR), "frontend")
DB_PATH = os.environ.get("BIOPREDICT_DB", os.path.join(DATA_DIR, "users.db"))

def _load_dotenv() -> None:
    """Tiny .env reader (project root or backend/) so no extra dependency is needed."""
    for d in (os.path.dirname(CURRENT_DIR), CURRENT_DIR):
        path = os.path.join(d, ".env")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv()

SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://xvbsnublyudellvkrriq.supabase.co").rstrip("/")
SUPABASE_KEY = os.environ.get("SUPABASE_ANON_KEY") or os.environ.get("SUPABASE_KEY") or ""
USE_SUPABASE = bool(SUPABASE_URL and SUPABASE_KEY)

COOKIE_NAME = "bp_session"
SESSION_TTL = 7 * 24 * 3600
PBKDF2_ITERS = 240_000
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

_db_lock = threading.Lock()


# ───────────────────────── secret key ─────────────────────────
def _load_secret() -> bytes:
    env = os.environ.get("BIOPREDICT_SECRET")
    if env:
        return env.encode()
    os.makedirs(DATA_DIR, exist_ok=True)
    path = os.path.join(DATA_DIR, ".secret")
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    key = secrets.token_bytes(32)
    with open(path, "wb") as f:
        f.write(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


SECRET = _load_secret()


# ───────────────────────── user store ─────────────────────────
def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               email TEXT NOT NULL UNIQUE COLLATE NOCASE,
               pw_salt TEXT NOT NULL,
               pw_hash TEXT NOT NULL,
               created_at INTEGER NOT NULL
           )"""
    )
    return conn


def hash_password(password: str, salt: Optional[bytes] = None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERS)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    _, digest = hash_password(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(digest, hash_hex)


def create_user(email: str, password: str) -> Optional[int]:
    """Returns the new user id, or None if the email is already registered."""
    salt, digest = hash_password(password)
    with _db_lock, _connect() as conn:
        try:
            cur = conn.execute(
                "INSERT INTO users (email, pw_salt, pw_hash, created_at) VALUES (?,?,?,?)",
                (email, salt, digest, int(time.time())),
            )
            return cur.lastrowid
        except sqlite3.IntegrityError:
            return None


def authenticate(email: str, password: str) -> Optional[sqlite3.Row]:
    with _db_lock, _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if row is None:
        # Burn comparable time so unknown emails are not distinguishable.
        hash_password(password)
        return None
    return row if verify_password(password, row["pw_salt"], row["pw_hash"]) else None


# ───────────────────────── Supabase Auth (REST) ─────────────────────────
class AuthError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message, self.status = message, status


def _sb_post(path: str, payload: dict) -> dict:
    req = urllib.request.Request(
        f"{SUPABASE_URL}{path}", data=json.dumps(payload).encode(), method="POST",
        headers={"apikey": SUPABASE_KEY, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read() or b"{}")
        except Exception:
            body = {}
        raise AuthError(body.get("msg") or body.get("error_description") or body.get("message") or "Auth request failed", e.code)
    except (urllib.error.URLError, TimeoutError):
        raise AuthError("Could not reach the database. Try again shortly.", 503)


def sb_signup(email: str, password: str) -> dict:
    """Returns {"id", "email", "confirmed": bool}. Raises AuthError."""
    data = _sb_post("/auth/v1/signup", {"email": email, "password": password})
    user = data.get("user") or data  # session response nests the user, confirm-pending does not
    # Supabase returns a user with no identities when the email is already registered.
    if user.get("identities") == []:
        raise AuthError("An account with this email already exists.", 409)
    return {"id": user.get("id"), "email": user.get("email", email), "confirmed": bool(data.get("access_token"))}


def sb_login(email: str, password: str) -> dict:
    data = _sb_post("/auth/v1/token?grant_type=password", {"email": email, "password": password})
    user = data.get("user") or {}
    return {"id": user.get("id"), "email": user.get("email", email)}


# ───────────────────────── session tokens ─────────────────────────
def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_token(user_id, email: str, ttl: int = SESSION_TTL) -> str:
    payload = _b64(json.dumps({"uid": user_id, "email": email, "exp": int(time.time()) + ttl}).encode())
    sig = _b64(hmac.new(SECRET, payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{sig}"


def read_token(token: Optional[str]) -> Optional[dict]:
    if not token or "." not in token:
        return None
    payload, sig = token.rsplit(".", 1)
    expected = _b64(hmac.new(SECRET, payload.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        data = json.loads(_unb64(payload))
    except Exception:
        return None
    return data if data.get("exp", 0) > time.time() else None


# ───────────────────────── brute-force throttle ─────────────────────────
_fails: dict = {}
MAX_FAILS, WINDOW = 5, 300


def _throttled(key: str) -> bool:
    now = time.time()
    recent = [t for t in _fails.get(key, []) if now - t < WINDOW]
    _fails[key] = recent
    return len(recent) >= MAX_FAILS


def _record_fail(key: str) -> None:
    _fails.setdefault(key, []).append(time.time())


# ───────────────────────── helpers ─────────────────────────
def safe_next(value: Optional[str]) -> str:
    """Only allow redirects back into the app itself."""
    if value and value.startswith("/app") and not value.startswith("//") and "\\" not in value:
        return value
    return "/app/"


def _set_cookie(resp, request: Request, token: str) -> None:
    resp.set_cookie(
        COOKIE_NAME, token, max_age=SESSION_TTL, httponly=True, samesite="lax",
        secure=request.url.scheme == "https", path="/",
    )


def current_user(request: Request) -> Optional[dict]:
    return read_token(request.cookies.get(COOKIE_NAME))


async def _json(request: Request) -> dict:
    try:
        data = await request.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


# ───────────────────────── routes ─────────────────────────
router = APIRouter()


@router.post("/auth/signup", include_in_schema=False)
async def signup(request: Request):
    body = await _json(request)
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
    if not EMAIL_RE.match(email) or len(email) > 254:
        return JSONResponse({"detail": "Enter a valid email address."}, status_code=400)
    if len(password) < 8:
        return JSONResponse({"detail": "Password must be at least 8 characters."}, status_code=400)
    if USE_SUPABASE:
        try:
            u = await asyncio.to_thread(sb_signup, email, password)
        except AuthError as e:
            return JSONResponse({"detail": e.message}, status_code=e.status if e.status in (409, 429, 503) else 400)
        if not u["confirmed"]:
            return JSONResponse({"ok": True, "confirm": True, "email": email,
                                 "detail": "Check your inbox to confirm your email, then log in."})
        uid, email = u["id"], u["email"]
    else:
        uid = create_user(email, password)
        if uid is None:
            return JSONResponse({"detail": "An account with this email already exists."}, status_code=409)
    resp = JSONResponse({"ok": True, "email": email, "next": safe_next(body.get("next"))})
    _set_cookie(resp, request, make_token(uid, email))
    return resp


@router.post("/auth/login", include_in_schema=False)
async def login(request: Request):
    body = await _json(request)
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
    key = f"{request.client.host if request.client else '?'}|{email}"
    if _throttled(key):
        return JSONResponse({"detail": "Too many attempts. Try again in a few minutes."}, status_code=429)
    uid = None
    if email and password:
        if USE_SUPABASE:
            try:
                u = await asyncio.to_thread(sb_login, email, password)
                uid, email = u["id"], u["email"]
            except AuthError as e:
                if e.status == 503:
                    return JSONResponse({"detail": e.message}, status_code=503)
                if "confirm" in e.message.lower():
                    return JSONResponse({"detail": "Please confirm your email first (check your inbox)."}, status_code=401)
        else:
            row = authenticate(email, password)
            if row:
                uid, email = row["id"], row["email"]
    if uid is None:
        _record_fail(key)
        return JSONResponse({"detail": "Incorrect email or password."}, status_code=401)
    _fails.pop(key, None)
    resp = JSONResponse({"ok": True, "email": email, "next": safe_next(body.get("next"))})
    _set_cookie(resp, request, make_token(uid, email))
    return resp


@router.post("/auth/logout", include_in_schema=False)
async def logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


@router.get("/auth/me", include_in_schema=False)
async def me(request: Request):
    user = current_user(request)
    if not user:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    return {"email": user["email"]}


# Login page + its static files (served without authentication)
_PUBLIC_FILES = {
    "/app/login": ("login.html", "text/html"),
    "/app/login.css": ("login.css", "text/css"),
    "/app/login.js": ("login.js", "application/javascript"),
    "/app/auth-ui.js": ("auth-ui.js", "application/javascript"),
}


def _make_file_route(filename: str, media: str):
    async def serve(request: Request, _f=filename, _m=media):
        # Already signed in? Skip the login screen.
        if _f == "login.html" and current_user(request):
            return RedirectResponse(safe_next(request.query_params.get("next")), status_code=302)
        return FileResponse(os.path.join(FRONTEND_DIR, _f), media_type=_m,
                            headers={"Cache-Control": "no-cache"})
    return serve


for _path, (_file, _media) in _PUBLIC_FILES.items():
    router.add_api_route(_path, _make_file_route(_file, _media), methods=["GET"], include_in_schema=False)


# ───────────────────────── route guard ─────────────────────────
PUBLIC_EXACT = {"/health", "/docs", "/openapi.json", "/redoc", "/favicon.ico", "/auth/login", "/auth/signup",
                "/auth/logout", "/auth/me", *_PUBLIC_FILES.keys()}


class AuthGuard(BaseHTTPMiddleware):
    """Everything except the login flow requires a valid session."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if request.method == "OPTIONS" or path in PUBLIC_EXACT or current_user(request):
            return await call_next(request)
        if path == "/" or path.startswith("/app"):
            if path.startswith("/app/assets/login-") or path == "/app/hero-molecule.js":
                return await call_next(request)
            target = path + (f"?{request.url.query}" if request.url.query else "")
            if path == "/":
                target = "/app/"
            from urllib.parse import quote
            return RedirectResponse(f"/app/login?next={quote(target, safe='/')}", status_code=302)
        return JSONResponse({"detail": "Authentication required"}, status_code=401)


def install(app) -> None:
    # Put auth routes first so they win over any catch-all in the compiled app.
    app.router.routes[0:0] = router.routes
    app.add_middleware(AuthGuard)
