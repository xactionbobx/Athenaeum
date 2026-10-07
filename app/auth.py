import asyncio
import ipaddress
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timezone, timedelta

from fastapi import Depends, HTTPException, Request, Response
from jose import JWTError, jwt

from .database import get_db
from .settings import get_settings, save_settings

ALGORITHM = "HS256"

# Identities asserted by a reverse proxy's auth headers are stored in the OIDC
# columns under this issuer, so they never collide with a real OIDC provider.
HEADER_ISS = "proxy-header"
_DNS_TTL = 60
_dns_cache: dict[str, tuple[float, set[str]]] = {}


def _auth_active(settings: dict) -> bool:
    auth = settings.get("auth", {})
    return auth.get("form_enabled") or auth.get("oidc_enabled") or auth.get("header_enabled")


def _active_modes(settings: dict) -> list[str]:
    auth = settings.get("auth", {})
    modes = []
    if auth.get("form_enabled"):
        modes.append("form")
    if auth.get("oidc_enabled"):
        modes.append("oidc")
    return modes


async def ensure_session_secret():
    """Auto-generate session_secret if not set. Called on startup."""
    settings = await get_settings()
    if not settings.get("auth", {}).get("session_secret"):
        await save_settings({"auth": {"session_secret": secrets.token_hex(32)}})


def _make_session_token(user_id: str, role: str, secret: str, days: int) -> str:
    exp = datetime.now(timezone.utc) + timedelta(days=int(days))
    return jwt.encode({"sub": user_id, "role": role, "exp": exp}, secret, algorithm=ALGORITHM)


def set_session_cookie(response: Response, token: str, request: Request, days: int):
    # Mark the long-lived session cookie Secure whenever the request is https —
    # either via the proxy's X-Forwarded-Proto or a direct TLS request (no proxy),
    # where only request.url.scheme reflects it. Missing this on direct HTTPS would
    # ship the session cookie over an insecure flag.
    secure = (
        request.headers.get("x-forwarded-proto", "").lower() == "https"
        or request.url.scheme == "https"
    )
    response.set_cookie(
        "session", token,
        httponly=True,
        samesite="lax",
        secure=secure,
        max_age=days * 86400,
        path="/",
    )


def clear_session_cookie(response: Response):
    response.delete_cookie("session", path="/")


# ── Reverse-proxy header auth (e.g. Authentik forward auth) ───────────────────

async def _resolve(name: str) -> set[str]:
    hit = _dns_cache.get(name)
    if hit and hit[0] > time.time():
        return hit[1]
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(name, None)
        ips = {info[4][0] for info in infos}
    except OSError:
        ips = set()
    _dns_cache[name] = (time.time() + _DNS_TTL, ips)
    return ips


async def _from_trusted_proxy(request: Request, proxies: list) -> bool:
    """True when the TCP peer is one of the trusted proxies (IPs, CIDRs or
    hostnames, resolved on demand). Only the direct peer counts: anything else
    on the network could set the identity headers itself."""
    host = request.client.host if request.client else ""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    for proxy in proxies:
        proxy = str(proxy).strip()
        if not proxy:
            continue
        try:
            if addr in ipaddress.ip_network(proxy, strict=False):
                return True
            continue
        except ValueError:
            pass
        if host in await _resolve(proxy):
            return True
    return False


async def _provision_header_user(db, sub: str, username: str, email: str) -> str:
    """Create a 'user' account for a proxy identity, stepping past username
    collisions the same way OIDC provisioning does. Returns the user id."""
    base = (username or "user")[:32]
    for n in range(1, 51):
        candidate = base if n == 1 else f"{base[:24]}-{n}"
        new_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        try:
            await db.execute(
                """INSERT INTO users (id, username, email, role, oidc_sub, oidc_iss, created_at, updated_at)
                   VALUES (?, ?, ?, 'user', ?, ?, ?, ?)""",
                (new_id, candidate, email or None, sub, HEADER_ISS, now, now),
            )
            await db.commit()
            return new_id
        except sqlite3.IntegrityError:
            await db.rollback()
            existing = await (
                await db.execute("SELECT id FROM users WHERE oidc_iss = ? AND oidc_sub = ?", (HEADER_ISS, sub))
            ).fetchone()
            if existing:
                return existing["id"]
    raise HTTPException(500, "Could not allocate a unique username for proxy user")


async def header_identity(request: Request, settings: dict) -> dict | None:
    """The user a trusted reverse proxy vouches for, or None.

    Accounts are linked by the proxy's stable user id header only (Authentik's
    X-authentik-uid), never by username or email, which users may be able to
    change themselves. An unknown id is provisioned as a 'user' when
    header_auto_create is on; existing accounts are linked by an admin setting
    oidc_iss = 'proxy-header' and oidc_sub = that id.
    """
    cfg = settings.get("auth", {})
    if not cfg.get("header_enabled"):
        return None
    sub = request.headers.get(cfg.get("header_uid") or "X-authentik-uid", "").strip()
    if not sub or not await _from_trusted_proxy(request, cfg.get("header_trusted_proxies") or ["traefik"]):
        return None
    async with get_db() as db:
        query = "SELECT id, username, email, role FROM users WHERE oidc_iss = ? AND oidc_sub = ?"
        row = await (await db.execute(query, (HEADER_ISS, sub))).fetchone()
        if not row and cfg.get("header_auto_create", True):
            username = request.headers.get(cfg.get("header_username") or "X-authentik-username", "").strip()
            email = request.headers.get(cfg.get("header_email") or "X-authentik-email", "").strip()
            await _provision_header_user(db, sub, username or sub[:12], email)
            row = await (await db.execute(query, (HEADER_ISS, sub))).fetchone()
    if not row:
        return None
    return {"user_id": row["id"], "role": row["role"], "username": row["username"], "email": row["email"] or ""}


async def require_auth(request: Request) -> dict:
    """Returns {user_id, role} or raises 401. Passthrough when auth is disabled."""
    settings = await get_settings()
    if not _auth_active(settings):
        return {"user_id": "anonymous", "role": "admin"}
    ident = await header_identity(request, settings)
    if ident:
        return {"user_id": ident["user_id"], "role": ident["role"]}
    token = request.cookies.get("session")
    if not token:
        raise HTTPException(401, detail={"modes": _active_modes(settings)})
    try:
        secret = settings["auth"]["session_secret"]
        payload = jwt.decode(token, secret, algorithms=[ALGORITHM])
        return {"user_id": payload["sub"], "role": payload["role"]}
    except JWTError:
        raise HTTPException(401, detail={"modes": _active_modes(settings)})


async def require_admin(auth: dict = Depends(require_auth)) -> dict:
    if auth["role"] != "admin":
        raise HTTPException(403, "Admin required")
    return auth
