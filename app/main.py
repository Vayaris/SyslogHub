import logging
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from .database import get_db, init_db, SessionLocal
from .auth import validate_session, refresh_session_token
from .models import Setting, Space as SpaceModel
from .routers import auth, spaces, logs, settings, users, compliance_chain, correlation, requisitions, compliance_docs
from .utils import service_active
from . import config

log = logging.getLogger("syslog-server")

BASE = Path("/opt/syslog-server")

app = FastAPI(title="Syslog Server", docs_url=None, redoc_url=None)
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="127.0.0.1")
# Short-lived starlette session — used by Authlib to stash OIDC state/nonce
# between /oidc/login → /oidc/callback. Not the application login session.
app.add_middleware(
    SessionMiddleware,
    secret_key=config.SECRET_KEY,
    session_cookie="oidc_state",
    same_site="lax",   # callback is a cross-site redirect
    https_only=False,  # honour whatever the proxy uses
    max_age=600,
)

# Static files
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
# v2.0.0 — logos per space (uploadés via API)
_BRANDING_ROOT = Path("/opt/syslog-server/data/branding")
_BRANDING_ROOT.mkdir(parents=True, exist_ok=True)
app.mount("/branding", StaticFiles(directory=str(_BRANDING_ROOT)), name="branding")

# Templates
templates = Jinja2Templates(directory=str(BASE / "templates"))

# API routers
app.include_router(auth.router)
app.include_router(spaces.router)
app.include_router(logs.router)
app.include_router(settings.router)
app.include_router(users.router)
app.include_router(compliance_chain.router)
app.include_router(correlation.router)
app.include_router(requisitions.router)
app.include_router(compliance_docs.router)


# ── Rolling session middleware ─────────────────────────────────────────────────

@app.middleware("http")
async def rolling_session(request: Request, call_next):
    response = await call_next(request)
    token = request.cookies.get("session")
    if token and validate_session(token):
        new_token = refresh_session_token(token)
        if new_token:
            is_https = request.url.scheme == "https"
            response.set_cookie(
                "session", new_token,
                httponly=True, secure=is_https,
                samesite="strict", path="/", max_age=86400,
            )
    return response


# ── Force password change middleware ─────────────────────────────────────────
# When the admin is still using the default `changeme` password seeded at
# install time, block every authenticated request except those needed to
# change it. The flag is only set for local `admin` logins; OIDC users
# never trip it.

_FORCE_CHANGE_ALLOWED_PREFIXES = (
    "/static/",
    "/api/auth/",         # login, logout, totp, oidc callback
    "/api/settings",      # GET current state + PUT new password
    "/login",
    "/health",
    "/favicon.ico",
)
_FORCE_CHANGE_ALLOWED_EXACT = {"/settings", "/logout", "/"}


def _password_must_change(username: str) -> bool:
    if not username:
        return False
    db = SessionLocal()
    try:
        flag = db.query(Setting).filter(
            Setting.key == "admin_password_must_change"
        ).first()
        if not flag or flag.value != "true":
            return False
        # Only applies to the local `admin` account, not to OIDC users whose
        # username is their email.
        admin_row = db.query(Setting).filter(
            Setting.key == "admin_username"
        ).first()
        admin_name = admin_row.value if admin_row else "admin"
        return username == admin_name
    finally:
        db.close()


@app.middleware("http")
async def force_password_change(request: Request, call_next):
    path = request.url.path
    if path in _FORCE_CHANGE_ALLOWED_EXACT or any(
        path.startswith(p) for p in _FORCE_CHANGE_ALLOWED_PREFIXES
    ):
        return await call_next(request)

    token = request.cookies.get("session")
    username = validate_session(token) if token else None
    if username and _password_must_change(username):
        if path.startswith("/api/"):
            return JSONResponse(
                {"error": "password_change_required",
                 "detail": "Définissez un mot de passe avant d'utiliser l'application."},
                status_code=403,
            )
        return RedirectResponse(url="/settings?force_password=1", status_code=302)
    return await call_next(request)


# ── Public endpoints ──────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return JSONResponse({
        "status": "ok",
        "version": "2.0.0",
        "services": {
            "rsyslog": service_active("rsyslog"),
            "nginx": service_active("nginx"),
        },
    })


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_authenticated(request: Request) -> bool:
    token = request.cookies.get("session")
    return bool(token and validate_session(token))


def _require_auth(request: Request):
    if not _is_authenticated(request):
        return RedirectResponse(url="/login", status_code=302)
    return None


def _fetch_space_or_redirect(space_id: int, redirect_url: str = "/dashboard"):
    """Look up a Space by id. Returns (space, None) on success, or
    (None, RedirectResponse) if not found. Caller is responsible for
    returning the redirect when present."""
    db: Session = next(get_db())
    try:
        space = db.query(SpaceModel).filter(SpaceModel.id == space_id).first()
        if not space:
            return None, RedirectResponse(url=redirect_url, status_code=302)
        return space, None
    finally:
        db.close()


# ── HTML page routes ──────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    redir = _require_auth(request)
    if redir:
        return redir
    return RedirectResponse(url="/dashboard", status_code=302)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if _is_authenticated(request):
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page(request: Request):
    redir = _require_auth(request)
    if redir:
        return redir
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/spaces", response_class=HTMLResponse)
def spaces_page(request: Request):
    redir = _require_auth(request)
    if redir:
        return redir
    return templates.TemplateResponse("spaces.html", {"request": request})


@app.get("/spaces/new", response_class=HTMLResponse)
def spaces_new_page(request: Request):
    redir = _require_auth(request)
    if redir:
        return redir
    return templates.TemplateResponse(
        "space_edit.html", {"request": request, "mode": "create", "space": None}
    )


@app.get("/spaces/{space_id}/edit", response_class=HTMLResponse)
def spaces_edit_page(request: Request, space_id: int):
    redir = _require_auth(request)
    if redir:
        return redir
    space, rr = _fetch_space_or_redirect(space_id, redirect_url="/spaces")
    if rr:
        return rr
    return templates.TemplateResponse(
        "space_edit.html",
        {"request": request, "mode": "edit", "space": space},
    )


@app.get("/logs/{space_id}", response_class=HTMLResponse)
def logs_space_page(request: Request, space_id: int):
    redir = _require_auth(request)
    if redir:
        return redir
    space, rr = _fetch_space_or_redirect(space_id)
    if rr:
        return rr
    return templates.TemplateResponse(
        "logs_space.html", {"request": request, "space": space}
    )


@app.get("/logs/{space_id}/merged", response_class=HTMLResponse)
def logs_merged_page(request: Request, space_id: int):
    redir = _require_auth(request)
    if redir:
        return redir
    space, rr = _fetch_space_or_redirect(space_id)
    if rr:
        return rr
    if not getattr(space, "lan_mode", False):
        return RedirectResponse(url=f"/logs/{space_id}", status_code=302)
    return templates.TemplateResponse(
        "logs_viewer.html",
        {"request": request, "space": space, "ip": "_all",
         "filename": "_all.log", "merged": True},
    )


@app.get("/logs/{space_id}/{ip}", response_class=HTMLResponse)
def logs_files_page(request: Request, space_id: int, ip: str):
    redir = _require_auth(request)
    if redir:
        return redir
    space, rr = _fetch_space_or_redirect(space_id)
    if rr:
        return rr
    return templates.TemplateResponse(
        "logs_files.html", {"request": request, "space": space, "ip": ip}
    )


@app.get("/logs/{space_id}/{ip}/view", response_class=HTMLResponse)
def logs_viewer_page(request: Request, space_id: int, ip: str):
    redir = _require_auth(request)
    if redir:
        return redir
    space, rr = _fetch_space_or_redirect(space_id)
    if rr:
        return rr
    filename = request.query_params.get("filename", f"{ip}.log")
    return templates.TemplateResponse(
        "logs_viewer.html",
        {"request": request, "space": space, "ip": ip,
         "filename": filename, "merged": False},
    )


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    redir = _require_auth(request)
    if redir:
        return redir
    return templates.TemplateResponse("settings.html", {"request": request})


@app.get("/users", response_class=HTMLResponse)
def users_page(request: Request):
    redir = _require_auth(request)
    if redir:
        return redir
    return templates.TemplateResponse("users.html", {"request": request})


# ── v2.0.0 — pages conformité ────────────────────────────────────────────────

@app.get("/compliance", response_class=HTMLResponse)
def compliance_page(request: Request):
    redir = _require_auth(request)
    if redir:
        return redir
    return templates.TemplateResponse("compliance.html", {"request": request})


@app.get("/compliance/chain", response_class=HTMLResponse)
def compliance_chain_page(request: Request):
    redir = _require_auth(request)
    if redir:
        return redir
    return templates.TemplateResponse("compliance_chain.html", {"request": request})


@app.get("/compliance/correlation", response_class=HTMLResponse)
def compliance_correlation_page(request: Request):
    redir = _require_auth(request)
    if redir:
        return redir
    return templates.TemplateResponse("compliance_correlation.html", {"request": request})


@app.get("/compliance/requisitions", response_class=HTMLResponse)
def compliance_requisitions_page(request: Request):
    redir = _require_auth(request)
    if redir:
        return redir
    return templates.TemplateResponse("compliance_requisitions.html", {"request": request})


@app.get("/compliance/documents", response_class=HTMLResponse)
def compliance_documents_page(request: Request):
    redir = _require_auth(request)
    if redir:
        return redir
    return templates.TemplateResponse("compliance_documents.html", {"request": request})


# ── Startup ───────────────────────────────────────────────────────────────────

@app.on_event("startup")
def startup():
    init_db()
    # Ensure initial rsyslog config is applied
    db: Session = next(get_db())
    try:
        from .services import rsyslog as rsyslog_svc
        from .services import audit as audit_svc
        from .auth import purge_stale_sessions

        spaces_list = db.query(SpaceModel).all()
        if spaces_list:
            try:
                rsyslog_svc.apply_rsyslog_config(spaces_list)
            except Exception as e:
                log.warning(f"rsyslog config apply at startup: {e}")

        # v1.9.0 — housekeeping
        audit_svc.purge_old(db, keep_days=180)
        purge_stale_sessions(db)

        # v1.10.0 — drop brute-force attempt rows older than a week.
        from .services import ratelimit as ratelimit_svc
        ratelimit_svc.purge_old(db, keep_days=7)

        # v1.10.0 — re-encrypt any remaining plaintext secrets in the DB.
        # Safe to run on every boot: already-wrapped values are skipped.
        from .services import crypto as crypto_svc
        try:
            crypto_svc.migrate_plaintext(db)
        except Exception as e:
            log.warning(f"crypto.migrate_plaintext failed: {e}")
    finally:
        db.close()

    # v2.0.0 — backfill rétroactif de la chaîne d'intégrité, une fois.
    # Tourne en background pour ne pas bloquer le démarrage (peut prendre
    # plusieurs minutes sur une install avec 365 jours de logs).
    import threading
    def _v2_chain_backfill():
        from .services import chain as chain_svc
        db2 = SessionLocal()
        try:
            flag = db2.query(Setting).filter(Setting.key == "v2_chain_migrated").first()
            if flag and flag.value == "true":
                return
            spaces = db2.query(SpaceModel).filter(SpaceModel.chain_enabled == True).all()  # noqa: E712
            total = 0
            for sp in spaces:
                try:
                    created = chain_svc.backfill_retroactive(
                        db2, sp, max_days=int(sp.retention_days or 365)
                    )
                    total += created
                    if created:
                        log.info(f"chain backfill: space={sp.id} {sp.name} → {created} manifests")
                except Exception as e:
                    log.warning(f"chain backfill space={sp.id} failed: {e}")
            if flag:
                flag.value = "true"
            else:
                db2.add(Setting(key="v2_chain_migrated", value="true"))
            db2.commit()
            log.info(f"v2_chain backfill terminé — {total} manifests créés au total")
        except Exception as e:
            log.warning(f"v2_chain backfill global failed: {e}")
        finally:
            db2.close()
    threading.Thread(target=_v2_chain_backfill, daemon=True, name="v2-chain-backfill").start()
