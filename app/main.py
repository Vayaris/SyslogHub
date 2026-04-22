import logging
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from .database import get_db, init_db
from .auth import validate_session, refresh_session_token
from .models import Space as SpaceModel
from .routers import auth, spaces, logs, settings
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

# Templates
templates = Jinja2Templates(directory=str(BASE / "templates"))

# API routers
app.include_router(auth.router)
app.include_router(spaces.router)
app.include_router(logs.router)
app.include_router(settings.router)


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


# ── Public endpoints ──────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return JSONResponse({
        "status": "ok",
        "version": "1.9.0",
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
    finally:
        db.close()
