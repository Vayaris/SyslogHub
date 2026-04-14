from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from .database import get_db, init_db
from .auth import validate_session, create_session
from .routers import auth, spaces, logs, settings
from .utils import service_active
from . import config

BASE = Path("/opt/syslog-server")

app = FastAPI(title="Syslog Server", docs_url=None, redoc_url=None)
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="127.0.0.1")

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
    if token:
        username = validate_session(token)
        if username:
            new_token = create_session(username)
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
        "version": "1.1.0",
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
    # Fetch space for pre-fill
    db: Session = next(get_db())
    try:
        from .models import Space as SpaceModel
        space = db.query(SpaceModel).filter(SpaceModel.id == space_id).first()
        if not space:
            return RedirectResponse(url="/spaces", status_code=302)
        return templates.TemplateResponse(
            "space_edit.html",
            {"request": request, "mode": "edit", "space": space},
        )
    finally:
        db.close()


@app.get("/logs/{space_id}", response_class=HTMLResponse)
def logs_space_page(request: Request, space_id: int):
    redir = _require_auth(request)
    if redir:
        return redir
    db: Session = next(get_db())
    try:
        from .models import Space as SpaceModel
        space = db.query(SpaceModel).filter(SpaceModel.id == space_id).first()
        if not space:
            return RedirectResponse(url="/dashboard", status_code=302)
        return templates.TemplateResponse(
            "logs_space.html", {"request": request, "space": space}
        )
    finally:
        db.close()


@app.get("/logs/{space_id}/{ip}", response_class=HTMLResponse)
def logs_files_page(request: Request, space_id: int, ip: str):
    redir = _require_auth(request)
    if redir:
        return redir
    db: Session = next(get_db())
    try:
        from .models import Space as SpaceModel
        space = db.query(SpaceModel).filter(SpaceModel.id == space_id).first()
        if not space:
            return RedirectResponse(url="/dashboard", status_code=302)
        return templates.TemplateResponse(
            "logs_files.html", {"request": request, "space": space, "ip": ip}
        )
    finally:
        db.close()


@app.get("/logs/{space_id}/{ip}/view", response_class=HTMLResponse)
def logs_viewer_page(request: Request, space_id: int, ip: str):
    redir = _require_auth(request)
    if redir:
        return redir
    db: Session = next(get_db())
    try:
        from .models import Space as SpaceModel
        space = db.query(SpaceModel).filter(SpaceModel.id == space_id).first()
        if not space:
            return RedirectResponse(url="/dashboard", status_code=302)
        filename = request.query_params.get("filename", f"{ip}.log")
        return templates.TemplateResponse(
            "logs_viewer.html",
            {"request": request, "space": space, "ip": ip, "filename": filename},
        )
    finally:
        db.close()


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
        from .models import Space as SpaceModel
        from .services import rsyslog as rsyslog_svc
        spaces = db.query(SpaceModel).all()
        if spaces:
            try:
                rsyslog_svc.apply_rsyslog_config(spaces)
            except Exception as e:
                # Non-fatal: rsyslog is already configured from install
                import logging
                logging.getLogger("syslog-server").warning(
                    f"rsyslog config apply at startup: {e}"
                )
    finally:
        db.close()
