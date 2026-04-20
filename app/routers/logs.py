import io
import ipaddress
import re
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..auth import get_current_user
from .. import config
from ..database import get_db
from ..models import Space
from ..schemas import (
    FileInfo, LogViewResult, SearchResponse, SearchResult,
    SourceInfo, SourceListResponse,
)
from ..services import omada as omada_svc
from ..services import log_scanner

router = APIRouter(prefix="/api/logs", tags=["logs"])


def _get_space_or_404(space_id: int, db: Session) -> Space:
    space = db.query(Space).filter(Space.id == space_id).first()
    if not space:
        raise HTTPException(status_code=404, detail="Espace introuvable")
    return space


def _validate_ip(ip: str) -> str:
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        raise HTTPException(status_code=400, detail="Adresse IP invalide")


def _validate_log_path(port: int, ip: str, filename: str) -> Path:
    _validate_ip(ip)
    base = Path(config.LOG_ROOT).resolve() / str(port)
    candidate = (base / filename).resolve()
    if not str(candidate).startswith(str(base) + "/"):
        raise HTTPException(status_code=403, detail="Accès refusé")
    if not candidate.exists():
        raise HTTPException(status_code=404, detail="Fichier introuvable")
    return candidate


@router.get("/search", response_model=SearchResponse)
def search_logs(
    q: str = Query(..., min_length=3),
    space_id: int = Query(default=None),
    lines: int = Query(default=200, ge=1, le=1000),
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    if space_id:
        spaces = db.query(Space).filter(Space.id == space_id).all()
    else:
        spaces = db.query(Space).all()

    results = []
    truncated = False

    for space in spaces:
        log_dir = Path(config.LOG_ROOT) / str(space.port)
        if not log_dir.exists():
            continue

        # Anchor regex on known log_dir to avoid colon-ambiguity in grep output
        line_re = re.compile(
            rf'^({re.escape(str(log_dir))}/[^:]+):(\d+):(.*)$'
        )

        try:
            proc = subprocess.run(
                ["grep", "-rn", "--include=*.log", "--exclude=_all.log",
                 "-m", str(lines), "--", q, str(log_dir)],
                capture_output=True, text=True, timeout=10,
            )
            for raw in proc.stdout.splitlines():
                if len(results) >= lines:
                    truncated = True
                    break
                m = line_re.match(raw)
                if not m:
                    continue
                filepath, lineno_str, content = m.group(1), m.group(2), m.group(3)
                fname = Path(filepath).name
                # Extract IP: everything before the first .log
                ip_part = fname.split(".log")[0]
                results.append(SearchResult(
                    space_id=space.id,
                    space_name=space.name,
                    port=space.port,
                    source_ip=ip_part,
                    filename=fname,
                    line_number=int(lineno_str),
                    line=content,
                ))
        except subprocess.TimeoutExpired:
            truncated = True

    return SearchResponse(results=results, truncated=truncated)


@router.delete("/{space_id}/sources/{ip}")
def delete_source(
    space_id: int,
    ip: str,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    space = _get_space_or_404(space_id, db)
    _validate_ip(ip)

    log_dir = Path(config.LOG_ROOT) / str(space.port)
    if not log_dir.exists():
        raise HTTPException(status_code=404, detail="Aucun log pour cet espace")

    deleted = []
    for f in log_dir.iterdir():
        if f.is_file() and (f.name == f"{ip}.log" or f.name.startswith(f"{ip}.log.")):
            f.unlink()
            deleted.append(f.name)

    if not deleted:
        raise HTTPException(status_code=404, detail="Aucun fichier trouvé pour cette source")

    return {"ok": True, "deleted_files": deleted}


@router.get("/{space_id}/sources", response_model=SourceListResponse)
def list_sources(
    space_id: int,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    filter_ip: str = Query(default=""),
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    space = _get_space_or_404(space_id, db)
    sources = log_scanner.list_sources(space.port)

    if filter_ip:
        fl = filter_ip.lower()
        sources = [s for s in sources if fl in s["ip"]]

    total = len(sources)
    pages = max(1, (total + per_page - 1) // per_page)
    start = (page - 1) * per_page
    items = [SourceInfo(**s) for s in sources[start:start + per_page]]

    return SourceListResponse(
        items=items, total=total, page=page, per_page=per_page, pages=pages
    )


@router.get("/{space_id}/sources/{ip}/files", response_model=list[FileInfo])
def list_files(
    space_id: int,
    ip: str,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    space = _get_space_or_404(space_id, db)
    _validate_ip(ip)
    files = log_scanner.list_files(space.port, ip)
    return [FileInfo(**f) for f in files]


@router.get("/{space_id}/ap-macs")
def list_ap_macs(
    space_id: int,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    space = _get_space_or_404(space_id, db)
    macs = log_scanner.list_ap_macs(space.port)

    omada = omada_svc.get_client_for_space(space)
    result = []
    for mac in macs:
        info: dict = {"mac": mac, "name": None, "model": None,
                      "type": None, "status": None}
        if omada:
            try:
                dev = omada.get_device_by_mac(mac)
                if dev:
                    info["name"]   = dev.get("name")
                    info["model"]  = dev.get("model")
                    info["type"]   = dev.get("type")
                    info["status"] = dev.get("status")
            except Exception:
                pass
        result.append(info)

    return {"devices": result, "count": len(result)}


@router.get("/{space_id}/sources/{ip}/view", response_model=LogViewResult)
def view_log(
    space_id: int,
    ip: str,
    filename: str = Query(...),
    lines: int = Query(default=100, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
    filter: str = Query(default=""),
    ap_mac: str = Query(default=""),
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    space = _get_space_or_404(space_id, db)
    path = _validate_log_path(space.port, ip, filename)
    result = log_scanner.read_log_tail(
        path, lines=lines, offset=offset,
        filter_str=filter, ap_mac_filter=ap_mac,
    )
    return LogViewResult(**result)


@router.get("/{space_id}/merged/view", response_model=LogViewResult)
def view_merged_log(
    space_id: int,
    lines: int = Query(default=100, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
    filter: str = Query(default=""),
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    space = _get_space_or_404(space_id, db)
    if not getattr(space, "lan_mode", False):
        raise HTTPException(status_code=404, detail="Mode LAN désactivé pour cet espace")
    path = log_scanner._merged_log_path(space.port)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Aucun log reçu pour l'instant")
    result = log_scanner.read_log_tail(
        path, lines=lines, offset=offset, filter_str=filter,
    )
    return LogViewResult(**result)


@router.get("/{space_id}/sources/{ip}/download")
def download_log(
    space_id: int,
    ip: str,
    filename: str = Query(...),
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    space = _get_space_or_404(space_id, db)
    path = _validate_log_path(space.port, ip, filename)

    def file_streamer():
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                yield chunk

    return StreamingResponse(
        file_streamer(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{space_id}/sources/{ip}/download-zip")
def download_source_zip(
    space_id: int,
    ip: str,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    space = _get_space_or_404(space_id, db)
    _validate_ip(ip)

    log_dir = Path(config.LOG_ROOT) / str(space.port)
    files = [
        f for f in log_dir.iterdir()
        if f.is_file() and (f.name == f"{ip}.log" or f.name.startswith(f"{ip}.log."))
    ] if log_dir.exists() else []

    if not files:
        raise HTTPException(status_code=404, detail="Aucun fichier pour cette source")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            zf.write(f, f.name)
    buf.seek(0)

    safe_ip = ip.replace(":", "-")
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{safe_ip}-logs.zip"'},
    )


@router.get("/{space_id}/sources/{ip}/download-range")
def download_source_range(
    space_id: int,
    ip: str,
    start: str = Query(..., description="YYYY-MM-DD, inclusif"),
    end:   str = Query(..., description="YYYY-MM-DD, inclusif"),
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    space = _get_space_or_404(space_id, db)
    _validate_ip(ip)

    try:
        d0 = datetime.strptime(start, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        d1 = datetime.strptime(end, "%Y-%m-%d").replace(
            hour=23, minute=59, second=59, tzinfo=timezone.utc
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Format de date invalide (YYYY-MM-DD)")
    if d0 > d1:
        raise HTTPException(status_code=400, detail="La date de début doit être antérieure à la date de fin")

    paths = log_scanner.files_in_date_range(
        space.port, ip, d0.timestamp(), d1.timestamp()
    )
    if not paths:
        raise HTTPException(status_code=404, detail="Aucun log dans la plage demandée")

    def streamer():
        for p in paths:
            yield from log_scanner.stream_file_contents(p)
            yield b"\n"

    safe_ip = ip.replace(":", "-")
    fname = f"{safe_ip}_{start}_to_{end}.log"
    return StreamingResponse(
        streamer(),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.get("/{space_id}/download-zip")
def download_space_zip(
    space_id: int,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    space = _get_space_or_404(space_id, db)
    log_dir = Path(config.LOG_ROOT) / str(space.port)

    if not log_dir.exists():
        raise HTTPException(status_code=404, detail="Aucun log pour cet espace")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in log_dir.rglob("*"):
            if f.is_file():
                zf.write(f, f.relative_to(log_dir))
    buf.seek(0)

    safe_name = space.name.replace(" ", "_").lower()
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}-port{space.port}.zip"'},
    )
