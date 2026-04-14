import ipaddress
import subprocess
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..auth import get_current_user
from .. import config
from ..database import get_db
from ..models import Space
from ..schemas import (
    FileInfo, LogViewResult, SearchResponse, SearchResult, SourceInfo
)
from ..services import log_scanner

router = APIRouter(prefix="/api/logs", tags=["logs"])


def _get_space_or_404(space_id: int, db: Session) -> Space:
    space = db.query(Space).filter(Space.id == space_id).first()
    if not space:
        raise HTTPException(status_code=404, detail="Espace introuvable")
    return space


def _validate_log_path(port: int, ip: str, filename: str) -> Path:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Adresse IP invalide")

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

        try:
            proc = subprocess.run(
                ["grep", "-rn", "--include=*.log", "-m", str(lines), q, str(log_dir)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            for line in proc.stdout.splitlines():
                if len(results) >= lines:
                    truncated = True
                    break
                # Format: /path/to/log:linenum:content
                parts = line.split(":", 2)
                if len(parts) < 3:
                    continue
                filepath = parts[0]
                try:
                    lineno = int(parts[1])
                except ValueError:
                    continue
                content = parts[2]
                fname = Path(filepath).name
                ip = fname.replace(".log", "").split(".log.")[0]
                results.append(SearchResult(
                    space_id=space.id,
                    space_name=space.name,
                    port=space.port,
                    source_ip=ip,
                    filename=fname,
                    line_number=lineno,
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
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Adresse IP invalide")

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


@router.get("/{space_id}/sources", response_model=list[SourceInfo])
def list_sources(
    space_id: int,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    space = _get_space_or_404(space_id, db)
    sources = log_scanner.list_sources(space.port)
    return [SourceInfo(**s) for s in sources]


@router.get("/{space_id}/sources/{ip}/files", response_model=list[FileInfo])
def list_files(
    space_id: int,
    ip: str,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    space = _get_space_or_404(space_id, db)
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Adresse IP invalide")
    files = log_scanner.list_files(space.port, ip)
    return [FileInfo(**f) for f in files]


@router.get("/{space_id}/sources/{ip}/view", response_model=LogViewResult)
def view_log(
    space_id: int,
    ip: str,
    filename: str = Query(...),
    lines: int = Query(default=100, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
    filter: str = Query(default=""),
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    space = _get_space_or_404(space_id, db)
    path = _validate_log_path(space.port, ip, filename)
    result = log_scanner.read_log_tail(path, lines=lines, offset=offset, filter_str=filter)
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
