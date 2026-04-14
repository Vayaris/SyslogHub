from fastapi import APIRouter, Response, Depends, HTTPException
from ..schemas import LoginRequest
from ..auth import authenticate_user, create_session, get_current_user

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login")
def login(body: LoginRequest, response: Response):
    if not authenticate_user(body.username, body.password):
        raise HTTPException(status_code=401, detail="Identifiants invalides")
    token = create_session(body.username)
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
        max_age=86400,
    )
    return {"ok": True}


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie("session", path="/")
    return {"ok": True}


@router.get("/me")
def me(username: str = Depends(get_current_user)):
    return {"username": username}
