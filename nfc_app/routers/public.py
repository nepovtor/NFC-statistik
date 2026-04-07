from __future__ import annotations

import sqlite3

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.responses import RedirectResponse

from ..auth import get_request_ip
from ..database import MIGRATIONS, close_connection, get_connection, get_pending_migrations, now_str
from ..repositories.visit_repository import record_visit

router = APIRouter()


@router.get("/")
def home() -> dict:
    return {
        "message": "Сервис работает.",
        "health": "/healthz",
        "ready": "/readyz",
        "admin": "/admin",
        "client_login": "/client/login",
        "go_example": "/go/table1",
    }


@router.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@router.get("/readyz")
def readyz():
    try:
        pending_migrations = get_pending_migrations()
    except sqlite3.Error as exc:
        return JSONResponse(status_code=503, content={"status": "not-ready", "detail": str(exc)})

    if pending_migrations:
        return JSONResponse(
            status_code=503,
            content={
                "status": "not-ready",
                "pending_migrations": pending_migrations,
            },
        )

    return {"status": "ready", "migrations_applied": len(MIGRATIONS)}


@router.get("/go/{tag_code}")
def go(tag_code: str, request: Request):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT code, target_url, is_active FROM tags WHERE code = ?",
        (tag_code,),
    )
    tag = cur.fetchone()

    if not tag:
        close_connection(conn)
        raise HTTPException(status_code=404, detail="Такой NFC-код не найден")
    if int(tag["is_active"]) != 1:
        close_connection(conn)
        raise HTTPException(status_code=403, detail="Эта NFC-метка выключена")

    ip_address = get_request_ip(request) or "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    referer = request.headers.get("referer", "")
    visited_at = now_str()

    close_connection(conn)
    record_visit(tag_code, tag["target_url"], visited_at, ip_address, user_agent, referer)

    return RedirectResponse(url=tag["target_url"], status_code=302)
