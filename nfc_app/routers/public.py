from __future__ import annotations

import sqlite3

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.responses import RedirectResponse

from ..auth import get_request_ip
from ..database import get_connection, now_str

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
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) AS total FROM schema_migrations")
        migrations_total = cur.fetchone()["total"]
        conn.close()
    except sqlite3.Error as exc:
        return JSONResponse(status_code=503, content={"status": "not-ready", "detail": str(exc)})

    return {"status": "ready", "migrations_applied": migrations_total}


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
        conn.close()
        raise HTTPException(status_code=404, detail="Такой NFC-код не найден")
    if int(tag["is_active"]) != 1:
        conn.close()
        raise HTTPException(status_code=403, detail="Эта NFC-метка выключена")

    ip_address = get_request_ip(request) or "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    referer = request.headers.get("referer", "")
    visited_at = now_str()

    cur.execute(
        """
        INSERT INTO visits (tag_code, target_url, visited_at, ip_address, user_agent, referer)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (tag_code, tag["target_url"], visited_at, ip_address, user_agent, referer),
    )
    conn.commit()
    conn.close()

    return RedirectResponse(url=tag["target_url"], status_code=302)
