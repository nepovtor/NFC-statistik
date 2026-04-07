from __future__ import annotations

import sqlite3

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.responses import JSONResponse
from fastapi.responses import RedirectResponse

from ..dashboard_service import get_admin_dashboard_data
from ..database import MIGRATIONS, close_connection, get_connection, get_pending_migrations, now_str
from ..repositories.common import rows_to_dicts
from ..repositories.visit_repository import record_visit
from ..security.network import get_request_ip
from ..settings import settings
from ..ui import templates
from ..urls import build_public_tag_url, get_public_base_url

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def home(request: Request):
    snapshot = get_admin_dashboard_data()
    featured_tags = rows_to_dicts(snapshot["tags"])[:3]
    if not featured_tags:
        featured_tags = [
            {
                "code": code,
                "name": f"Сценарий: {code}",
                "target_url": target_url,
                "clicks": 0,
                "is_active": 1,
            }
            for code, target_url in list(settings.default_tags.items())[:3]
        ]

    example_tag_code = "table1"
    return templates.TemplateResponse(
        request,
        "public/home.html",
        {
            "request": request,
            "page_title": "NFC Flow Control",
            "public_base_url": get_public_base_url(request),
            "example_public_url": build_public_tag_url(request, example_tag_code),
            "health_url": "/healthz",
            "ready_url": "/readyz",
            "stats": {
                "total_visits": snapshot["total_visits"],
                "total_tags": snapshot["total_tags"],
                "active_tags": snapshot["active_tags"],
                "total_clients": snapshot["total_clients"],
                "assigned_tags": snapshot["assigned_tags"],
                "today_visits": snapshot["today_visits"],
                "last_24h_visits": snapshot["last_24h_visits"],
            },
            "featured_tags": featured_tags,
        },
    )


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
