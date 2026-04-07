from __future__ import annotations

import csv
import hmac
import io
import re
import sqlite3
from typing import Optional
from urllib.parse import quote_plus

from fastapi import APIRouter, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from ..auth import (
    build_admin_cookie,
    client_exists,
    has_admin_access,
    hash_password,
    normalize_client_id,
    require_admin,
    safe_admin_path,
    valid_client_login,
)
from ..database import get_connection, now_str
from ..dashboard_service import get_admin_dashboard_data
from ..settings import settings
from ..ui import admin_context, templates
from ..validators import is_public_http_url

router = APIRouter()


def rows_to_dicts(rows) -> list[dict]:
    return [dict(row) for row in rows]


def build_chart_rows(top_tags: list[dict]) -> list[dict]:
    max_clicks = max([row["total_clicks"] for row in top_tags], default=1)
    if max_clicks <= 0:
        return []
    chart_rows = []
    for row in top_tags:
        chart_rows.append(
            {
                "tag_code": row["tag_code"],
                "total_clicks": row["total_clicks"],
                "width": round((row["total_clicks"] / max_clicks) * 100, 1),
            }
        )
    return chart_rows


@router.get("/admin/login", response_class=HTMLResponse)
def admin_login_page(request: Request, message: Optional[str] = None, next: str = Query("/admin")):
    next_path = safe_admin_path(next)
    if has_admin_access(request):
        return RedirectResponse(url=next_path, status_code=303)

    return templates.TemplateResponse(
        request,
        "admin/login.html",
        admin_context(
            request,
            page_title="Вход в админку",
            active_nav="/admin",
            message=message,
            next_path=next_path,
        ),
    )


@router.post("/admin/login")
def admin_login_submit(
    request: Request,
    password: str = Form(...),
    next: str = Form("/admin"),
):
    next_path = safe_admin_path(next)
    if hmac.compare_digest(password.encode("utf-8"), settings.admin_password.encode("utf-8")):
        response = RedirectResponse(url=next_path, status_code=303)
        response.set_cookie(settings.admin_cookie_name, build_admin_cookie(), httponly=True, samesite="lax", max_age=60 * 60 * 12)
        return response
    return RedirectResponse(
        url="/admin/login?message=" + quote_plus("Неверный пароль") + "&next=" + quote_plus(next_path),
        status_code=303,
    )


@router.post("/admin/logout")
def admin_logout(request: Request):
    response = RedirectResponse(url="/admin/login?message=" + quote_plus("Вы вышли из админки"), status_code=303)
    response.delete_cookie(settings.admin_cookie_name)
    return response


@router.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request):
    auth_redirect = require_admin(request)
    if auth_redirect:
        return auth_redirect

    data = get_admin_dashboard_data()
    top_tags = rows_to_dicts(data["top_tags"])
    tags = rows_to_dicts(data["tags"])
    last_visits = rows_to_dicts(data["last_visits"])

    return templates.TemplateResponse(
        request,
        "admin/dashboard.html",
        admin_context(
            request,
            page_title="NFC Admin",
            active_nav="/admin",
            total_visits=data["total_visits"],
            total_tags=data["total_tags"],
            active_tags=data["active_tags"],
            total_clients=data["total_clients"],
            assigned_tags=data["assigned_tags"],
            today_visits=data["today_visits"],
            last_24h_visits=data["last_24h_visits"],
            chart_rows=build_chart_rows(top_tags),
            tags=tags,
            last_visits=last_visits,
        ),
    )


@router.get("/admin/clients", response_class=HTMLResponse)
def admin_clients(request: Request, message: Optional[str] = None):
    auth_redirect = require_admin(request)
    if auth_redirect:
        return auth_redirect

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            c.id,
            c.name,
            c.login,
            c.is_active,
            c.created_at,
            (SELECT COUNT(*) FROM tags t WHERE t.client_id = c.id) AS tags_count,
            (
                SELECT COUNT(*)
                FROM visits v
                JOIN tags t ON t.code = v.tag_code
                WHERE t.client_id = c.id
            ) AS visits_count
        FROM clients c
        ORDER BY c.id DESC
        """
    )
    clients = rows_to_dicts(cur.fetchall())
    conn.close()

    return templates.TemplateResponse(
        request,
        "admin/clients.html",
        admin_context(
            request,
            page_title="Клиенты",
            active_nav="/admin/clients",
            message=message,
            clients=clients,
        ),
    )


@router.post("/admin/clients/create")
def admin_clients_create(
    request: Request,
    name: str = Form(...),
    login: str = Form(...),
    password: str = Form(...),
):
    auth_redirect = require_admin(request)
    if auth_redirect:
        return auth_redirect

    name = name.strip()
    login = login.strip().lower()
    password = password.strip()

    if not name:
        return RedirectResponse(url="/admin/clients?message=" + quote_plus("Имя клиента не должно быть пустым"), status_code=303)
    if not valid_client_login(login):
        return RedirectResponse(
            url="/admin/clients?message=" + quote_plus("Логин должен быть 3-50 символов и состоять из латиницы, цифр, ., _, -, @"),
            status_code=303,
        )
    if len(password) < 6:
        return RedirectResponse(url="/admin/clients?message=" + quote_plus("Пароль клиента должен быть не короче 6 символов"), status_code=303)

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO clients (name, login, password_hash, is_active, created_at)
            VALUES (?, ?, ?, 1, ?)
            """,
            (name, login, hash_password(password), now_str()),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return RedirectResponse(url="/admin/clients?message=" + quote_plus("Такой логин клиента уже существует"), status_code=303)

    conn.close()
    return RedirectResponse(
        url="/admin/clients?message=" + quote_plus("Клиент создан. Передай ему ссылку /client/login, логин и пароль."),
        status_code=303,
    )


@router.post("/admin/clients/{client_id}/toggle")
def admin_client_toggle(client_id: int, request: Request):
    auth_redirect = require_admin(request)
    if auth_redirect:
        return auth_redirect

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT is_active FROM clients WHERE id = ?", (client_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Клиент не найден")

    new_status = 0 if int(row["is_active"]) == 1 else 1
    cur.execute("UPDATE clients SET is_active = ? WHERE id = ?", (new_status, client_id))
    conn.commit()
    conn.close()

    return RedirectResponse(url="/admin/clients?message=" + quote_plus("Статус клиента изменён"), status_code=303)


@router.get("/admin/tags", response_class=HTMLResponse)
def admin_tags(request: Request, message: Optional[str] = None):
    auth_redirect = require_admin(request)
    if auth_redirect:
        return auth_redirect

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name, login, is_active FROM clients ORDER BY name ASC, login ASC")
    clients = rows_to_dicts(cur.fetchall())

    cur.execute(
        """
        SELECT
            t.id,
            t.code,
            t.name,
            t.target_url,
            t.is_active,
            t.created_at,
            t.client_id,
            c.name AS client_name,
            c.login AS client_login,
            c.is_active AS client_is_active,
            (SELECT COUNT(*) FROM visits v WHERE v.tag_code = t.code) AS clicks
        FROM tags t
        LEFT JOIN clients c ON c.id = t.client_id
        ORDER BY t.id DESC
        """
    )
    tags = rows_to_dicts(cur.fetchall())
    conn.close()

    return templates.TemplateResponse(
        request,
        "admin/tags.html",
        admin_context(
            request,
            page_title="Метки",
            active_nav="/admin/tags",
            message=message,
            clients=clients,
            tags=tags,
        ),
    )


@router.post("/admin/tags/create")
def admin_tags_create(
    request: Request,
    code: str = Form(...),
    name: str = Form(""),
    target_url: str = Form(...),
    client_id: str = Form(""),
):
    auth_redirect = require_admin(request)
    if auth_redirect:
        return auth_redirect

    code = code.strip().lower()
    name = (name or code).strip()
    target_url = target_url.strip()

    try:
        owner_id = normalize_client_id(client_id)
    except ValueError:
        return RedirectResponse(url="/admin/tags?message=" + quote_plus("Некорректный ID клиента"), status_code=303)

    if not code:
        return RedirectResponse(url="/admin/tags?message=" + quote_plus("Код не должен быть пустым"), status_code=303)
    if not re.fullmatch(r"[a-z0-9._-]{2,80}", code):
        return RedirectResponse(
            url="/admin/tags?message=" + quote_plus("Код метки должен состоять из латиницы, цифр, ., _ или -"),
            status_code=303,
        )
    if not is_public_http_url(target_url):
        return RedirectResponse(url="/admin/tags?message=" + quote_plus("Ссылка должна начинаться с http:// или https://"), status_code=303)

    conn = get_connection()
    cur = conn.cursor()

    if owner_id is not None and not client_exists(cur, owner_id):
        conn.close()
        return RedirectResponse(url="/admin/tags?message=" + quote_plus("Такой клиент не найден"), status_code=303)

    try:
        cur.execute(
            """
            INSERT INTO tags (code, name, target_url, is_active, created_at, client_id)
            VALUES (?, ?, ?, 1, ?, ?)
            """,
            (code, name, target_url, now_str(), owner_id),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return RedirectResponse(url="/admin/tags?message=" + quote_plus("Такой код уже существует"), status_code=303)

    conn.close()
    return RedirectResponse(url="/admin/tags?message=" + quote_plus("Метка успешно создана"), status_code=303)


@router.post("/admin/tags/{tag_id}/assign")
def admin_tag_assign(tag_id: int, request: Request, client_id: str = Form("")):
    auth_redirect = require_admin(request)
    if auth_redirect:
        return auth_redirect

    try:
        owner_id = normalize_client_id(client_id)
    except ValueError:
        return RedirectResponse(url="/admin/tags?message=" + quote_plus("Некорректный ID клиента"), status_code=303)

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM tags WHERE id = ?", (tag_id,))
    tag = cur.fetchone()
    if not tag:
        conn.close()
        raise HTTPException(status_code=404, detail="Метка не найдена")

    if owner_id is not None and not client_exists(cur, owner_id):
        conn.close()
        return RedirectResponse(url="/admin/tags?message=" + quote_plus("Такой клиент не найден"), status_code=303)

    cur.execute("UPDATE tags SET client_id = ? WHERE id = ?", (owner_id, tag_id))
    conn.commit()
    conn.close()

    message = "Владелец метки сохранён" if owner_id is not None else "Метка отвязана от клиента"
    return RedirectResponse(url="/admin/tags?message=" + quote_plus(message), status_code=303)


@router.post("/admin/tags/{tag_id}/toggle")
def admin_tag_toggle(tag_id: int, request: Request):
    auth_redirect = require_admin(request)
    if auth_redirect:
        return auth_redirect

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT is_active FROM tags WHERE id = ?", (tag_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Метка не найдена")

    new_status = 0 if int(row["is_active"]) == 1 else 1
    cur.execute("UPDATE tags SET is_active = ? WHERE id = ?", (new_status, tag_id))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin/tags?message=" + quote_plus("Статус метки изменён"), status_code=303)


@router.post("/admin/tags/{tag_id}/delete")
def admin_tag_delete(tag_id: int, request: Request):
    auth_redirect = require_admin(request)
    if auth_redirect:
        return auth_redirect

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM tags WHERE id = ?", (tag_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin/tags?message=" + quote_plus("Метка удалена"), status_code=303)


@router.get("/admin/visits", response_class=HTMLResponse)
def admin_visits(request: Request, tag: str = Query(""), limit: int = Query(100)):
    auth_redirect = require_admin(request)
    if auth_redirect:
        return auth_redirect

    limit = max(1, min(limit, 500))
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT code FROM tags ORDER BY code ASC")
    tag_options = [row["code"] for row in cur.fetchall()]

    if tag:
        cur.execute(
            """
            SELECT
                v.id,
                v.tag_code,
                v.target_url,
                v.visited_at,
                v.ip_address,
                v.user_agent,
                v.referer,
                c.name AS client_name,
                c.login AS client_login
            FROM visits v
            LEFT JOIN tags t ON t.code = v.tag_code
            LEFT JOIN clients c ON c.id = t.client_id
            WHERE v.tag_code = ?
            ORDER BY v.id DESC
            LIMIT ?
            """,
            (tag, limit),
        )
    else:
        cur.execute(
            """
            SELECT
                v.id,
                v.tag_code,
                v.target_url,
                v.visited_at,
                v.ip_address,
                v.user_agent,
                v.referer,
                c.name AS client_name,
                c.login AS client_login
            FROM visits v
            LEFT JOIN tags t ON t.code = v.tag_code
            LEFT JOIN clients c ON c.id = t.client_id
            ORDER BY v.id DESC
            LIMIT ?
            """,
            (limit,),
        )
    visits = rows_to_dicts(cur.fetchall())
    conn.close()

    return templates.TemplateResponse(
        request,
        "admin/visits.html",
        admin_context(
            request,
            page_title="Журнал переходов",
            active_nav="/admin/visits",
            visits=visits,
            tag_options=tag_options,
            selected_tag=tag,
            limit=limit,
        ),
    )


@router.get("/admin/export.csv")
def admin_export_csv(request: Request):
    auth_redirect = require_admin(request)
    if auth_redirect:
        return auth_redirect

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            v.id,
            v.tag_code,
            v.target_url,
            v.visited_at,
            v.ip_address,
            v.user_agent,
            v.referer,
            c.name AS client_name,
            c.login AS client_login
        FROM visits v
        LEFT JOIN tags t ON t.code = v.tag_code
        LEFT JOIN clients c ON c.id = t.client_id
        ORDER BY v.id DESC
        """
    )
    rows = cur.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        ["id", "tag_code", "client_name", "client_login", "target_url", "visited_at", "ip_address", "user_agent", "referer"]
    )
    for row in rows:
        writer.writerow(
            [
                row["id"],
                row["tag_code"],
                row["client_name"] or "",
                row["client_login"] or "",
                row["target_url"],
                row["visited_at"],
                row["ip_address"],
                row["user_agent"],
                row["referer"],
            ]
        )

    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=nfc_visits.csv"},
    )
