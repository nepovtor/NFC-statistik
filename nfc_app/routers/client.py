from __future__ import annotations

import csv
import io
from typing import Optional
from urllib.parse import quote_plus

from fastapi import APIRouter, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from ..auth import (
    SESSION_SCOPE_CLIENT,
    clear_scope_cookie,
    create_client_session,
    ensure_scope_session,
    get_current_client,
    revoke_scope_session,
    require_client,
    safe_client_path,
    set_scope_cookie,
    validate_csrf_token,
    verify_password,
)
from ..database import get_connection
from ..dashboard_service import get_client_dashboard_data
from ..ui import client_context, templates
from ..urls import build_public_tag_url, get_public_base_url
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


def client_message_url(path: str, message: str) -> str:
    separator = "&" if "?" in path else "?"
    return path + separator + "message=" + quote_plus(message)


def require_client_post(request: Request, csrf_token: str, redirect_path: str) -> Optional[RedirectResponse]:
    auth_redirect = require_client(request)
    if auth_redirect:
        return auth_redirect
    if validate_csrf_token(request, SESSION_SCOPE_CLIENT, csrf_token):
        return None
    return RedirectResponse(
        url=client_message_url(redirect_path, "Сессия формы истекла. Обновите страницу и повторите действие."),
        status_code=303,
    )


@router.get("/client/login", response_class=HTMLResponse)
def client_login_page(request: Request, message: Optional[str] = None, next: str = Query("/client")):
    next_path = safe_client_path(next)
    if get_current_client(request):
        return RedirectResponse(url=next_path, status_code=303)

    _, raw_token = ensure_scope_session(request, SESSION_SCOPE_CLIENT)
    response = templates.TemplateResponse(
        request,
        "client/login.html",
        client_context(
            request,
            page_title="Вход клиента",
            active_nav="/client/login",
            message=message,
            next_path=next_path,
        ),
    )
    if raw_token:
        set_scope_cookie(response, SESSION_SCOPE_CLIENT, raw_token)
    return response


@router.post("/client/login")
def client_login_submit(
    request: Request,
    login: str = Form(...),
    password: str = Form(...),
    next: str = Form("/client"),
    csrf_token: str = Form(...),
):
    next_path = safe_client_path(next)
    login = login.strip().lower()

    if not validate_csrf_token(request, SESSION_SCOPE_CLIENT, csrf_token):
        revoke_scope_session(request, SESSION_SCOPE_CLIENT)
        response = RedirectResponse(
            url="/client/login?message=" + quote_plus("Сессия входа устарела. Обновите страницу и попробуйте снова.") + "&next=" + quote_plus(next_path),
            status_code=303,
        )
        clear_scope_cookie(response, SESSION_SCOPE_CLIENT)
        return response

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, password_hash, is_active
        FROM clients
        WHERE login = ?
        """,
        (login,),
    )
    client = cur.fetchone()
    conn.close()

    if client and int(client["is_active"]) == 1 and verify_password(password, client["password_hash"]):
        _, raw_token = create_client_session(request, client["id"])
        response = RedirectResponse(url=next_path, status_code=303)
        set_scope_cookie(response, SESSION_SCOPE_CLIENT, raw_token)
        return response

    return RedirectResponse(
        url="/client/login?message=" + quote_plus("Неверный логин или пароль") + "&next=" + quote_plus(next_path),
        status_code=303,
    )


@router.post("/client/logout")
def client_logout(request: Request, csrf_token: str = Form(...)):
    if not validate_csrf_token(request, SESSION_SCOPE_CLIENT, csrf_token):
        return RedirectResponse(
            url=client_message_url("/client", "Сессия формы истекла. Обновите страницу и повторите действие."),
            status_code=303,
        )

    revoke_scope_session(request, SESSION_SCOPE_CLIENT)
    response = RedirectResponse(url="/client/login?message=" + quote_plus("Вы вышли из личного кабинета"), status_code=303)
    clear_scope_cookie(response, SESSION_SCOPE_CLIENT)
    return response


@router.get("/client", response_class=HTMLResponse)
def client_dashboard(request: Request):
    auth_redirect = require_client(request)
    if auth_redirect:
        return auth_redirect

    client_row = get_current_client(request)
    if not client_row:
        return RedirectResponse(url="/client/login", status_code=303)

    client = dict(client_row)
    data = get_client_dashboard_data(client["id"])
    top_tags = rows_to_dicts(data["top_tags"])
    tags = rows_to_dicts(data["tags"])
    last_visits = rows_to_dicts(data["last_visits"])

    return templates.TemplateResponse(
        request,
        "client/dashboard.html",
        client_context(
            request,
            page_title="Личный кабинет",
            active_nav="/client",
            client=client,
            total_tags=data["total_tags"],
            active_tags=data["active_tags"],
            total_visits=data["total_visits"],
            today_visits=data["today_visits"],
            last_24h_visits=data["last_24h_visits"],
            chart_rows=build_chart_rows(top_tags),
            tags=tags,
            last_visits=last_visits,
        ),
    )


@router.get("/client/tags", response_class=HTMLResponse)
def client_tags(request: Request, message: Optional[str] = None):
    auth_redirect = require_client(request)
    if auth_redirect:
        return auth_redirect

    client = get_current_client(request)
    if not client:
        return RedirectResponse(url="/client/login", status_code=303)

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            t.id,
            t.code,
            t.name,
            t.target_url,
            t.is_active,
            t.created_at,
            (SELECT COUNT(*) FROM visits v WHERE v.tag_code = t.code) AS clicks
        FROM tags t
        WHERE t.client_id = ?
        ORDER BY t.id DESC
        """,
        (client["id"],),
    )
    tags = rows_to_dicts(cur.fetchall())
    conn.close()

    for row in tags:
        row["public_url"] = build_public_tag_url(request, row["code"])

    return templates.TemplateResponse(
        request,
        "client/tags.html",
        client_context(
            request,
            page_title="Мои NFC",
            active_nav="/client/tags",
            message=message,
            tags=tags,
            public_base_url=get_public_base_url(request),
        ),
    )


@router.post("/client/tags/{tag_id}/update")
def client_tag_update(
    tag_id: int,
    request: Request,
    name: str = Form(...),
    target_url: str = Form(...),
    is_active: str = Form("1"),
    csrf_token: str = Form(...),
):
    auth_redirect = require_client_post(request, csrf_token, "/client/tags")
    if auth_redirect:
        return auth_redirect

    client = get_current_client(request)
    if not client:
        return RedirectResponse(url="/client/login", status_code=303)

    name = name.strip()
    target_url = target_url.strip()
    is_active_value = 1 if str(is_active) == "1" else 0

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, code
        FROM tags
        WHERE id = ? AND client_id = ?
        """,
        (tag_id, client["id"]),
    )
    tag = cur.fetchone()
    if not tag:
        conn.close()
        raise HTTPException(status_code=404, detail="Метка не найдена")
    tag_code = tag["code"]

    if not name:
        conn.close()
        return RedirectResponse(url="/client/tags?message=" + quote_plus("Название метки не должно быть пустым"), status_code=303)
    if not is_public_http_url(target_url):
        conn.close()
        return RedirectResponse(url="/client/tags?message=" + quote_plus("Ссылка должна начинаться с http:// или https://"), status_code=303)

    cur.execute(
        """
        UPDATE tags
        SET name = ?, target_url = ?, is_active = ?
        WHERE id = ? AND client_id = ?
        """,
        (name, target_url, is_active_value, tag_id, client["id"]),
    )
    conn.commit()
    conn.close()

    return RedirectResponse(
        url="/client/tags?message=" + quote_plus(f"Изменения для метки {tag_code} сохранены"),
        status_code=303,
    )


@router.get("/client/visits", response_class=HTMLResponse)
def client_visits(request: Request, tag: str = Query(""), limit: int = Query(100)):
    auth_redirect = require_client(request)
    if auth_redirect:
        return auth_redirect

    client = get_current_client(request)
    if not client:
        return RedirectResponse(url="/client/login", status_code=303)

    limit = max(1, min(limit, 500))
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT code FROM tags WHERE client_id = ? ORDER BY code ASC", (client["id"],))
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
                v.referer
            FROM visits v
            JOIN tags t ON t.code = v.tag_code
            WHERE t.client_id = ? AND v.tag_code = ?
            ORDER BY v.id DESC
            LIMIT ?
            """,
            (client["id"], tag, limit),
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
                v.referer
            FROM visits v
            JOIN tags t ON t.code = v.tag_code
            WHERE t.client_id = ?
            ORDER BY v.id DESC
            LIMIT ?
            """,
            (client["id"], limit),
        )
    visits = rows_to_dicts(cur.fetchall())
    conn.close()

    return templates.TemplateResponse(
        request,
        "client/visits.html",
        client_context(
            request,
            page_title="Мои переходы",
            active_nav="/client/visits",
            visits=visits,
            tag_options=tag_options,
            selected_tag=tag,
            limit=limit,
        ),
    )


@router.get("/client/export.csv")
def client_export_csv(request: Request):
    auth_redirect = require_client(request)
    if auth_redirect:
        return auth_redirect

    client = get_current_client(request)
    if not client:
        return RedirectResponse(url="/client/login", status_code=303)

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
            v.referer
        FROM visits v
        JOIN tags t ON t.code = v.tag_code
        WHERE t.client_id = ?
        ORDER BY v.id DESC
        """,
        (client["id"],),
    )
    rows = cur.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "tag_code", "target_url", "visited_at", "ip_address", "user_agent", "referer"])
    for row in rows:
        writer.writerow(
            [
                row["id"],
                row["tag_code"],
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
        headers={"Content-Disposition": f"attachment; filename=client_{client['login']}_visits.csv"},
    )
