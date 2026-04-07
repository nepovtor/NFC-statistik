from __future__ import annotations

import csv
import io
from typing import Optional
from urllib.parse import quote_plus

from fastapi import APIRouter, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from ..auth import (
    SESSION_SCOPE_ADMIN,
    clear_scope_cookie,
    create_admin_session,
    ensure_scope_session,
    get_request_ip,
    has_admin_access,
    revoke_scope_session,
    require_admin,
    safe_admin_path,
    set_scope_cookie,
    validate_csrf_token,
)
from ..dashboard_service import get_admin_dashboard_data
from ..repositories.common import rows_to_dicts
from ..services.admin_service import (
    assign_tag_owner_record,
    create_client_account,
    create_tag_record,
    delete_tag_record,
    get_clients_page_data,
    get_export_rows,
    get_tags_page_data,
    get_visits_page_data,
    toggle_client_access,
    toggle_tag_access,
)
from ..services.auth_service import authenticate_admin
from ..services.errors import ConflictError, NotFoundError, ValidationError
from ..ui import admin_context, templates

router = APIRouter()


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


def admin_message_url(path: str, message: str) -> str:
    separator = "&" if "?" in path else "?"
    return path + separator + "message=" + quote_plus(message)


def require_admin_post(request: Request, csrf_token: str, redirect_path: str) -> Optional[RedirectResponse]:
    auth_redirect = require_admin(request)
    if auth_redirect:
        return auth_redirect
    if validate_csrf_token(request, SESSION_SCOPE_ADMIN, csrf_token):
        return None
    return RedirectResponse(
        url=admin_message_url(redirect_path, "Сессия формы истекла. Обнови страницу и повтори действие."),
        status_code=303,
    )


@router.get("/admin/login", response_class=HTMLResponse)
def admin_login_page(request: Request, message: Optional[str] = None, next: str = Query("/admin")):
    next_path = safe_admin_path(next)
    if has_admin_access(request):
        return RedirectResponse(url=next_path, status_code=303)

    _, raw_token = ensure_scope_session(request, SESSION_SCOPE_ADMIN)
    response = templates.TemplateResponse(
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
    if raw_token:
        set_scope_cookie(response, SESSION_SCOPE_ADMIN, raw_token)
    return response


@router.post("/admin/login")
def admin_login_submit(
    request: Request,
    login: str = Form(...),
    password: str = Form(...),
    next: str = Form("/admin"),
    csrf_token: str = Form(...),
):
    next_path = safe_admin_path(next)
    login = login.strip().lower()

    if not validate_csrf_token(request, SESSION_SCOPE_ADMIN, csrf_token):
        revoke_scope_session(request, SESSION_SCOPE_ADMIN)
        response = RedirectResponse(
            url="/admin/login?message=" + quote_plus("Сессия входа устарела. Обнови страницу и попробуй снова.") + "&next=" + quote_plus(next_path),
            status_code=303,
        )
        clear_scope_cookie(response, SESSION_SCOPE_ADMIN)
        return response

    login_result = authenticate_admin(login, password, get_request_ip(request) or "unknown")
    if login_result.ok and login_result.principal_id is not None:
        _, raw_token = create_admin_session(request, login_result.principal_id)
        response = RedirectResponse(url=next_path, status_code=303)
        set_scope_cookie(response, SESSION_SCOPE_ADMIN, raw_token)
        return response

    return RedirectResponse(
        url="/admin/login?message=" + quote_plus(login_result.message or "Неверный логин или пароль") + "&next=" + quote_plus(next_path),
        status_code=303,
    )


@router.post("/admin/logout")
def admin_logout(request: Request, csrf_token: str = Form(...)):
    if not validate_csrf_token(request, SESSION_SCOPE_ADMIN, csrf_token):
        return RedirectResponse(
            url=admin_message_url("/admin", "Сессия формы истекла. Обнови страницу и повтори действие."),
            status_code=303,
        )

    revoke_scope_session(request, SESSION_SCOPE_ADMIN)
    response = RedirectResponse(url="/admin/login?message=" + quote_plus("Вы вышли из админки"), status_code=303)
    clear_scope_cookie(response, SESSION_SCOPE_ADMIN)
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

    clients = get_clients_page_data()["clients"]

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
    csrf_token: str = Form(...),
):
    auth_redirect = require_admin_post(request, csrf_token, "/admin/clients")
    if auth_redirect:
        return auth_redirect

    try:
        message = create_client_account(name, login, password)
    except (ConflictError, ValidationError) as exc:
        return RedirectResponse(url="/admin/clients?message=" + quote_plus(str(exc)), status_code=303)

    return RedirectResponse(url="/admin/clients?message=" + quote_plus(message), status_code=303)


@router.post("/admin/clients/{client_id}/toggle")
def admin_client_toggle(client_id: int, request: Request, csrf_token: str = Form(...)):
    auth_redirect = require_admin_post(request, csrf_token, "/admin/clients")
    if auth_redirect:
        return auth_redirect

    try:
        message = toggle_client_access(client_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return RedirectResponse(url="/admin/clients?message=" + quote_plus(message), status_code=303)


@router.get("/admin/tags", response_class=HTMLResponse)
def admin_tags(request: Request, message: Optional[str] = None):
    auth_redirect = require_admin(request)
    if auth_redirect:
        return auth_redirect

    data = get_tags_page_data()

    return templates.TemplateResponse(
        request,
        "admin/tags.html",
        admin_context(
            request,
            page_title="Метки",
            active_nav="/admin/tags",
            message=message,
            clients=data["clients"],
            tags=data["tags"],
        ),
    )


@router.post("/admin/tags/create")
def admin_tags_create(
    request: Request,
    code: str = Form(...),
    name: str = Form(""),
    target_url: str = Form(...),
    client_id: str = Form(""),
    csrf_token: str = Form(...),
):
    auth_redirect = require_admin_post(request, csrf_token, "/admin/tags")
    if auth_redirect:
        return auth_redirect

    try:
        message = create_tag_record(code, name, target_url, client_id)
    except (ConflictError, ValidationError) as exc:
        return RedirectResponse(url="/admin/tags?message=" + quote_plus(str(exc)), status_code=303)

    return RedirectResponse(url="/admin/tags?message=" + quote_plus(message), status_code=303)


@router.post("/admin/tags/{tag_id}/assign")
def admin_tag_assign(tag_id: int, request: Request, client_id: str = Form(""), csrf_token: str = Form(...)):
    auth_redirect = require_admin_post(request, csrf_token, "/admin/tags")
    if auth_redirect:
        return auth_redirect

    try:
        message = assign_tag_owner_record(tag_id, client_id)
    except ValidationError as exc:
        return RedirectResponse(url="/admin/tags?message=" + quote_plus(str(exc)), status_code=303)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return RedirectResponse(url="/admin/tags?message=" + quote_plus(message), status_code=303)


@router.post("/admin/tags/{tag_id}/toggle")
def admin_tag_toggle(tag_id: int, request: Request, csrf_token: str = Form(...)):
    auth_redirect = require_admin_post(request, csrf_token, "/admin/tags")
    if auth_redirect:
        return auth_redirect

    try:
        message = toggle_tag_access(tag_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return RedirectResponse(url="/admin/tags?message=" + quote_plus(message), status_code=303)


@router.post("/admin/tags/{tag_id}/delete")
def admin_tag_delete(tag_id: int, request: Request, csrf_token: str = Form(...)):
    auth_redirect = require_admin_post(request, csrf_token, "/admin/tags")
    if auth_redirect:
        return auth_redirect

    try:
        message = delete_tag_record(tag_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return RedirectResponse(url="/admin/tags?message=" + quote_plus(message), status_code=303)


@router.get("/admin/visits", response_class=HTMLResponse)
def admin_visits(request: Request, tag: str = Query(""), limit: int = Query(100)):
    auth_redirect = require_admin(request)
    if auth_redirect:
        return auth_redirect

    data = get_visits_page_data(tag, limit)

    return templates.TemplateResponse(
        request,
        "admin/visits.html",
        admin_context(
            request,
            page_title="Журнал переходов",
            active_nav="/admin/visits",
            visits=data["visits"],
            tag_options=data["tag_options"],
            selected_tag=data["selected_tag"],
            limit=data["limit"],
        ),
    )


@router.get("/admin/export.csv")
def admin_export_csv(request: Request):
    auth_redirect = require_admin(request)
    if auth_redirect:
        return auth_redirect

    rows = get_export_rows()

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
