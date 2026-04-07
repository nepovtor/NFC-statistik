from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..auth import (
    SESSION_SCOPE_ADMIN,
    clear_scope_cookie,
    create_admin_session,
    ensure_scope_session,
    get_admin_session,
    get_request_ip,
    has_admin_access,
    revoke_scope_session,
    require_admin,
    safe_admin_path,
    set_scope_cookie,
    validate_csrf_token,
)
from ..dashboard_service import get_admin_dashboard_data
from ..presentation import build_chart_rows, csv_response, redirect_with_query
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
from ..services.admin_audit_service import get_admin_audit_page_data, record_admin_audit_event
from ..services.auth_service import authenticate_admin
from ..services.errors import ConflictError, NotFoundError, ValidationError
from ..ui import admin_context, templates
from ..visit_policy import sanitize_visit_rows

router = APIRouter()


def require_admin_post(request: Request, csrf_token: str, redirect_path: str) -> Optional[RedirectResponse]:
    auth_redirect = require_admin(request)
    if auth_redirect:
        return auth_redirect
    if validate_csrf_token(request, SESSION_SCOPE_ADMIN, csrf_token):
        return None
    return redirect_with_query(
        redirect_path,
        message="Сессия формы истекла. Обнови страницу и повтори действие.",
    )


def audit_admin_action(
    request: Request,
    *,
    action: str,
    target_type: str,
    target_id: int | str | None = None,
    target_label: str | None = None,
    details: dict | None = None,
    admin_id: int | None = None,
    admin_login: str | None = None,
) -> None:
    session = get_admin_session(request) if admin_id is None or admin_login is None else None
    resolved_admin_id = admin_id if admin_id is not None else (int(session["admin_id"]) if session and session.get("admin_id") else None)
    resolved_admin_login = admin_login if admin_login is not None else (str(session["admin_login"]) if session and session.get("admin_login") else "")
    if not resolved_admin_login:
        return

    record_admin_audit_event(
        admin_id=resolved_admin_id,
        admin_login=resolved_admin_login,
        action=action,
        target_type=target_type,
        target_id=target_id,
        target_label=target_label,
        ip_address=get_request_ip(request),
        user_agent=request.headers.get("user-agent", "").strip(),
        details=details,
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
        response = redirect_with_query(
            "/admin/login",
            message="Сессия входа устарела. Обнови страницу и попробуй снова.",
            next=next_path,
        )
        clear_scope_cookie(response, SESSION_SCOPE_ADMIN)
        return response

    login_result = authenticate_admin(login, password, get_request_ip(request) or "unknown")
    if login_result.ok and login_result.principal_id is not None:
        _, raw_token = create_admin_session(request, login_result.principal_id)
        audit_admin_action(
            request,
            action="admin.login",
            target_type="admin",
            target_id=login_result.principal_id,
            target_label=login,
            details={"next": next_path},
            admin_id=login_result.principal_id,
            admin_login=login,
        )
        response = RedirectResponse(url=next_path, status_code=303)
        set_scope_cookie(response, SESSION_SCOPE_ADMIN, raw_token)
        return response

    return redirect_with_query(
        "/admin/login",
        message=login_result.message or "Неверный логин или пароль",
        next=next_path,
    )


@router.post("/admin/logout")
def admin_logout(request: Request, csrf_token: str = Form(...)):
    if not validate_csrf_token(request, SESSION_SCOPE_ADMIN, csrf_token):
        return redirect_with_query("/admin", message="Сессия формы истекла. Обнови страницу и повтори действие.")

    session = get_admin_session(request)
    revoke_scope_session(request, SESSION_SCOPE_ADMIN)
    if session:
        audit_admin_action(
            request,
            action="admin.logout",
            target_type="admin",
            target_id=session.get("admin_id"),
            target_label=session.get("admin_login"),
            admin_id=int(session["admin_id"]) if session.get("admin_id") else None,
            admin_login=str(session["admin_login"]),
        )
    response = redirect_with_query("/admin/login", message="Вы вышли из админки")
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
    last_visits = sanitize_visit_rows(rows_to_dicts(data["last_visits"]))

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
        return redirect_with_query("/admin/clients", message=str(exc))

    audit_admin_action(
        request,
        action="client.created",
        target_type="client",
        target_label=login.strip().lower(),
        details={"name": name.strip()},
    )
    return redirect_with_query("/admin/clients", message=message)


@router.post("/admin/clients/{client_id}/toggle")
def admin_client_toggle(client_id: int, request: Request, csrf_token: str = Form(...)):
    auth_redirect = require_admin_post(request, csrf_token, "/admin/clients")
    if auth_redirect:
        return auth_redirect

    try:
        message = toggle_client_access(client_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    audit_admin_action(
        request,
        action="client.toggled",
        target_type="client",
        target_id=client_id,
    )
    return redirect_with_query("/admin/clients", message=message)


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
        return redirect_with_query("/admin/tags", message=str(exc))

    audit_admin_action(
        request,
        action="tag.created",
        target_type="tag",
        target_label=code.strip().lower(),
        details={"client_id": client_id.strip() or None},
    )
    return redirect_with_query("/admin/tags", message=message)


@router.post("/admin/tags/{tag_id}/assign")
def admin_tag_assign(tag_id: int, request: Request, client_id: str = Form(""), csrf_token: str = Form(...)):
    auth_redirect = require_admin_post(request, csrf_token, "/admin/tags")
    if auth_redirect:
        return auth_redirect

    try:
        message = assign_tag_owner_record(tag_id, client_id)
    except ValidationError as exc:
        return redirect_with_query("/admin/tags", message=str(exc))
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    audit_admin_action(
        request,
        action="tag.owner_assigned",
        target_type="tag",
        target_id=tag_id,
        details={"client_id": client_id.strip() or None},
    )
    return redirect_with_query("/admin/tags", message=message)


@router.post("/admin/tags/{tag_id}/toggle")
def admin_tag_toggle(tag_id: int, request: Request, csrf_token: str = Form(...)):
    auth_redirect = require_admin_post(request, csrf_token, "/admin/tags")
    if auth_redirect:
        return auth_redirect

    try:
        message = toggle_tag_access(tag_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    audit_admin_action(
        request,
        action="tag.toggled",
        target_type="tag",
        target_id=tag_id,
    )
    return redirect_with_query("/admin/tags", message=message)


@router.post("/admin/tags/{tag_id}/delete")
def admin_tag_delete(tag_id: int, request: Request, csrf_token: str = Form(...)):
    auth_redirect = require_admin_post(request, csrf_token, "/admin/tags")
    if auth_redirect:
        return auth_redirect

    try:
        message = delete_tag_record(tag_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    audit_admin_action(
        request,
        action="tag.deleted",
        target_type="tag",
        target_id=tag_id,
    )
    return redirect_with_query("/admin/tags", message=message)


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


@router.get("/admin/audit", response_class=HTMLResponse)
def admin_audit(request: Request, limit: int = Query(100)):
    auth_redirect = require_admin(request)
    if auth_redirect:
        return auth_redirect

    data = get_admin_audit_page_data(limit)

    return templates.TemplateResponse(
        request,
        "admin/audit.html",
        admin_context(
            request,
            page_title="Аудит действий",
            active_nav="/admin/audit",
            events=data["events"],
            limit=data["limit"],
        ),
    )


@router.get("/admin/export.csv")
def admin_export_csv(request: Request):
    auth_redirect = require_admin(request)
    if auth_redirect:
        return auth_redirect

    rows = get_export_rows()
    return csv_response(
        "nfc_visits.csv",
        [
            ("id", "id"),
            ("tag_code", "tag_code"),
            ("client_name", "client_name"),
            ("client_login", "client_login"),
            ("target_url", "target_url"),
            ("visited_at", "visited_at"),
            ("ip_address", "ip_address"),
            ("user_agent", "user_agent"),
            ("referer", "referer"),
        ],
        rows,
    )
