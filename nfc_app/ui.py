from __future__ import annotations

from fastapi import Request
from fastapi.templating import Jinja2Templates

from .security.constants import SESSION_SCOPE_ADMIN, SESSION_SCOPE_CLIENT
from .security.csrf import get_session_csrf_token
from .settings import settings

templates = Jinja2Templates(directory=str(settings.base_dir / "templates"))

ADMIN_NAV_SECTIONS = [
    {
        "title": "Основное",
        "links": [
            {"href": "/admin", "label": "Дашборд", "icon": "dashboard"},
            {"href": "/admin/clients", "label": "Клиенты", "icon": "clients"},
            {"href": "/admin/tags", "label": "Метки и ссылки", "icon": "tags"},
            {"href": "/admin/visits", "label": "Все переходы", "icon": "visits"},
            {"href": "/admin/audit", "label": "Аудит", "icon": "audit"},
        ],
    },
    {
        "title": "Инструменты",
        "links": [
            {"href": "/admin/export.csv", "label": "Экспорт CSV", "icon": "export"},
            {"href": "/", "label": "Публичный сайт", "icon": "spark"},
        ],
    },
]

CLIENT_NAV_SECTIONS = [
    {
        "title": "Основное",
        "links": [
            {"href": "/client", "label": "Дашборд", "icon": "dashboard"},
            {"href": "/client/tags", "label": "Мои ссылки", "icon": "tags"},
            {"href": "/client/visits", "label": "Мои переходы", "icon": "visits"},
        ],
    },
    {
        "title": "Инструменты",
        "links": [
            {"href": "/client/export.csv", "label": "Отчёт CSV", "icon": "export"},
            {"href": "/", "label": "Витрина", "icon": "spark"},
            {"href": "/client/login", "label": "Вход", "icon": "login"},
        ],
    },
]


def admin_context(request: Request, page_title: str, active_nav: str | None, **context) -> dict:
    return {
        "request": request,
        "page_title": page_title,
        "brand": "NFC Admin",
        "brand_subtitle": "Управление метками и клиентами",
        "ui_mode": "admin-mode",
        "nav_sections": ADMIN_NAV_SECTIONS,
        "active_nav": active_nav,
        "csrf_token": context.pop("csrf_token", None) or get_session_csrf_token(request, SESSION_SCOPE_ADMIN),
        **context,
    }


def client_context(request: Request, page_title: str, active_nav: str | None, **context) -> dict:
    return {
        "request": request,
        "page_title": page_title,
        "brand": "My NFC Links",
        "brand_subtitle": "Ссылки, статусы и переходы без лишней админщины",
        "ui_mode": "client-mode",
        "nav_sections": CLIENT_NAV_SECTIONS,
        "active_nav": active_nav,
        "csrf_token": context.pop("csrf_token", None) or get_session_csrf_token(request, SESSION_SCOPE_CLIENT),
        **context,
    }
