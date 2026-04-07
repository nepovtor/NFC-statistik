from __future__ import annotations

from fastapi import Request
from fastapi.templating import Jinja2Templates

from .settings import settings

templates = Jinja2Templates(directory=str(settings.base_dir / "templates"))

ADMIN_NAV_LINKS = [
    ("/admin", "Дашборд"),
    ("/admin/clients", "Клиенты"),
    ("/admin/tags", "Метки и ссылки"),
    ("/admin/visits", "Все переходы"),
    ("/admin/export.csv", "Экспорт CSV"),
    ("/", "Проверка API"),
]

CLIENT_NAV_LINKS = [
    ("/client", "Дашборд"),
    ("/client/tags", "Мои NFC"),
    ("/client/visits", "Мои переходы"),
    ("/client/export.csv", "Экспорт CSV"),
    ("/client/login", "Вход"),
]


def admin_context(request: Request, page_title: str, active_nav: str | None, **context) -> dict:
    return {
        "request": request,
        "page_title": page_title,
        "brand": "NFC Admin",
        "brand_subtitle": "Управление метками и клиентами",
        "nav_links": ADMIN_NAV_LINKS,
        "active_nav": active_nav,
        **context,
    }


def client_context(request: Request, page_title: str, active_nav: str | None, **context) -> dict:
    return {
        "request": request,
        "page_title": page_title,
        "brand": "NFC Cabinet",
        "brand_subtitle": "Личный кабинет клиента",
        "nav_links": CLIENT_NAV_LINKS,
        "active_nav": active_nav,
        **context,
    }
