from __future__ import annotations

import sqlite3
import re

from ..auth import hash_password, normalize_client_id, valid_client_login
from ..repositories.admin_repository import (
    assign_tag_owner,
    create_client,
    create_tag,
    delete_tag,
    get_client_identity,
    get_tag_identity,
    list_clients_for_assignment,
    list_clients_with_stats,
    list_tags_with_clients,
    toggle_client_status,
    toggle_tag_status,
)
from ..services.errors import ConflictError, NotFoundError, ValidationError
from ..validators import is_public_http_url
from ..visit_policy import sanitize_visit_rows
from ..repositories.visit_repository import list_admin_visit_tag_codes, list_admin_visits, list_admin_visits_for_export


def get_clients_page_data() -> dict:
    return {"clients": list_clients_with_stats()}


def create_client_account(name: str, login: str, password: str) -> str:
    name = name.strip()
    login = login.strip().lower()
    password = password.strip()

    if not name:
        raise ValidationError("Имя клиента не должно быть пустым")
    if not valid_client_login(login):
        raise ValidationError("Логин должен быть 3-50 символов и состоять из латиницы, цифр, ., _, -, @")
    if len(password) < 6:
        raise ValidationError("Пароль клиента должен быть не короче 6 символов")

    try:
        create_client(name, login, hash_password(password))
    except sqlite3.IntegrityError as exc:
        raise ConflictError("Такой логин клиента уже существует") from exc

    return "Клиент создан. Передай ему ссылку /client/login, логин и пароль."


def toggle_client_access(client_id: int) -> str:
    new_status = toggle_client_status(client_id)
    if new_status is None:
        raise NotFoundError("Клиент не найден")
    return "Статус клиента изменён"


def get_tags_page_data() -> dict:
    return {
        "clients": list_clients_for_assignment(),
        "tags": list_tags_with_clients(),
    }


def create_tag_record(code: str, name: str, target_url: str, client_id: str) -> str:
    code = code.strip().lower()
    name = (name or code).strip()
    target_url = target_url.strip()

    try:
        owner_id = normalize_client_id(client_id)
    except ValueError as exc:
        raise ValidationError("Некорректный ID клиента") from exc

    if not code:
        raise ValidationError("Код не должен быть пустым")
    if not re.fullmatch(r"[a-z0-9._-]{2,80}", code):
        raise ValidationError("Код метки должен состоять из латиницы, цифр, ., _ или -")
    if not is_public_http_url(target_url):
        raise ValidationError("Ссылка должна начинаться с http:// или https://")
    if owner_id is not None and not get_client_identity(owner_id):
        raise ValidationError("Такой клиент не найден")

    try:
        create_tag(code, name, target_url, owner_id)
    except sqlite3.IntegrityError as exc:
        raise ConflictError("Такой код уже существует") from exc

    return "Метка успешно создана"


def assign_tag_owner_record(tag_id: int, client_id: str) -> str:
    try:
        owner_id = normalize_client_id(client_id)
    except ValueError as exc:
        raise ValidationError("Некорректный ID клиента") from exc

    if not get_tag_identity(tag_id):
        raise NotFoundError("Метка не найдена")
    if owner_id is not None and not get_client_identity(owner_id):
        raise ValidationError("Такой клиент не найден")

    assign_tag_owner(tag_id, owner_id)
    return "Владелец метки сохранён" if owner_id is not None else "Метка отвязана от клиента"


def toggle_tag_access(tag_id: int) -> str:
    new_status = toggle_tag_status(tag_id)
    if new_status is None:
        raise NotFoundError("Метка не найдена")
    return "Статус метки изменён"


def delete_tag_record(tag_id: int) -> str:
    if not delete_tag(tag_id):
        raise NotFoundError("Метка не найдена")
    return "Метка удалена"


def get_visits_page_data(tag: str, limit: int) -> dict:
    bounded_limit = max(1, min(limit, 500))
    return {
        "tag_options": list_admin_visit_tag_codes(),
        "selected_tag": tag,
        "limit": bounded_limit,
        "visits": sanitize_visit_rows(list_admin_visits(tag, bounded_limit)),
    }


def get_export_rows() -> list[dict]:
    return sanitize_visit_rows(list_admin_visits_for_export())
