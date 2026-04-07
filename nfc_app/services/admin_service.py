from __future__ import annotations

import sqlite3
import re

from ..auth import hash_password, normalize_client_id, valid_client_login
from ..repositories.visit_repository import list_admin_visit_tag_codes, list_admin_visits, list_admin_visits_for_export
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
from ..services.admin_audit_service import AdminAuditActor, record_admin_audit_event
from ..services.errors import ConflictError, NotFoundError, ValidationError
from ..validators import is_public_http_url
from ..visit_policy import sanitize_visit_rows


def get_clients_page_data() -> dict:
    return {"clients": list_clients_with_stats()}


def create_client_account(actor: AdminAuditActor, name: str, login: str, password: str) -> str:
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

    record_admin_audit_event(
        actor=actor,
        action="client.created",
        target_type="client",
        target_label=login,
        details={"name": name},
    )

    return "Клиент создан. Передай ему ссылку /client/login, логин и пароль."


def toggle_client_access(actor: AdminAuditActor, client_id: int) -> str:
    new_status = toggle_client_status(client_id)
    if new_status is None:
        raise NotFoundError("Клиент не найден")

    record_admin_audit_event(
        actor=actor,
        action="client.toggled",
        target_type="client",
        target_id=client_id,
        details={"is_active": new_status},
    )
    return "Статус клиента изменён"


def get_tags_page_data() -> dict:
    return {
        "clients": list_clients_for_assignment(),
        "tags": list_tags_with_clients(),
    }


def create_tag_record(actor: AdminAuditActor, code: str, name: str, target_url: str, client_id: str) -> str:
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

    record_admin_audit_event(
        actor=actor,
        action="tag.created",
        target_type="tag",
        target_label=code,
        details={"client_id": owner_id},
    )

    return "Метка успешно создана"


def assign_tag_owner_record(actor: AdminAuditActor, tag_id: int, client_id: str) -> str:
    try:
        owner_id = normalize_client_id(client_id)
    except ValueError as exc:
        raise ValidationError("Некорректный ID клиента") from exc

    if not get_tag_identity(tag_id):
        raise NotFoundError("Метка не найдена")
    if owner_id is not None and not get_client_identity(owner_id):
        raise ValidationError("Такой клиент не найден")

    assign_tag_owner(tag_id, owner_id)
    record_admin_audit_event(
        actor=actor,
        action="tag.owner_assigned",
        target_type="tag",
        target_id=tag_id,
        details={"client_id": owner_id},
    )
    return "Владелец метки сохранён" if owner_id is not None else "Метка отвязана от клиента"


def toggle_tag_access(actor: AdminAuditActor, tag_id: int) -> str:
    new_status = toggle_tag_status(tag_id)
    if new_status is None:
        raise NotFoundError("Метка не найдена")

    record_admin_audit_event(
        actor=actor,
        action="tag.toggled",
        target_type="tag",
        target_id=tag_id,
        details={"is_active": new_status},
    )
    return "Статус метки изменён"


def delete_tag_record(actor: AdminAuditActor, tag_id: int) -> str:
    if not delete_tag(tag_id):
        raise NotFoundError("Метка не найдена")

    record_admin_audit_event(
        actor=actor,
        action="tag.deleted",
        target_type="tag",
        target_id=tag_id,
    )
    return "Метка удалена"


def get_visits_page_data(tag: str, client_login: str, limit: int) -> dict:
    bounded_limit = max(1, min(limit, 500))
    normalized_tag = (tag or "").strip()
    normalized_client_login = (client_login or "").strip().lower()
    return {
        "tag_options": list_admin_visit_tag_codes(),
        "selected_tag": normalized_tag,
        "selected_client_login": normalized_client_login,
        "limit": bounded_limit,
        "visits": sanitize_visit_rows(list_admin_visits(normalized_tag, normalized_client_login, bounded_limit)),
    }


def get_export_rows(tag: str, client_login: str, limit: int) -> list[dict]:
    bounded_limit = max(1, min(limit, 5000))
    normalized_tag = (tag or "").strip()
    normalized_client_login = (client_login or "").strip().lower()
    return sanitize_visit_rows(list_admin_visits_for_export(normalized_tag, normalized_client_login, bounded_limit))
