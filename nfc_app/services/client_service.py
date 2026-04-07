from __future__ import annotations

from ..repositories.client_repository import get_client_tag, list_tags_for_client, update_client_tag
from ..repositories.visit_repository import (
    list_client_visit_tag_codes,
    list_client_visits,
    list_client_visits_for_export,
)
from ..services.errors import NotFoundError, ValidationError
from ..validators import is_public_http_url
from ..visit_policy import sanitize_visit_rows


def get_client_tags_page_data(client_id: int) -> dict:
    return {"tags": list_tags_for_client(client_id)}


def update_client_tag_record(client_id: int, tag_id: int, name: str, target_url: str, is_active: str) -> str:
    name = name.strip()
    target_url = target_url.strip()
    is_active_value = 1 if str(is_active) == "1" else 0

    tag = get_client_tag(tag_id, client_id)
    if not tag:
        raise NotFoundError("Метка не найдена")
    if not name:
        raise ValidationError("Название метки не должно быть пустым")
    if not is_public_http_url(target_url):
        raise ValidationError("Ссылка должна начинаться с http:// или https://")

    update_client_tag(tag_id, client_id, name, target_url, is_active_value)
    return f"Изменения для метки {tag['code']} сохранены"


def get_client_visits_page_data(client_id: int, tag: str, limit: int) -> dict:
    bounded_limit = max(1, min(limit, 500))
    return {
        "tag_options": list_client_visit_tag_codes(client_id),
        "selected_tag": tag,
        "limit": bounded_limit,
        "visits": sanitize_visit_rows(list_client_visits(client_id, tag, bounded_limit)),
    }


def get_client_export_rows(client_id: int) -> list[dict]:
    return sanitize_visit_rows(list_client_visits_for_export(client_id))
