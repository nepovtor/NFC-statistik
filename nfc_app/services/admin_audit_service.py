from __future__ import annotations

import json
from dataclasses import dataclass

from ..repositories.audit_repository import (
    count_admin_audit_logs,
    count_admin_audit_logs_for_actions,
    create_admin_audit_log,
    get_latest_admin_audit_event_for_actions,
    list_admin_audit_logs,
)

LOGIN_SUCCESS_ACTIONS = ("admin.login",)
AUTH_ISSUE_ACTIONS = ("admin.login_failed", "admin.login_rate_limited")
RATE_LIMIT_ACTIONS = ("admin.login_rate_limited",)
MUTATION_ACTIONS = (
    "client.created",
    "client.toggled",
    "tag.created",
    "tag.owner_assigned",
    "tag.toggled",
    "tag.deleted",
)

_ACTION_META = {
    "admin.login": {"label": "Успешный вход", "tone": "ok", "icon": "login"},
    "admin.logout": {"label": "Выход", "tone": "muted", "icon": "logout"},
    "admin.login_failed": {"label": "Ошибка входа", "tone": "warn", "icon": "warning"},
    "admin.login_rate_limited": {"label": "Блокировка rate limit", "tone": "danger", "icon": "warning"},
    "client.created": {"label": "Клиент создан", "tone": "ok", "icon": "clients"},
    "client.toggled": {"label": "Доступ клиента изменён", "tone": "warn", "icon": "clients"},
    "tag.created": {"label": "Метка создана", "tone": "ok", "icon": "tags"},
    "tag.owner_assigned": {"label": "Владелец метки изменён", "tone": "accent", "icon": "tags"},
    "tag.toggled": {"label": "Статус метки изменён", "tone": "warn", "icon": "tags"},
    "tag.deleted": {"label": "Метка удалена", "tone": "danger", "icon": "tags"},
}


@dataclass(frozen=True)
class AdminAuditActor:
    admin_id: int | None
    admin_login: str
    ip_address: str | None = None
    user_agent: str | None = None


def record_admin_audit_event(
    *,
    actor: AdminAuditActor,
    action: str,
    target_type: str,
    target_id: int | str | None = None,
    target_label: str | None = None,
    details: dict | None = None,
) -> None:
    details_json = None
    if details:
        details_json = json.dumps(details, ensure_ascii=False, sort_keys=True)

    create_admin_audit_log(
        admin_id=actor.admin_id,
        admin_login=actor.admin_login,
        action=action,
        target_type=target_type,
        target_id=None if target_id is None else str(target_id),
        target_label=(target_label or "").strip() or None,
        ip_address=(actor.ip_address or "").strip() or None,
        user_agent=(actor.user_agent or "").strip() or None,
        details_json=details_json,
    )


def _deserialize_details(details_json: str | None) -> dict:
    if not details_json:
        return {}
    try:
        data = json.loads(details_json)
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _detail_value(value) -> str:
    if isinstance(value, bool):
        return "да" if value else "нет"
    return str(value)


def _format_details_display(action: str, details_json: str | None) -> str:
    details = _deserialize_details(details_json)
    if not details:
        return details_json or ""

    if action == "admin.login_rate_limited" and details.get("retry_after_seconds"):
        return f"повторить через {details['retry_after_seconds']} с"
    if action == "admin.login_failed" and details.get("login_key"):
        return f"логин: {details['login_key']}"
    if action == "client.created" and details.get("name"):
        return f"имя: {details['name']}"
    if action in {"client.toggled", "tag.toggled"} and "is_active" in details:
        return "включено" if details["is_active"] else "выключено"
    if action == "tag.owner_assigned" and "client_id" in details:
        return f"client_id: {details['client_id']}" if details["client_id"] is not None else "владелец снят"

    return ", ".join(f"{key}: {_detail_value(value)}" for key, value in details.items())


def _serialize_audit_events(events: list[dict]) -> list[dict]:
    serialized_events = []
    for event in events:
        row = dict(event)
        action_meta = _ACTION_META.get(
            row["action"],
            {"label": row["action"], "tone": "muted", "icon": "audit"},
        )
        target_parts = [row["target_type"]]
        if row.get("target_id"):
            target_parts.append(f"#{row['target_id']}")
        if row.get("target_label"):
            target_parts.append(str(row["target_label"]))
        row["target_display"] = " ".join(part for part in target_parts if part)
        row["action_label"] = action_meta["label"]
        row["action_tone"] = action_meta["tone"]
        row["action_icon"] = action_meta["icon"]
        row["details_display"] = _format_details_display(row["action"], row.get("details_json"))
        serialized_events.append(row)
    return serialized_events


def _summary_timestamp(row: dict | None) -> str:
    if not row:
        return "ещё не было"
    return row.get("created_at") or "ещё не было"


def get_admin_audit_summary(admin_login: str = "") -> dict:
    normalized_admin_login = (admin_login or "").strip().lower()
    return {
        "total_events": count_admin_audit_logs("", normalized_admin_login),
        "successful_logins": count_admin_audit_logs_for_actions(LOGIN_SUCCESS_ACTIONS, normalized_admin_login),
        "auth_issues": count_admin_audit_logs_for_actions(AUTH_ISSUE_ACTIONS, normalized_admin_login),
        "rate_limit_blocks": count_admin_audit_logs_for_actions(RATE_LIMIT_ACTIONS, normalized_admin_login),
        "last_successful_login_at": _summary_timestamp(
            get_latest_admin_audit_event_for_actions(LOGIN_SUCCESS_ACTIONS, normalized_admin_login)
        ),
        "last_mutation_at": _summary_timestamp(
            get_latest_admin_audit_event_for_actions(MUTATION_ACTIONS, normalized_admin_login)
        ),
        "last_auth_issue_at": _summary_timestamp(
            get_latest_admin_audit_event_for_actions(AUTH_ISSUE_ACTIONS, normalized_admin_login)
        ),
    }


def get_admin_audit_page_data(action: str, admin_login: str, page: int, limit: int) -> dict:
    bounded_limit = max(1, min(limit, 500))
    current_page = max(1, page)
    normalized_action = (action or "").strip()
    normalized_admin_login = (admin_login or "").strip().lower()
    total = count_admin_audit_logs(normalized_action, normalized_admin_login)
    total_pages = max(1, (total + bounded_limit - 1) // bounded_limit)
    effective_page = min(current_page, total_pages)
    events = _serialize_audit_events(
        list_admin_audit_logs(
            bounded_limit,
            page=effective_page,
            action=normalized_action,
            admin_login=normalized_admin_login,
        )
    )
    return {
        "limit": bounded_limit,
        "page": effective_page,
        "total": total,
        "total_pages": total_pages,
        "has_prev": effective_page > 1,
        "has_next": effective_page < total_pages,
        "selected_action": normalized_action,
        "selected_admin_login": normalized_admin_login,
        "summary": get_admin_audit_summary(normalized_admin_login),
        "events": events,
    }


def get_admin_audit_export_rows(action: str, admin_login: str, limit: int) -> list[dict]:
    bounded_limit = max(1, min(limit, 5000))
    normalized_action = (action or "").strip()
    normalized_admin_login = (admin_login or "").strip().lower()
    return _serialize_audit_events(
        list_admin_audit_logs(
            bounded_limit,
            page=1,
            action=normalized_action,
            admin_login=normalized_admin_login,
        )
    )
