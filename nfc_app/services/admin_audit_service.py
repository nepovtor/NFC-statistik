from __future__ import annotations

import json
from dataclasses import dataclass

from ..repositories.audit_repository import count_admin_audit_logs, create_admin_audit_log, list_admin_audit_logs


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


def _serialize_audit_events(events: list[dict]) -> list[dict]:
    serialized_events = []
    for event in events:
        row = dict(event)
        target_parts = [row["target_type"]]
        if row.get("target_id"):
            target_parts.append(f"#{row['target_id']}")
        if row.get("target_label"):
            target_parts.append(str(row["target_label"]))
        row["target_display"] = " ".join(part for part in target_parts if part)
        row["details_display"] = row.get("details_json") or ""
        serialized_events.append(row)
    return serialized_events


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
