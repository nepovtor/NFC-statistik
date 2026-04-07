from __future__ import annotations

import json

from ..repositories.audit_repository import create_admin_audit_log, list_admin_audit_logs


def record_admin_audit_event(
    *,
    admin_id: int | None,
    admin_login: str,
    action: str,
    target_type: str,
    target_id: int | str | None = None,
    target_label: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    details: dict | None = None,
) -> None:
    details_json = None
    if details:
        details_json = json.dumps(details, ensure_ascii=False, sort_keys=True)

    create_admin_audit_log(
        admin_id=admin_id,
        admin_login=admin_login,
        action=action,
        target_type=target_type,
        target_id=None if target_id is None else str(target_id),
        target_label=(target_label or "").strip() or None,
        ip_address=(ip_address or "").strip() or None,
        user_agent=(user_agent or "").strip() or None,
        details_json=details_json,
    )


def get_admin_audit_page_data(limit: int) -> dict:
    bounded_limit = max(1, min(limit, 500))
    events = list_admin_audit_logs(bounded_limit)
    for event in events:
        target_parts = [event["target_type"]]
        if event.get("target_id"):
            target_parts.append(f"#{event['target_id']}")
        if event.get("target_label"):
            target_parts.append(str(event["target_label"]))
        event["target_display"] = " ".join(part for part in target_parts if part)
        event["details_display"] = event.get("details_json") or ""
    return {"limit": bounded_limit, "events": events}
