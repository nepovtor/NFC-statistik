from __future__ import annotations

from .repositories.analytics_repository import get_admin_dashboard_snapshot, get_client_dashboard_snapshot


def get_admin_dashboard_data() -> dict:
    return get_admin_dashboard_snapshot()


def get_client_dashboard_data(client_id: int) -> dict:
    return get_client_dashboard_snapshot(client_id)
