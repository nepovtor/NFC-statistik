from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta
from typing import Mapping
from urllib.parse import urlsplit, urlunsplit

from .settings import settings


def visit_retention_cutoff() -> str | None:
    if settings.visit_retention_days <= 0:
        return None
    return (datetime.utcnow() - timedelta(days=settings.visit_retention_days)).strftime("%Y-%m-%d %H:%M:%S")


def _mask_ip_address(ip_value: str) -> str:
    value = ip_value.strip()
    if not value or value == "unknown":
        return value

    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "hidden"

    if ip.version == 4:
        network = ipaddress.ip_network(f"{ip}/24", strict=False)
        return f"{network.network_address}/24"

    network = ipaddress.ip_network(f"{ip}/64", strict=False)
    return f"{network.network_address.compressed}/64"


def _mask_user_agent(user_agent: str) -> str:
    value = user_agent.strip()
    if not value or value == "unknown":
        return value
    return "hidden"


def _mask_referer(referer: str) -> str:
    value = referer.strip()
    if not value:
        return ""

    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.netloc:
        return "hidden"

    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def sanitize_visit_row(row: Mapping) -> dict:
    visit_row = dict(row)
    if settings.visit_data_exposure == "full":
        return visit_row

    visit_row["ip_address"] = _mask_ip_address(str(visit_row.get("ip_address") or ""))
    visit_row["user_agent"] = _mask_user_agent(str(visit_row.get("user_agent") or ""))
    visit_row["referer"] = _mask_referer(str(visit_row.get("referer") or ""))
    return visit_row


def sanitize_visit_rows(rows) -> list[dict]:
    return [sanitize_visit_row(row) for row in rows]
