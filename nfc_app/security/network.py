from __future__ import annotations

import ipaddress
from typing import Optional

from fastapi import Request
from fastapi.responses import HTMLResponse

from ..settings import settings


def _request_peer_ip(request: Request) -> Optional[str]:
    if request.client:
        return request.client.host
    return None


def _is_ip_in_networks(ip_value: str, network_values: tuple[str, ...]) -> bool:
    try:
        ip = ipaddress.ip_address(ip_value)
    except ValueError:
        return False

    for network_value in network_values:
        try:
            network = ipaddress.ip_network(network_value, strict=False)
        except ValueError:
            continue
        if ip in network:
            return True
    return False


def _normalize_ip_value(ip_value: str) -> Optional[str]:
    candidate = ip_value.strip()
    if not candidate:
        return None
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _is_trusted_proxy_request(request: Request) -> bool:
    if not settings.trust_proxy_headers:
        return False

    peer_ip = _request_peer_ip(request)
    if not peer_ip:
        return False
    return _is_ip_in_networks(peer_ip, settings.trusted_proxy_networks)


def _get_forwarded_ip(request: Request) -> Optional[str]:
    if not _is_trusted_proxy_request(request):
        return None

    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        first_hop = forwarded_for.split(",", 1)[0].strip()
        normalized_ip = _normalize_ip_value(first_hop)
        if normalized_ip:
            return normalized_ip

    return _normalize_ip_value(request.headers.get("x-real-ip", ""))


def get_request_ip(request: Request) -> Optional[str]:
    forwarded_ip = _get_forwarded_ip(request)
    if forwarded_ip:
        return forwarded_ip
    return _request_peer_ip(request)


def is_ip_allowed_for_admin(ip_value: str) -> bool:
    return _is_ip_in_networks(ip_value, settings.admin_allowed_networks)


def is_admin_request_allowed(request: Request) -> bool:
    if not settings.admin_tailscale_only:
        return True

    request_ip = get_request_ip(request)
    if not request_ip:
        return False
    return is_ip_allowed_for_admin(request_ip)


def admin_tailscale_block_response() -> HTMLResponse:
    return HTMLResponse(
        """
        <!doctype html>
        <html lang="ru">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Админка только через Tailscale</title>
            <style>
                body { margin: 0; font-family: Arial, sans-serif; background: #081120; color: #e5edf7; }
                main { max-width: 680px; margin: 8vh auto; padding: 24px; }
                .panel { padding: 24px; border-radius: 18px; background: rgba(15, 23, 42, 0.96); border: 1px solid rgba(148, 163, 184, 0.18); }
                h1 { margin-top: 0; font-size: 30px; }
                p { line-height: 1.6; color: #cbd5e1; }
                code { padding: 2px 6px; border-radius: 8px; background: rgba(56, 189, 248, 0.1); }
            </style>
        </head>
        <body>
            <main>
                <section class="panel">
                    <h1>Админка доступна только через Tailscale</h1>
                    <p>Публичный вход в <code>/admin</code> отключён. Открой админку через Tailscale с сервера, его Tailscale IP или через Tailscale Serve.</p>
                </section>
            </main>
        </body>
        </html>
        """,
        status_code=403,
    )
