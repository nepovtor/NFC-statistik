from __future__ import annotations

import os
import sys

import uvicorn

from .database import assert_database_ready, main as database_main
from .settings import validate_runtime_settings


def main(argv: list[str] | None = None) -> int:
    args = argv or sys.argv[1:]
    if args and args[0] in {"migrate", "check", "sync-admin"}:
        return database_main(args)
    if not args or args[0] != "serve":
        print("Usage: python3 -m nfc_app [serve|migrate|check|sync-admin]", file=sys.stderr)
        return 1

    validate_runtime_settings()
    assert_database_ready()

    host = os.getenv("APP_HOST", "0.0.0.0")
    port = int(os.getenv("APP_PORT", "8001"))
    uvicorn.run("main:app", host=host, port=port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
