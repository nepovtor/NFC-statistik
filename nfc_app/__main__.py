from __future__ import annotations

import os
import sys

import uvicorn

from .database import main as database_main, run_migrations
from .settings import validate_runtime_settings


def main(argv: list[str] | None = None) -> int:
    args = argv or sys.argv[1:]
    if args and args[0] in {"migrate", "check"}:
        return database_main(args)

    validate_runtime_settings()
    run_migrations()

    host = os.getenv("APP_HOST", "0.0.0.0")
    port = int(os.getenv("APP_PORT", "8001"))
    uvicorn.run("main:app", host=host, port=port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
