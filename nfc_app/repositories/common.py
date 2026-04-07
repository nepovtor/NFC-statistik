from __future__ import annotations


def rows_to_dicts(rows) -> list[dict]:
    return [dict(row) for row in rows]
