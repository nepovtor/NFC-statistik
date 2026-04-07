from __future__ import annotations

import csv
import io
from urllib.parse import urlencode

from fastapi.responses import RedirectResponse, Response


def build_chart_rows(top_tags: list[dict]) -> list[dict]:
    max_clicks = max([row["total_clicks"] for row in top_tags], default=1)
    if max_clicks <= 0:
        return []

    chart_rows = []
    for row in top_tags:
        chart_rows.append(
            {
                "tag_code": row["tag_code"],
                "total_clicks": row["total_clicks"],
                "width": round((row["total_clicks"] / max_clicks) * 100, 1),
            }
        )
    return chart_rows


def build_redirect_url(path: str, **params) -> str:
    query_items = [(key, str(value)) for key, value in params.items() if value is not None]
    if not query_items:
        return path
    separator = "&" if "?" in path else "?"
    return path + separator + urlencode(query_items)


def redirect_with_query(path: str, *, status_code: int = 303, **params) -> RedirectResponse:
    return RedirectResponse(url=build_redirect_url(path, **params), status_code=status_code)


def csv_response(filename: str, columns: list[tuple[str, str]], rows: list[dict]) -> Response:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([label for _, label in columns])
    for row in rows:
        writer.writerow(["" if row.get(key) is None else row.get(key) for key, _ in columns])

    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
