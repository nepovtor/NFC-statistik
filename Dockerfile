ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

USER root

RUN getent group app >/dev/null || addgroup --system app
RUN id -u app >/dev/null 2>&1 || adduser --system --ingroup app --uid 10001 app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=app:app . .

RUN mkdir -p /data && chown -R app:app /app /data

USER app

EXPOSE 8001

CMD ["python", "-m", "nfc_app", "serve"]
