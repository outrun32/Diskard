FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/src
WORKDIR /app

COPY pyproject.toml README.md LICENSE ./

RUN pip install --no-cache-dir '.[console]'

COPY src ./src
COPY ui ./ui
COPY migrations ./migrations
COPY alembic.ini ./
COPY config ./config

EXPOSE 8700
CMD ["uvicorn", "ui.server:app", "--host", "0.0.0.0", "--port", "8700"]
