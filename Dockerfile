FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/src PATH="/app/.venv/bin:$PATH"
WORKDIR /app

RUN pip install --no-cache-dir uv==0.8.15
COPY pyproject.toml uv.lock README.md LICENSE ./

RUN uv sync --frozen --extra console --no-dev --no-install-project

COPY src ./src
COPY ui ./ui
COPY migrations ./migrations
COPY alembic.ini ./
COPY config ./config
RUN uv sync --frozen --extra console --no-dev

EXPOSE 8700
CMD ["uvicorn", "ui.server:app", "--host", "0.0.0.0", "--port", "8700"]
