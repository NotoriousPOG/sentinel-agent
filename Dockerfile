FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN useradd --create-home --uid 10001 sentinel

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

COPY alembic.ini ./
COPY alembic ./alembic

USER sentinel

EXPOSE 8091

# Bind all interfaces inside the container network namespace only.
# Compose publishes the port on 127.0.0.1. Alembic applies the empty baseline.
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn sentinel.api.app:app --host 0.0.0.0 --port 8091"]
