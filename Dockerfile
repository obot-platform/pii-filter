FROM python:3.13-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_INSTALL_DIR=/usr/local/bin \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH="/app/.venv/bin:/usr/local/bin:${PATH}" \
    HOME=/home/app

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | sh

RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin app

COPY pyproject.toml uv.lock README.md .python-version ./
COPY main.py filters.py ./

RUN uv sync --frozen --no-dev

RUN chown -R app:app /app /home/app

USER 10001

EXPOSE 8080

CMD ["pii-filter-mcp"]
