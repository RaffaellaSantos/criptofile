FROM python:3.13-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

WORKDIR /app

COPY pyproject.toml uv.lock* ./

RUN uv sync --frozen --no-cache

COPY . .

CMD ["sh", "-c", "uv run alembic upgrade head && uv run python main.py"]
