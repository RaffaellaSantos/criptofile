FROM python:3.13-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

WORKDIR /app

COPY pyproject.toml uv.lock* ./

RUN uv sync --frozen --no-cache

COPY . .

# O projeto define o entrypoint `criptofile` (pyproject.toml -> app.main:main).
# Argumentos passados via `docker compose run app -p ...` chegam como $@.
ENTRYPOINT ["uv", "run", "criptofile"]
CMD ["--help"]