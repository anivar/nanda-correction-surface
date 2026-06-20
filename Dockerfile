# uv-native, non-root, latest CPython.
FROM python:3.14-slim

# Bring in the uv binary from its published image (pinned).
COPY --from=ghcr.io/astral-sh/uv:0.11.6 /uv /uvx /bin/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

# Install dependencies from the lockfile first (cached layer). package=false, so
# uv installs only the pinned deps — no project build, no source needed yet.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev

COPY . .

# Run as a non-root user; give it ownership of the venv and the writable state dir.
RUN useradd --create-home --uid 1000 appuser \
    && mkdir -p /app/shared \
    && chown -R appuser:appuser /app
USER appuser

# Put the uv-managed venv on PATH so `uvicorn`/`python` resolve directly.
ENV PATH="/app/.venv/bin:$PATH"

# Overridden per service by docker-compose.
CMD ["uvicorn", "index.app:app", "--host", "0.0.0.0", "--port", "8000"]
