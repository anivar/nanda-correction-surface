FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Dependencies first for layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# All services share this one image; docker-compose overrides `command` per service.
# Default command runs the index service.
CMD ["uvicorn", "index.app:app", "--host", "0.0.0.0", "--port", "8000"]
