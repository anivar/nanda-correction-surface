.PHONY: help sync test lint format demo up docker-demo down clean

help:
	@echo "make sync         - create/refresh the uv environment (Python 3.14)"
	@echo "make demo         - run the full demo locally with uv (no Docker)"
	@echo "make explorer     - serve the protocol explorer UI at http://localhost:8090"
	@echo "make test         - run the test suite (uv run pytest)"
	@echo "make lint         - ruff check + format --check"
	@echo "make format       - ruff format + check --fix"
	@echo "make up           - build and start all services with docker compose"
	@echo "make docker-demo  - run the end-to-end demo inside docker compose"
	@echo "make down         - stop docker compose"
	@echo "make clean        - remove venv, caches and runtime state"

sync:
	uv sync --frozen

test:
	uv run pytest -q

lint:
	uv run ruff check .
	uv run ruff format --check .

format:
	uv run ruff format .
	uv run ruff check --fix .

demo:
	./demo/run_local.sh

explorer:
	uv run uvicorn explorer.app:app --host 0.0.0.0 --port 8090

up:
	docker compose up --build -d

docker-demo: up
	docker compose --profile demo run --rm demo

down:
	docker compose down

clean:
	rm -rf .venv shared .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
