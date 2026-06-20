.PHONY: help venv test demo up docker-demo down clean

help:
	@echo "make demo         - run the full demo locally (no Docker)"
	@echo "make test         - run the unit/integration test suite"
	@echo "make up           - build and start all services with docker compose"
	@echo "make docker-demo  - run the end-to-end demo inside docker compose"
	@echo "make down         - stop docker compose and remove volumes"
	@echo "make clean        - remove venv, caches and runtime state"

venv:
	@if command -v uv >/dev/null 2>&1; then uv venv .venv && uv pip install -r requirements.txt -r requirements-dev.txt; \
	else python3 -m venv .venv && .venv/bin/pip install -r requirements.txt -r requirements-dev.txt; fi

test:
	@. .venv/bin/activate && python -m pytest tests/ -q

demo:
	@./demo/run_local.sh

up:
	docker compose up --build -d

docker-demo: up
	docker compose --profile demo run --rm demo

down:
	docker compose down -v

clean:
	rm -rf .venv shared **/__pycache__ .pytest_cache
