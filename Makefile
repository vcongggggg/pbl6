.PHONY: help install test lint format build docker-config docker-build docker-up docker-down

help:
	@echo "PBL6 — Web API Security Platform Build Commands:"
	@echo "  make install        Install backend and frontend dependencies"
	@echo "  make test           Run backend unit and integration test suite"
	@echo "  make lint           Run static analysis and linter (ruff)"
	@echo "  make format         Format codebase with ruff"
	@echo "  make build          Build frontend production bundle"
	@echo "  make docker-config  Validate docker-compose.yml configuration"
	@echo "  make docker-build   Build all container images"
	@echo "  make docker-up      Start all services with docker compose"
	@echo "  make docker-down    Stop all running services"

install:
	pip install -e gateway/
	cd dashboard && npm install

test:
	python -m pytest gateway/tests

lint:
	ruff check gateway

format:
	ruff format gateway

build:
	cd dashboard && npm run build

docker-config:
	docker compose config

docker-build:
	docker compose build

docker-up:
	docker compose up -d

docker-down:
	docker compose down
