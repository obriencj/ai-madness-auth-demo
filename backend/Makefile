# Makefile for AI Auth Backend development

.PHONY: help install install-dev build clean test lint format check build-wheel install-wheel run dev

help:  ## Show this help message
	@echo "AI Auth Backend - Development Commands"
	@echo "====================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Install the package in production mode
	pip install .

install-dev:  ## Install the package in development mode with dev dependencies
	pip install -e .[dev]

build:  ## Build the package
	python -m build

clean:  ## Clean build artifacts
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/ .coverage htmlcov/

test:  ## Run tests
	pytest tests/ -v --cov=ai_auth_backend --cov-report=html

lint:  ## Run linting checks
	flake8 ai_auth_backend/ tests/
	mypy ai_auth_backend/

format:  ## Format code with black
	black ai_auth_backend/ tests/

check: format lint test  ## Run all quality checks

build-wheel:  ## Build the wheel package
	python -m build --wheel

install-wheel: build-wheel  ## Build and install the wheel
	pip install dist/*.whl

run:  ## Run the application in production mode
	gunicorn --bind 0.0.0.0:5000 --workers 4 --timeout 120 wsgi:app

dev:  ## Run the application in development mode
	FLASK_APP=ai_auth_backend.app:create_app FLASK_ENV=development python -m flask run --host 0.0.0.0 --port 5000

docker-build:  ## Build the production Docker image
	docker build -t ai-auth-backend:latest .

docker-build-dev:  ## Build the development Docker image
	docker build -f Dockerfile.dev -t ai-auth-backend:dev .

docker-run:  ## Run the production Docker container
	docker run -p 5000:5000 --env-file .env ai-auth-backend:latest

docker-run-dev:  ## Run the development Docker container
	docker run -p 5000:5000 --env-file .env -v $(PWD):/app ai-auth-backend:dev

# The end.
