# Auth Demo Application Stack Makefile

# Detect compose command (podman-compose or docker-compose)
COMPOSE_CMD := $(shell if command -v podman-compose >/dev/null 2>&1; then echo "podman-compose"; elif command -v docker-compose >/dev/null 2>&1; then echo "docker-compose"; else echo "echo 'Error: Neither podman-compose nor docker-compose found' && exit 1"; fi)

.PHONY: help build start stop restart logs clean status

# Default target
help:
	@echo "Auth Demo Application Stack - Available targets:"
	@echo "  build   - Build all containers"
	@echo "  start   - Start the application stack"
	@echo "  stop    - Stop the application stack"
	@echo "  restart - Restart the application stack"
	@echo "  logs    - View application logs"
	@echo "  status  - Show service status"
	@echo "  clean   - Stop and remove all containers, networks, and volumes"
	@echo "  oauth-setup - Configure OAuth providers in database"
	@echo "  oauth-migrate - Run OAuth database migration"
	@echo "  oauth-scope-migrate - Run OAuth scope field migration"
	@echo ""
	@echo "Using: $(COMPOSE_CMD)"

# Build all containers
build:
	@echo "Building containers..."
	$(COMPOSE_CMD) build

# Start the application stack
start:
	@echo "Starting Auth Demo Application Stack..."
	$(COMPOSE_CMD) up --build
	@echo "Waiting for services to be ready..."
	@sleep 10
	@echo ""
	@echo "Application is starting up!"
	@echo "Application: http://localhost:8080"
	@echo "Frontend: http://localhost:8080 (served under /)"
	@echo "Backend API: http://localhost:8080/api/v1"
	@echo ""
	@echo "Default admin credentials:"
	@echo "Username: admin"
	@echo "Password: admin123"
	@echo ""
	@echo "To view logs: make logs"
	@echo "To stop: make stop"

# Stop the application stack
stop:
	@echo "Stopping Auth Demo Application Stack..."
	$(COMPOSE_CMD) down
	@echo "Application stack stopped successfully!"

# Restart the application stack
restart: stop start

# View application logs
logs:
	@echo "Viewing application logs..."
	$(COMPOSE_CMD) logs -f

# Show service status
status:
	@echo "Service status:"
	$(COMPOSE_CMD) ps

# Clean up everything (stop, remove containers, networks, and volumes)
clean:
	@echo "Cleaning up all containers, networks, and volumes..."
	$(COMPOSE_CMD) down -v --remove-orphans
	@echo "Cleanup completed!"

# Configure OAuth providers in database
oauth-setup:
	@echo "Setting up OAuth providers..."
	@echo "Make sure you have set the OAuth environment variables:"
	@echo "  - GOOGLE_CLIENT_ID"
	@echo "  - GOOGLE_CLIENT_SECRET"
	@echo "  - GITHUB_CLIENT_ID"
	@echo "  - GITHUB_CLIENT_SECRET"
	@echo ""
	@echo "Running OAuth setup script..."
	python3 setup_oauth.py

# Run OAuth database migration
oauth-migrate:
	@echo "Running OAuth database migration..."
	@echo "Connecting to database..."
	@echo "Make sure the database is running (make start)"
	@echo ""
	PGPASSWORD=auth_password psql -h localhost -U auth_user -d auth_demo -f init/02-oauth-support.sql
	@echo "OAuth migration completed!"

# Run OAuth scope field migration
oauth-scope-migrate:
	@echo "Running OAuth scope field migration..."
	@echo "Make sure the database is running (make start)"
	@echo ""
	python3 migrate_scope.py
	@echo "OAuth scope migration completed!"
