# Gilla Authentication API Backend

This is the backend service for the Gilla Authentication Demo, packaged as a Python wheel for deployment in containerized environments.

## Package Structure

The backend is organized as a namespace package:

```
gilla_auth/
├── __init__.py          # Namespace package (empty)
└── api/
    ├── __init__.py      # Flask app factory and main routes
    ├── config.py        # Configuration management
    ├── jwt.py          # JWT authentication utilities
    ├── model.py        # Database models and SQLAlchemy setup
    ├── oauth.py        # OAuth provider integration
    └── user.py         # User management endpoints
```

## Development Setup

### Prerequisites

- Python 3.11+
- pip
- build tools

### Local Development

1. **Install in development mode:**
   ```bash
   cd backend
   pip install -e .
   ```

2. **Run the Flask app:**
   ```bash
   export FLASK_APP=gilla_auth.api:app
   export FLASK_ENV=development
   flask run
   ```

3. **Run tests:**
   ```bash
   python -m nose
   ```

4. **Lint code:**
   ```bash
   python -m flake8 gilla_auth/
   ```

## Building the Wheel

### Manual Build

```bash
cd backend
python -m build
```

This creates a wheel file in `dist/` that can be installed in other environments.

### Container Build

The multi-stage `Containerfile` automatically builds the wheel during the container build process:

1. **Build stage:** Uses `python:3.11-slim` to build the wheel
2. **Runtime stage:** Uses `python:3.11-alpine` with gunicorn to run the service

## Package Configuration

### setup.cfg

The package configuration is defined in `setup.cfg`:

- **Package metadata:** Name, version, description, author
- **Dependencies:** All required packages with version constraints
- **Testing:** Tox configuration for multiple Python versions
- **Linting:** Flake8 configuration and exclusions

### setup.py

A minimal `setup.py` that delegates to `setup.cfg` for all configuration.

## Deployment

### Container Deployment

The service is designed to run in containers with:

- **Entry point:** `gilla_auth.api:app`
- **Server:** Gunicorn with 4 workers
- **Port:** 5000 (internal)
- **User:** Non-root `gilla` user

### Environment Variables

Required environment variables:

- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string  
- `JWT_SECRET_KEY`: Secret key for JWT signing

## API Endpoints

The service provides REST API endpoints under `/api/v1/`:

- **Authentication:** JWT-based login/logout
- **User Management:** Registration, profile updates
- **OAuth:** Third-party authentication providers
- **Configuration:** App settings and feature flags

## Development Workflow

1. **Code changes:** Modify files in `gilla_auth/api/`
2. **Testing:** Run tests with `python -m nose`
3. **Linting:** Check code quality with `python -m flake8`
4. **Building:** Create wheel with `python -m build`
5. **Deployment:** Build and run container with the new wheel

## Dependencies

All dependencies are managed through `setup.cfg` and installed when the wheel is built. The container build process handles dependency resolution and installation.

## License

MIT License - see the main project README for details.
