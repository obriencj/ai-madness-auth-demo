# Gilla Authentication API Backend

This is the backend service for the Gilla Authentication Demo, packaged as a Python wheel for deployment in containerized environments. The backend provides a comprehensive authentication system supporting JWT, OAuth, and GSSAPI/Kerberos authentication methods.

## Package Structure

The backend is organized as a namespace package with comprehensive authentication modules:

```
gilla_auth/
├── __init__.py          # Namespace package (empty)
└── api/
    ├── __init__.py      # Flask app factory and main routes
    ├── config.py        # Configuration management and admin endpoints
    ├── jwt.py          # JWT authentication utilities and session management
    ├── model.py        # Database models and SQLAlchemy setup
    ├── oauth.py        # OAuth provider integration and workflow
    ├── gssapi.py       # GSSAPI/Kerberos authentication system
    ├── user.py         # User management endpoints
    ├── crypto.py       # Cryptographic utilities and keytab encryption
    ├── keytab_cache.py # Keytab caching and management
    └── utils.py        # Utility functions and helpers
```

## Authentication Features

### JWT Authentication
- Secure token-based authentication with configurable expiration
- Redis-based token blacklisting for secure logout
- Session management with automatic token validation
- Role-based access control (admin/user permissions)

### OAuth Integration
- Support for Google, GitHub, and configurable OAuth providers
- Dynamic OAuth provider configuration via database
- Automatic user creation and account linking
- Secure OAuth provider management (admin only)

### GSSAPI/Kerberos Authentication
- Enterprise-grade Kerberos authentication
- Encrypted keytab storage with master key encryption
- Realm configuration management
- Automatic user creation and linking
- Keytab validation and caching

### User Management
- Comprehensive user CRUD operations
- Password hashing with bcrypt
- Email validation and uniqueness
- Admin privilege management
- OAuth account linking and management

## Development Setup

### Prerequisites

- Python 3.11+
- pip
- build tools
- PostgreSQL development libraries
- GSSAPI development libraries (for Kerberos support)

### Local Development

1. **Install in development mode:**
   ```bash
   cd backend
   pip install -e .
   ```

2. **Set up environment variables:**
   ```bash
   export DATABASE_URL="postgresql://user:pass@localhost:5432/auth_demo"
   export REDIS_URL="redis://localhost:6379"
   export JWT_SECRET_KEY="your-secret-key"
   export GSSAPI_MASTER_KEY="your-gssapi-master-key"
   ```

3. **Run the Flask app:**
   ```bash
   export FLASK_APP=gilla_auth.api:app
   export FLASK_ENV=development
   flask run
   ```

4. **Run tests:**
   ```bash
   python -m nose
   ```

5. **Lint code:**
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

The multi-stage `Dockerfile` automatically builds the wheel during the container build process:

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

## API Endpoints

The service provides REST API endpoints under `/api/v1/`:

### Authentication Endpoints
- **JWT:** Login, logout, token validation
- **OAuth:** Authorization, callback, provider management
- **GSSAPI:** Authentication initiation, completion, realm management

### User Management
- **Users:** CRUD operations, admin controls
- **OAuth Accounts:** Linking, management, removal
- **GSSAPI Accounts:** Kerberos account management

### Administrative
- **OAuth Providers:** Full CRUD for OAuth configuration
- **GSSAPI Realms:** Kerberos realm configuration
- **System Configuration:** Application settings and feature flags

## Database Models

### Core Models
- **User:** User accounts with authentication methods
- **OAuthProvider:** OAuth provider configuration
- **OAuthAccount:** User OAuth account links
- **GSSAPIRealm:** Kerberos realm configuration
- **GSSAPIAccount:** User Kerberos account links
- **JWTSession:** JWT session tracking

### Security Features
- Encrypted keytab storage
- Secure password hashing
- Token blacklisting
- Session management

## Security Features

### Authentication Security
- JWT token encryption and validation
- OAuth provider security validation
- GSSAPI keytab encryption
- Password strength requirements

### Data Protection
- Encrypted sensitive data storage
- Secure session management
- CORS protection
- Input validation and sanitization

### Access Control
- Role-based permissions
- Admin privilege management
- Secure endpoint protection
- Audit logging capabilities

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
- `GSSAPI_MASTER_KEY`: Master key for GSSAPI keytab encryption

### Health Checks

The service includes health check endpoints:
- `/api/v1/test` - Basic connectivity test
- Database connection validation
- Redis connection validation

## Development Workflow

1. **Code changes:** Modify files in `gilla_auth/api/`
2. **Testing:** Run tests with `python -m nose`
3. **Linting:** Check code quality with `python -m flake8`
4. **Building:** Create wheel with `python -m build`
5. **Deployment:** Build and run container with the new wheel

## Dependencies

All dependencies are managed through `setup.cfg` and installed when the wheel is built:

### Core Dependencies
- Flask 2.3+ for web framework
- SQLAlchemy 3.0+ for database ORM
- Flask-JWT-Extended 4.5+ for JWT authentication
- Redis 5.0+ for caching and sessions

### Authentication Dependencies
- GSSAPI 1.8+ for Kerberos support
- Flask-OAuthlib for OAuth integration
- bcrypt for password hashing
- cryptography for encryption utilities

### Database Dependencies
- psycopg2-binary for PostgreSQL
- Flask-SQLAlchemy for ORM integration

The container build process handles dependency resolution and installation.

## Testing

### Test Configuration
- Nose test runner
- Coverage reporting
- Multiple Python version support via Tox
- Linting integration

### Running Tests
```bash
# Run all tests
python -m nose

# Run with coverage
python -m nose --with-coverage

# Run specific test file
python -m nose test_gssapi.py
```

## License

GNU General Public License v3 (GPLv3)

<!-- The end. -->


