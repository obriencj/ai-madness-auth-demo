# Daft Gila Authentication Demo Application Stack

A comprehensive demonstration of enterprise-grade authentication systems featuring JWT authentication, OAuth integration, and GSSAPI/Kerberos authentication with Redis session management, PostgreSQL database, and a modern web interface.

The Daft Gila name is meaningless. Coolname suggested "daft skink" but I was listening to "Gila Monster by King Gizard and the Lizard Wizard" at the time. Gila also means daft in Indonesian apparently. That's fate, surely.

## Architecture

- **Backend**: Python package-based API with Flask, JWT authentication, OAuth integration, and GSSAPI/Kerberos support
- **Frontend**: Flask web application with Jinja2 templates and minimal JavaScript
- **Database**: PostgreSQL for persistent user data storage with automatic initialization
- **Cache**: Redis for JWT token blacklisting and session management
- **Proxy**: Nginx reverse proxy for unified interface
- **Containerization**: Docker/Podman with docker-compose orchestration
- **Authentication**: Multi-method authentication (JWT, OAuth, GSSAPI/Kerberos)

## Features

### Authentication Methods
- **JWT Authentication**: Secure token-based authentication with configurable expiration
- **OAuth Integration**: Support for Google, GitHub, and configurable OAuth providers
- **GSSAPI/Kerberos**: Enterprise-grade Kerberos authentication with keytab management
- **Password Authentication**: Traditional username/password with bcrypt hashing

### Backend API Endpoints

#### Core Authentication
- `POST /api/v1/auth/login` - User authentication (JWT)
- `POST /api/v1/auth/logout` - User logout (token blacklisting)
- `GET /api/v1/auth/me` - Get current user info
- `POST /api/v1/register` - Create new users (admin only)

#### OAuth Authentication
- `GET /api/v1/auth/oauth/<provider>/authorize` - OAuth authorization
- `GET /api/v1/auth/oauth/<provider>/callback` - OAuth callback handling
- `GET /api/v1/auth/oauth/providers` - List available OAuth providers

#### GSSAPI/Kerberos Authentication
- `POST /api/v1/auth/gssapi/initiate` - Initiate GSSAPI authentication
- `POST /api/v1/auth/gssapi/authenticate` - Complete GSSAPI authentication
- `GET /api/v1/auth/gssapi/realms` - List available GSSAPI realms

#### User Management
- `GET /api/v1/users` - List all users (admin only)
- `PUT /api/v1/users/<id>` - Update user (admin only)
- `GET /api/v1/users/<id>/oauth-accounts` - Get user OAuth accounts (admin)
- `DELETE /api/v1/users/<id>/oauth-accounts/<id>` - Remove user OAuth account (admin)

#### OAuth Provider Management (Admin)
- `GET /api/v1/admin/oauth-providers` - Get all OAuth providers
- `POST /api/v1/admin/oauth-providers` - Create new OAuth provider
- `PUT /api/v1/admin/oauth-providers/<id>` - Update OAuth provider
- `DELETE /api/v1/admin/oauth-providers/<id>` - Delete OAuth provider

#### GSSAPI Realm Management (Admin)
- `GET /api/v1/admin/gssapi-realms` - Get all GSSAPI realms
- `POST /api/v1/admin/gssapi-realms` - Create new GSSAPI realm
- `PUT /api/v1/admin/gssapi-realms/<id>` - Update GSSAPI realm
- `DELETE /api/v1/admin/gssapi-realms/<id>` - Delete GSSAPI realm

#### Utility Endpoints
- `GET /api/v1/hello` - Protected hello world endpoint
- `GET /api/v1/test` - Backend health check

### Frontend Features
- User login/logout with session management
- **OAuth login support (Google, GitHub, configurable providers)**
- **GSSAPI/Kerberos authentication interface**
- **User self-registration**
- **OAuth provider management (admin)**
- **GSSAPI realm management (admin)**
- Admin dashboard for user management
- Hello world page demonstrating API integration
- Responsive Bootstrap UI
- Flash message notifications

## Prerequisites

- Podman (or Docker)
- podman-compose (or docker-compose)
- Make

## Quick Start

1. **Clone and navigate to the project:**
   ```bash
   cd /path/to/your/project
   ```

2. **Start the application stack:**
   ```bash
   make start
   ```

## Makefile Commands

The project includes a Makefile for easy management:

- `make help` - Show available commands
- `make build` - Build all containers
- `make start` - Start the application stack
- `make stop` - Stop the application stack
- `make restart` - Restart the application stack
- `make logs` - View application logs
- `make status` - Show service status
- `make clean` - Stop and remove all containers, networks, and volumes
- `make requirements` - Generate backend requirements.txt from setup.cfg

3. **Access the application:**
   - Application: http://localhost:8080
   - Frontend: http://localhost:8080 (served under /)
   - Backend API: http://localhost:8080/api/v1
   - PostgreSQL: localhost:5432
   - Redis: localhost:6379

4. **Default admin credentials:**
   - Username: `admin`
   - Password: `admin123`

### OAuth Provider Management

OAuth provider configuration is stored in the database, including:
- Client ID and Secret
- Authorization, Token, and User Info URLs
- Scope values
- Active status

### GSSAPI/Kerberos Configuration

GSSAPI realm configuration includes:
- Realm name and service principal
- Encrypted keytab storage
- Active status and validation
- Automatic user creation and linking

## Service Details

### Nginx Proxy Service (Port 8080)
- Reverse proxy for unified interface
- Routes frontend requests to port 8000
- Routes API requests to port 5000
- Handles CORS and request forwarding

### Backend Service (Port 5000)
- Python package-based Flask application with JWT authentication
- Gunicorn WSGI server for production deployment
- PostgreSQL integration for user management
- Redis integration for token blacklisting
- OAuth provider integration (Google, GitHub, configurable)
- GSSAPI/Kerberos authentication support
- CORS enabled for frontend communication
- Database connection validation on startup

### Frontend Service (Port 8000)
- Flask web application with session management
- Gunicorn WSGI server for production deployment
- Jinja2 templates with Bootstrap styling
- Minimal JavaScript for enhanced UX
- Admin dashboard for user and authentication management
- Session-aware navigation

### Database Service (Port 5432)
- PostgreSQL 15 with persistent volume
- Database: `auth_demo`
- User: `auth_user`
- Password: `auth_password`
- Automatic schema initialization and admin user creation

### Cache Service (Port 6379)
- Redis 7 Alpine for JWT token blacklisting
- Session management and caching

## API Usage Examples

### JWT Login
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

### Access Protected Endpoint
```bash
curl -X GET http://localhost:8080/api/v1/hello \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Create User (Admin Only)
```bash
curl -X POST http://localhost:8080/api/v1/register \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username": "newuser", "email": "user@example.com", "password": "password123"}'
```

### OAuth Provider Management (Admin Only)
```bash
curl -X POST http://localhost:8080/api/v1/admin/oauth-providers \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "custom_provider",
    "client_id": "your_client_id",
    "client_secret": "your_client_secret",
    "authorize_url": "https://provider.com/oauth/authorize",
    "token_url": "https://provider.com/oauth/token",
    "userinfo_url": "https://provider.com/oauth/userinfo",
    "scope": "read profile"
  }'
```

## Security Features

- **Multi-Method Authentication**: JWT, OAuth, and GSSAPI/Kerberos support
- **JWT Tokens**: Secure authentication with configurable expiration
- **Password Hashing**: bcrypt for secure password storage
- **Token Blacklisting**: Redis-based token invalidation on logout
- **Admin Authorization**: Role-based access control
- **CORS Protection**: Configured for secure cross-origin requests
- **Session Management**: Server-side session tracking
- **Keytab Encryption**: Secure storage of Kerberos keytabs
- **OAuth Security**: Secure OAuth provider configuration management

## Development

### Environment Variables
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `JWT_SECRET_KEY`: Secret key for JWT signing
- `GSSAPI_MASTER_KEY`: Master key for GSSAPI keytab encryption
- `BACKEND_URL`: Backend API URL (for frontend)

### Adding New Features
1. Backend: Add routes in `backend/gilla_auth/api/` package
2. Frontend: Add templates in `frontend/templates/`
3. Update docker-compose.yml if new services are needed

## Troubleshooting

### Common Issues

1. **Port conflicts**: Ensure ports 5000, 8000, 5432, and 6379 are available
2. **Database connection**: Wait for PostgreSQL health check to pass
3. **Redis connection**: Ensure Redis service is running
4. **Permission issues**: Run with appropriate user permissions
5. **GSSAPI issues**: Ensure proper keytab configuration and encryption keys

### Logs
```bash
# View all service logs
make logs

# View specific service logs
make logs backend
make logs frontend
```

### Reset Database
```bash
# Stop services and remove volumes
make clean

# Restart services
make start
```

## Production Considerations

- Change default passwords and secret keys
- Use environment-specific configuration
- Enable HTTPS/TLS
- Configure proper logging
- Set up monitoring and health checks
- Use production-grade database and Redis instances
- Implement rate limiting and security headers
- Secure GSSAPI keytab storage and encryption
- Configure OAuth providers with production credentials

## License

GNU General Public License v3 (GPLv3)

<!-- The end. -->
