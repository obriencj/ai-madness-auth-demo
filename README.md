# Daft Gila - Minimal Viable Authentication Platform

A lightweight, configurable authentication platform and OIDC provider designed for simplicity and reusability. Daft Gila provides the absolute minimum necessary to enable user accounts with a wide range of authentication options, making it easy to provide authentication for other services and web applications.

The Daft Gila name is meaningless. Coolname suggested "daft skink" but I was listening to "Gila Monster by King Gizard and the Lizard Wizard" at the time. Gila also means daft in Indonesian apparently. That's fate, surely.

## Project Goals

- **Minimalism**: Only essential authentication features, no bloat
- **Flexibility**: Runtime configuration for all authentication methods
- **Reusability**: Easy integration with other services and applications
- **OIDC Ready**: Built-in OpenID Connect provider capabilities
- **Cross-Domain**: Domain-level session cookies for seamless cross-app authentication

## Architecture

- **Backend**: `daftgila.api` - Python package with Flask, comprehensive authentication methods
- **Frontend**: `daftgila.web` - Flask web application for user management (optional)
- **Database**: PostgreSQL for persistent user data and configuration
- **Cache**: Redis for session management, token blacklisting, and caching
- **Proxy**: Nginx reverse proxy for unified interface
- **Containerization**: Docker/Podman with docker-compose orchestration

## Core Features

### Authentication Methods
- **JWT Authentication**: Secure token-based authentication with configurable expiration
- **OAuth Integration**: Support for Google, GitHub, and configurable OAuth providers
- **GSSAPI/Kerberos**: Enterprise-grade Kerberos authentication with keytab management
- **Password Authentication**: Traditional username/password with bcrypt hashing

### Key Capabilities
- **Runtime Configuration**: All authentication methods configurable via database/admin interface
- **User Management**: Simple user CRUD with role-based access control
- **Session Management**: Redis-based session handling with configurable expiration
- **OIDC Foundation**: Built-in support for OpenID Connect provider functionality
- **Cross-Domain Ready**: Designed for domain-level session cookies and SSO

## Quick Start

1. **Clone and navigate to the project:**
   ```bash
   cd /path/to/your/project
   ```

2. **Start the application stack:**
   ```bash
   make start
   ```

3. **Access the application:**
   - Application: http://localhost:8080
   - Frontend: http://localhost:8080 (served under /)
   - Backend API: http://localhost:8080/api/v1
   - PostgreSQL: localhost:5432
   - Redis: localhost:6379

4. **Default admin credentials:**
   - Username: `admin`
   - Password: `admin123`

## Makefile Commands

- `make help` - Show available commands
- `make build` - Build all containers
- `make start` - Start the application stack
- `make stop` - Stop the application stack
- `make restart` - Restart the application stack
- `make logs` - View application logs
- `make status` - Show service status
- `make clean` - Stop and remove all containers, networks, and volumes
- `make requirements` - Generate backend requirements.txt from setup.cfg

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

## Integration Patterns

### As an Authentication Service
```python
import requests

# Login to get JWT token
response = requests.post('http://localhost:8080/api/v1/auth/login', json={
    'username': 'user@example.com',
    'password': 'password'
})
token = response.json()['access_token']

# Use token for authenticated requests
headers = {'Authorization': f'Bearer {token}'}
user_info = requests.get('http://localhost:8080/api/v1/auth/me', headers=headers)
```

### OAuth Provider Configuration
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

## Development

### Environment Variables
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `JWT_SECRET_KEY`: Secret key for JWT signing
- `GSSAPI_MASTER_KEY`: Master key for GSSAPI keytab encryption
- `BACKEND_URL`: Backend API URL (for frontend)

### Adding New Features
1. Backend: Add routes in `backend/daftgila/api/` package
2. Frontend: Add templates in `frontend/daftgila/web/templates/`
3. Update docker-compose.yml if new services are needed

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
