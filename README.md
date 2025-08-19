# Auth Demo Application Stack

A complete demonstration of JWT authentication with Redis session management, featuring a Flask backend API and a Flask frontend web application.

## Architecture

- **Backend**: Flask API with JWT authentication, PostgreSQL database, and Redis session management
- **Frontend**: Flask web application with Jinja2 templates and minimal JavaScript
- **Database**: PostgreSQL for persistent user data storage with automatic initialization
- **Cache**: Redis for JWT token blacklisting and session management
- **Proxy**: Nginx reverse proxy for unified interface
- **Containerization**: Docker/Podman with docker-compose orchestration

## Features

### Backend API Endpoints
- `POST /api/v1/auth/login` - User authentication
- `POST /api/v1/auth/logout` - User logout (token blacklisting)
- `POST /api/v1/auth/register` - Self-registration for new users
- `POST /api/v1/register` - Create new users (admin only)
- `GET /api/v1/users` - List all users (admin only)
- `PUT /api/v1/users/<id>` - Update user (admin only)
- `GET /api/v1/hello` - Protected hello world endpoint
- `GET /api/v1/me` - Get current user info
- `GET /api/v1/auth/oauth/<provider>/authorize` - OAuth authorization
- `GET /api/v1/auth/oauth/<provider>/callback` - OAuth callback handling
- `GET /api/v1/auth/oauth/providers` - List available OAuth providers

### Frontend Features
- User login/logout with session management
- **OAuth login support (Google, GitHub)**
- **User self-registration**
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

3. **Access the application:**
   - Application: http://localhost:8080
   - Frontend: http://localhost:8080 (served under /)
   - Backend API: http://localhost:8080/api/v1
   - PostgreSQL: localhost:5432
   - Redis: localhost:6379

4. **Default admin credentials:**
   - Username: `admin`
   - Password: `admin123`

## OAuth Setup

The application supports OAuth authentication with Google and GitHub. To enable OAuth:

1. **Set up OAuth applications** in Google Cloud Console and GitHub Developer Settings
2. **Configure environment variables** with your OAuth client IDs and secrets
3. **Run the OAuth database migration** to create required tables
4. **Restart the application** to load OAuth configuration

For detailed setup instructions, see [OAUTH_SETUP.md](OAUTH_SETUP.md).

## Service Details

### Nginx Proxy Service (Port 8080)
- Reverse proxy for unified interface
- Routes frontend requests to port 8000
- Routes API requests to port 5000
- Handles CORS and request forwarding

### Backend Service (Port 5000)
- Flask application with JWT authentication
- Gunicorn WSGI server for production deployment
- PostgreSQL integration for user management
- Redis integration for token blacklisting
- CORS enabled for frontend communication
- Database connection validation on startup

### Frontend Service (Port 8000)
- Flask web application with session management
- Gunicorn WSGI server for production deployment
- Jinja2 templates with Bootstrap styling
- Minimal JavaScript for enhanced UX
- Admin dashboard for user management
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

### Login
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

## Security Features

- **JWT Tokens**: Secure authentication with configurable expiration
- **Password Hashing**: bcrypt for secure password storage
- **Token Blacklisting**: Redis-based token invalidation on logout
- **Admin Authorization**: Role-based access control
- **CORS Protection**: Configured for secure cross-origin requests
- **Session Management**: Server-side session tracking

## Development

### Environment Variables
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `JWT_SECRET_KEY`: Secret key for JWT signing
- `BACKEND_URL`: Backend API URL (for frontend)
- `GOOGLE_CLIENT_ID`: Google OAuth client ID
- `GOOGLE_CLIENT_SECRET`: Google OAuth client secret
- `GITHUB_CLIENT_ID`: GitHub OAuth client ID
- `GITHUB_CLIENT_SECRET`: GitHub OAuth client secret

### Adding New Features
1. Backend: Add routes in `backend/app.py`
2. Frontend: Add templates in `frontend/templates/`
3. Update docker-compose.yml if new services are needed

## Troubleshooting

### Common Issues

1. **Port conflicts**: Ensure ports 5000, 8000, 5432, and 6379 are available
2. **Database connection**: Wait for PostgreSQL health check to pass
3. **Redis connection**: Ensure Redis service is running
4. **Permission issues**: Run with appropriate user permissions

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

## License

This project is for demonstration purposes. Please review and modify security settings before production use.
