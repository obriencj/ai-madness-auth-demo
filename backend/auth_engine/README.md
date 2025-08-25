# Authentication Engine

A modular, configurable authentication system for Flask applications.

## Overview

The Authentication Engine provides a complete authentication solution that can be easily integrated into any Flask application. It supports multiple authentication providers, session management, and role-based access control.

## Features

- **Multiple Authentication Providers**: Password-based and OAuth (Google, GitHub, etc.)
- **JWT Token Management**: Secure token-based authentication with Redis blacklisting
- **Session Tracking**: Monitor and manage active user sessions
- **Role-Based Access Control**: Flexible permission system
- **Modular Architecture**: Easy to extend and customize
- **Configuration-Driven**: Highly configurable for different use cases
- **Admin Interface**: Built-in admin endpoints for user and session management

## Quick Start

### 1. Installation

```bash
pip install -r requirements.txt
```

### 2. Basic Integration

```python
from flask import Flask
from auth_engine import AuthEngine, AuthConfig
from auth_engine.models import User, OAuthProvider, OAuthAccount, JWTSession

app = Flask(__name__)

# Configure authentication
auth_config = AuthConfig({
    'providers': ['password', 'oauth_google'],
    'session_store': 'redis',
    'jwt_expiry': '1h',
    'enable_admin': True
})

# Set up models
app.user_model = User
app.oauth_provider_model = OAuthProvider
app.oauth_account_model = OAuthAccount
app.session_model = JWTSession

# Initialize auth engine
auth_engine = AuthEngine(app, auth_config)

# Use authentication decorators
@app.route('/protected')
@auth_engine.require_auth()
def protected_route():
    return {'message': 'Authenticated!'}

@app.route('/admin')
@auth_engine.require_auth('admin')
def admin_route():
    return {'message': 'Admin only!'}
```

## Configuration

### AuthConfig Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `providers` | List[str] | `['password']` | Enabled authentication providers |
| `session_store` | str | `'memory'` | Session storage (`memory`, `redis`, `database`) |
| `jwt_expiry` | str | `'1h'` | JWT token expiry time |
| `jwt_secret_key` | str | Environment variable | JWT secret key |
| `database_url` | str | Environment variable | Database connection URL |
| `redis_url` | str | Environment variable | Redis connection URL |
| `user_model` | str | `'User'` | Custom user model class name |
| `enable_admin` | bool | `True` | Enable admin functionality |
| `enable_oauth` | bool | `True` | Enable OAuth functionality |
| `enable_session_tracking` | bool | `True` | Enable session tracking |
| `permissions` | List[str] | `['read', 'write', 'admin']` | Available permissions |

### Environment Variables

```bash
# Required
JWT_SECRET_KEY=your-super-secret-key
DATABASE_URL=postgresql://user:pass@localhost/dbname

# Optional
REDIS_URL=redis://localhost:6379
```

## API Endpoints

### Authentication

- `POST /api/v1/auth/login` - Password login
- `POST /api/v1/auth/logout` - Logout
- `POST /api/v1/auth/register` - User registration
- `GET /api/v1/auth/me` - Get current user

### OAuth

- `GET /api/v1/auth/oauth/providers` - List OAuth providers
- `GET /api/v1/auth/oauth/<provider>/authorize` - Start OAuth flow
- `GET /api/v1/auth/oauth/<provider>/callback` - OAuth callback
- `GET /api/v1/auth/oauth/<provider>/link` - Link OAuth account

### Admin (if enabled)

- `GET /api/v1/admin/users` - List all users
- `POST /api/v1/admin/users` - Create user
- `PUT /api/v1/admin/users/<id>` - Update user
- `GET /api/v1/admin/sessions` - List active sessions

## Models

### User Model

The engine expects a User model that implements the `AbstractUser` interface:

```python
from auth_engine.core.models import AbstractUser

class User(db.Model, AbstractUser):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    
    def check_password(self, password: str) -> bool:
        # Implement password verification
        pass
    
    def set_password(self, password: str):
        # Implement password hashing
        pass
    
    def has_permission(self, permission: str) -> bool:
        # Implement permission checking
        pass
    
    def get_permissions(self) -> List[str]:
        # Return user permissions
        pass
```

## Authentication Providers

### Password Provider

Default provider for username/password authentication.

### OAuth Providers

Support for OAuth providers like Google, GitHub, etc. Configure providers in the database:

```sql
INSERT INTO oauth_provider (name, client_id, client_secret, authorize_url, token_url, userinfo_url, scope, is_active) 
VALUES (
    'google',
    'your-client-id',
    'your-client-secret',
    'https://accounts.google.com/o/oauth2/v2/auth',
    'https://oauth2.googleapis.com/token',
    'https://www.googleapis.com/oauth2/v2/userinfo',
    'openid email profile',
    true
);
```

## Middleware

### Authentication Decorators

```python
from auth_engine.middleware import auth_required, permission_required

@app.route('/protected')
@auth_required
def protected_route():
    return {'message': 'Authenticated!'}

@app.route('/admin')
@permission_required('admin')
def admin_route():
    return {'message': 'Admin only!'}
```

## Service Layer

The engine provides service classes for common operations:

```python
# Get services from app context
auth_service = app.auth_services['auth']
user_service = app.auth_services['user']
session_service = app.auth_services['session']

# Use services
user = user_service.get_user_by_username('john')
sessions = session_service.get_active_sessions()
```

## Customization

### Custom User Model

```python
class CustomUser(User):
    # Add custom fields
    department = db.Column(db.String(100))
    
    def has_permission(self, permission: str) -> bool:
        # Custom permission logic
        if permission == 'department_admin':
            return self.department == 'IT'
        return super().has_permission(permission)
```

### Custom Authentication Provider

```python
from auth_engine.providers.base import BaseProvider

class CustomProvider(BaseProvider):
    def authenticate(self, credentials):
        # Custom authentication logic
        pass
    
    def get_name(self):
        return 'custom'
    
    def is_enabled(self):
        return True
```

## Database Schema

The engine requires these tables:

- `user` - User accounts
- `oauth_provider` - OAuth provider configurations
- `oauth_account` - Linked OAuth accounts
- `jwt_session` - JWT session tracking

See the `init/` directory for SQL scripts.

## Security Considerations

- Use strong JWT secret keys
- Enable HTTPS in production
- Configure proper CORS settings
- Use Redis for session storage in production
- Regularly rotate OAuth client secrets
- Implement rate limiting
- Monitor session activity

## Examples

See `app_new.py` for a complete integration example.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License

# The end.
