# Daft Gila Frontend

A Flask-based web application that provides a user-friendly interface for the Daft Gila authentication platform. This frontend application serves as the primary user interface for user management, authentication, and administrative functions.

## Overview

The frontend is built using Flask and provides a comprehensive web interface for:
- User authentication and registration
- User account management
- Administrative functions
- OAuth provider configuration
- GSSAPI/Kerberos realm management
- JWT session management
- System configuration

## Architecture

- **Framework**: Flask 2.3.3
- **WSGI Server**: Gunicorn with 4 workers
- **Templates**: Jinja2 HTML templates
- **Client Library**: daftgila.client for backend API communication
- **Containerization**: Multi-stage Docker build

## Features

### User Interface
- **Authentication Pages**: Login, registration, and password management
- **Dashboard**: User overview and quick actions
- **Account Management**: Profile editing and settings
- **Admin Panel**: Comprehensive administrative interface

### Administrative Functions
- **User Management**: Create, edit, and delete user accounts
- **OAuth Providers**: Configure external OAuth authentication services
- **GSSAPI Realms**: Manage Kerberos authentication realms
- **JWT Sessions**: Monitor and manage active JWT sessions
- **System Configuration**: Runtime configuration management

### Security Features
- **Session Management**: Secure user sessions with Redis backend
- **Role-Based Access**: Admin and user role separation
- **CSRF Protection**: Built-in CSRF token validation
- **Secure Headers**: Security-focused HTTP headers

## Project Structure

```
frontend/
├── daftgila/
│   └── web/
│       ├── __init__.py          # Flask app initialization
│       ├── admin.py             # Administrative routes and views
│       ├── dashboard.py         # Dashboard functionality
│       ├── user.py              # User management routes
│       ├── client_factory.py    # Backend API client factory
│       ├── utils.py             # Utility functions
│       ├── auth/                # Authentication-related modules
│       └── templates/           # Jinja2 HTML templates
│           ├── base.html        # Base template with common layout
│           ├── login.html       # User login form
│           ├── register.html    # User registration form
│           ├── dashboard.html   # User dashboard
│           ├── account.html     # Account management
│           ├── admin.html       # Admin panel
│           ├── config.html      # System configuration
│           ├── oauth_providers.html  # OAuth provider management
│           ├── gssapi_realms.html    # GSSAPI realm management
│           └── jwt_sessions.html     # JWT session management
├── Dockerfile                   # Multi-stage Docker build
├── setup.py                     # Python package configuration
├── setup.cfg                    # Package metadata and dependencies
└── README.md                    # This file
```

## Dependencies

### Core Dependencies
- **Flask**: Web framework (2.3.3)
- **requests**: HTTP client library (2.31.0)
- **gunicorn**: WSGI HTTP server (21.2.0)
- **daftgila.client**: Backend API client library (0.1.0)

### Development Dependencies
- **nose**: Testing framework
- **flake8**: Code linting
- **tox**: Test automation

## Quick Start

### Using Docker (Recommended)

1. **Build the frontend container:**
   ```bash
   make build
   ```

2. **Start the application stack:**
   ```bash
   make up
   ```

3. **Access the frontend:**
   - Frontend: http://localhost:8080
   - Backend API: http://localhost:8080/api/v1

### Local Development

1. **Install dependencies:**
   ```bash
   cd frontend
   pip install -e .
   ```

2. **Set environment variables:**
   ```bash
   export BACKEND_URL=http://localhost:8000
   export FLASK_ENV=development
   ```

3. **Run the development server:**
   ```bash
   python -m daftgila.web
   ```

## Configuration

### Environment Variables
- `BACKEND_URL`: URL of the backend API service
- `FLASK_ENV`: Flask environment (development/production)
- `SECRET_KEY`: Flask secret key for session security

### Runtime Configuration
The frontend can be configured through the web interface at `/admin/config` for:
- Authentication method settings
- OAuth provider configurations
- GSSAPI realm settings
- JWT token configurations
- System-wide settings

## API Integration

The frontend communicates with the backend through the `daftgila.client` library, which provides:
- **Authentication**: Login, logout, and token management
- **User Management**: CRUD operations for user accounts
- **Configuration**: Runtime configuration management
- **Admin Functions**: Administrative API endpoints

## Templates

### Base Template
- `base.html`: Common layout with navigation, CSS, and JavaScript
- Responsive design with Bootstrap-like styling
- Navigation menu with role-based access control

### Authentication Templates
- `login.html`: User login form with multiple authentication methods
- `register.html`: User registration form
- `account.html`: User profile and account management

### Administrative Templates
- `admin.html`: Main admin panel with navigation
- `config.html`: System configuration interface
- `oauth_providers.html`: OAuth provider management
- `gssapi_realms.html`: GSSAPI realm configuration
- `jwt_sessions.html`: JWT session monitoring

## Development

### Code Style
- Follow PEP 8 for Python code
- Use type hints where appropriate
- Add docstrings to functions and classes
- Follow the project's flake8 configuration

### Testing
```bash
# Run tests with nose
python -m nose

# Run linting with flake8
python -m flake8 daftgila/
```

### Adding New Features
1. **Routes**: Add new routes in the appropriate module (admin.py, user.py, etc.)
2. **Templates**: Create new Jinja2 templates in the templates/ directory
3. **Client Integration**: Use the client factory for backend API calls
4. **Testing**: Add tests for new functionality

## Docker Build Process

The Dockerfile uses a multi-stage build process:

1. **Build Client**: Compiles the daftgila.client package
2. **Build Frontend**: Compiles the daftgila.web package
3. **Runtime Container**: Creates the final Alpine-based container

### Build Commands
```bash
# Build all containers
make build

# Build only frontend
docker build -f frontend/Dockerfile -t daftgila-frontend .
```

## Security Considerations

- **Session Security**: Secure session management with Redis
- **CSRF Protection**: Built-in CSRF token validation
- **Input Validation**: Server-side validation of all user inputs
- **Role-Based Access**: Proper separation of admin and user functions
- **Secure Headers**: Security-focused HTTP response headers

## Troubleshooting

### Common Issues

1. **Backend Connection Errors**
   - Verify `BACKEND_URL` environment variable
   - Check backend service status
   - Review network connectivity

2. **Template Rendering Issues**
   - Check Jinja2 template syntax
   - Verify template file paths
   - Review template inheritance

3. **Authentication Problems**
   - Verify backend authentication endpoints
   - Check session configuration
   - Review user role assignments

### Logs
```bash
# View frontend logs
make logs frontend

# View all service logs
make logs
```

## Contributing

1. Follow the project's coding standards
2. Add tests for new functionality
3. Update documentation as needed
4. Use descriptive commit messages
5. Test changes in the Docker environment

## License

GNU General Public License v3 (GPLv3)

<!-- The end. -->
