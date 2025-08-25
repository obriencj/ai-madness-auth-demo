# Demo Application

A demonstration application showcasing integration with the standalone Authentication Service.

## Overview

This demo application shows how to integrate with the Auth Service using:
- **JWT Token Authentication**: Secure token-based authentication
- **API Key Authentication**: Service-to-service authentication
- **Session Management**: Client-side session handling
- **Protected Endpoints**: API endpoints requiring authentication

## Features

- ✅ **Login/Logout**: Integration with Auth Service authentication
- ✅ **Protected Pages**: Hello world page requiring authentication
- ✅ **API Endpoints**: Protected REST API endpoints
- ✅ **User Information**: Display current user details
- ✅ **Admin Access**: Redirect to Auth Service admin interface
- ✅ **Session Validation**: Automatic token validation on each request

## Architecture

```
┌─────────────────┐    ┌─────────────────┐
│   Demo App      │    │   Auth Service  │
│   (Port 5001)   │◄──►│   (Port 5000)   │
│                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │   Frontend  │ │    │ │   Backend   │ │
│ │   (Flask)   │ │    │ │   (Flask)   │ │
│ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘
         │                       │
         │                       │
         └───────────────────────┼───────────────────────┐
                                 │                       │
                    ┌─────────────────┐    ┌─────────────────┐
                    │   PostgreSQL    │    │     Redis       │
                    │   Database      │    │   (Sessions)    │
                    └─────────────────┘    └─────────────────┘
```

## Quick Start

### 1. Prerequisites

- Docker and Docker Compose
- Auth Service running on port 5000
- PostgreSQL database
- Redis server

### 2. Environment Variables

```bash
# Demo App Configuration
SECRET_KEY=demo-secret-key-change-in-production
AUTH_SERVICE_URL=http://localhost:5000
DEMO_API_KEY=demo-api-key

# Database (if running standalone)
DATABASE_URL=postgresql://user:pass@localhost:5432/demo
```

### 3. Run with Docker

```bash
# Build and run
docker build -t demo-app .
docker run -p 5001:5001 \
  -e AUTH_SERVICE_URL=http://localhost:5000 \
  -e DEMO_API_KEY=demo-api-key \
  demo-app
```

### 4. Run Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

## API Endpoints

### Public Endpoints

- `GET /` - Home page (redirects to login or hello)
- `GET /login` - Login page
- `POST /login` - Login form submission

### Protected Endpoints

- `GET /hello` - Hello world page (requires authentication)
- `GET /api/hello` - Hello world API (requires authentication)
- `GET /admin` - Admin dashboard redirect (requires admin)
- `GET /logout` - Logout user

## Authentication Flow

1. **User visits demo app** → Redirected to login
2. **User submits credentials** → Demo app calls Auth Service
3. **Auth Service validates** → Returns JWT token
4. **Demo app stores token** → In session storage
5. **User accesses protected page** → Demo app validates token
6. **Token validation** → Demo app calls Auth Service `/me` endpoint
7. **User sees protected content** → Authentication successful

## Integration Points

### 1. Login Integration

```python
# Demo app calls Auth Service login
response = requests.post(
    f'{AUTH_SERVICE_URL}/api/v1/auth/login',
    json={'username': username, 'password': password},
    headers={'X-API-Key': DEMO_API_KEY}
)
```

### 2. Token Validation

```python
# Demo app validates token with Auth Service
response = requests.get(
    f'{AUTH_SERVICE_URL}/api/v1/me',
    headers={
        'Authorization': f'Bearer {token}',
        'X-API-Key': DEMO_API_KEY
    }
)
```

### 3. Logout Integration

```python
# Demo app calls Auth Service logout
response = requests.post(
    f'{AUTH_SERVICE_URL}/api/v1/auth/logout',
    headers={
        'Authorization': f'Bearer {token}',
        'X-API-Key': DEMO_API_KEY
    }
)
```

## Demo Credentials

The demo app uses the same credentials as the Auth Service:

- **Admin User**: `admin` / `admin123`
- **Regular User**: `user` / `password`

## Development

### Project Structure

```
demo/
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── Dockerfile         # Container configuration
├── README.md          # This file
└── templates/         # HTML templates
    ├── login.html     # Login page
    └── hello.html     # Hello world page
```

### Adding New Features

1. **New Protected Page**:
   ```python
   @app.route('/new-page')
   @login_required
   def new_page():
       return render_template('new_page.html')
   ```

2. **New API Endpoint**:
   ```python
   @app.route('/api/new-endpoint')
   @login_required
   def new_api():
       return jsonify({'message': 'New endpoint'})
   ```

3. **Admin-Only Features**:
   ```python
   @app.route('/admin-only')
   @login_required
   def admin_only():
       if not session.get('is_admin'):
           flash('Admin privileges required', 'error')
           return redirect(url_for('hello'))
       return render_template('admin_page.html')
   ```

## Troubleshooting

### Common Issues

1. **Connection Error to Auth Service**:
   - Check if Auth Service is running on port 5000
   - Verify `AUTH_SERVICE_URL` environment variable
   - Check network connectivity

2. **Invalid API Key**:
   - Verify `DEMO_API_KEY` matches Auth Service configuration
   - Check Auth Service tenant configuration

3. **Session Expired**:
   - JWT token may have expired
   - Auth Service may be unavailable
   - Check Redis connectivity for session storage

### Debug Mode

Enable debug mode for detailed error messages:

```python
app.run(debug=True, host='0.0.0.0', port=5001)
```

## Security Considerations

- **API Keys**: Store API keys securely in environment variables
- **HTTPS**: Use HTTPS in production for secure communication
- **Token Storage**: JWT tokens are stored in session (server-side)
- **Validation**: All protected endpoints validate tokens with Auth Service
- **Logout**: Properly invalidate tokens on logout

## Next Steps

This demo application can be extended to:

1. **Add more protected pages** and API endpoints
2. **Implement user registration** integration
3. **Add OAuth provider** integration
4. **Create custom user profiles** with Auth Service user mapping
5. **Add role-based access control** (RBAC)
6. **Implement audit logging** for user actions

# The end.
