# Demo Application

**Author**: Christopher O'Brien <obriencj@gmail.com>  
**Assisted-By**: Cursor AI (Claude Sonnet 4)

A demonstration application that showcases how to integrate with the standalone authentication service.

## Overview

This demo application provides a simple "Hello World" interface that demonstrates:

- **Authentication Integration**: How to authenticate users via the auth service
- **JWT Token Management**: How to handle JWT tokens from the auth service
- **Protected Routes**: How to protect routes using authentication
- **Service Communication**: How to communicate with the auth service API

## Features

### 🔐 **Authentication Flow**
1. User visits the demo app
2. Redirected to login if not authenticated
3. Login credentials sent to auth service
4. JWT token received and stored in session
5. User can access protected routes

### 🛡️ **Protected Endpoints**
- `/hello` - Protected page showing user info
- `/api/hello` - Protected API endpoint
- `/admin` - Admin-only route (redirects to auth service)

### 🔄 **Session Management**
- JWT tokens validated on each request
- Automatic session expiration handling
- Seamless logout process

## Quick Start

### 1. **Start the Auth Service**
```bash
# From the project root
docker-compose up -d backend
```

### 2. **Start the Demo App**
```bash
# From the project root
docker-compose up -d demo
```

### 3. **Access the Demo**
- **URL**: http://localhost:5001
- **Default Credentials**: Use the admin account from the auth service

## Architecture

```
┌─────────────────┐    ┌─────────────────┐
│   Demo App      │◄──►│   Auth Service  │
│   (Port 5001)   │    │   (Port 5000)   │
│                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │   Frontend  │ │    │ │   Backend   │ │
│ │   Routes    │ │    │ │   API       │ │
│ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘
```

### **Integration Points**
- **Authentication**: `/api/v1/auth/login`
- **User Info**: `/api/v1/me`
- **Logout**: `/api/v1/auth/logout`
- **Admin**: `/admin` (redirects to auth service)

## API Endpoints

### **Public Routes**
- `GET /` - Home page (redirects to login or hello)
- `GET /login` - Login form
- `POST /login` - Process login

### **Protected Routes**
- `GET /hello` - Protected hello world page
- `GET /api/hello` - Protected API endpoint
- `GET /admin` - Admin dashboard (redirects to auth service)

### **Session Management**
- `GET /logout` - Logout and clear session

## Authentication Flow

### **1. Login Process**
```python
# User submits login form
response = requests.post(
    'http://auth-service:5000/api/v1/auth/login',
    json={'username': username, 'password': password}
)

# Store JWT token in session
session['access_token'] = response.json()['access_token']
```

### **2. Token Validation**
```python
# Validate token on each request
headers = {'Authorization': f'Bearer {session["access_token"]}'}
response = requests.get(
    'http://auth-service:5000/api/v1/me',
    headers=headers
)

# Update session with fresh user data
session['user'] = response.json()['user']
```

### **3. Logout Process**
```python
# Send logout request to auth service
headers = {'Authorization': f'Bearer {session["access_token"]}'}
requests.post(
    'http://auth-service:5000/api/v1/auth/logout',
    headers=headers
)

# Clear local session
session.clear()
```

## Demo Credentials

Use the default admin account created by the auth service:

- **Username**: `admin`
- **Password**: `admin123`

## Development

### **Local Development**
```bash
cd demo
pip install -r requirements.txt
python app.py
```

### **Docker Development**
```bash
# Build and run
docker build -t demo-app .
docker run -p 5001:5001 demo-app

# With environment variables
docker run -p 5001:5001 \
  -e AUTH_SERVICE_URL=http://localhost:5000 \
  -e SECRET_KEY=your-secret-key \
  demo-app
```

### **Environment Variables**
```bash
AUTH_SERVICE_URL=http://localhost:5000  # Auth service URL
SECRET_KEY=your-secret-key              # Flask secret key
```

## Troubleshooting

### **Common Issues**

#### **1. Auth Service Unavailable**
```
Error: Connection error to auth service
```
**Solution**: Ensure the auth service is running on the expected port.

#### **2. JWT Validation Fails**
```
Error: JWT validation failed: 401
```
**Solution**: Check that the JWT token is valid and not expired.

#### **3. Session Always Expired**
```
Error: Your session has expired
```
**Solution**: Verify the auth service `/api/v1/me` endpoint is working.

### **Debug Mode**
Enable debug mode to see detailed error messages:

```bash
export FLASK_DEBUG=1
python app.py
```

## Security Considerations

### **Production Deployment**
- **Change Default Secrets**: Update `SECRET_KEY` in production
- **HTTPS**: Use HTTPS in production environments
- **Token Expiry**: Configure appropriate JWT token expiry times
- **Rate Limiting**: Implement rate limiting for login attempts

### **Session Security**
- **Secure Cookies**: Use secure cookies in production
- **HTTP Only**: Set appropriate cookie flags
- **CSRF Protection**: Consider adding CSRF protection

## Integration Examples

### **Other Applications**
This demo shows the pattern for integrating any application with the auth service:

1. **Send login requests** to the auth service
2. **Store JWT tokens** in your application's session
3. **Validate tokens** on protected routes
4. **Handle logout** by clearing local sessions

### **Customization**
- **Theming**: Customize the UI to match your application
- **Additional Routes**: Add your own protected routes
- **User Profiles**: Extend with user profile management
- **Role-Based Access**: Implement custom permission logic

## Contributing

This demo application is part of the larger AI Auth Backend project. To contribute:

1. **Fork the repository**
2. **Create a feature branch**
3. **Make your changes**
4. **Submit a pull request**

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

---

**Get started with authentication in minutes!** 🚀

# The end.
