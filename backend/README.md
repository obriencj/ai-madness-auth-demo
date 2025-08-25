# Authentication Service

A **self-hosted, open-source authentication service** that provides user management, OAuth integration, and JWT authentication for your applications.

## 🎯 **Use Case**

Add authentication to your application with **minimal setup**:

```yaml
# Add to your docker-compose.yml
services:
  auth-service:
    image: your-registry/auth-service:latest
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/auth
      - REDIS_URL=redis://redis:6379
    ports:
      - "5000:5000"
```

**Result**: Get user management, OAuth, JWT auth "for free"!

## 🚀 **Quick Start**

### 1. Add to Your Project

```bash
# Clone this repository
git clone https://github.com/your-org/auth-service.git
cd auth-service

# Start the services
docker-compose up -d
```

### 2. Integrate with Your App

```python
# Your application code
import requests

def login_user(username, password):
    response = requests.post(
        'http://localhost:5000/api/v1/auth/login',
        json={'username': username, 'password': password}
    )
    return response.json()

def validate_token(token):
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(
        'http://localhost:5000/api/v1/me',
        headers=headers
    )
    return response.json()
```

### 3. Access Admin Interface

- **URL**: http://localhost:8080
- **Default Admin**: `admin` / `admin123`

## 🏗️ **Architecture**

```
┌─────────────────┐    ┌─────────────────┐
│   Your App      │◄──►│   Auth Service  │
│                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │   Frontend  │ │    │ │   Backend   │ │
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

## 📋 **Features**

### ✅ **Core Authentication**
- **User Registration & Login**
- **JWT Token Management**
- **Password Hashing** (bcrypt)
- **Session Management**

### ✅ **OAuth Integration**
- **Google OAuth**
- **GitHub OAuth**
- **Extensible Provider System**

### ✅ **Admin Interface**
- **User Management**
- **OAuth Provider Configuration**
- **Session Monitoring**
- **Audit Logging**

### ✅ **API Endpoints**
- **RESTful API Design**
- **OpenAPI Documentation**
- **Rate Limiting**
- **CORS Support**

## 🔧 **Configuration**

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql://user:pass@host:5432/dbname

# Redis (for sessions)
REDIS_URL=redis://host:6379

# Security
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret

# OAuth (optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
```

### Docker Compose Integration

```yaml
version: '3.8'

services:
  # Your existing services...
  your-app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - AUTH_SERVICE_URL=http://auth-service:5000

  # Add auth service
  auth-service:
    build: ./auth-service
    environment:
      - DATABASE_URL=postgresql://auth_user:auth_pass@postgres:5432/auth_db
      - REDIS_URL=redis://redis:6379
    ports:
      - "5000:5000"
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: auth_db
      POSTGRES_USER: auth_user
      POSTGRES_PASSWORD: auth_pass
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
```

## 📚 **API Documentation**

### Authentication Endpoints

```http
POST /api/v1/auth/login
POST /api/v1/auth/logout
POST /api/v1/auth/register
GET  /api/v1/me
```

### User Management

```http
GET    /api/v1/users
GET    /api/v1/users/{id}
PUT    /api/v1/users/{id}
DELETE /api/v1/users/{id}
```

### OAuth Endpoints

```http
GET /api/v1/auth/oauth/{provider}/authorize
GET /api/v1/auth/oauth/{provider}/callback
GET /api/v1/auth/oauth/providers
```

**Full API Documentation**: http://localhost:5000/docs

## 🔐 **Security Features**

- **JWT Token Authentication**
- **Password Hashing** (bcrypt)
- **Session Management**
- **Rate Limiting**
- **CORS Configuration**
- **Audit Logging**
- **Input Validation**

## 🎨 **Customization**

### Theming the Admin Interface

```css
:root {
  --primary-color: #your-brand-color;
  --secondary-color: #your-secondary-color;
  --logo-url: url('/your-logo.png');
}
```

### Custom OAuth Providers

```python
# Add custom OAuth providers
class CustomOAuthProvider:
    name = 'custom'
    client_id = 'your-client-id'
    client_secret = 'your-client-secret'
    # ... implementation
```

## 📊 **Monitoring**

### Health Checks

```http
GET /health
```

### Metrics

- **User registration rates**
- **Login success/failure rates**
- **OAuth provider usage**
- **API response times**

## 🚀 **Deployment**

### Production Checklist

- [ ] **Change default secrets**
- [ ] **Configure HTTPS**
- [ ] **Set up monitoring**
- [ ] **Configure backups**
- [ ] **Set up logging**
- [ ] **Configure OAuth providers**

### Environment-Specific Configs

```bash
# Development
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up

# Production
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up
```

## 🤝 **Contributing**

1. **Fork the repository**
2. **Create a feature branch**
3. **Make your changes**
4. **Add tests**
5. **Submit a pull request**

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 **Support**

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/your-org/auth-service/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/auth-service/discussions)

## 🎯 **Roadmap**

- [ ] **Multi-factor Authentication (MFA)**
- [ ] **Single Sign-On (SSO)**
- [ ] **Advanced Role-Based Access Control**
- [ ] **API Key Management**
- [ ] **Webhook System**
- [ ] **Mobile SDKs**

---

**Get started in minutes, not months!** 🚀

# The end.
