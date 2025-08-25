"""
Migration script to transition from monolithic auth to Auth Engine.

This script helps migrate existing applications to use the new Auth Engine.
"""

import os
import sys
from pathlib import Path


def create_migration_guide():
    """Create a migration guide for users."""
    guide = """
# Migration Guide: From Monolithic Auth to Auth Engine

## Overview

This guide helps you migrate from the old monolithic authentication system to the new modular Auth Engine.

## Step 1: Update Dependencies

Add the auth engine to your requirements:

```bash
pip install -e .
```

## Step 2: Update Your Flask App

### Old Structure (app/__init__.py)
```python
# Old monolithic approach
from app.model import db, User
from app.jwt import configure_jwt
from app.oauth import oauth_bp

def create_app():
    app = Flask(__name__)
    db.init_app(app)
    configure_jwt(app)
    app.register_blueprint(oauth_bp)
    # ... lots of route definitions
    return app
```

### New Structure (app_new.py)
```python
# New modular approach
from auth_engine import AuthEngine, AuthConfig
from auth_engine.models import User, OAuthProvider, OAuthAccount, JWTSession

def create_app():
    app = Flask(__name__)
    
    # Configure auth engine
    auth_config = AuthConfig({
        'providers': ['password', 'oauth_google', 'oauth_github'],
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
    
    return app
```

## Step 3: Update Route Decorators

### Old Approach
```python
from app.jwt import jwt_required

@app.route('/protected')
@jwt_required()
def protected_route():
    # Get user manually
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()
    return {'message': 'Protected!'}
```

### New Approach
```python
@app.route('/protected')
@auth_engine.require_auth()
def protected_route():
    # User is automatically available
    return {'message': 'Protected!'}

@app.route('/admin')
@auth_engine.require_auth('admin')
def admin_route():
    return {'message': 'Admin only!'}
```

## Step 4: Update Service Calls

### Old Approach
```python
# Direct database queries everywhere
user = User.query.filter_by(username=username).first()
if user and user.check_password(password):
    # Create JWT manually
    access_token = create_access_token(identity=user.username)
```

### New Approach
```python
# Use service layer
auth_service = app.auth_services['auth']
result = auth_service.authenticate_with_password(username, password)
# Returns {'access_token': token, 'user': user_data}
```

## Step 5: Update Configuration

### Old Approach
```python
# Hardcoded configuration scattered across files
app.config['JWT_SECRET_KEY'] = 'hardcoded-secret'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
```

### New Approach
```python
# Centralized configuration
auth_config = AuthConfig({
    'jwt_secret_key': os.getenv('JWT_SECRET_KEY'),
    'jwt_expiry': '1h',
    'providers': ['password', 'oauth_google'],
    'enable_admin': True
})
```

## Step 6: Update Model Usage

### Old Approach
```python
# Direct model imports and usage
from app.model import User, OAuthProvider, OAuthAccount

user = User.query.get(user_id)
oauth_accounts = user.oauth_accounts
```

### New Approach
```python
# Use service layer
user_service = app.auth_services['user']
user = user_service.get_user_by_id(user_id)
oauth_accounts = user_service.get_user_oauth_accounts(user_id)
```

## Step 7: Update Error Handling

### Old Approach
```python
# Manual error handling
if not user:
    return jsonify({'error': 'User not found'}), 404
if not user.is_admin:
    return jsonify({'error': 'Admin required'}), 403
```

### New Approach
```python
# Automatic error handling with decorators
@app.route('/admin')
@auth_engine.require_auth('admin')
def admin_route():
    # Errors handled automatically
    return {'message': 'Admin only!'}
```

## Step 8: Update API Endpoints

The Auth Engine provides all the same endpoints as the old system:

- `/api/v1/auth/login` - Password login
- `/api/v1/auth/logout` - Logout
- `/api/v1/auth/register` - User registration
- `/api/v1/auth/me` - Get current user
- `/api/v1/auth/oauth/*` - OAuth endpoints
- `/api/v1/admin/*` - Admin endpoints

## Step 9: Test Migration

1. Run your existing tests
2. Test all authentication flows
3. Verify OAuth still works
4. Check admin functionality
5. Test session management

## Benefits of Migration

- **Modularity**: Easy to extend and customize
- **Configuration**: Centralized, environment-driven config
- **Service Layer**: Clean separation of concerns
- **Type Safety**: Better IDE support and error catching
- **Reusability**: Can be used in multiple applications
- **Maintainability**: Easier to test and debug

## Troubleshooting

### Common Issues

1. **Import Errors**: Make sure auth_engine is installed
2. **Model Conflicts**: Ensure model names don't conflict
3. **Configuration**: Check all required config values
4. **Database**: Verify database schema matches expectations

### Getting Help

- Check the Auth Engine README
- Review the example in `app_new.py`
- Check the API documentation
- Look at the test files for usage examples

## Rollback Plan

If you need to rollback:

1. Keep your old `app/` directory as backup
2. Update your Dockerfile to use the old app.py
3. Revert any database schema changes
4. Test thoroughly before deploying

# The end.
"""
    
    with open('MIGRATION_GUIDE.md', 'w') as f:
        f.write(guide)
    
    print("Migration guide created: MIGRATION_GUIDE.md")


def create_comparison_table():
    """Create a comparison table between old and new approaches."""
    comparison = """
# Old vs New Authentication System Comparison

## Architecture

| Aspect | Old System | New Auth Engine |
|--------|------------|-----------------|
| Structure | Monolithic (656-line __init__.py) | Modular (separate modules) |
| Configuration | Scattered across files | Centralized AuthConfig |
| Models | Direct SQLAlchemy usage | Abstract interfaces + concrete implementations |
| Services | Inline database queries | Service layer abstraction |
| Providers | Hardcoded OAuth logic | Plugin-based provider system |
| Middleware | Manual JWT handling | Decorator-based middleware |
| Error Handling | Manual in each route | Automatic with decorators |
| Testing | Hard to test | Service layer easily testable |
| Reusability | Application-specific | Framework-agnostic |
| Extensibility | Requires code changes | Plugin architecture |

## Code Examples

### Authentication

**Old:**
```python
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and user.check_password(data['password']):
        access_token = create_access_token(identity=user.username)
        # Manual session creation...
        return jsonify({'access_token': access_token})
    return jsonify({'error': 'Invalid credentials'}), 401
```

**New:**
```python
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    result = auth_service.authenticate_with_password(
        data['username'], data['password']
    )
    return jsonify(result)
```

### Protected Routes

**Old:**
```python
@app.route('/protected')
@jwt_required()
def protected():
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'message': 'Protected'})
```

**New:**
```python
@app.route('/protected')
@auth_engine.require_auth()
def protected():
    return jsonify({'message': 'Protected'})
```

### Admin Routes

**Old:**
```python
@app.route('/admin/users')
@jwt_required()
def get_users():
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()
    if not user or not user.is_admin:
        return jsonify({'error': 'Admin required'}), 403
    users = User.query.all()
    return jsonify({'users': [serialize_user(u) for u in users]})
```

**New:**
```python
@app.route('/admin/users')
@auth_engine.require_auth('admin')
def get_users():
    users = user_service.get_all_users()
    return jsonify({'users': [user_service.serialize_user(u) for u in users]})
```

## Configuration

**Old:**
```python
# Scattered across multiple files
app.config['JWT_SECRET_KEY'] = 'hardcoded-secret'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://...'
# ... many more config lines
```

**New:**
```python
# Centralized configuration
auth_config = AuthConfig({
    'providers': ['password', 'oauth_google'],
    'session_store': 'redis',
    'jwt_expiry': '1h',
    'enable_admin': True,
    'enable_oauth': True
})
```

## Benefits Summary

### For Developers
- **Cleaner Code**: Less boilerplate, more readable
- **Better Testing**: Service layer easily mockable
- **Type Safety**: Better IDE support and error catching
- **Modularity**: Easy to extend and customize

### For Applications
- **Reusability**: Can be used across multiple projects
- **Maintainability**: Easier to debug and update
- **Scalability**: Better separation of concerns
- **Security**: Centralized security logic

### For Operations
- **Configuration**: Environment-driven configuration
- **Monitoring**: Better session tracking and logging
- **Deployment**: Easier to deploy and manage
- **Documentation**: Comprehensive API documentation

# The end.
"""
    
    with open('COMPARISON.md', 'w') as f:
        f.write(comparison)
    
    print("Comparison table created: COMPARISON.md")


def main():
    """Main migration script."""
    print("Auth Engine Migration Tools")
    print("==========================")
    print()
    
    create_migration_guide()
    create_comparison_table()
    
    print()
    print("Migration files created successfully!")
    print("Next steps:")
    print("1. Review MIGRATION_GUIDE.md")
    print("2. Review COMPARISON.md")
    print("3. Update your application to use the Auth Engine")
    print("4. Test thoroughly before deploying")


if __name__ == '__main__':
    main()

# The end.
