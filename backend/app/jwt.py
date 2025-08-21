"""
JWT and Redis configuration for the Auth Demo application.

This module handles JWT token management, Redis connection for token blacklisting,
and JWT error handling.
"""

import os
import redis
from datetime import timedelta
from flask import jsonify
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity, get_jwt
)


# Initialize JWT manager (will be configured in app.py)
jwt = JWTManager()

# Redis connection for JWT token blacklisting
redis_client = redis.from_url(
    os.getenv('REDIS_URL', 'redis://localhost:6379')
)


def configure_jwt(app):
    """Configure JWT settings for the Flask application."""
    app.config['JWT_SECRET_KEY'] = os.getenv(
        'JWT_SECRET_KEY',
        'your-super-secret-jwt-key-change-in-production'
    )
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
    app.config['JWT_ALGORITHM'] = 'HS256'
    app.config['JWT_TOKEN_LOCATION'] = ['headers']
    app.config['JWT_HEADER_NAME'] = 'Authorization'
    app.config['JWT_HEADER_TYPE'] = 'Bearer'
    
    # Initialize JWT with the app
    jwt.init_app(app)


# JWT token blocklist loader
@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, jwt_payload):
    """Check if JWT token is in blocklist (Redis)."""
    try:
        jti = jwt_payload.get("jti")
        if not jti:
            return False
        token_in_redis = redis_client.get(jti)
        return token_in_redis is not None
    except Exception as e:
        print(f"Error checking token blocklist: {e}")
        return False


# JWT error handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    """Handle expired JWT tokens."""
    print(f"JWT expired token callback: {jwt_payload}")
    return jsonify({'error': 'Token has expired'}), 401


@jwt.invalid_token_loader
def invalid_token_callback(error):
    """Handle invalid JWT tokens."""
    print(f"JWT invalid token callback: {error}")
    return jsonify({'error': 'Invalid token'}), 401


@jwt.unauthorized_loader
def missing_token_callback(error):
    """Handle missing JWT tokens."""
    print(f"JWT missing token callback: {error}")
    return jsonify({'error': 'Missing authorization token'}), 401


def blacklist_token(jti, expires_in=None):
    """Add a JWT token to the blacklist (Redis)."""
    if expires_in is None:
        expires_in = timedelta(hours=1)
    
    try:
        redis_client.setex(jti, expires_in, "true")
        return True
    except Exception as e:
        print(f"Error blacklisting token: {e}")
        return False


def is_token_blacklisted(jti):
    """Check if a JWT token is blacklisted."""
    try:
        return redis_client.get(jti) is not None
    except Exception as e:
        print(f"Error checking token blacklist: {e}")
        return False
