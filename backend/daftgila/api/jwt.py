"""
JWT and Redis configuration for the Auth Demo application.

This module handles JWT token management, Redis connection for token blacklisting,
and JWT error handling.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import os
import redis
from datetime import timedelta, datetime
from flask import request, jsonify, Blueprint
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity, get_jwt
)
from .model import db, User, JWTSession
from .utils import admin_required, success_response, error_response


# Initialize JWT manager (will be configured in app.py)
jwt = JWTManager()

# Redis connection for JWT token blacklisting
redis_client = redis.from_url(
    os.getenv('REDIS_URL', 'redis://localhost:6379')
)

# Create JWT blueprint
jwt_bp = Blueprint('jwt', __name__, url_prefix='/api/v1/admin')


def create_jwt_session(jti, user_id, auth_method, expires_in=None):
    """Create a JWT session record in the database."""
    if expires_in is None:
        expires_in = timedelta(hours=1)

    expires_at = datetime.utcnow() + expires_in

    session = JWTSession(
        jti=jti,
        user_id=user_id,
        auth_method=auth_method,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        expires_at=expires_at
    )

    db.session.add(session)
    db.session.commit()
    return session


def expire_jwt_session(jti):
    blacklist_token(jti, timedelta(hours=1))

    # Mark session as inactive
    session = JWTSession.query.filter_by(jti=jti).first()
    if session:
        session.is_active = False
        db.session.commit()


def get_client_ip():
    """Get the client's IP address, handling proxy headers."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr


def configure_jwt(app):
    """Configure JWT settings for the Flask application."""
    app.config['JWT_SECRET_KEY'] = os.getenv(
        'JWT_SECRET_KEY',
        'your-super-secret-jwt-key-change-in-production'
    )
    
    # Get JWT lifetime from configuration, default to 1 hour
    try:
        from .config import get_jwt_lifetime_hours
        jwt_lifetime = get_jwt_lifetime_hours()
        app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=jwt_lifetime)
    except:
        # Fallback to default if config service is not available
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
        print(f"Error checking token blocklist: {e}")
        return False


# JWT Session Management Routes (Admin Only)
@jwt_bp.route('/sessions', methods=['GET'])
@jwt_required()
@admin_required
def get_active_sessions():
    """Get all active JWT sessions (admin only)"""
    try:
        # Get active sessions that haven't expired
        active_sessions = JWTSession.query.filter(
            JWTSession.is_active == True,
            JWTSession.expires_at > datetime.utcnow()
        ).order_by(JWTSession.created_at.desc()).all()

        sessions_data = []
        for session in active_sessions:
            sessions_data.append({
                'id': session.id,
                'jti': session.jti,
                'user_id': session.user_id,
                'username': session.user.username,
                'email': session.user.email,
                'auth_method': session.auth_method,
                'auth_method_display': session.auth_method_display,
                'ip_address': session.ip_address,
                'user_agent': session.user_agent,
                'created_at': session.created_at.isoformat(),
                'expires_at': session.expires_at.isoformat(),
                'is_expired': session.is_expired
            })

        return success_response(
            'Active sessions retrieved successfully',
            {
                'sessions': sessions_data,
                'total': len(sessions_data)
            }
        )
    except Exception as e:
        return error_response(f'Failed to retrieve sessions: {str(e)}', 500)


@jwt_bp.route('/sessions/<int:session_id>/expire', methods=['POST'])
@jwt_required()
@admin_required
def expire_session(session_id):
    """Force expire a JWT session (admin only)"""
    try:
        session = JWTSession.query.get(session_id)
        if not session:
            return error_response('Session not found', 404)

        # Mark session as inactive
        session.is_active = False
        db.session.commit()

        # Add token to blacklist
        blacklist_token(session.jti, timedelta(hours=1))

        return success_response(
            'Session expired successfully',
            {'session_id': session_id}
        )
    except Exception as e:
        return error_response(f'Failed to expire session: {str(e)}', 500)


@jwt_bp.route('/sessions/expire-all', methods=['POST'])
@jwt_required()
@admin_required
def expire_all_sessions():
    """Expire all active JWT sessions (admin only)"""
    try:
        # Get all active sessions
        active_sessions = JWTSession.query.filter(
            JWTSession.is_active == True,
            JWTSession.expires_at > datetime.utcnow()
        ).all()

        expired_count = 0
        for session in active_sessions:
            session.is_active = False
            # Add token to blacklist
            blacklist_token(session.jti, timedelta(hours=1))
            expired_count += 1

        db.session.commit()

        return success_response(
            f'Successfully expired {expired_count} sessions',
            {'expired_count': expired_count}
        )
    except Exception as e:
        return error_response(f'Failed to expire all sessions: {str(e)}', 500)


# The end.
