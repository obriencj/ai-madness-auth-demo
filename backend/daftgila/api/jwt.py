"""
JWT session management for the Auth Demo application.

This module handles JWT token creation, validation, and session management.
It provides endpoints for JWT operations and integrates with Redis for
token blacklisting and session tracking.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import os
from datetime import datetime, timedelta
from flask import request, Blueprint
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity,
    get_jwt, verify_jwt_in_request
)
from .model import db, JWTSession, User
from .utils import success_response, error_response, get_current_user
from .audit import log_session_action, AuditActions

# Create JWT blueprint
jwt_bp = Blueprint('jwt', __name__, url_prefix='/api/v1/jwt')

# Initialize JWT manager
jwt = JWTManager()


def configure_jwt(app):
    """Configure JWT settings for the application."""
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
    app.config['JWT_TOKEN_LOCATION'] = ['headers']
    app.config['JWT_HEADER_NAME'] = 'Authorization'
    app.config['JWT_HEADER_TYPE'] = 'Bearer'
    
    # Initialize JWT with the app
    jwt.init_app(app)
    
    # Register JWT error handlers
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return error_response('Token has expired', 401)
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return error_response('Invalid token', 401)
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return error_response('Missing authorization token', 401)


def create_jwt_session(jti, user_id, auth_method):
    """Create a new JWT session record."""
    try:
        # Get client IP and user agent
        ip_address = _get_client_ip()
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # Calculate expiration time (1 hour from now, matching JWT token expiration)
        expires_at = datetime.utcnow() + timedelta(hours=1)
        
        # Create session record
        session = JWTSession(
            jti=jti,
            user_id=user_id,
            auth_method=auth_method,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expires_at
        )
        
        db.session.add(session)
        db.session.commit()
        
        return session
    except Exception as e:
        db.session.rollback()
        return None


def expire_jwt_session(jti):
    """Expire a JWT session by setting it as inactive."""
    try:
        session = JWTSession.query.filter_by(jti=jti, is_active=True).first()
        if session:
            session.is_active = False
            db.session.commit()
            return True
        return False
    except Exception as e:
        db.session.rollback()
        return False


def _get_client_ip():
    """Get the client's IP address from request headers."""
    # Check for forwarded headers first (for proxy setups)
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr


# JWT Blueprint Routes

@jwt_bp.route('/validate', methods=['GET'])
@jwt_required()
def validate_token():
    """Validate the current JWT token."""
    try:
        current_user = get_current_user()
        if not current_user:
            return error_response('User not found', 404)
        
        return success_response(
            'Token is valid',
            {'user': {
                'id': current_user.id,
                'username': current_user.username,
                'email': current_user.email,
                'is_admin': current_user.is_admin
            }}
        )
    except Exception as e:
        return error_response(f'Token validation failed: {str(e)}', 500)


@jwt_bp.route('/refresh', methods=['POST'])
@jwt_required()
def refresh_token():
    """Refresh the current JWT token."""
    try:
        current_user = get_current_user()
        if not current_user:
            return error_response('User not found', 404)
        
        # Create new access token
        new_access_token = create_access_token(identity=current_user.username)
        
        # Get JTI from the new token
        from flask_jwt_extended import decode_token
        token_data = decode_token(new_access_token)
        jti = token_data['jti']
        
        # Create new session record
        new_session = create_jwt_session(jti, current_user.id, 'refresh')
        
        if new_session:
            return success_response(
                'Token refreshed successfully',
                {
                    'access_token': new_access_token,
                    'user': {
                        'id': current_user.id,
                        'username': current_user.username,
                        'email': current_user.email,
                        'is_admin': current_user.is_admin
                    }
                }
            )
        else:
            return error_response('Failed to create session record', 500)
    except Exception as e:
        return error_response(f'Token refresh failed: {str(e)}', 500)


@jwt_bp.route('/sessions', methods=['GET'])
@jwt_required()
def get_user_sessions():
    """Get all active sessions for the current user."""
    try:
        current_user = get_current_user()
        if not current_user:
            return error_response('User not found', 404)
        
        # Get active sessions for the user
        sessions = JWTSession.query.filter_by(
            user_id=current_user.id, 
            is_active=True
        ).all()
        
        session_data = []
        for session in sessions:
            session_data.append({
                'id': session.id,
                'jti': session.jti,
                'auth_method': session.auth_method,
                'ip_address': session.ip_address,
                'user_agent': session.user_agent,
                'created_at': session.created_at.isoformat() if session.created_at else None,
                'expires_at': session.expires_at.isoformat() if session.expires_at else None,
                'last_activity_at': session.last_activity_at.isoformat() if session.last_activity_at else None
            })
        
        return success_response(
            'User sessions retrieved successfully',
            {'sessions': session_data}
        )
    except Exception as e:
        return error_response(f'Failed to retrieve sessions: {str(e)}', 500)


@jwt_bp.route('/sessions/<int:session_id>', methods=['DELETE'])
@jwt_required()
def expire_user_session(session_id):
    """Expire a specific session for the current user."""
    try:
        current_user = get_current_user()
        if not current_user:
            return error_response('User not found', 404)
        
        # Find the session
        session = JWTSession.query.filter_by(
            id=session_id,
            user_id=current_user.id,
            is_active=True
        ).first()
        
        if not session:
            return error_response('Session not found', 404)
        
        # Expire the session
        session.is_active = False
        db.session.commit()
        
        # Log the action
        log_session_action(
            user_id=current_user.id,
            action=AuditActions.SESSION_EXPIRED,
            session_id=session.id,
            details={'jti': session.jti, 'auth_method': session.auth_method}
        )
        
        return success_response('Session expired successfully')
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to expire session: {str(e)}', 500)


@jwt_bp.route('/sessions/expire-all', methods=['POST'])
@jwt_required()
def expire_all_user_sessions():
    """Expire all active sessions for the current user."""
    try:
        current_user = get_current_user()
        if not current_user:
            return error_response('User not found', 404)
        
        # Get all active sessions for the user
        active_sessions = JWTSession.query.filter_by(
            user_id=current_user.id,
            is_active=True
        ).all()
        
        session_count = len(active_sessions)
        
        # Expire all sessions
        for session in active_sessions:
            session.is_active = False
        
        db.session.commit()
        
        # Log the action
        log_session_action(
            user_id=current_user.id,
            action=AuditActions.SESSION_EXPIRED_ALL,
            details={'sessions_expired': session_count}
        )
        
        return success_response(f'{session_count} sessions expired successfully')
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to expire sessions: {str(e)}', 500)


# The end.
