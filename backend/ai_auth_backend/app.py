"""
Main Flask application factory for the AI Auth Backend.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Cursor AI (Claude Sonnet 4)
"""

import os
from flask import Flask
from flask_jwt_extended import JWTManager
from .auth_engine import AuthEngine, AuthConfig
from .models import db, User, OAuthProvider, OAuthAccount, JWTSession


def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Basic configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
        'DATABASE_URL',
        'postgresql://auth_user:auth_password@localhost:5432/auth_demo'
    )
    
    # Initialize extensions
    db.init_app(app)
    
    jwt = JWTManager()
    jwt.init_app(app)
    
    # Configure models for auth engine
    app.user_model = User
    app.oauth_provider_model = OAuthProvider
    app.oauth_account_model = OAuthAccount
    app.session_model = JWTSession
    
    # Set database instance for the auth engine
    app.db = db
    
    # Initialize auth engine
    auth_config = AuthConfig({
        'providers': ['password', 'oauth_google', 'oauth_github'],
        'session_store': 'redis',
        'jwt_expiry': '1h',
        'enable_admin': True,
        'enable_oauth': True,
        'enable_session_tracking': True,
        'permissions': ['read', 'write', 'admin']
    })
    
    auth_engine = AuthEngine(app, auth_config)
    app.auth_engine = auth_engine
    
    # Add /me endpoint for frontend session validation
    @app.route('/api/v1/me', methods=['GET'])
    @auth_engine.require_auth()
    def get_current_user():
        """Get current user information for frontend session validation."""
        try:
            user = auth_engine.get_current_user()
            
            if not user:
                return {'error': 'User not found'}, 404
            
            return {
                'user': auth_engine.services['user'].serialize_user(user)
            }, 200
        except Exception:
            return {'error': 'Failed to get user info'}, 500
    
    return app


# Don't create the app instance during import
# This will be created when needed

# The end.
