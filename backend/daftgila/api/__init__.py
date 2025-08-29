"""
Gilla Auth API Module

This module provides the main Flask application factory and API routes for the Gilla Auth system.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import os
from datetime import timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS

# Import models and database instances
from .model import db, User, OAuthProvider, OAuthAccount, GSSAPIRealm, GSSAPIAccount, JWTSession

# Import JWT functionality
from .jwt import (
    configure_jwt, expire_jwt_session,
    jwt_required, create_access_token, create_jwt_session,
    get_jwt_identity, get_jwt, jwt_bp
)

# Import blueprints
from .oauth import oauth_bp
from .gssapi import gssapi_bp
from .config import config_bp, public_config_bp
from .user import user_bp
from .admin import admin_bp

# Import utility functions
from .utils import (
    admin_required, get_current_user, validate_required_fields,
    validate_email_format, validate_username_format,
    format_user_response, format_oauth_provider_response,
    success_response, error_response
)


def create_app():
    app = Flask(__name__)

    # Configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
        'DATABASE_URL',
        'postgresql://auth_user:auth_password@localhost:5432/auth_demo'
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize extensions
    db.init_app(app)
    configure_jwt(app)  # Configure JWT settings
    CORS(app)

    # Register blueprints
    app.register_blueprint(oauth_bp)
    app.register_blueprint(gssapi_bp)
    app.register_blueprint(jwt_bp)
    app.register_blueprint(config_bp)
    app.register_blueprint(public_config_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(admin_bp)

    return app


app = create_app()


# Core API Routes (non-admin, non-blueprint)

@app.route('/api/v1/test', methods=['GET'])
def test():
    """Test endpoint to verify backend connectivity."""
    return success_response('Backend is working')


@app.route('/api/v1/hello', methods=['GET'])
@jwt_required()
def hello():
    """Protected hello endpoint for testing authentication."""
    try:
        current_user = get_current_user()
        if not current_user:
            return error_response('User not found', 404)
        
        return success_response('hello world')
    except Exception as e:
        return error_response(f'Internal server error: {str(e)}', 500)


# The end.
