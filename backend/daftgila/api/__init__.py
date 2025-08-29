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

    return app


app = create_app()


# Routes

@app.route('/api/v1/register', methods=['POST'])
@jwt_required()
@admin_required
def register_user():
    data = request.get_json()
    
    # Validate required fields
    is_valid, error_msg = validate_required_fields(
        data, ['username', 'email', 'password']
    )
    if not is_valid:
        return error_response(error_msg, 400)
    
    # Validate field formats
    if not validate_username_format(data['username']):
        return error_response('Invalid username format. Use only letters, numbers, dots, underscores, and hyphens.', 400)
    
    if not validate_email_format(data['email']):
        return error_response('Invalid email format.', 400)
    
    # Check if user already exists
    if User.query.filter_by(username=data['username']).first():
        return error_response('Username already exists', 400)
    
    if User.query.filter_by(email=data['email']).first():
        return error_response('Email already exists', 400)
    
    # Create new user
    new_user = User(
        username=data['username'],
        email=data['email'],
        is_admin=data.get('is_admin', False)
    )
    new_user.set_password(data['password'])
    
    try:
        db.session.add(new_user)
        db.session.commit()
        
        return success_response(
            'User created successfully',
            {'user': format_user_response(new_user)},
            201
        )
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to create user: {str(e)}', 500)


@app.route('/api/v1/users', methods=['GET'])
@jwt_required()
@admin_required
def get_users():
    try:
        users = User.query.all()
        return success_response(
            'Users retrieved successfully',
            {'users': [format_user_response(user) for user in users]}
        )
    except Exception as e:
        return error_response(f'Failed to retrieve users: {str(e)}', 500)


@app.route('/api/v1/users/<int:user_id>', methods=['PUT'])
@jwt_required()
@admin_required
def update_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return error_response('User not found', 404)
    
    data = request.get_json()
    if not data:
        return error_response('Request data is required', 400)
    
    # Update email if provided
    if 'email' in data:
        if not validate_email_format(data['email']):
            return error_response('Invalid email format.', 400)
        
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user and existing_user.id != user_id:
            return error_response('Email already exists', 400)
        user.email = data['email']
    
    # Update other fields
    if 'is_admin' in data:
        user.is_admin = data['is_admin']
    
    if 'is_active' in data:
        user.is_active = data['is_active']
    
    if 'password' in data and data['password']:
        user.set_password(data['password'])
    
    try:
        db.session.commit()
        return success_response(
            'User updated successfully',
            {'user': format_user_response(user)}
        )
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to update user: {str(e)}', 500)


@app.route('/api/v1/test', methods=['GET'])
def test():
    return success_response('Backend is working')


@app.route('/api/v1/hello', methods=['GET'])
@jwt_required()
def hello():
    try:
        current_user = get_current_user()
        if not current_user:
            return error_response('User not found', 404)
        
        return success_response('hello world')
    except Exception as e:
        return error_response(f'Internal server error: {str(e)}', 500)


# Admin OAuth Management Routes
@app.route('/api/v1/users/<int:user_id>/oauth-accounts', methods=['GET'])
@jwt_required()
@admin_required
def get_user_oauth_accounts(user_id):
    """Get OAuth accounts for a specific user (admin only)"""
    user = User.query.get(user_id)
    if not user:
        return error_response('User not found', 404)
    
    oauth_accounts = []
    for oauth_account in user.oauth_accounts:
        oauth_accounts.append({
            'id': oauth_account.id,
            'provider': oauth_account.provider.name,
            'provider_user_id': oauth_account.provider_user_id,
            'connected_at': oauth_account.created_at.isoformat() if oauth_account.created_at else None
        })
    
    return success_response(
        'OAuth accounts retrieved successfully',
        {
            'user_id': user.id,
            'username': user.username,
            'oauth_accounts': oauth_accounts
        }
    )


@app.route('/api/v1/users/<int:user_id>/oauth-accounts/<int:oauth_account_id>', methods=['DELETE'])
@jwt_required()
@admin_required
def admin_remove_user_oauth_account(user_id, oauth_account_id):
    """Remove OAuth account from a user (admin only)"""
    user = User.query.get(user_id)
    if not user:
        return error_response('User not found', 404)
    
    oauth_account = OAuthAccount.query.filter_by(
        id=oauth_account_id, user_id=user.id
    ).first()
    
    if not oauth_account:
        return error_response('OAuth account not found', 404)
    
    # Check if user would be left without any authentication method
    if not user.password_hash and len(user.oauth_accounts) <= 1:
        return error_response(
            'Cannot remove OAuth account. User must have at least one authentication method.',
            400
        )
    
    try:
        db.session.delete(oauth_account)
        db.session.commit()
        return success_response('OAuth account removed successfully')
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to remove OAuth account: {str(e)}', 500)


# OAuth Provider Management Routes (Admin Only)
@app.route('/api/v1/admin/oauth-providers', methods=['GET'])
@jwt_required()
@admin_required
def get_oauth_providers_admin():
    """Get all OAuth providers (admin only)"""
    try:
        providers = OAuthProvider.query.all()
        return success_response(
            'OAuth providers retrieved successfully',
            {'providers': [format_oauth_provider_response(provider) for provider in providers]}
        )
    except Exception as e:
        return error_response(f'Failed to retrieve OAuth providers: {str(e)}', 500)


@app.route('/api/v1/admin/oauth-providers', methods=['POST'])
@jwt_required()
@admin_required
def create_oauth_provider():
    """Create new OAuth provider (admin only)"""
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['name', 'client_id', 'client_secret', 'authorize_url', 'token_url', 'userinfo_url', 'scope']
    is_valid, error_msg = validate_required_fields(data, required_fields)
    if not is_valid:
        return error_response(error_msg, 400)
    
    # Check if provider name already exists
    if OAuthProvider.query.filter_by(name=data['name']).first():
        return error_response('Provider name already exists', 400)
    
    # Create new provider
    new_provider = OAuthProvider(
        name=data['name'],
        client_id=data['client_id'],
        client_secret=data['client_secret'],
        authorize_url=data['authorize_url'],
        token_url=data['token_url'],
        userinfo_url=data['userinfo_url'],
        scope=data['scope'],
        is_active=data.get('is_active', True)
    )
    
    try:
        db.session.add(new_provider)
        db.session.commit()
        
        return success_response(
            'OAuth provider created successfully',
            {'provider': format_oauth_provider_response(new_provider)},
            201
        )
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to create provider: {str(e)}', 500)


@app.route('/api/v1/admin/oauth-providers/<int:provider_id>', methods=['PUT'])
@jwt_required()
@admin_required
def update_oauth_provider(provider_id):
    """Update OAuth provider (admin only)"""
    provider = OAuthProvider.query.get(provider_id)
    if not provider:
        return error_response('OAuth provider not found', 404)
    
    data = request.get_json()
    if not data:
        return error_response('Request data is required', 400)
    
    # Update fields if provided
    if 'name' in data:
        # Check if new name conflicts with existing provider
        existing_provider = OAuthProvider.query.filter_by(name=data['name']).first()
        if existing_provider and existing_provider.id != provider_id:
            return error_response('Provider name already exists', 400)
        provider.name = data['name']
    
    if 'client_id' in data:
        provider.client_id = data['client_id']
    
    if 'client_secret' in data and data['client_secret']:
        provider.client_secret = data['client_secret']
    
    if 'authorize_url' in data:
        provider.authorize_url = data['authorize_url']
    
    if 'token_url' in data:
        provider.token_url = data['token_url']
    
    if 'userinfo_url' in data:
        provider.userinfo_url = data['userinfo_url']
    
    if 'scope' in data:
        provider.scope = data['scope']
    
    if 'is_active' in data:
        provider.is_active = data['is_active']
    
    try:
        db.session.commit()
        
        return success_response(
            'OAuth provider updated successfully',
            {'provider': format_oauth_provider_response(provider)}
        )
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to update provider: {str(e)}', 500)


@app.route('/api/v1/admin/oauth-providers/<int:provider_id>', methods=['DELETE'])
@jwt_required()
@admin_required
def delete_oauth_provider(provider_id):
    """Delete OAuth provider (admin only)"""
    provider = OAuthProvider.query.get(provider_id)
    if not provider:
        return error_response('OAuth provider not found', 404)
    
    # Check if provider has connected accounts
    connected_accounts = OAuthAccount.query.filter_by(provider_id=provider_id).count()
    if connected_accounts > 0:
        return error_response(
            f'Cannot delete provider. {connected_accounts} user(s) have connected accounts.',
            400
        )
    
    try:
        db.session.delete(provider)
        db.session.commit()
        
        return success_response('OAuth provider deleted successfully')
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to delete provider: {str(e)}', 500)


# The end.
