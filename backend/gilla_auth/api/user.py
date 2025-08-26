"""
User authentication and self-management endpoints for the Auth Demo application.
This module handles user authentication, registration, and account management.


Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token, decode_token
from .model import db, User
from .jwt import expire_jwt_session, create_jwt_session
from .config import is_registration_allowed, is_user_login_allowed

# Create user blueprint
user_bp = Blueprint('user', __name__, url_prefix='/api/v1/auth')


@user_bp.route('/login', methods=['POST'])
def login():
    """User login endpoint."""
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing username or password'}), 400

    user = User.query.filter_by(username=data['username']).first()

    if user and user.check_password(data['password']) and user.is_active:
        # Check if non-admin user login is allowed
        if not user.is_admin:
            if not is_user_login_allowed():
                return jsonify({'error': 'User login is currently disabled'}), 403
        
        # Create JWT token
        access_token = create_access_token(identity=user.username)

        # Get JTI from the token
        token_data = decode_token(access_token)
        jti = token_data['jti']

        # Create session record
        create_jwt_session(jti, user.id, 'password')

        return jsonify({
            'access_token': access_token,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin
            }
        }), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401


@user_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """User logout endpoint."""
    expire_jwt_session(request.get_json()["jti"])
    return jsonify({'message': 'Successfully logged out'}), 200


@user_bp.route('/register', methods=['POST'])
def self_register():
    """Allow new users to register themselves."""
    # Check if registration is allowed
    if not is_registration_allowed():
        return jsonify({'error': 'User registration is currently disabled'}), 403
    
    data = request.get_json()

    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing required fields'}), 400

    # Check if user already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400

    # Create new user (non-admin by default)
    new_user = User(
        username=data['username'],
        email=data['email'],
        is_admin=False
    )
    new_user.set_password(data['password'])

    try:
        db.session.add(new_user)
        db.session.commit()

        # Create JWT token for immediate login
        access_token = create_access_token(identity=new_user.username)

        # Get JTI from the token
        token_data = decode_token(access_token)
        jti = token_data['jti']

        # Create session record
        create_jwt_session(jti, new_user.id, 'password')

        return jsonify({
            'message': 'User registered successfully',
            'access_token': access_token,
            'user': {
                'id': new_user.id,
                'username': new_user.username,
                'email': new_user.email,
                'is_admin': new_user.is_admin
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to create user'}), 500





@user_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current user information."""
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_admin': user.is_admin
        }
    }), 200


@user_bp.route('/account', methods=['GET'])
@jwt_required()
def get_user_account():
    """Get user account information including OAuth accounts."""
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Get OAuth accounts
    oauth_accounts = []
    for oauth_account in user.oauth_accounts:
        oauth_accounts.append({
            'id': oauth_account.id,
            'provider': oauth_account.provider.name,
            'provider_user_id': oauth_account.provider_user_id,
            'created_at': oauth_account.created_at.isoformat()
        })

    return jsonify({
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_admin': user.is_admin,
            'oauth_accounts': oauth_accounts
        }
    }), 200


@user_bp.route('/account', methods=['PUT'])
@jwt_required()
def update_user_account():
    """Update user account information."""
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()

    if 'email' in data:
        # Check if email is already taken by another user
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user and existing_user.id != user.id:
            return jsonify({'error': 'Email already exists'}), 400
        user.email = data['email']

    if 'password' in data and data['password']:
        user.set_password(data['password'])

    db.session.commit()

    return jsonify({
        'message': 'Account updated successfully',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_admin': user.is_admin
        }
    }), 200


@user_bp.route('/account/oauth/<int:oauth_account_id>', methods=['DELETE'])
@jwt_required()
def remove_oauth_account(oauth_account_id):
    """Remove OAuth account from user."""
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Find the OAuth account
    oauth_account = None
    for account in user.oauth_accounts:
        if account.id == oauth_account_id:
            oauth_account = account
            break

    if not oauth_account:
        return jsonify({'error': 'OAuth account not found'}), 404

    # Delete the OAuth account
    db.session.delete(oauth_account)
    db.session.commit()

    return jsonify({
        'message': 'OAuth account removed successfully'
    }), 200


@user_bp.route('/account/oauth/link/<provider>', methods=['GET'])
@jwt_required()
def link_oauth_account(provider):
    """Initiate OAuth account linking."""
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Check if user already has this provider connected
    for oauth_account in user.oauth_accounts:
        if oauth_account.provider.name == provider:
            return jsonify({'error': f'Already connected to {provider}'}), 400

    # This would typically redirect to OAuth provider
    # For now, return a placeholder response
    return jsonify({
        'message': f'OAuth linking for {provider} would be initiated here'
    }), 200


@user_bp.route('/account/oauth/link/<provider>/callback', methods=['GET'])
@jwt_required()
def link_oauth_callback(provider):
    """Handle OAuth account linking callback."""
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # This would handle the OAuth callback and link the account
    # For now, return a placeholder response
    return jsonify({
        'message': f'OAuth linking callback for {provider} would be handled here'
    }), 200


# The end.
