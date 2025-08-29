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
from .utils import success_response, error_response, format_user_response, validate_required_fields, validate_email_format

# Create user blueprint
user_bp = Blueprint('user', __name__, url_prefix='/api/v1/auth')


@user_bp.route('/login', methods=['POST'])
def login():
    """User login endpoint."""
    data = request.get_json()

    # Validate required fields
    is_valid, error_msg = validate_required_fields(data, ['username', 'password'])
    if not is_valid:
        return error_response(error_msg, 400)

    user = User.query.filter_by(username=data['username']).first()

    if user and user.check_password(data['password']) and user.is_active:
        # Check if non-admin user login is allowed
        if not user.is_admin:
            if not is_user_login_allowed():
                return error_response('User login is currently disabled', 403)
        
        # Create JWT token
        access_token = create_access_token(identity=user.username)

        # Get JTI from the token
        token_data = decode_token(access_token)
        jti = token_data['jti']

        # Create session record
        create_jwt_session(jti, user.id, 'password')

        return success_response(
            'Login successful',
            {
                'access_token': access_token,
                'user': format_user_response(user)
            }
        )
    else:
        return error_response('Invalid credentials', 401)


@user_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """User logout endpoint."""
    expire_jwt_session(request.get_json()["jti"])
    return success_response('Successfully logged out')


@user_bp.route('/register', methods=['POST'])
def self_register():
    """Allow new users to register themselves."""
    # Check if registration is allowed
    if not is_registration_allowed():
        return error_response('User registration is currently disabled', 403)
    
    data = request.get_json()

    # Validate required fields
    is_valid, error_msg = validate_required_fields(data, ['username', 'email', 'password'])
    if not is_valid:
        return error_response(error_msg, 400)

    # Check if user already exists
    if User.query.filter_by(username=data['username']).first():
        return error_response('Username already exists', 400)

    if User.query.filter_by(email=data['email']).first():
        return error_response('Email already exists', 400)

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

        return success_response(
            'User registered successfully',
            {
                'access_token': access_token,
                'user': format_user_response(new_user)
            },
            201
        )
    except Exception as e:
        db.session.rollback()
        return error_response('Failed to create user', 500)





@user_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current user information."""
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()

    if not user:
        return error_response('User not found', 404)

    return success_response(
        'User information retrieved successfully',
        {'user': format_user_response(user)}
    )


@user_bp.route('/account', methods=['GET'])
@jwt_required()
def get_user_account():
    """Get user account information including OAuth accounts."""
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()

    if not user:
        return error_response('User not found', 404)

    # Get OAuth accounts
    oauth_accounts = []
    for oauth_account in user.oauth_accounts:
        oauth_accounts.append({
            'id': oauth_account.id,
            'provider': oauth_account.provider.name,
            'provider_user_id': oauth_account.provider_user_id,
            'created_at': oauth_account.created_at.isoformat()
        })

    # Get GSSAPI accounts
    gssapi_accounts = []
    for gssapi_account in user.gssapi_accounts:
        gssapi_accounts.append({
            'id': gssapi_account.id,
            'realm': gssapi_account.realm.name,
            'realm_display_name': gssapi_account.realm.name,  # You might want to add display_name to GSSAPIRealm
            'principal_name': gssapi_account.principal_name,
            'created_at': gssapi_account.created_at.isoformat()
        })

    return success_response(
        'User account information retrieved successfully',
        {
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin,
                'oauth_accounts': oauth_accounts,
                'gssapi_accounts': gssapi_accounts
            }
        }
    )


@user_bp.route('/account', methods=['PUT'])
@jwt_required()
def update_user_account():
    """Update user account information."""
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()

    if not user:
        return error_response('User not found', 404)

    data = request.get_json()

    if 'email' in data:
        # Validate email format
        if not validate_email_format(data['email']):
            return error_response('Invalid email format', 400)
        
        # Check if email is already taken by another user
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user and existing_user.id != user.id:
            return error_response('Email already exists', 400)
        user.email = data['email']

    if 'password' in data and data['password']:
        user.set_password(data['password'])

    try:
        db.session.commit()
        return success_response(
            'Account updated successfully',
            {'user': format_user_response(user)}
        )
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to update account: {str(e)}', 500)


@user_bp.route('/account/oauth/<int:oauth_account_id>', methods=['DELETE'])
@jwt_required()
def remove_oauth_account(oauth_account_id):
    """Remove OAuth account from user."""
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()

    if not user:
        return error_response('User not found', 404)

    # Find the OAuth account
    oauth_account = None
    for account in user.oauth_accounts:
        if account.id == oauth_account_id:
            oauth_account = account
            break

    if not oauth_account:
        return error_response('OAuth account not found', 404)

    # Delete the OAuth account
    try:
        db.session.delete(oauth_account)
        db.session.commit()
        return success_response('OAuth account removed successfully')
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to remove OAuth account: {str(e)}', 500)


@user_bp.route('/account/oauth/link/<provider>', methods=['GET'])
@jwt_required()
def link_oauth_account(provider):
    """Initiate OAuth account linking."""
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()

    if not user:
        return error_response('User not found', 404)

    # Check if user already has this provider connected
    for oauth_account in user.oauth_accounts:
        if oauth_account.provider.name == provider:
            return error_response(f'Already connected to {provider}', 400)

    # This would typically redirect to OAuth provider
    # For now, return a placeholder response
    return success_response(f'OAuth linking for {provider} would be initiated here')


@user_bp.route('/account/oauth/link/<provider>/callback', methods=['GET'])
@jwt_required()
def link_oauth_callback(provider):
    """Handle OAuth account linking callback."""
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()

    if not user:
        return error_response('User not found', 404)

    # This would handle the OAuth callback and link the account
    # For now, return a placeholder response
    return success_response(f'OAuth linking callback for {provider} would be handled here')


# The end.
