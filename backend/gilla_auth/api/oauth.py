"""
OAuth login workflow for the Auth Demo application.

This module handles OAuth authentication flow, including:
- Provider configuration retrieval
- Token exchange with OAuth providers
- User information retrieval
- User creation and linking
- OAuth account management

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import requests
from flask import jsonify, session, request, Blueprint
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from .model import db, User, OAuthProvider, OAuthAccount


def get_oauth_provider_config(provider_name):
    """Get OAuth provider configuration from database"""
    provider = OAuthProvider.query.filter_by(
        name=provider_name, is_active=True
    ).first()
    if not provider:
        return None
    return {
        'client_id': provider.client_id,
        'client_secret': provider.client_secret,
        'authorize_url': provider.authorize_url,
        'token_url': provider.token_url,
        'userinfo_url': provider.userinfo_url,
        'scope': provider.scope
    }


def exchange_code_for_token(provider_name, code, redirect_uri):
    """Exchange authorization code for access token"""
    config = get_oauth_provider_config(provider_name)
    if not config:
        return None, "Provider not found or inactive"

    if provider_name == 'google':
        return _exchange_google_token(config, code, redirect_uri)
    elif provider_name == 'github':
        return _exchange_github_token(config, code, redirect_uri)
    else:
        return None, "Unsupported provider"


def _exchange_google_token(config, code, redirect_uri):
    """Exchange Google authorization code for token"""
    try:
        response = requests.post(config['token_url'], data={
            'client_id': config['client_id'],
            'client_secret': config['client_secret'],
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri
        })

        if response.status_code == 200:
            token_data = response.json()
            return token_data, None
        else:
            return None, f"Token exchange failed: {response.status_code}"
    except Exception as e:
        return None, f"Token exchange error: {str(e)}"


def _exchange_github_token(config, code, redirect_uri):
    """Exchange GitHub authorization code for token"""
    try:
        response = requests.post(config['token_url'], data={
            'client_id': config['client_id'],
            'client_secret': config['client_secret'],
            'code': code,
            'redirect_uri': redirect_uri
        }, headers={'Accept': 'application/json'})

        if response.status_code == 200:
            token_data = response.json()
            return token_data, None
        else:
            return None, f"Token exchange failed: {response.status_code}"
    except Exception as e:
        return None, f"Token exchange error: {str(e)}"


def get_user_info(provider_name, access_token):
    """Get user information from OAuth provider"""
    config = get_oauth_provider_config(provider_name)
    if not config:
        return None, "Provider not found or inactive"

    try:
        headers = {'Authorization': f'Bearer {access_token}'}
        if provider_name == 'github':
            headers['Accept'] = 'application/vnd.github.v3+json'

        response = requests.get(config['userinfo_url'], headers=headers)

        if response.status_code == 200:
            return response.json(), None
        else:
            return None, f"Failed to get user info: {response.status_code}"
    except Exception as e:
        return None, f"Error getting user info: {str(e)}"


def _find_or_create_oauth_user(provider, user_info, token_data):
    """Find existing user or create new one from OAuth data"""
    # Try to find existing OAuth account
    oauth_account = OAuthAccount.query.filter_by(
        provider_id=OAuthProvider.query.filter_by(name=provider).first().id,
        provider_user_id=str(user_info.get('id', user_info.get('sub', '')))
    ).first()

    if oauth_account:
        return oauth_account.user

    # Try to find user by email
    email = user_info.get('email')
    if email:
        user = User.query.filter_by(email=email).first()
        if user:
            return user

    # Create new user
    username = _generate_unique_username(user_info)
    email = user_info.get('email', f"{username}@{provider}.oauth")

    new_user = User(
        username=username,
        email=email,
        password_hash=None,  # OAuth users don't have passwords
        is_admin=False,
        is_active=True
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        return new_user
    except Exception as e:
        db.session.rollback()
        print(f"Error creating OAuth user: {e}")
        return None


def _generate_unique_username(user_info):
    """Generate unique username from OAuth user info"""
    base_username = user_info.get('login', user_info.get('name', 'user'))
    base_username = ''.join(c for c in base_username if c.isalnum() or c in '._-')

    counter = 1
    username = base_username
    while User.query.filter_by(username=username).first():
        username = f"{base_username}{counter}"
        counter += 1

    return username


def _store_oauth_account(user_id, provider, user_info, token_data):
    """Store OAuth account information"""
    provider_model = OAuthProvider.query.filter_by(name=provider).first()
    if not provider_model:
        return

    # Check if OAuth account already exists
    existing_account = OAuthAccount.query.filter_by(
        user_id=user_id,
        provider_id=provider_model.id
    ).first()

    if existing_account:
        # Update existing account
        existing_account.access_token = token_data.get('access_token')
        existing_account.refresh_token = token_data.get('refresh_token')
        existing_account.updated_at = db.func.current_timestamp()
    else:
        # Create new account
        new_account = OAuthAccount(
            user_id=user_id,
            provider_id=provider_model.id,
            provider_user_id=str(user_info.get('id', user_info.get('sub', ''))),
            access_token=token_data.get('access_token'),
            refresh_token=token_data.get('refresh_token')
        )
        db.session.add(new_account)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error storing OAuth account: {e}")


def _get_provider_color(provider_name):
    """Get display color for OAuth provider"""
    colors = {
        'google': '#4285f4',
        'github': '#333',
        'facebook': '#1877f2',
        'twitter': '#1da1f2',
        'linkedin': '#0077b5',
        'microsoft': '#00a4ef'
    }
    return colors.get(provider_name.lower(), '#6c757d')


def handle_oauth_authorize(provider, redirect_uri):
    """Handle OAuth authorization request"""
    config = get_oauth_provider_config(provider)
    if not config:
        return jsonify({'error': 'Provider not found or inactive'}), 404

    # Store redirect URI in session for later use
    session['oauth_redirect_uri'] = redirect_uri
    session['oauth_provider'] = provider

    # Build authorization URL
    auth_params = {
        'client_id': config['client_id'],
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': config['scope']
    }

    auth_url = f"{config['authorize_url']}?{'&'.join([f'{k}={v}' for k, v in auth_params.items()])}"

    return jsonify({'authorization_url': auth_url}), 200


def handle_oauth_callback(provider, code, error):
    """Handle OAuth callback from provider"""
    if error:
        return jsonify({'error': f'OAuth error: {error}'}), 400

    if not code:
        return jsonify({'error': 'Missing authorization code'}), 400

    # Get stored redirect URI from session
    redirect_uri = session.get('oauth_redirect_uri')
    if not redirect_uri:
        return jsonify({'error': 'Missing redirect URI'}), 400

    # Exchange code for token
    token_data, error_msg = exchange_code_for_token(provider, code, redirect_uri)
    if error_msg:
        return jsonify({'error': error_msg}), 400

    # Get user information from provider
    user_info, error_msg = get_user_info(provider, token_data['access_token'])
    if error_msg:
        return jsonify({'error': error_msg}), 400

    # Find or create user
    user = _find_or_create_oauth_user(provider, user_info, token_data)
    if not user:
        return jsonify({'error': 'Failed to create or find user'}), 500

    # Create JWT token
    access_token = create_access_token(identity=user.username)
    
    # Get JTI from the token and create session record
    from flask_jwt_extended import decode_token
    token_data_jwt = decode_token(access_token)
    jti = token_data_jwt['jti']
    
    # Create session record
    from .utils import create_jwt_session
    create_jwt_session(jti, user.id, f'oauth_{provider}')

    # Store OAuth account information
    _store_oauth_account(user.id, provider, user_info, token_data)

    # Clear session data
    session.pop('oauth_redirect_uri', None)
    session.pop('oauth_provider', None)

    return jsonify({
        'access_token': access_token,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_admin': user.is_admin
        }
    }), 200


def handle_oauth_link(provider, code, error, current_user):
    """Handle OAuth linking for existing users"""
    if error:
        return jsonify({'error': f'OAuth error: {error}'}), 400

    if not code:
        return jsonify({'error': 'Missing authorization code'}), 400

    if not current_user:
        return jsonify({'error': 'User not found'}), 404

    # Get redirect URI from query parameter
    redirect_uri = request.args.get('redirect_uri')
    if not redirect_uri:
        return jsonify({'error': 'Missing redirect URI'}), 400

    # Exchange code for token
    token_data, error_msg = exchange_code_for_token(provider, code, redirect_uri)
    if error_msg:
        return jsonify({'error': error_msg}), 400

    # Get user information from provider
    user_info, error_msg = get_user_info(provider, token_data['access_token'])
    if error_msg:
        return jsonify({'error': error_msg}), 400

    # Check if this OAuth account is already linked to another user
    provider_model = OAuthProvider.query.filter_by(name=provider).first()
    if provider_model:
        existing_oauth_account = OAuthAccount.query.filter_by(
            provider_id=provider_model.id,
            provider_user_id=str(user_info.get('id', user_info.get('sub', '')))
        ).first()

        if existing_oauth_account and existing_oauth_account.user_id != current_user.id:
            return jsonify({'error': 'This OAuth account is already linked to another user'}), 400

    # Store OAuth account information for current user
    _store_oauth_account(current_user.id, provider, user_info, token_data)

    return jsonify({
        'message': f'Successfully linked {provider} to your account',
        'user': {
            'id': current_user.id,
            'username': current_user.username,
            'email': current_user.email,
            'is_admin': current_user.is_admin
        }
    }), 200


def get_oauth_providers_list():
    """Get list of available OAuth providers"""
    providers = OAuthProvider.query.filter_by(is_active=True).all()
    return jsonify({
        'providers': [{
            'name': provider.name,
            'display_name': provider.name.title(),
            'icon': f'fab fa-{provider.name}',
            'color': _get_provider_color(provider.name)
        } for provider in providers]
    }), 200


# OAuth Blueprint
oauth_bp = Blueprint('oauth', __name__, url_prefix='/api/v1/auth/oauth')


@oauth_bp.route('/<provider>/authorize', methods=['GET'])
def oauth_authorize(provider):
    """Redirect user to OAuth provider for authorization"""
    from flask import request
    redirect_uri = request.args.get('redirect_uri')
    if not redirect_uri:
        return jsonify({'error': 'Missing redirect_uri parameter'}), 400

    return handle_oauth_authorize(provider, redirect_uri)


@oauth_bp.route('/<provider>/callback', methods=['GET'])
def oauth_callback(provider):
    """Handle OAuth callback from provider"""
    from flask import request
    code = request.args.get('code')
    error = request.args.get('error')

    return handle_oauth_callback(provider, code, error)


@oauth_bp.route('/<provider>/link', methods=['GET'])
@jwt_required()
def oauth_link(provider):
    """Handle OAuth linking for existing users"""
    from flask import request
    code = request.args.get('code')
    error = request.args.get('error')

    # Get current user from JWT
    current_username = get_jwt_identity()
    current_user = User.query.filter_by(username=current_username).first()

    if not current_user:
        return jsonify({'error': 'User not found'}), 404

    return handle_oauth_link(provider, code, error, current_user)


@oauth_bp.route('/providers', methods=['GET'])
def get_oauth_providers():
    """Get list of available OAuth providers"""
    return get_oauth_providers_list()


@oauth_bp.route('/connect/<provider>', methods=['POST'])
@jwt_required()
def connect_oauth_provider(provider):
    """Connect OAuth provider to existing user account"""
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # This endpoint would handle connecting additional OAuth providers
    # For now, we'll return a message indicating it's not implemented
    return jsonify({'message': 'OAuth provider connection not yet implemented'}), 501


# The end.
