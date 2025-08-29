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
from flask import session, request, Blueprint
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from .model import db, User, OAuthProvider, OAuthAccount
from .utils import generate_unique_username, success_response, error_response, format_user_response
from .audit import log_oauth_action, AuditActions

# Create OAuth blueprint
oauth_bp = Blueprint('oauth', __name__, url_prefix='/api/v1/auth/oauth')


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
        
        if provider_name == 'google':
            response = requests.get(config['userinfo_url'], headers=headers)
        elif provider_name == 'github':
            response = requests.get(config['userinfo_url'], headers=headers)
        else:
            return None, "Unsupported provider"

        if response.status_code == 200:
            return response.json(), None
        else:
            return None, f"Failed to get user info: {response.status_code}"
    except Exception as e:
        return None, f"Error getting user info: {str(e)}"


def _find_or_create_oauth_user(provider, user_info, token_data):
    """Find existing user or create new one from OAuth data"""
    # Try to find user by email first
    email = user_info.get('email')
    if email:
        user = User.query.filter_by(email=email).first()
        if user:
            return user

    # Try to find user by OAuth account
    provider_user_id = user_info.get('id') or user_info.get('sub')
    if provider_user_id:
        oauth_account = OAuthAccount.query.filter_by(
            provider_user_id=str(provider_user_id),
            provider_id=OAuthProvider.query.filter_by(name=provider).first().id
        ).first()
        if oauth_account:
            return oauth_account.user

    # Create new user
    username = user_info.get('login') or user_info.get('name') or user_info.get('given_name')
    if not username:
        username = generate_unique_username()

    # Ensure username is unique
    while User.query.filter_by(username=username).first():
        username = generate_unique_username()

    new_user = User(
        username=username,
        email=email,
        is_admin=False
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        return new_user
    except Exception as e:
        db.session.rollback()
        return None


def _store_oauth_account(user_id, provider, user_info, token_data):
    """Store OAuth account information"""
    provider_obj = OAuthProvider.query.filter_by(name=provider).first()
    if not provider_obj:
        return

    provider_user_id = user_info.get('id') or user_info.get('sub')
    if not provider_user_id:
        return

    # Check if account already exists
    existing_account = OAuthAccount.query.filter_by(
        user_id=user_id,
        provider_id=provider_obj.id
    ).first()

    if existing_account:
        # Update existing account
        existing_account.provider_user_id = str(provider_user_id)
        existing_account.access_token = token_data.get('access_token')
        existing_account.refresh_token = token_data.get('refresh_token')
        existing_account.token_expires_at = None  # Set based on token_data if available
    else:
        # Create new account
        new_account = OAuthAccount(
            user_id=user_id,
            provider_id=provider_obj.id,
            provider_user_id=str(provider_user_id),
            access_token=token_data.get('access_token'),
            refresh_token=token_data.get('refresh_token'),
            token_expires_at=None  # Set based on token_data if available
        )
        db.session.add(new_account)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()


# OAuth Blueprint Routes

@oauth_bp.route('/<provider>/authorize', methods=['GET'])
def oauth_authorize(provider):
    """Initiate OAuth authorization flow."""
    # Get OAuth provider configuration
    config = get_oauth_provider_config(provider)
    if not config:
        return error_response('Provider not found or inactive', 404)

    # Get redirect URI from query parameter
    redirect_uri = request.args.get('redirect_uri')
    if not redirect_uri:
        return error_response('Missing redirect_uri parameter', 400)

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

    return success_response(
        'Authorization URL generated successfully',
        {'authorization_url': auth_url}
    )


@oauth_bp.route('/<provider>/callback', methods=['GET'])
def oauth_callback(provider):
    """Handle OAuth callback from provider."""
    error = request.args.get('error')
    code = request.args.get('code')

    if error:
        return error_response(f'OAuth error: {error}', 400)

    if not code:
        return error_response('Missing authorization code', 400)

    # Get stored redirect URI from session
    redirect_uri = session.get('oauth_redirect_uri')
    if not redirect_uri:
        return error_response('Missing redirect URI', 400)

    # Exchange code for token
    token_data, error_msg = exchange_code_for_token(provider, code, redirect_uri)
    if error_msg:
        return error_response(error_msg, 400)

    # Get user information from provider
    user_info, error_msg = get_user_info(provider, token_data['access_token'])
    if error_msg:
        return error_response(error_msg, 400)

    # Find or create user
    user = _find_or_create_oauth_user(provider, user_info, token_data)
    if not user:
        return error_response('Failed to create or find user', 500)

    # Create JWT token
    access_token = create_access_token(identity=user.username)
    
    # Get JTI from the token and create session record
    from flask_jwt_extended import decode_token
    token_data_jwt = decode_token(access_token)
    jti = token_data_jwt['jti']
    
    # Create session record
    from .jwt import create_jwt_session
    create_jwt_session(jti, user.id, f'oauth_{provider}')

    # Store OAuth account information
    _store_oauth_account(user.id, provider, user_info, token_data)

    # Clear session data
    session.pop('oauth_redirect_uri', None)
    session.pop('oauth_provider', None)

    return success_response(
        'OAuth authentication successful',
        {
            'access_token': access_token,
            'user': format_user_response(user)
        }
    )


@oauth_bp.route('/<provider>/link', methods=['GET'])
@jwt_required()
def oauth_link(provider):
    """Initiate OAuth account linking for existing users."""
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()

    if not user:
        return error_response('User not found', 404)

    # Check if user already has this provider connected
    for oauth_account in user.oauth_accounts:
        if oauth_account.provider.name == provider:
            return error_response(f'Already connected to {provider}', 400)

    # Get OAuth provider configuration
    config = get_oauth_provider_config(provider)
    if not config:
        return error_response('Provider not found or inactive', 404)

    # Get redirect URI from query parameter
    redirect_uri = request.args.get('redirect_uri')
    if not redirect_uri:
        return error_response('Missing redirect_uri parameter', 400)

    # Store linking information in session
    session['oauth_link_user_id'] = user.id
    session['oauth_link_provider'] = provider
    session['oauth_link_redirect_uri'] = redirect_uri

    # Build authorization URL
    auth_params = {
        'client_id': config['client_id'],
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': config['scope']
    }

    auth_url = f"{config['authorize_url']}?{'&'.join([f'{k}={v}' for k, v in auth_params.items()])}"

    return success_response(
        'OAuth linking initiated successfully',
        {'authorization_url': auth_url}
    )


@oauth_bp.route('/<provider>/link/callback', methods=['GET'])
def oauth_link_callback(provider):
    """Handle OAuth linking callback."""
    error = request.args.get('error')
    code = request.args.get('code')

    if error:
        return error_response(f'OAuth error: {error}', 400)

    if not code:
        return error_response('Missing authorization code', 400)

    # Get stored linking information from session
    user_id = session.get('oauth_link_user_id')
    redirect_uri = session.get('oauth_link_redirect_uri')
    
    if not user_id or not redirect_uri:
        return error_response('Missing linking information', 400)

    user = User.query.get(user_id)
    if not user:
        return error_response('User not found', 404)

    # Exchange code for token
    token_data, error_msg = exchange_code_for_token(provider, code, redirect_uri)
    if error_msg:
        return error_response(error_msg, 400)

    # Get user information from provider
    user_info, error_msg = get_user_info(provider, token_data['access_token'])
    if error_msg:
        return error_response(error_msg, 400)

    # Check if this OAuth account is already linked to another user
    provider_user_id = user_info.get('id') or user_info.get('sub')
    if provider_user_id:
        existing_account = OAuthAccount.query.filter_by(
            provider_user_id=str(provider_user_id),
            provider_id=OAuthProvider.query.filter_by(name=provider).first().id
        ).first()
        
        if existing_account and existing_account.user_id != user_id:
            return error_response('This OAuth account is already linked to another user', 400)

    # Store OAuth account information
    _store_oauth_account(user.id, provider, user_info, token_data)

    # Clear session data
    session.pop('oauth_link_user_id', None)
    session.pop('oauth_link_provider', None)
    session.pop('oauth_link_redirect_uri', None)

    return success_response(
        f'OAuth account linked successfully to {provider}',
        {'user': format_user_response(user)}
    )


@oauth_bp.route('/providers', methods=['GET'])
def get_oauth_providers():
    """Get list of available OAuth providers."""
    try:
        providers = OAuthProvider.query.filter_by(is_active=True).all()
        provider_list = []
        
        for provider in providers:
            provider_list.append({
                'name': provider.name,
                'display_name': provider.name.title(),
                'scope': provider.scope
            })
        
        return success_response(
            'OAuth providers retrieved successfully',
            {'providers': provider_list}
        )
    except Exception as e:
        return error_response(f'Failed to retrieve OAuth providers: {str(e)}', 500)


@oauth_bp.route('/<provider>/status', methods=['GET'])
@jwt_required()
def get_oauth_status(provider):
    """Get OAuth connection status for current user."""
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()

    if not user:
        return error_response('User not found', 404)

    # Check if user has this provider connected
    connected = False
    account_info = None
    
    for oauth_account in user.oauth_accounts:
        if oauth_account.provider.name == provider:
            connected = True
            account_info = {
                'id': oauth_account.id,
                'provider_user_id': oauth_account.provider_user_id,
                'connected_at': oauth_account.created_at.isoformat() if oauth_account.created_at else None
            }
            break

    return success_response(
        'OAuth status retrieved successfully',
        {
            'provider': provider,
            'connected': connected,
            'account_info': account_info
        }
    )


# The end.
