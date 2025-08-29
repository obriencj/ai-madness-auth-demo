"""
Admin management endpoints for the Daft Gila authentication platform.

This module handles all administrative operations including user management,
OAuth provider management, GSSAPI realm management, and system configuration.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

from flask import Blueprint, request
from .model import db, User, OAuthProvider, OAuthAccount, GSSAPIRealm, GSSAPIAccount, JWTSession, AppConfigVersion
from .jwt import jwt_required
from .utils import (
    admin_required, get_current_user, validate_required_fields,
    validate_email_format, validate_username_format,
    format_user_response, format_oauth_provider_response,
    success_response, error_response
)
from .audit import (
    log_user_action, log_oauth_action, log_gssapi_action,
    log_config_action, log_session_action, AuditActions
)

# Create admin blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/api/v1/admin')


# User Management Routes
@admin_bp.route('/users', methods=['POST'])
@jwt_required()
@admin_required
def register_user():
    """Create a new user (admin only)."""
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
        
        # Log the action
        current_user = get_current_user()
        log_user_action(
            user_id=current_user.id,
            action=AuditActions.USER_CREATED,
            target_user_id=new_user.id,
            details={'username': new_user.username, 'email': new_user.email, 'is_admin': new_user.is_admin}
        )
        
        return success_response(
            'User created successfully',
            {'user': format_user_response(new_user)},
            201
        )
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to create user: {str(e)}', 500)


@admin_bp.route('/users', methods=['GET'])
@jwt_required()
@admin_required
def get_users():
    """Get all users (admin only)."""
    try:
        users = User.query.all()
        return success_response(
            'Users retrieved successfully',
            {'users': [format_user_response(user) for user in users]}
        )
    except Exception as e:
        return error_response(f'Failed to retrieve users: {str(e)}', 500)


@admin_bp.route('/users/<int:user_id>', methods=['PUT'])
@jwt_required()
@admin_required
def update_user(user_id):
    """Update a user (admin only)."""
    user = User.query.get(user_id)
    if not user:
        return error_response('User not found', 404)
    
    data = request.get_json()
    if not data:
        return error_response('Request data is required', 400)
    
    # Track changes for audit
    changes = {}
    
    # Update email if provided
    if 'email' in data:
        if not validate_email_format(data['email']):
            return error_response('Invalid email format.', 400)
        
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user and existing_user.id != user_id:
            return error_response('Email already exists', 400)
        
        if user.email != data['email']:
            changes['email'] = {'old': user.email, 'new': data['email']}
            user.email = data['email']
    
    # Update other fields
    if 'is_admin' in data and user.is_admin != data['is_admin']:
        changes['is_admin'] = {'old': user.is_admin, 'new': data['is_admin']}
        user.is_admin = data['is_admin']
    
    if 'is_active' in data and user.is_active != data['is_active']:
        changes['is_active'] = {'old': user.is_active, 'new': data['is_active']}
        user.is_active = data['is_active']
    
    if 'password' in data and data['password']:
        user.set_password(data['password'])
        changes['password'] = {'changed': True}
    
    try:
        db.session.commit()
        
        # Log the action if there were changes
        if changes:
            current_user = get_current_user()
            log_user_action(
                user_id=current_user.id,
                action=AuditActions.USER_UPDATED,
                target_user_id=user.id,
                details={'changes': changes}
            )
        
        return success_response(
            'User updated successfully',
            {'user': format_user_response(user)}
        )
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to update user: {str(e)}', 500)


@admin_bp.route('/users/<int:user_id>/oauth-accounts', methods=['GET'])
@jwt_required()
@admin_required
def get_user_oauth_accounts(user_id):
    """Get OAuth accounts for a specific user (admin only)."""
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


@admin_bp.route('/users/<int:user_id>/oauth-accounts/<int:oauth_account_id>', methods=['DELETE'])
@jwt_required()
@admin_required
def admin_remove_user_oauth_account(user_id, oauth_account_id):
    """Remove OAuth account from a user (admin only)."""
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
        
        # Log the action
        current_user = get_current_user()
        log_oauth_action(
            user_id=current_user.id,
            action=AuditActions.OAUTH_ACCOUNT_UNLINKED,
            provider_id=oauth_account.provider_id,
            details={'user_id': user_id, 'provider_user_id': oauth_account.provider_user_id}
        )
        
        return success_response('OAuth account removed successfully')
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to remove OAuth account: {str(e)}', 500)


# OAuth Provider Management Routes
@admin_bp.route('/oauth-providers', methods=['GET'])
@jwt_required()
@admin_required
def get_oauth_providers_admin():
    """Get all OAuth providers (admin only)."""
    try:
        providers = OAuthProvider.query.all()
        return success_response(
            'OAuth providers retrieved successfully',
            {'providers': [format_oauth_provider_response(provider) for provider in providers]}
        )
    except Exception as e:
        return error_response(f'Failed to retrieve OAuth providers: {str(e)}', 500)


@admin_bp.route('/oauth-providers', methods=['POST'])
@jwt_required()
@admin_required
def create_oauth_provider():
    """Create new OAuth provider (admin only)."""
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
        
        # Log the action
        current_user = get_current_user()
        log_oauth_action(
            user_id=current_user.id,
            action=AuditActions.OAUTH_PROVIDER_CREATED,
            provider_id=new_provider.id,
            details={'name': new_provider.name, 'is_active': new_provider.is_active}
        )
        
        return success_response(
            'OAuth provider created successfully',
            {'provider': format_oauth_provider_response(new_provider)},
            201
        )
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to create provider: {str(e)}', 500)


@admin_bp.route('/oauth-providers/<int:provider_id>', methods=['PUT'])
@jwt_required()
@admin_required
def update_oauth_provider(provider_id):
    """Update OAuth provider (admin only)."""
    provider = OAuthProvider.query.get(provider_id)
    if not provider:
        return error_response('OAuth provider not found', 404)
    
    data = request.get_json()
    if not data:
        return error_response('Request data is required', 400)
    
    # Track changes for audit
    changes = {}
    
    # Update fields if provided
    if 'name' in data:
        # Check if new name conflicts with existing provider
        existing_provider = OAuthProvider.query.filter_by(name=data['name']).first()
        if existing_provider and existing_provider.id != provider_id:
            return error_response('Provider name already exists', 400)
        
        if provider.name != data['name']:
            changes['name'] = {'old': provider.name, 'new': data['name']}
            provider.name = data['name']
    
    if 'client_id' in data and provider.client_id != data['client_id']:
        changes['client_id'] = {'changed': True}
        provider.client_id = data['client_id']
    
    if 'client_secret' in data and data['client_secret']:
        provider.client_secret = data['client_secret']
        changes['client_secret'] = {'changed': True}
    
    if 'authorize_url' in data and provider.authorize_url != data['authorize_url']:
        changes['authorize_url'] = {'old': provider.authorize_url, 'new': data['authorize_url']}
        provider.authorize_url = data['authorize_url']
    
    if 'token_url' in data and provider.token_url != data['token_url']:
        changes['token_url'] = {'old': provider.token_url, 'new': data['token_url']}
        provider.token_url = data['token_url']
    
    if 'userinfo_url' in data and provider.userinfo_url != data['userinfo_url']:
        changes['userinfo_url'] = {'old': provider.userinfo_url, 'new': data['userinfo_url']}
        provider.userinfo_url = data['userinfo_url']
    
    if 'scope' in data and provider.scope != data['scope']:
        changes['scope'] = {'old': provider.scope, 'new': data['scope']}
        provider.scope = data['scope']
    
    if 'is_active' in data and provider.is_active != data['is_active']:
        changes['is_active'] = {'old': provider.is_active, 'new': data['is_active']}
        provider.is_active = data['is_active']
    
    try:
        db.session.commit()
        
        # Log the action if there were changes
        if changes:
            current_user = get_current_user()
            log_oauth_action(
                user_id=current_user.id,
                action=AuditActions.OAUTH_PROVIDER_UPDATED,
                provider_id=provider.id,
                details={'changes': changes}
            )
        
        return success_response(
            'OAuth provider updated successfully',
            {'provider': format_oauth_provider_response(provider)}
        )
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to update provider: {str(e)}', 500)


@admin_bp.route('/oauth-providers/<int:provider_id>', methods=['DELETE'])
@jwt_required()
@admin_required
def delete_oauth_provider(provider_id):
    """Delete OAuth provider (admin only)."""
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
        
        # Log the action
        current_user = get_current_user()
        log_oauth_action(
            user_id=current_user.id,
            action=AuditActions.OAUTH_PROVIDER_DELETED,
            provider_id=provider_id,
            details={'name': provider.name}
        )
        
        return success_response('OAuth provider deleted successfully')
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to delete provider: {str(e)}', 500)


# JWT Session Management Routes
@admin_bp.route('/sessions', methods=['GET'])
@jwt_required()
@admin_required
def get_active_sessions():
    """Get all active JWT sessions (admin only)."""
    try:
        sessions = JWTSession.query.filter_by(is_active=True).all()
        session_data = []
        for session in sessions:
            session_data.append({
                'id': session.id,
                'jti': session.jti,
                'user_id': session.user_id,
                'username': session.user.username,
                'auth_method': session.auth_method,
                'ip_address': session.ip_address,
                'user_agent': session.user_agent,
                'created_at': session.created_at.isoformat() if session.created_at else None,
                'expires_at': session.expires_at.isoformat() if session.expires_at else None,
                'last_activity_at': session.last_activity_at.isoformat() if session.last_activity_at else None
            })
        
        return success_response(
            'Active sessions retrieved successfully',
            {'sessions': session_data}
        )
    except Exception as e:
        return error_response(f'Failed to retrieve sessions: {str(e)}', 500)


@admin_bp.route('/sessions/<int:session_id>/expire', methods=['POST'])
@jwt_required()
@admin_required
def expire_session(session_id):
    """Expire a specific JWT session (admin only)."""
    session = JWTSession.query.get(session_id)
    if not session:
        return error_response('Session not found', 404)
    
    try:
        session.is_active = False
        db.session.commit()
        
        # Log the action
        current_user = get_current_user()
        log_session_action(
            user_id=current_user.id,
            action=AuditActions.SESSION_EXPIRED,
            session_id=session.id,
            details={'jti': session.jti, 'user_id': session.user_id}
        )
        
        return success_response('Session expired successfully')
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to expire session: {str(e)}', 500)


@admin_bp.route('/sessions/expire-all', methods=['POST'])
@jwt_required()
@admin_required
def expire_all_sessions():
    """Expire all active JWT sessions (admin only)."""
    try:
        active_sessions = JWTSession.query.filter_by(is_active=True).all()
        session_count = len(active_sessions)
        
        for session in active_sessions:
            session.is_active = False
        
        db.session.commit()
        
        # Log the action
        current_user = get_current_user()
        log_session_action(
            user_id=current_user.id,
            action=AuditActions.SESSION_EXPIRED_ALL,
            details={'sessions_expired': session_count}
        )
        
        return success_response(f'{session_count} sessions expired successfully')
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to expire sessions: {str(e)}', 500)


# Configuration Management Routes
@admin_bp.route('/config', methods=['GET'])
@jwt_required()
@admin_required
def get_active_config():
    """Get the currently active configuration (admin only)."""
    try:
        from .config import get_active_config as get_config, get_default_config
        
        config_data = get_config()
        if not config_data:
            return error_response('No active configuration found', 404)
        
        return success_response(
            'Active configuration retrieved successfully',
            config_data
        )
    except Exception as e:
        return error_response(f'Failed to retrieve configuration: {str(e)}', 500)


@admin_bp.route('/config', methods=['POST'])
@jwt_required()
@admin_required
def create_config_version():
    """Create a new configuration version (admin only)."""
    data = request.get_json()
    
    # Validate required fields
    is_valid, error_msg = validate_required_fields(data, ['config_data'])
    if not is_valid:
        return error_response(error_msg, 400)
    
    try:
        # Get the next version number
        latest_version = AppConfigVersion.query.order_by(AppConfigVersion.version.desc()).first()
        next_version = (latest_version.version + 1) if latest_version else 1
        
        # Create new configuration version
        current_user = get_current_user()
        new_config = AppConfigVersion(
            version=next_version,
            config_data=data['config_data'],
            description=data.get('description', f'Configuration version {next_version}'),
            created_by=current_user.id
        )
        
        db.session.add(new_config)
        db.session.commit()
        
        # Log the action
        log_config_action(
            user_id=current_user.id,
            action=AuditActions.CONFIG_CREATED,
            config_version_id=new_config.id,
            details={'version': next_version, 'description': new_config.description}
        )
        
        return success_response(
            'Configuration version created successfully',
            {
                'id': new_config.id,
                'version': new_config.version,
                'description': new_config.description
            },
            201
        )
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to create configuration: {str(e)}', 500)


@admin_bp.route('/config/versions', methods=['GET'])
@jwt_required()
@admin_required
def get_config_versions():
    """Get all configuration versions (admin only)."""
    try:
        configs = AppConfigVersion.query.order_by(AppConfigVersion.version.desc()).all()
        config_data = []
        for config in configs:
            config_data.append({
                'id': config.id,
                'version': config.version,
                'description': config.description,
                'is_active': config.is_active,
                'created_at': config.created_at.isoformat() if config.created_at else None,
                'activated_at': config.activated_at.isoformat() if config.activated_at else None,
                'created_by': config.creator.username if config.creator else None,
                'activated_by': config.activator.username if config.activator else None
            })
        
        return success_response(
            'Configuration versions retrieved successfully',
            {'configurations': config_data}
        )
    except Exception as e:
        return error_response(f'Failed to retrieve configurations: {str(e)}', 500)


@admin_bp.route('/config/versions/<int:version_id>', methods=['GET'])
@jwt_required()
@admin_required
def get_config_version(version_id):
    """Get a specific configuration version (admin only)."""
    config = AppConfigVersion.query.get(version_id)
    if not config:
        return error_response('Configuration version not found', 404)
    
    return success_response(
        'Configuration version retrieved successfully',
        {
            'id': config.id,
            'version': config.version,
            'config_data': config.config_data,
            'description': config.description,
            'is_active': config.is_active,
            'created_at': config.created_at.isoformat() if config.created_at else None,
            'activated_at': config.activated_at.isoformat() if config.activated_at else None,
            'created_by': config.creator.username if config.creator else None,
            'activated_by': config.activator.username if config.activator else None
        }
    )


@admin_bp.route('/config/versions/<int:version_id>/activate', methods=['POST'])
@jwt_required()
@admin_required
def activate_config_version(version_id):
    """Activate a configuration version (admin only)."""
    config = AppConfigVersion.query.get(version_id)
    if not config:
        return error_response('Configuration version not found', 404)
    
    try:
        # Deactivate all other configurations
        AppConfigVersion.query.update({'is_active': False})
        
        # Activate the selected configuration
        current_user = get_current_user()
        config.is_active = True
        config.activated_at = db.func.current_timestamp()
        config.activated_by = current_user.id
        
        db.session.commit()
        
        # Log the action
        log_config_action(
            user_id=current_user.id,
            action=AuditActions.CONFIG_ACTIVATED,
            config_version_id=config.id,
            details={'version': config.version, 'description': config.description}
        )
        
        return success_response('Configuration version activated successfully')
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to activate configuration: {str(e)}', 500)


@admin_bp.route('/config/versions/<int:version_id>', methods=['DELETE'])
@jwt_required()
@admin_required
def delete_config_version(version_id):
    """Delete a configuration version (admin only)."""
    config = AppConfigVersion.query.get(version_id)
    if not config:
        return error_response('Configuration version not found', 404)
    
    if config.is_active:
        return error_response('Cannot delete active configuration', 400)
    
    try:
        db.session.delete(config)
        db.session.commit()
        
        # Log the action
        current_user = get_current_user()
        log_config_action(
            user_id=current_user.id,
            action=AuditActions.CONFIG_DELETED,
            details={'version': config.version, 'description': config.description}
        )
        
        return success_response('Configuration version deleted successfully')
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to delete configuration: {str(e)}', 500)


# The end.
