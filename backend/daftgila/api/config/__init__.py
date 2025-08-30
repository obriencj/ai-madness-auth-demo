"""
Configuration management for the Auth Demo application.

This module handles application configuration, including:
- Configuration retrieval and updates
- Configuration versioning
- Configuration caching
- Feature flags

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import json
import os
from datetime import datetime
from flask import Blueprint, request
from flask_jwt_extended import jwt_required
from ..model import db, AppConfigVersion, OAuthProvider, GSSAPIRealm
from ..utils import admin_required, get_current_user, success_response, error_response
from ..audit import log_config_action, AuditActions
from .schema import SystemConfig, get_schema_info, validate_config

# Create configuration blueprints
config_bp = Blueprint('config', __name__, url_prefix='/api/v1/admin/config')
public_config_bp = Blueprint('public_config', __name__, url_prefix='/api/v1/config')


def get_active_config():
    """Get the currently active configuration."""
    try:
        active_config = AppConfigVersion.query.filter_by(is_active=True).first()
        if not active_config:
            return get_default_config()
        return active_config.config_data
    except Exception as e:
        return get_default_config()


def get_default_config():
    """Get default configuration if no active config exists."""
    # Use the schema defaults for consistency
    default_config = SystemConfig()
    return default_config.dict()


def get_config_value(key_path, default=None):
    """Get a specific configuration value by key path."""
    try:
        config = get_active_config()
        keys = key_path.split('.')
        value = config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    except Exception:
        return default


def is_registration_allowed():
    """Check if user registration is currently allowed."""
    return get_config_value('auth.allow_user_registration', True)


def is_user_login_allowed():
    """Check if user login is currently allowed."""
    return get_config_value('auth.allow_user_login', True)


def get_jwt_lifetime_hours():
    """Get JWT token lifetime in hours."""
    return get_config_value('auth.jwt_lifetime_hours', 1)


# Configuration Blueprint Routes

@config_bp.route('/active', methods=['GET'])
@jwt_required()
@admin_required
def get_active_config_endpoint():
    """Get the currently active configuration (admin only)."""
    try:
        active_config = AppConfigVersion.query.filter_by(is_active=True).first()
        if not active_config:
            return success_response(
                'No active configuration found, using defaults',
                {'config': get_default_config()}
            )
        
        return success_response(
            'Active configuration retrieved successfully',
            {
                'id': active_config.id,
                'version': active_config.version,
                'config_data': active_config.config_data,
                'description': active_config.description,
                'created_at': active_config.created_at.isoformat() if active_config.created_at else None,
                'activated_at': active_config.activated_at.isoformat() if active_config.activated_at else None,
                'created_by': active_config.creator.username if active_config.creator else None,
                'activated_by': active_config.activator.username if active_config.activator else None
            }
        )
    except Exception as e:
        return error_response(f'Failed to retrieve configuration: {str(e)}', 500)


@config_bp.route('/schema', methods=['GET'])
@jwt_required()
@admin_required
def get_config_schema():
    """Get configuration schema information (admin only)."""
    try:
        schema_info = get_schema_info()
        
        return success_response(
            'Configuration schema retrieved successfully',
            {'schema': schema_info}
        )
    except Exception as e:
        return error_response(f'Failed to retrieve schema: {str(e)}', 500)


@config_bp.route('/update', methods=['PUT'])
@jwt_required()
@admin_required
def update_config():
    """Update the active configuration (admin only)."""
    try:
        active_config = AppConfigVersion.query.filter_by(is_active=True).first()
        if not active_config:
            return error_response('No active configuration found', 404)
        
        data = request.get_json()
        if not data or 'config_data' not in data:
            return error_response('Missing config_data', 400)
        
        # Validate configuration against schema
        is_valid, error_message, validated_config = validate_config(data['config_data'])
        if not is_valid:
            return error_response(error_message, 400)
        
        # Update configuration with validated data
        active_config.config_data = validated_config.dict()
        active_config.updated_at = db.func.current_timestamp()
        
        # Log the configuration update
        current_user = get_current_user()
        log_config_action(
            user_id=current_user.id,
            action=AuditActions.CONFIG_UPDATED,
            details=f"Configuration updated to version {active_config.version}"
        )
        
        db.session.commit()
        
        return success_response(
            'Configuration updated successfully',
            {
                'id': active_config.id,
                'version': active_config.version,
                'description': data.get('description', 'Configuration updated')
            }
        )
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to update configuration: {str(e)}', 500)


@config_bp.route('/versions', methods=['GET'])
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
            {'versions': config_data}
        )
    except Exception as e:
        return error_response(f'Failed to retrieve versions: {str(e)}', 500)


@config_bp.route('/versions/<int:version_id>', methods=['GET'])
@jwt_required()
@admin_required
def get_config_version(version_id):
    """Get a specific configuration version (admin only)."""
    try:
        config = AppConfigVersion.query.get(version_id)
        if not config:
            return error_response('Version not found', 404)
        
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
    except Exception as e:
        return error_response(f'Failed to retrieve version: {str(e)}', 500)


@config_bp.route('/versions/<int:version_id>/activate', methods=['POST'])
@jwt_required()
@admin_required
def activate_config_version(version_id):
    """Activate a configuration version (admin only)."""
    try:
        config = AppConfigVersion.query.get(version_id)
        if not config:
            return error_response('Version not found', 404)
        
        # Validate JSON configuration before activation
        try:
            if isinstance(config.config_data, str):
                json.loads(config.config_data)
            else:
                json.dumps(config.config_data)
        except Exception as e:
            return error_response(f'Invalid configuration format: {str(e)}', 400)
        
        # Deactivate all other configurations
        AppConfigVersion.query.update({'is_active': False})
        
        # Activate the selected configuration
        current_user = get_current_user()
        config.is_active = True
        config.activated_at = db.func.current_timestamp()
        config.activated_by = current_user.id
        
        db.session.commit()
        
        return success_response('Configuration version activated successfully')
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to activate version: {str(e)}', 500)


@config_bp.route('/versions/<int:version_id>', methods=['DELETE'])
@jwt_required()
@admin_required
def delete_config_version(version_id):
    """Delete a configuration version (admin only)."""
    try:
        config = AppConfigVersion.query.get(version_id)
        if not config:
            return error_response('Version not found', 404)
        
        if config.is_active:
            return error_response('Cannot delete active configuration', 400)
        
        db.session.delete(config)
        db.session.commit()
        
        return success_response('Configuration version deleted successfully')
    except Exception as e:
        db.session.rollback()
        return error_response(f'Failed to delete version: {str(e)}', 500)


@config_bp.route('/cache/refresh', methods=['POST'])
@jwt_required()
@admin_required
def refresh_config_cache():
    """Refresh configuration cache (admin only)."""
    try:
        # This would typically clear any in-memory configuration cache
        # For now, we'll just return success as the database is the source of truth
        
        return success_response('Configuration cache refreshed successfully')
    except Exception as e:
        return error_response(f'Failed to refresh cache: {str(e)}', 500)


@config_bp.route('/cache/status', methods=['GET'])
@jwt_required()
@admin_required
def get_cache_status():
    """Get configuration cache status (admin only)."""
    try:
        # This would typically return cache statistics
        # For now, we'll return basic information
        
        cache_status = {
            'cache_type': 'database',
            'last_updated': datetime.utcnow().isoformat(),
            'cache_size': 'N/A',
            'hit_rate': 'N/A'
        }
        
        return success_response(
            'Cache status retrieved successfully',
            {'cache_status': cache_status}
        )
    except Exception as e:
        return error_response(f'Failed to get cache status: {str(e)}', 500)


# Public Configuration Blueprint Routes

@public_config_bp.route('/public', methods=['GET'])
def get_public_config():
    """Get public configuration information (no authentication required)."""
    try:
        config = get_active_config()
        
        # Get currently enabled OAuth providers
        oauth_providers = []
        if config.get('oauth', {}).get('enabled', False):
            providers = OAuthProvider.query.filter_by(is_active=True, is_deleted=False).all()
            oauth_providers = [
                {
                    'name': provider.name,
                    'display_name': provider.name.title(),  # Capitalize first letter
                    'icon': 'fab fa-' + provider.name.lower(),  # FontAwesome icon class
                    'color': '#000000'  # Default color
                }
                for provider in providers
            ]
        
        # Get currently enabled GSSAPI realms
        gssapi_realms = []
        if config.get('gssapi', {}).get('enabled', False):
            realms = GSSAPIRealm.query.filter_by(is_active=True, is_deleted=False).all()
            gssapi_realms = [
                {
                    'name': realm.name,
                    'realm': realm.realm,
                    'display_name': realm.name,
                    'default_realm': realm.default_realm
                }
                for realm in realms
            ]
        
        # Only return public configuration values
        public_config = {
            'auth': {
                'allow_user_registration': config.get('auth', {}).get('allow_user_registration', True),
                'allow_user_login': config.get('auth', {}).get('allow_user_login', True),
                'oauth_enabled': config.get('oauth', {}).get('enabled', False),
                'gssapi_enabled': config.get('gssapi', {}).get('enabled', False)
            },
            'oauth': {
                'enabled': config.get('oauth', {}).get('enabled', False),
                'providers': oauth_providers
            },
            'gssapi': {
                'enabled': config.get('gssapi', {}).get('enabled', False),
                'realms': gssapi_realms
            }
        }
        
        return success_response(
            'Public configuration retrieved successfully',
            {'config': public_config}
        )
    except Exception as e:
        return error_response(f'Failed to retrieve configuration: {str(e)}', 500)


# The end.
