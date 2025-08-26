"""
Configuration service and API endpoints for the Auth Demo application.

This module handles application configuration management, including:
- Configuration retrieval with defaults and Redis caching
- Version management and rollbacks
- REST API endpoints for configuration management
- Cache management and monitoring

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import json
import redis
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from .model import db, AppConfigVersion, User

# Create blueprints
config_bp = Blueprint('config', __name__, url_prefix='/api/v1/admin')
public_config_bp = Blueprint('public_config', __name__, url_prefix='/api/v1/auth')


class ConfigService:
    """Service class for managing application configuration."""
    
    # Redis cache settings
    CACHE_TTL = 300  # 5 minutes cache TTL
    CACHE_KEY_PREFIX = "app_config:"
    
    @classmethod
    def _get_redis_client(cls):
        """Get Redis client instance."""
        try:
            from .jwt import redis_client
            return redis_client
        except ImportError:
            # Fallback if Redis is not available
            return None
    
    @classmethod
    def _get_cache_key(cls, key=None):
        """Generate cache key for configuration."""
        if key:
            return f"{cls.CACHE_KEY_PREFIX}{key}"
        return f"{cls.CACHE_KEY_PREFIX}active"
    
    @classmethod
    def _get_from_cache(cls, key=None):
        """Get configuration from Redis cache."""
        redis_client = cls._get_redis_client()
        if not redis_client:
            return None
        
        try:
            cache_key = cls._get_cache_key(key)
            cached_data = redis_client.get(cache_key)
            if cached_data:
                return json.loads(cached_data)
        except Exception as e:
            print(f"Cache read error: {e}")
        return None
    
    @classmethod
    def _set_cache(cls, data, key=None, ttl=None):
        """Set configuration in Redis cache."""
        redis_client = cls._get_redis_client()
        if not redis_client:
            return False
        
        try:
            cache_key = cls._get_cache_key(key)
            cache_ttl = ttl or cls.CACHE_TTL
            redis_client.setex(cache_key, cache_ttl, json.dumps(data))
            return True
        except Exception as e:
            print(f"Cache write error: {e}")
            return False
    
    @classmethod
    def _invalidate_cache(cls, key=None):
        """Invalidate configuration cache."""
        redis_client = cls._get_redis_client()
        if not redis_client:
            return False
        
        try:
            if key:
                # Invalidate specific key
                cache_key = cls._get_cache_key(key)
                redis_client.delete(cache_key)
            else:
                # Invalidate all config cache keys
                pattern = f"{cls.CACHE_KEY_PREFIX}*"
                keys = redis_client.keys(pattern)
                if keys:
                    redis_client.delete(*keys)
            return True
        except Exception as e:
            print(f"Cache invalidation error: {e}")
            return False
    
    @staticmethod
    def get_active_config():
        """Get the currently active configuration with caching."""
        # Try to get from cache first
        cached_config = ConfigService._get_from_cache()
        if cached_config:
            return cached_config
        
        # Cache miss, get from database
        active_config = AppConfigVersion.query.filter_by(is_active=True).first()
        if active_config:
            config_data = active_config.config_data
        else:
            config_data = ConfigService.get_default_config()
        
        # Cache the result
        ConfigService._set_cache(config_data)
        
        return config_data
    
    @staticmethod
    def get_default_config():
        """Return default configuration."""
        return {
            "auth": {
                "allow_registration": True,
                "allow_user_login": True,
                "jwt_lifetime_hours": 1,
                "max_login_attempts": 5
            },
            "app": {
                "maintenance_mode": False,
                "site_name": "Auth Demo",
                "contact_email": "admin@example.com"
            }
        }
    
    @staticmethod
    def get_config_value(key_path, default=None):
        """Get a specific configuration value using dot notation (e.g., 'auth.allow_registration')."""
        config = ConfigService.get_active_config()
        keys = key_path.split('.')
        
        current = config
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        
        return current
    
    @staticmethod
    def create_new_version(config_data, description, user_id):
        """Create a new configuration version."""
        # Deactivate current active config
        current_active = AppConfigVersion.query.filter_by(is_active=True).first()
        if current_active:
            current_active.is_active = False
        
        # Create new version
        new_version = AppConfigVersion(
            version=(current_active.version + 1) if current_active else 1,
            config_data=config_data,
            description=description,
            created_by=user_id,
            is_active=True,
            activated_at=datetime.utcnow(),
            activated_by=user_id
        )
        
        db.session.add(new_version)
        db.session.commit()
        
        # Invalidate cache after configuration change
        ConfigService._invalidate_cache()
        
        return new_version
    
    @staticmethod
    def rollback_to_version(version_id, user_id):
        """Rollback to a specific configuration version."""
        target_version = AppConfigVersion.query.get(version_id)
        if not target_version:
            raise ValueError("Version not found")
        
        new_version = ConfigService.create_new_version(
            target_version.config_data,
            f"Rollback to version {target_version.version}",
            user_id
        )
        
        # Cache invalidation is handled in create_new_version
        return new_version
    
    @staticmethod
    def get_all_versions():
        """Get all configuration versions ordered by creation date."""
        return AppConfigVersion.query.order_by(AppConfigVersion.created_at.desc()).all()
    
    @staticmethod
    def get_version_by_id(version_id):
        """Get a specific configuration version by ID."""
        return AppConfigVersion.query.get(version_id)
    
    @staticmethod
    def delete_version(version_id):
        """Delete a configuration version (only if not active)."""
        version = AppConfigVersion.query.get(version_id)
        if not version:
            raise ValueError("Version not found")
        
        if version.is_active:
            raise ValueError("Cannot delete active configuration")
        
        db.session.delete(version)
        db.session.commit()
        
        # Invalidate cache after deletion
        ConfigService._invalidate_cache()
        
        return True
    
    @staticmethod
    def refresh_cache():
        """Manually refresh the configuration cache."""
        ConfigService._invalidate_cache()
        # Force a fresh read from database
        return ConfigService.get_active_config()


# Convenience functions for easy access
def get_config():
    """Get the active configuration."""
    return ConfigService.get_active_config()


def get_config_value(key_path, default=None):
    """Get a specific configuration value."""
    return ConfigService.get_config_value(key_path, default)


def is_registration_allowed():
    """Check if user registration is allowed."""
    return get_config_value('auth.allow_registration', True)


def is_user_login_allowed():
    """Check if non-admin user login is allowed."""
    return get_config_value('auth.allow_user_login', True)


def get_jwt_lifetime_hours():
    """Get JWT token lifetime in hours."""
    return get_config_value('auth.jwt_lifetime_hours', 1)


def get_max_login_attempts():
    """Get maximum login attempts allowed."""
    return get_config_value('auth.max_login_attempts', 5)


def is_maintenance_mode():
    """Check if the application is in maintenance mode."""
    return get_config_value('app.maintenance_mode', False)


def get_site_name():
    """Get the site name."""
    return get_config_value('app.site_name', 'Auth Demo')


def get_contact_email():
    """Get the contact email."""
    return get_config_value('app.contact_email', 'admin@example.com')


def refresh_config_cache():
    """Manually refresh the configuration cache."""
    return ConfigService.refresh_cache()


# ============================================================================
# ADMIN API ENDPOINTS
# ============================================================================

@config_bp.route('/config', methods=['GET'])
@jwt_required()
def get_active_config():
    """Get the currently active configuration."""
    current_username = get_jwt_identity()
    current_user = User.query.filter_by(username=current_username).first()
    
    if not current_user or not current_user.is_admin:
        return jsonify({'error': 'Admin privileges required'}), 403
    
    try:
        config = ConfigService.get_active_config()
        return jsonify({
            'config': config,
            'message': 'Configuration retrieved successfully'
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to retrieve configuration: {str(e)}'}), 500


@config_bp.route('/config', methods=['POST'])
@jwt_required()
def create_config_version():
    """Create a new configuration version."""
    current_username = get_jwt_identity()
    current_user = User.query.filter_by(username=current_username).first()
    
    if not current_user or not current_user.is_admin:
        return jsonify({'error': 'Admin privileges required'}), 403
    
    data = request.get_json()
    
    if not data or 'config_data' not in data:
        return jsonify({'error': 'Missing config_data'}), 400
    
    config_data = data['config_data']
    description = data.get('description', 'Configuration update')
    
    try:
        new_version = ConfigService.create_new_version(
            config_data, description, current_user.id
        )
        
        return jsonify({
            'message': 'Configuration updated successfully',
            'version': {
                'id': new_version.id,
                'version': new_version.version,
                'description': new_version.description,
                'created_at': new_version.created_at.isoformat(),
                'is_active': new_version.is_active
            }
        }), 201
    except Exception as e:
        return jsonify({'error': f'Failed to update configuration: {str(e)}'}), 500


@config_bp.route('/config/versions', methods=['GET'])
@jwt_required()
def get_config_versions():
    """Get all configuration versions."""
    current_username = get_jwt_identity()
    current_user = User.query.filter_by(username=current_username).first()
    
    if not current_user or not current_user.is_admin:
        return jsonify({'error': 'Admin privileges required'}), 403
    
    try:
        versions = ConfigService.get_all_versions()
        
        versions_data = []
        for version in versions:
            creator = User.query.get(version.created_by)
            activator = User.query.get(version.activated_by) if version.activated_by else None
            
            versions_data.append({
                'id': version.id,
                'version': version.version,
                'description': version.description,
                'created_at': version.created_at.isoformat(),
                'is_active': version.is_active,
                'activated_at': version.activated_at.isoformat() if version.activated_at else None,
                'creator': {
                    'id': creator.id,
                    'username': creator.username
                } if creator else None,
                'activator': {
                    'id': activator.id,
                    'username': activator.username
                } if activator else None
            })
        
        return jsonify({
            'versions': versions_data,
            'message': 'Configuration versions retrieved successfully'
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to retrieve versions: {str(e)}'}), 500


@config_bp.route('/config/versions/<int:version_id>', methods=['GET'])
@jwt_required()
def get_config_version(version_id):
    """Get a specific configuration version."""
    current_username = get_jwt_identity()
    current_user = User.query.filter_by(username=current_username).first()
    
    if not current_user or not current_user.is_admin:
        return jsonify({'error': 'Admin privileges required'}), 403
    
    try:
        version = ConfigService.get_version_by_id(version_id)
        if not version:
            return jsonify({'error': 'Version not found'}), 404
        
        creator = User.query.get(version.created_by)
        activator = User.query.get(version.activated_by) if version.activated_by else None
        
        version_data = {
            'id': version.id,
            'version': version.version,
            'config_data': version.config_data,
            'description': version.description,
            'created_at': version.created_at.isoformat(),
            'is_active': version.is_active,
            'activated_at': version.activated_at.isoformat() if version.activated_at else None,
            'creator': {
                'id': creator.id,
                'username': creator.username
            } if creator else None,
            'activator': {
                'id': activator.id,
                'username': activator.username
            } if activator else None
        }
        
        return jsonify({
            'version': version_data,
            'message': 'Configuration version retrieved successfully'
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to retrieve version: {str(e)}'}), 500


@config_bp.route('/config/versions/<int:version_id>/activate', methods=['POST'])
@jwt_required()
def activate_config_version(version_id):
    """Activate a specific configuration version."""
    current_username = get_jwt_identity()
    current_user = User.query.filter_by(username=current_username).first()
    
    if not current_user or not current_user.is_admin:
        return jsonify({'error': 'Admin privileges required'}), 403
    
    try:
        new_version = ConfigService.rollback_to_version(version_id, current_user.id)
        
        return jsonify({
            'message': 'Configuration version activated successfully',
            'version': {
                'id': new_version.id,
                'version': new_version.version,
                'description': new_version.description,
                'created_at': new_version.created_at.isoformat(),
                'is_active': new_version.is_active
            }
        }), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Failed to activate version: {str(e)}'}), 500


@config_bp.route('/config/versions/<int:version_id>', methods=['DELETE'])
@jwt_required()
def delete_config_version(version_id):
    """Delete a configuration version (only if not active)."""
    current_username = get_jwt_identity()
    current_user = User.query.filter_by(username=current_username).first()
    
    if not current_user or not current_user.is_admin:
        return jsonify({'error': 'Admin privileges required'}), 403
    
    try:
        ConfigService.delete_version(version_id)
        
        return jsonify({
            'message': 'Configuration version deleted successfully'
        }), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Failed to delete version: {str(e)}'}), 500


@config_bp.route('/config/cache/refresh', methods=['POST'])
@jwt_required()
def refresh_config_cache():
    """Manually refresh the configuration cache (admin only)."""
    current_username = get_jwt_identity()
    current_user = User.query.filter_by(username=current_username).first()
    
    if not current_user or not current_user.is_admin:
        return jsonify({'error': 'Admin privileges required'}), 403
    
    try:
        refreshed_config = ConfigService.refresh_cache()
        
        return jsonify({
            'message': 'Configuration cache refreshed successfully',
            'config': refreshed_config
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to refresh cache: {str(e)}'}), 500


@config_bp.route('/config/cache/status', methods=['GET'])
@jwt_required()
def get_cache_status():
    """Get configuration cache status (admin only)."""
    current_username = get_jwt_identity()
    current_user = User.query.filter_by(username=current_username).first()
    
    if not current_user or not current_user.is_admin:
        return jsonify({'error': 'Admin privileges required'}), 403
    
    try:
        redis_client = ConfigService._get_redis_client()
        
        if not redis_client:
            return jsonify({
                'cache_enabled': False,
                'message': 'Redis cache not available'
            }), 200
        
        # Check cache keys
        pattern = f"{ConfigService.CACHE_KEY_PREFIX}*"
        cache_keys = redis_client.keys(pattern)
        
        cache_info = {}
        for key in cache_keys:
            try:
                ttl = redis_client.ttl(key)
                cache_info[key.decode('utf-8')] = {
                    'ttl': ttl if ttl > 0 else 'expired',
                    'exists': True
                }
            except Exception as e:
                cache_info[key.decode('utf-8')] = {
                    'error': str(e),
                    'exists': False
                }
        
        return jsonify({
            'cache_enabled': True,
            'cache_ttl': ConfigService.CACHE_TTL,
            'cache_keys': cache_info,
            'message': 'Cache status retrieved successfully'
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to get cache status: {str(e)}'}), 500


# ============================================================================
# PUBLIC API ENDPOINTS
# ============================================================================

@public_config_bp.route('/config', methods=['GET'])
def get_auth_config():
    """Get public authentication configuration (no authentication required)."""
    try:
        config = ConfigService.get_active_config()
        
        # Only expose non-sensitive configuration needed for login/register pages
        public_config = {
            'auth': {
                'allow_registration': config.get('auth', {}).get('allow_registration', True),
                'allow_user_login': config.get('auth', {}).get('allow_user_login', True)
            }
        }
        
        return jsonify({
            'config': public_config,
            'message': 'Authentication configuration retrieved successfully'
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to retrieve configuration: {str(e)}'}), 500

# The end.
