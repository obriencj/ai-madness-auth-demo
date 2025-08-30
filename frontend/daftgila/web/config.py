"""
Configuration blueprint for the Daft Gila web frontend.

This module handles all configuration-related routes including:
- Configuration retrieval and updates
- Configuration versioning
- Configuration caching
- Configuration management interface

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

from flask import Blueprint, render_template, request, jsonify, g
from .auth import admin_required

# Create configuration blueprint
config_bp = Blueprint('config', __name__, url_prefix='/config')


@config_bp.route('/')
@admin_required
def config_management():
    """Configuration management page"""
    return render_template('config.html')


@config_bp.route('/api/active', methods=['GET'])
@admin_required
def get_active_config():
    """Get the currently active configuration (admin only)"""
    try:
        response = g.client.config.get_active()
        
        if response.is_success:
            return jsonify({
                'success': True,
                'data': response.data
            })
        else:
            return jsonify({
                'success': False,
                'message': response.message or 'Failed to retrieve configuration'
            }), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Connection error: {str(e)}'
        }), 500


@config_bp.route('/api/update', methods=['POST'])
@admin_required
def update_config():
    """Update system configuration (admin only)"""
    try:
        data = request.get_json()
        print(f"Update config: {data}")
        print(f"Update config: {data['config_data']}")

        if not data or 'config_data' not in data:
            return jsonify({
                'success': False,
                'message': 'Missing configuration data'
            }), 400
        
        if not data.get('description'):
            return jsonify({
                'success': False,
                'message': 'Description is required for configuration changes'
            }), 400
        
        # Update the configuration using the backend API
        response = g.client.config.update(data)
        
        if response.is_success:
            return jsonify({
                'success': True,
                'message': 'Configuration updated successfully',
                'data': response.data
            })
        else:
            return jsonify({
                'success': False,
                'message': response.message or 'Failed to update configuration'
            }), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Connection error: {str(e)}'
        }), 500


@config_bp.route('/api/versions', methods=['GET'])
@admin_required
def get_config_versions():
    """Get all configuration versions (admin only)"""
    try:
        response = g.client.config.get_versions()
        
        if response.is_success:
            return jsonify({
                'success': True,
                'data': response.data
            })
        else:
            return jsonify({
                'success': False,
                'message': response.message or 'Failed to retrieve configuration versions'
            }), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Connection error: {str(e)}'
        }), 500


@config_bp.route('/api/versions/<int:version_id>', methods=['GET'])
@admin_required
def get_config_version(version_id):
    """Get a specific configuration version (admin only)"""
    try:
        response = g.client.config.get_version(version_id)
        
        if response.is_success:
            return jsonify({
                'success': True,
                'data': response.data
            })
        else:
            return jsonify({
                'success': False,
                'message': response.message or 'Failed to retrieve configuration version'
            }), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Connection error: {str(e)}'
        }), 500


@config_bp.route('/api/versions/<int:version_id>/activate', methods=['POST'])
@admin_required
def activate_config_version(version_id):
    """Activate a configuration version (admin only)"""
    try:
        response = g.client.config.activate_version(version_id)
        
        if response.is_success:
            return jsonify({
                'success': True,
                'message': 'Configuration version activated successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': response.message or 'Failed to activate configuration version'
            }), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Connection error: {str(e)}'
        }), 500


@config_bp.route('/api/cache/status', methods=['GET'])
@admin_required
def get_cache_status():
    """Get configuration cache status (admin only)"""
    try:
        response = g.client.config.get_cache_status()
        
        if response.is_success:
            return jsonify({
                'success': True,
                'data': response.data
            })
        else:
            return jsonify({
                'success': False,
                'message': response.message or 'Failed to retrieve cache status'
            }), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Connection error: {str(e)}'
        }), 500


@config_bp.route('/api/cache/refresh', methods=['POST'])
@admin_required
def refresh_config_cache():
    """Refresh configuration cache (admin only)"""
    try:
        response = g.client.config.refresh_cache()
        
        if response.is_success:
            return jsonify({
                'success': True,
                'message': 'Configuration cache refreshed successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': response.message or 'Failed to refresh cache'
            }), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Connection error: {str(e)}'
        }), 500


# The end.
