"""
Admin blueprint for the Daft Gila web frontend.

This module handles all administrative routes including:
- User management (create, update, delete)
- OAuth provider management
- JWT session management
- GSSAPI realm management
- System configuration

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, session, g
from flask import jsonify

# Create admin blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Import decorators from auth package
from .auth import admin_required

@admin_bp.route('/')
@admin_required
def admin_dashboard():
    """Admin dashboard - user management"""
    try:
        # Use injected client instead of direct requests
        print("Admin route: Fetching users via DaftGilaClient")
        response = g.client.admin.get_users()
        print(f"Admin route: Response success: {response.is_success}")
        
        if response.is_success:
            users = response.data['users']
            print(f"Admin route: Loaded {len(users)} users")
            
            # Fetch OAuth account information for each user
            for user in users:
                try:
                    oauth_response = g.client.admin.get_user_oauth_accounts(user["id"])
                    if oauth_response.is_success:
                        user['oauth_accounts'] = oauth_response.data['oauth_accounts']
                    else:
                        user['oauth_accounts'] = []
                        print(f"Failed to fetch OAuth accounts for user {user['id']}: {oauth_response.message}")
                except Exception as e:
                    user['oauth_accounts'] = []
                    print(f"Exception fetching OAuth accounts for user {user['id']}: {e}")
        else:
            users = []
            flash(f'Error fetching users: {response.message}', 'error')
            print(f"Admin route: Error - {response.message}")
            
    except Exception as e:
        users = []
        flash(f'Connection error: {str(e)}', 'error')
        print(f"Admin route: Connection error - {str(e)}")
    
    return render_template('admin.html', users=users)

@admin_bp.route('/api/users', methods=['POST'])
@admin_required
def create_user():
    """Create new user"""
    data = {
        'username': request.form.get('username'),
        'email': request.form.get('email'),
        'password': request.form.get('password'),
        'is_admin': request.form.get('is_admin') == 'on'
    }
    
    try:
        # Use injected client instead of direct requests
        response = g.client.admin.create_user(
            username=data['username'],
            email=data['email'],
            password=data['password'],
            is_admin=data['is_admin']
        )
        
        if response.is_success:
            flash('User created successfully', 'success')
        else:
            flash(f'Error: {response.message}', 'error')
    except Exception as e:
        flash(f'Connection error: {str(e)}', 'error')
    
    return redirect(url_for('admin.admin'))

@admin_bp.route('/api/users/<int:user_id>', methods=['POST'])
@admin_required
def update_user(user_id):
    """Update existing user"""
    data = {
        'email': request.form.get('email'),
        'is_admin': request.form.get('is_admin') == 'on',
        'is_active': request.form.get('is_active') == 'on'
    }
    
    password = request.form.get('password')
    if password:
        data['password'] = password
    
    try:
        # Use injected client instead of direct requests
        response = g.client.admin.update_user(user_id, **data)
        
        if response.is_success:
            flash('User updated successfully', 'success')
        else:
            flash(f'Error: {response.message}', 'error')
    except Exception as e:
        flash(f'Connection error: {str(e)}', 'error')
    
    return redirect(url_for('admin.admin'))

@admin_bp.route('/api/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Delete user"""
    try:
        # Use injected client instead of direct requests
        response = g.client.admin.delete_user(user_id)
        
        if response.is_success:
            flash('User deleted successfully', 'success')
        else:
            flash(f'Error: {response.message}', 'error')
    except Exception as e:
        flash(f'Connection error: {str(e)}', 'error')
    
    return redirect(url_for('admin.admin'))

@admin_bp.route('/sessions')
@admin_required
def jwt_sessions():
    """JWT sessions management page"""
    try:
        response = g.client.admin.get_jwt_sessions()        
        if response.is_success:
            sessions_data = response.data
            return render_template('jwt_sessions.html', sessions=sessions_data['sessions'])
        else:
            flash('Failed to load JWT sessions', 'error')
            return redirect(url_for('admin.admin_dashboard'))
    except Exception as e:
        flash('Connection error', 'error')
        return redirect(url_for('admin.admin_dashboard'))


@admin_bp.route('/sessions/<int:session_id>/expire', methods=['POST'])
@admin_required
def expire_session(session_id):
    """Expire a specific JWT session"""
    try:
        response = g.client.admin.expire_jwt_session(session_id)
        if response.is_success:
            return jsonify({'message': 'Session expired successfully'}), 200
        else:
            return jsonify({'error': response.message or 'Unknown error'}), 400
    except Exception as e:
        return jsonify({'error': 'Connection error'}), 500


@admin_bp.route('/sessions/expire-all', methods=['POST'])
@admin_required
def expire_all_sessions():
    """Expire all active JWT sessions"""
    try:
        response = g.client.admin.expire_all_jwt_sessions()        
        if response.is_success:
            return jsonify({'message': 'All sessions expired successfully'}), 200
        else:
            return jsonify({'error': response.message or 'Unknown error'}), 400
    except Exception as e:
        return jsonify({'error': 'Connection error'}), 500


@admin_bp.route('/config')
@admin_required
def config_management():
    """Configuration management page"""
    return render_template('config.html')


@admin_bp.route('/api/config/active', methods=['GET'])
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


@admin_bp.route('/api/config/update', methods=['POST'])
@admin_required
def update_config():
    """Update system configuration (admin only)"""
    try:
        data = request.get_json()
        
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
        response = g.client.config.update(data['config_data'])
        
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


@admin_bp.route('/api/config/versions', methods=['GET'])
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


@admin_bp.route('/api/config/versions/<int:version_id>', methods=['GET'])
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


@admin_bp.route('/api/config/versions/<int:version_id>/activate', methods=['POST'])
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


@admin_bp.route('/api/config/cache/status', methods=['GET'])
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


@admin_bp.route('/api/config/cache/refresh', methods=['POST'])
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


@admin_bp.route('/oauth-providers')
@admin_required
def oauth_providers():
    """OAuth provider management page"""
    try:
        # Use injected client instead of direct requests
        response = g.client.admin.get_oauth_providers()
        
        if response.is_success:
            providers = response.data['providers']
        else:
            providers = []
            flash(f'Error fetching OAuth providers: {response.message}', 'error')
            
    except Exception as e:
        providers = []
        flash(f'Connection error: {str(e)}', 'error')
    
    return render_template('oauth_providers.html', providers=providers)

@admin_bp.route('/api/oauth-providers', methods=['POST'])
@admin_required
def create_oauth_provider():
    """Create new OAuth provider"""
    data = {
        'name': request.form.get('name'),
        'client_id': request.form.get('client_id'),
        'client_secret': request.form.get('client_secret'),
        'authorize_url': request.form.get('authorize_url'),
        'token_url': request.form.get('token_url'),
        'userinfo_url': request.form.get('userinfo_url'),
        'scope': request.form.get('scope', 'read profile')
    }
    
    try:
        # Use injected client instead of direct requests
        response = g.client.admin.create_oauth_provider(
            name=data['name'],
            client_id=data['client_id'],
            client_secret=data['client_secret'],
            authorize_url=data['authorize_url'],
            token_url=data['token_url'],
            userinfo_url=data['userinfo_url'],
            scope=data['scope']
        )
        
        if response.is_success:
            flash('OAuth provider created successfully', 'success')
        else:
            flash(f'Error: {response.message}', 'error')
    except Exception as e:
        flash(f'Connection error: {str(e)}', 'error')
    
    return redirect(url_for('admin.oauth_providers'))

@admin_bp.route('/api/oauth-providers/<int:provider_id>', methods=['POST'])
@admin_required
def update_oauth_provider(provider_id):
    """Update OAuth provider"""
    data = {}
    
    # Only include fields that are provided
    if request.form.get('name'):
        data['name'] = request.form.get('name')
    if request.form.get('client_id'):
        data['client_id'] = request.form.get('client_id')
    if request.form.get('client_secret'):
        data['client_secret'] = request.form.get('client_secret')
    if request.form.get('authorize_url'):
        data['authorize_url'] = request.form.get('authorize_url')
    if request.form.get('token_url'):
        data['token_url'] = request.form.get('token_url')
    if request.form.get('userinfo_url'):
        data['userinfo_url'] = request.form.get('userinfo_url')
    if request.form.get('scope'):
        data['scope'] = request.form.get('scope')
    
    if not data:
        flash('No fields to update', 'error')
        return redirect(url_for('admin.oauth_providers'))
    
    try:
        # Use injected client instead of direct requests
        response = g.client.admin.update_oauth_provider(provider_id, **data)
        
        if response.is_success:
            flash('OAuth provider updated successfully', 'success')
        else:
            flash(f'Error: {response.message}', 'error')
    except Exception as e:
        flash(f'Connection error: {str(e)}', 'error')
    
    return redirect(url_for('admin.oauth_providers'))

@admin_bp.route('/api/oauth-providers/<int:provider_id>/delete', methods=['POST'])
@admin_required
def delete_oauth_provider(provider_id):
    """Delete OAuth provider"""
    try:
        # Use injected client instead of direct requests
        response = g.client.admin.delete_oauth_provider(provider_id)
        
        if response.is_success:
            flash('OAuth provider deleted successfully', 'success')
        else:
            flash(f'Error: {response.message}', 'error')
    except Exception as e:
        flash(f'Connection error: {str(e)}', 'error')
    
    return redirect(url_for('admin.oauth_providers'))

@admin_bp.route('/gssapi-realms')
@admin_required
def gssapi_realms():
    """GSSAPI realm management page"""
    try:
        # Use injected client instead of direct requests
        response = g.client.admin.get_gssapi_realms()
        
        if response.is_success:
            realms = response.data['gssapi_realms']
        else:
            realms = []
            flash(f'Error fetching GSSAPI realms: {response.message}', 'error')
            
    except Exception as e:
        realms = []
        flash(f'Connection error: {str(e)}', 'error')
    
    return render_template('gssapi_realms.html', realms=realms)

@admin_bp.route('/api/gssapi-realms', methods=['POST'])
@admin_required
def create_gssapi_realm():
    """Create new GSSAPI realm"""
    data = {
        'name': request.form.get('name'),
        'keytab_data': request.form.get('keytab_data'),
        'description': request.form.get('description', '')
    }
    
    try:
        # Use injected client instead of direct requests
        response = g.client.admin.create_gssapi_realm(
            name=data['name'],
            keytab_data=data['keytab_data'],
            description=data['description']
        )
        
        if response.is_success:
            flash('GSSAPI realm created successfully', 'success')
        else:
            flash(f'Error: {response.message}', 'error')
    except Exception as e:
        flash(f'Connection error: {str(e)}', 'error')
    
    return redirect(url_for('admin.gssapi_realms'))

@admin_bp.route('/api/gssapi-realms/<int:realm_id>', methods=['POST'])
@admin_required
def update_gssapi_realm(realm_id):
    """Update GSSAPI realm"""
    data = {}
    
    # Only include fields that are provided
    if request.form.get('name'):
        data['name'] = request.form.get('name')
    if request.form.get('keytab_data'):
        data['keytab_data'] = request.form.get('keytab_data')
    if request.form.get('description'):
        data['description'] = request.form.get('description')
    
    if not data:
        flash('No fields to update', 'error')
        return redirect(url_for('admin.gssapi_realms'))
    
    try:
        # Use injected client instead of direct requests
        response = g.client.admin.update_gssapi_realm(realm_id, **data)
        
        if response.is_success:
            flash('GSSAPI realm updated successfully', 'success')
        else:
            flash(f'Error: {response.message}', 'error')
    except Exception as e:
        flash(f'Connection error: {str(e)}', 'error')
    
    return redirect(url_for('admin.gssapi_realms'))

@admin_bp.route('/api/gssapi-realms/<int:realm_id>/delete', methods=['POST'])
@admin_required
def delete_gssapi_realm(realm_id):
    """Delete GSSAPI realm"""
    try:
        # Use injected client instead of direct requests
        response = g.client.admin.delete_gssapi_realm(realm_id)
        
        if response.is_success:
            flash('GSSAPI realm deleted successfully', 'success')
        else:
            flash(f'Error: {response.message}', 'error')
    except Exception as e:
        flash(f'Connection error: {str(e)}', 'error')
    
    return redirect(url_for('admin.gssapi_realms'))


@admin_bp.route('/api/users/<int:user_id>/oauth-accounts/<int:oauth_account_id>/remove', methods=['POST'])
@admin_required
def remove_oauth_account(user_id, oauth_account_id):
    """Remove OAuth account from a user (admin only)"""
    try:
        # Use injected client instead of direct requests
        response = g.client.admin.remove_user_oauth_account(user_id, oauth_account_id)
        
        if response.is_success:
            flash('OAuth account removed successfully', 'success')
        else:
            flash(f'Error: {response.message}', 'error')
    except Exception as e:
        flash(f'Connection error: {str(e)}', 'error')
    
    return redirect(url_for('admin.admin_dashboard'))


# The end.
