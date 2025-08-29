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

import requests
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask import jsonify # Added missing import for jsonify

# Import shared utilities
from .utils import BACKEND_URL, extract_api_data

# Create admin blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Import decorators from auth package
from .auth.core import admin_required

@admin_bp.route('/')
@admin_required
def admin():
    """Admin dashboard - user management"""
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        print(f"Admin route: Making request to {BACKEND_URL}/api/v1/admin/users")
        response = requests.get(f'{BACKEND_URL}/api/v1/admin/users', headers=headers)
        print(f"Admin route: Response status: {response.status_code}")
        
        users = extract_api_data(response, 'users', default=[])
        print(f"Admin route: Loaded {len(users)} users")
        
        # Fetch OAuth account information for each user
        for user in users:
            try:
                oauth_response = requests.get(
                    f'{BACKEND_URL}/api/v1/admin/users/{user["id"]}/oauth-accounts',
                    headers=headers
                )
                user['oauth_accounts'] = extract_api_data(oauth_response, 'oauth_accounts', default=[])
            except requests.RequestException:
                user['oauth_accounts'] = []
                print(f"Failed to fetch OAuth accounts for user {user['id']}")
    except requests.RequestException as e:
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
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.post(f'{BACKEND_URL}/api/v1/register', 
                               json=data, headers=headers)
        
        if response.status_code == 201:
            flash('User created successfully', 'success')
        else:
            error_message = extract_api_data(response, 'error', default='Unknown error')
            flash(f'Error: {error_message}', 'error')
    except requests.RequestException:
        flash('Connection error', 'error')
    
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
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.put(
            f'{BACKEND_URL}/api/v1/admin/users/{user_id}',
            json=data, headers=headers
        )
        
        if response.status_code == 200:
            flash('User updated successfully', 'success')
        else:
            error_message = extract_api_data(response, 'error', default='Unknown error')
            flash(f'Error: {error_message}', 'error')
    except requests.RequestException:
        flash('Connection error', 'error')
    
    return redirect(url_for('admin.admin'))

@admin_bp.route('/api/users/<int:user_id>/oauth-accounts/<int:oauth_account_id>/remove', methods=['POST'])
@admin_required
def remove_oauth_account(user_id, oauth_account_id):
    """Remove OAuth account from user"""
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.delete(
            f'{BACKEND_URL}/api/v1/admin/users/{user_id}/oauth-accounts/{oauth_account_id}',
            headers=headers
        )
        
        if response.status_code == 200:
            flash('OAuth account removed successfully', 'success')
        else:
            error_message = extract_api_data(response, 'error', default='Unknown error')
            flash(f'Error: {error_message}', 'error')
    except requests.RequestException:
        flash('Connection error', 'error')
    
    return redirect(url_for('admin.admin'))

@admin_bp.route('/oauth-providers')
@admin_required
def oauth_providers():
    """OAuth provider management page"""
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.get(
            f'{BACKEND_URL}/api/v1/admin/oauth-providers',
            headers=headers
        )
        
        providers = extract_api_data(response, 'providers', default=[])
        if providers:
            return render_template('oauth_providers.html', providers=providers)
        else:
            flash('Failed to load OAuth providers', 'error')
            return redirect(url_for('admin.admin'))
    except requests.RequestException:
        flash('Connection error', 'error')
        return redirect(url_for('admin.admin'))

@admin_bp.route('/oauth-providers/create', methods=['POST'])
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
        'scope': request.form.get('scope'),
        'is_active': request.form.get('is_active') == 'on'
    }
    
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.post(
            f'{BACKEND_URL}/api/v1/admin/oauth-providers',
            json=data, headers=headers
        )
        
        if response.status_code == 201:
            flash('OAuth provider created successfully', 'success')
        else:
            error_message = extract_api_data(response, 'error', default='Unknown error')
            flash(f'Error: {error_message}', 'error')
    except requests.RequestException:
        flash('Connection error', 'error')
    
    return redirect(url_for('admin.oauth_providers'))

@admin_bp.route('/oauth-providers/<int:provider_id>/update', methods=['POST'])
@admin_required
def update_oauth_provider(provider_id):
    """Update OAuth provider"""
    data = {
        'name': request.form.get('name'),
        'client_id': request.form.get('client_id'),
        'authorize_url': request.form.get('authorize_url'),
        'token_url': request.form.get('token_url'),
        'userinfo_url': request.form.get('userinfo_url'),
        'scope': request.form.get('scope'),
        'is_active': request.form.get('is_active') == 'on'
    }
    
    # Only include client_secret if it's provided (to avoid overwriting with empty string)
    client_secret = request.form.get('client_secret')
    if client_secret:
        data['client_secret'] = client_secret
    
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.put(
            f'{BACKEND_URL}/api/v1/admin/oauth-providers/{provider_id}',
            json=data, headers=headers
        )
        
        if response.status_code == 200:
            flash('OAuth provider updated successfully', 'success')
        else:
            error_message = extract_api_data(response, 'error', default='Unknown error')
            flash(f'Error: {error_message}', 'error')
    except requests.RequestException:
        flash('Connection error', 'error')
    
    return redirect(url_for('admin.oauth_providers'))

@admin_bp.route('/oauth-providers/<int:provider_id>/delete', methods=['POST'])
@admin_required
def delete_oauth_provider(provider_id):
    """Delete OAuth provider"""
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.delete(
            f'{BACKEND_URL}/api/v1/admin/oauth-providers/{provider_id}',
            headers=headers
        )
        
        if response.status_code == 200:
            flash('OAuth provider deleted successfully', 'success')
        else:
            error_message = extract_api_data(response, 'error', default='Unknown error')
            flash(f'Error: {error_message}', 'error')
    except requests.RequestException:
        flash('Connection error', 'error')
    
    return redirect(url_for('admin.oauth_providers'))

@admin_bp.route('/sessions')
@admin_required
def jwt_sessions():
    """JWT sessions management page"""
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.get(
            f'{BACKEND_URL}/api/v1/admin/sessions',
            headers=headers
        )
        
        sessions = extract_api_data(response, 'sessions', default=[])
        if sessions:
            return render_template('jwt_sessions.html', sessions=sessions)
        else:
            flash('Failed to load JWT sessions', 'error')
            return redirect(url_for('admin.admin'))
    except requests.RequestException:
        flash('Connection error', 'error')
        return redirect(url_for('admin.admin'))

@admin_bp.route('/config')
@admin_required
def config():
    """System configuration management page"""
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.get(
            f'{BACKEND_URL}/api/v1/admin/config',
            headers=headers
        )
        
        config_data = extract_api_data(response, 'config', default={})
        return render_template('config.html', config=config_data)
    except requests.RequestException:
        flash('Connection error', 'error')
        return redirect(url_for('admin.admin'))

@admin_bp.route('/sessions/<int:session_id>/expire', methods=['POST'])
@admin_required
def expire_session(session_id):
    """Expire a specific JWT session"""
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.post(
            f'{BACKEND_URL}/api/v1/admin/sessions/{session_id}/expire',
            headers=headers
        )
        
        if response.status_code == 200:
            return jsonify({'message': 'Session expired successfully'}), 200
        else:
            error_message = extract_api_data(response, 'error', default='Unknown error')
            return jsonify({'error': error_message}), 400
    except requests.RequestException:
        return jsonify({'error': 'Connection error'}), 500

@admin_bp.route('/sessions/expire-all', methods=['POST'])
@admin_required
def expire_all_sessions():
    """Expire all active JWT sessions"""
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.post(
            f'{BACKEND_URL}/api/v1/admin/sessions/expire-all',
            headers=headers
        )
        
        if response.status_code == 200:
            return jsonify({'message': 'All sessions expired successfully'}), 200
        else:
            error_message = extract_api_data(response, 'error', default='Unknown error')
            return jsonify({'error': error_message}), 400
    except requests.RequestException:
        return jsonify({'error': 'Connection error'}), 500

@admin_bp.route('/gssapi-realms')
@admin_required
def gssapi_realms():
    """GSSAPI realm management page"""
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.get(
            f'{BACKEND_URL}/api/v1/auth/gssapi/realms',
            headers=headers
        )
        
        realms = extract_api_data(response, 'realms', default=[])
        if realms:
            return render_template('gssapi_realms.html', realms=realms)
        else:
            flash('Failed to load GSSAPI realms', 'error')
            return redirect(url_for('admin.admin'))
    except requests.RequestException:
        flash('Connection error', 'error')
        return redirect(url_for('admin.admin'))

@admin_bp.route('/gssapi-realms/create', methods=['POST'])
@admin_required
def create_gssapi_realm():
    """Create new GSSAPI realm"""
    # Handle file upload for keytab
    keytab_file = request.files.get('keytab_file')
    keytab_data = None
    
    if keytab_file and keytab_file.filename:
        try:
            # Read file content and encode as base64
            import base64
            keytab_content = keytab_file.read()
            keytab_data = base64.b64encode(keytab_content).decode('utf-8')
        except Exception as e:
            flash(f'Error processing keytab file: {str(e)}', 'error')
            return redirect(url_for('admin.gssapi_realms'))
    
    data = {
        'name': request.form.get('name'),
        'realm': request.form.get('realm'),
        'kdc_hosts': request.form.get('kdc_hosts').split(',') if request.form.get('kdc_hosts') else [],
        'admin_server': request.form.get('admin_server') or None,
        'service_principal': request.form.get('service_principal'),
        'default_realm': request.form.get('default_realm') == 'on',
        'is_active': request.form.get('is_active') == 'on'
    }
    
    # Only include keytab_data if file was uploaded
    if keytab_data:
        data['keytab_data'] = keytab_data
    
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.post(
            f'{BACKEND_URL}/api/v1/auth/gssapi/realms',
            json=data, headers=headers
        )
        
        if response.status_code == 201:
            flash('GSSAPI realm created successfully', 'success')
        else:
            error_message = extract_api_data(response, 'error', default='Unknown error')
            flash(f'Error: {error_message}', 'error')
    except requests.RequestException:
        flash('Connection error', 'error')
    
    return redirect(url_for('admin.gssapi_realms'))

@admin_bp.route('/gssapi-realms/<int:realm_id>/update', methods=['POST'])
@admin_required
def update_gssapi_realm(realm_id):
    """Update GSSAPI realm"""
    data = {
        'name': request.form.get('name'),
        'realm': request.form.get('realm'),
        'kdc_hosts': request.form.get('kdc_hosts').split(',') if request.form.get('kdc_hosts') else [],
        'admin_server': request.form.get('admin_server') or None,
        'service_principal': request.form.get('service_principal'),
        'default_realm': request.form.get('default_realm') == 'on',
        'is_active': request.form.get('is_active') == 'on'
    }
    
    # Only include keytab_data if it's provided
    keytab_file = request.files.get('keytab_file')
    if keytab_file and keytab_file.filename:
        try:
            import base64
            keytab_content = keytab_file.read()
            data['keytab_data'] = base64.b64encode(keytab_content).decode('utf-8')
        except Exception as e:
            flash(f'Error processing keytab file: {str(e)}', 'error')
            return redirect(url_for('admin.gssapi_realms'))
    
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.put(
            f'{BACKEND_URL}/api/v1/auth/gssapi/realms/{realm_id}',
            json=data, headers=headers
        )
        
        if response.status_code == 200:
            flash('GSSAPI realm updated successfully', 'success')
        else:
            error_message = extract_api_data(response, 'error', default='Unknown error')
            flash(f'Error: {error_message}', 'error')
    except requests.RequestException:
        flash('Connection error', 'error')
    
    return redirect(url_for('admin.gssapi_realms'))

@admin_bp.route('/gssapi-realms/<int:realm_id>/delete', methods=['POST'])
@admin_required
def delete_gssapi_realm(realm_id):
    """Delete GSSAPI realm"""
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.delete(
            f'{BACKEND_URL}/api/v1/auth/gssapi/realms/{realm_id}',
            headers=headers
        )
        
        if response.status_code == 200:
            flash('GSSAPI realm deleted successfully', 'success')
        else:
            error_message = extract_api_data(response, 'error', default='Unknown error')
            flash(f'Error: {error_message}', 'error')
    except requests.RequestException:
        flash('Connection error', 'error')
    
    return redirect(url_for('admin.gssapi_realms'))

# The end.
