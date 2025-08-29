"""
User blueprint for the Daft Gila web frontend.

This module handles all user account management routes including:
- User profile updates
- OAuth account linking and management
- Account settings and preferences

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import requests
from flask import Blueprint, render_template, request, redirect, url_for, flash, session

# Import shared utilities
from .utils import BACKEND_URL, extract_api_data

# Create user blueprint
user_bp = Blueprint('user', __name__, url_prefix='/account')

# Import decorators from auth blueprint
from .auth import login_required

@user_bp.route('/')
@login_required
def account():
    """User account management page"""
    if 'user' not in session:
        return redirect(url_for('auth.login'))
    
    response = requests.get(f"{BACKEND_URL}/api/v1/account")
    account = extract_api_data(response, 'user', default={})
    # Get configuration to check if OAuth is enabled
    config = {}
    try:
        config_response = requests.get(f'{BACKEND_URL}/api/v1/auth/config')
        config = extract_api_data(config_response, 'config', default={})
    except requests.RequestException:
        pass  # Use default values if config service is unavailable
    
    return render_template('account.html', account=account, config=config)

@user_bp.route('/update', methods=['POST'])
@login_required
def update_account():
    """Update user account information"""
    if 'user' not in session:
        return redirect(url_for('auth.login'))
    
    user_id = session['user']['id']
    
    data = {
        'email': request.form.get('email')
    }
    
    password = request.form.get('password')
    if password:
        data['password'] = password
    
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.put(
            f'{BACKEND_URL}/api/v1/users/{user_id}',
            json=data, headers=headers
        )
        
        if response.status_code == 200:
            # Update session with new user data
            updated_user = extract_api_data(response, 'user')
            if updated_user:
                session['user'] = updated_user
            flash('Account updated successfully', 'success')
        else:
            error_message = extract_api_data(response, 'error', default='Unknown error')
            flash(f'Error: {error_message}', 'error')
    except requests.RequestException:
        flash('Connection error', 'error')
    
    return redirect(url_for('user.account'))

@user_bp.route('/oauth/<int:oauth_account_id>/remove', methods=['POST'])
@login_required
def remove_oauth_account(oauth_account_id):
    """Remove OAuth account from user"""
    if 'user' not in session:
        return redirect(url_for('auth.login'))
    
    user_id = session['user']['id']
    
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.delete(
            f'{BACKEND_URL}/api/v1/users/{user_id}/oauth-accounts/{oauth_account_id}',
            headers=headers
        )
        
        if response.status_code == 200:
            flash('OAuth account removed successfully', 'success')
        else:
            error_message = extract_api_data(response, 'error', default='Unknown error')
            flash(f'Error: {error_message}', 'error')
    except requests.RequestException:
        flash('Connection error', 'error')
    
    return redirect(url_for('user.account'))

@user_bp.route('/oauth/link/<provider>')
@login_required
def link_oauth_account(provider):
    """Initiate OAuth account linking"""
    if 'user' not in session:
        return redirect(url_for('auth.login'))
    
    # Check if OAuth is enabled in configuration
    try:
        config_response = requests.get(f'{BACKEND_URL}/api/v1/auth/config')
        config = extract_api_data(config_response, 'config', default={})
        if not config.get('auth', {}).get('oauth_enabled', True):
            flash('OAuth authentication is currently disabled', 'error')
            return redirect(url_for('user.account'))
        
        # Check if provider exists in configuration
        oauth_providers = config.get('oauth_providers', [])
        provider_names = [p['name'] for p in oauth_providers]
        if provider not in provider_names:
            flash('Unsupported OAuth provider', 'error')
            return redirect(url_for('user.account'))
    except requests.RequestException:
        flash('Connection error', 'error')
        return redirect(url_for('user.account'))
    
    # Build redirect URI for OAuth callback
    redirect_uri = url_for('user.link_oauth_callback', provider=provider, _external=True)
    
    try:
        response = requests.get(
            f'{BACKEND_URL}/api/v1/auth/oauth/{provider}/authorize',
            params={'redirect_uri': redirect_uri, 'link_account': 'true'}
        )
        
        auth_data = extract_api_data(response)
        if auth_data:
            return redirect(auth_data.get('authorization_url'))
        else:
            flash('Failed to initiate OAuth account linking', 'error')
            return redirect(url_for('user.account'))
    except requests.RequestException:
        flash('Connection error', 'error')
        return redirect(url_for('user.account'))

@user_bp.route('/oauth/link/<provider>/callback')
@login_required
def link_oauth_callback(provider):
    """Handle OAuth account linking callback"""
    if 'user' not in session:
        return redirect(url_for('auth.login'))
    
    # Check if OAuth is enabled in configuration
    try:
        config_response = requests.get(f'{BACKEND_URL}/api/v1/auth/config')
        config = extract_api_data(config_response, 'config', default={})
        if not config.get('auth', {}).get('oauth_enabled', True):
            flash('OAuth authentication is currently disabled', 'error')
            return redirect(url_for('user.account'))
        
        # Check if provider exists in configuration
        oauth_providers = config.get('oauth_providers', [])
        provider_names = [p['name'] for p in oauth_providers]
        if provider not in provider_names:
            flash('Unsupported OAuth provider', 'error')
            return redirect(url_for('user.account'))
    except requests.RequestException:
        flash('Connection error', 'error')
        return redirect(url_for('user.account'))
    
    code = request.args.get('code')
    error = request.args.get('error')
    
    if error:
        flash(f'OAuth error: {error}', 'error')
        return redirect(url_for('user.account'))
    
    if not code:
        flash('Missing authorization code', 'error')
        return redirect(url_for('user.account'))
    
    # Build redirect URI for OAuth callback
    redirect_uri = url_for('user.link_oauth_callback', provider=provider, _external=True)
    
    try:
        response = requests.get(
            f'{BACKEND_URL}/api/v1/auth/oauth/{provider}/callback',
            params={'code': code, 'redirect_uri': redirect_uri, 'link_account': 'true'}
        )
        
        data = extract_api_data(response)
        if data:
            flash(f'OAuth account linked successfully with {provider.title()}!', 'success')
        else:
            error_message = extract_api_data(response, 'error', default='Unknown error')
            flash(f'OAuth linking error: {error_message}', 'error')
    except requests.RequestException:
        flash('Connection error', 'error')
    
    return redirect(url_for('user.account'))

# The end.
