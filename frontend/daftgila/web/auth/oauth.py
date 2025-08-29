"""
OAuth authentication module for the Daft Gila web frontend.

This module handles OAuth authentication flows:
- OAuth login initiation
- OAuth callback handling
- OAuth provider configuration checks

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import requests
from flask import Blueprint, request, redirect, url_for, flash, session

# Import shared utilities
from ..utils import BACKEND_URL, extract_api_data

# Create OAuth blueprint
oauth_bp = Blueprint('oauth', __name__, url_prefix='/oauth')

@oauth_bp.route('/<provider>/login')
def oauth_login(provider):
    """Initiate OAuth login flow"""
    # Check if OAuth is enabled in configuration
    try:
        config_response = requests.get(f'{BACKEND_URL}/api/v1/auth/config')
        config = extract_api_data(config_response, 'config', default={})
        if not config.get('auth', {}).get('oauth_enabled', True):
            flash('OAuth authentication is currently disabled', 'error')
            return redirect(url_for('auth.login'))
        
        # Check if provider exists in configuration
        oauth_providers = config.get('oauth_providers', [])
        provider_names = [p['name'] for p in oauth_providers]
        if provider not in provider_names:
            flash('Unsupported OAuth provider', 'error')
            return redirect(url_for('auth.login'))
    except requests.RequestException:
        flash('Connection error', 'error')
        return redirect(url_for('auth.login'))
    
    # Build redirect URI for OAuth callback
    redirect_uri = url_for('oauth.oauth_callback', provider=provider, _external=True)
    
    try:
        response = requests.get(
            f'{BACKEND_URL}/api/v1/auth/oauth/{provider}/authorize',
            params={'redirect_uri': redirect_uri}
        )
        
        auth_data = extract_api_data(response)
        if auth_data:
            return redirect(auth_data.get('authorization_url'))
        else:
            flash('Failed to initiate OAuth login', 'error')
            return redirect(url_for('auth.login'))
    except requests.RequestException:
        flash('Connection error', 'error')
        return redirect(url_for('auth.login'))

@oauth_bp.route('/<provider>/callback')
def oauth_callback(provider):
    """Handle OAuth callback"""
    # Check if OAuth is enabled in configuration
    try:
        config_response = requests.get(f'{BACKEND_URL}/api/v1/auth/config')
        config = extract_api_data(config_response, 'config', default={})
        if not config.get('auth', {}).get('oauth_enabled', True):
            flash('OAuth authentication is currently disabled', 'error')
            return redirect(url_for('auth.login'))
        
        # Check if provider exists in configuration
        oauth_providers = config.get('oauth_providers', [])
        provider_names = [p['name'] for p in oauth_providers]
        if provider not in provider_names:
            flash('Unsupported OAuth provider', 'error')
            return redirect(url_for('auth.login'))
    except requests.RequestException:
        flash('Connection error', 'error')
        return redirect(url_for('auth.login'))
    
    code = request.args.get('code')
    error = request.args.get('error')
    
    if error:
        flash(f'OAuth error: {error}', 'error')
        return redirect(url_for('auth.login'))
    
    if not code:
        flash('Missing authorization code', 'error')
        return redirect(url_for('auth.login'))
    
    # Build redirect URI for OAuth callback
    redirect_uri = url_for('oauth.oauth_callback', provider=provider, _external=True)
    
    try:
        response = requests.get(
            f'{BACKEND_URL}/api/v1/auth/oauth/{provider}/callback',
            params={'code': code, 'redirect_uri': redirect_uri}
        )
        
        data = extract_api_data(response)
        if data:
            session['access_token'] = data.get('access_token')
            session['user'] = data.get('user')
            session['is_admin'] = data.get('user', {}).get('is_admin')
            flash(f'Login successful with {provider.title()}!', 'success')
            return redirect(url_for('dashboard.dashboard'))
        else:
            error_message = extract_api_data(response, 'error', default='Unknown error')
            flash(f'OAuth error: {error_message}', 'error')
            return redirect(url_for('auth.login'))
    except requests.RequestException:
        flash('Connection error', 'error')
        return redirect(url_for('auth.login'))

# The end.
