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

from flask import Blueprint, request, redirect, url_for, flash, session, g

# Create OAuth blueprint
oauth_bp = Blueprint('oauth', __name__, url_prefix='/oauth')

@oauth_bp.route('/<provider>/login')
def oauth_login(provider):
    """Initiate OAuth login flow"""
    # Check if OAuth is enabled in configuration
    try:
        # For now, we'll use a simple approach to get config
        # In a real implementation, you might want to add a config endpoint
        config = {
            'auth': {
                'oauth_enabled': True,
                'gssapi_enabled': True
            },
            'oauth_providers': [],
            'gssapi_realms': []
        }
        
        if not config.get('auth', {}).get('oauth_enabled', True):
            flash('OAuth authentication is currently disabled', 'error')
            return redirect(url_for('auth.login'))
        
        # Check if provider exists in configuration
        oauth_providers = config.get('oauth_providers', [])
        provider_names = [p['name'] for p in oauth_providers]
        if provider not in provider_names:
            flash('Unsupported OAuth provider', 'error')
            return redirect(url_for('auth.login'))
    except Exception:
        flash('Connection error', 'error')
        return redirect(url_for('auth.login'))
    
    # Build redirect URI for OAuth callback
    redirect_uri = url_for('oauth.oauth_callback', provider=provider, _external=True)
    
    try:
        # Use injected client instead of direct requests
        auth_url = g.client.auth.oauth_authorize(provider, redirect_uri)
        return redirect(auth_url)
    except Exception as e:
        flash(f'Connection error: {str(e)}', 'error')
        return redirect(url_for('auth.login'))

@oauth_bp.route('/<provider>/callback')
def oauth_callback(provider):
    """Handle OAuth callback"""
    # Check if OAuth is enabled in configuration
    try:
        # For now, we'll use a simple approach to get config
        # In a real implementation, you might want to add a config endpoint
        config = {
            'auth': {
                'oauth_enabled': True,
                'gssapi_enabled': True
            },
            'oauth_providers': [],
            'gssapi_realms': []
        }
        
        if not config.get('auth', {}).get('oauth_enabled', True):
            flash('OAuth authentication is currently disabled', 'error')
            return redirect(url_for('auth.login'))
        
        # Check if provider exists in configuration
        oauth_providers = config.get('oauth_providers', [])
        provider_names = [p['name'] for p in oauth_providers]
        if provider not in provider_names:
            flash('Unsupported OAuth provider', 'error')
            return redirect(url_for('auth.login'))
    except Exception:
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
        # Use injected client instead of direct requests
        response = g.client.auth.oauth_callback(provider, code, redirect_uri)
        
        if response.is_success:
            # Store authentication data in session
            session['access_token'] = response.data.get('access_token')
            session['user'] = response.data.get('user')
            session['is_admin'] = response.data.get('user', {}).get('is_admin')
            flash(f'OAuth login successful with {provider.title()}!', 'success')
            return redirect(url_for('dashboard.dashboard'))
        else:
            flash(f'OAuth login failed: {response.message}', 'error')
            return redirect(url_for('auth.login'))
    except Exception as e:
        flash(f'Connection error: {str(e)}', 'error')
        return redirect(url_for('auth.login'))


# The end.
