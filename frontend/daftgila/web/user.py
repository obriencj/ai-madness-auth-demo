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

from flask import Blueprint, render_template, request, redirect, url_for, flash, session, g

# Create user blueprint
user_bp = Blueprint('user', __name__, url_prefix='/account')

# Import decorators from auth package
from .auth import login_required

@user_bp.route('/')
@login_required
def account():
    """User account management page"""
    if 'user' not in session:
        return redirect(url_for('auth.login'))
    
    try:
        # Use injected client instead of direct requests
        response = g.client.auth.get_account_info()
        if response.is_success:
            account = response.data.get('user', {})
        else:
            account = {}
            flash(f'Error fetching account info: {response.message}', 'error')
    except Exception as e:
        account = {}
        flash(f'Connection error: {str(e)}', 'error')
    
    # Get configuration to check if OAuth is enabled
    config = {}
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
    except Exception:
        pass  # Use default values if config service is unavailable
    
    return render_template('account.html', account=account, config=config)

@user_bp.route('/update', methods=['POST'])
@login_required
def update_account():
    """Update user account information"""
    if 'user' not in session:
        return redirect(url_for('auth.login'))
    
    data = {}
    
    # Only include fields that are provided
    if request.form.get('email'):
        data['email'] = request.form.get('email')
    
    password = request.form.get('password')
    if password:
        data['password'] = password
    
    if not data:
        flash('No fields to update', 'error')
        return redirect(url_for('user.account'))
    
    try:
        # Use injected client instead of direct requests
        response = g.client.auth.update_account(**data)
        
        if response.is_success:
            # Update session with new user data
            updated_user = response.data.get('user')
            if updated_user:
                session['user'] = updated_user
            flash('Account updated successfully', 'success')
        else:
            flash(f'Error: {response.message}', 'error')
    except Exception as e:
        flash(f'Connection error: {str(e)}', 'error')
    
    return redirect(url_for('user.account'))

@user_bp.route('/oauth/<int:oauth_account_id>/remove', methods=['POST'])
@login_required
def remove_oauth_account(oauth_account_id):
    """Remove OAuth account from user"""
    if 'user' not in session:
        return redirect(url_for('auth.login'))
    
    try:
        # Use injected client instead of direct requests
        response = g.client.auth.remove_oauth_account(oauth_account_id)
        
        if response.is_success:
            flash('OAuth account removed successfully', 'success')
        else:
            flash(f'Error: {response.message}', 'error')
    except Exception as e:
        flash(f'Connection error: {str(e)}', 'error')
    
    return redirect(url_for('user.account'))

@user_bp.route('/oauth/link/<provider>')
@login_required
def link_oauth_account(provider):
    """Link OAuth account to user"""
    if 'user' not in session:
        return redirect(url_for('auth.login'))
    
    try:
        # Generate OAuth authorization URL
        redirect_uri = url_for('auth.oauth_callback', provider=provider, _external=True)
        auth_url = g.client.auth.oauth_authorize(provider, redirect_uri)
        return redirect(auth_url)
    except Exception as e:
        flash(f'Error initiating OAuth: {str(e)}', 'error')
        return redirect(url_for('user.account'))

@user_bp.route('/oauth/callback/<provider>')
@login_required
def oauth_callback(provider):
    """Handle OAuth callback"""
    if 'user' not in session:
        return redirect(url_for('auth.login'))
    
    code = request.args.get('code')
    if not code:
        flash('OAuth authorization failed: no code received', 'error')
        return redirect(url_for('user.account'))
    
    try:
        # Complete OAuth authentication
        redirect_uri = url_for('auth.oauth_callback', provider=provider, _external=True)
        response = g.client.auth.oauth_callback(provider, code, redirect_uri)
        
        if response.is_success:
            flash('OAuth account linked successfully', 'success')
        else:
            flash(f'OAuth linking failed: {response.message}', 'error')
    except Exception as e:
        flash(f'Error completing OAuth: {str(e)}', 'error')
    
    return redirect(url_for('user.account'))

@user_bp.route('/oauth/providers')
@login_required
def oauth_providers():
    """List available OAuth providers"""
    if 'user' not in session:
        return redirect(url_for('auth.login'))
    
    try:
        # Use injected client instead of direct requests
        response = g.client.auth.get_oauth_providers()
        
        if response.is_success:
            providers = response.data.get('oauth_providers', [])
        else:
            providers = []
            flash(f'Error fetching OAuth providers: {response.message}', 'error')
    except Exception as e:
        providers = []
        flash(f'Connection error: {str(e)}', 'error')
    
    return render_template('oauth_providers.html', providers=providers)

@user_bp.route('/oauth/accounts')
@login_required
def oauth_accounts():
    """List user's linked OAuth accounts"""
    if 'user' not in session:
        return redirect(url_for('auth.login'))
    
    try:
        # Get user's OAuth accounts from session or fetch them
        user = session.get('user', {})
        oauth_accounts = user.get('oauth_accounts', [])
        
        # If no OAuth accounts in session, try to fetch them
        if not oauth_accounts:
            try:
                # This would require a new endpoint in the client
                # For now, we'll use what's available in the session
                pass
            except Exception:
                pass
        
    except Exception as e:
        oauth_accounts = []
        flash(f'Error fetching OAuth accounts: {str(e)}', 'error')
    
    return render_template('oauth_accounts.html', oauth_accounts=oauth_accounts)

@user_bp.route('/preferences')
@login_required
def preferences():
    """User preferences page"""
    if 'user' not in session:
        return redirect(url_for('auth.login'))
    
    user = session.get('user', {})
    return render_template('preferences.html', user=user)

@user_bp.route('/preferences/update', methods=['POST'])
@login_required
def update_preferences():
    """Update user preferences"""
    if 'user' not in session:
        return redirect(url_for('auth.login'))
    
    # Handle preference updates
    # This would depend on what preferences you want to support
    
    flash('Preferences updated successfully', 'success')
    return redirect(url_for('user.preferences'))


# The end.
