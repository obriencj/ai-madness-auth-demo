"""
GSSAPI authentication module for the Daft Gila web frontend.

This module handles GSSAPI/Kerberos authentication:
- GSSAPI login flow
- GSSAPI token validation
- GSSAPI configuration checks

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

from flask import Blueprint, request, redirect, url_for, flash, session, jsonify, g

# Create GSSAPI blueprint
gssapi_bp = Blueprint('gssapi', __name__, url_prefix='/gssapi')

@gssapi_bp.route('/login')
def gssapi_login():
    """GSSAPI login page"""
    # Check if GSSAPI is enabled in configuration
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
        
        if not config.get('auth', {}).get('gssapi_enabled', True):
            flash('GSSAPI authentication is currently disabled', 'error')
            return redirect(url_for('auth.login'))
    except Exception:
        flash('Connection error', 'error')
        return redirect(url_for('auth.login'))
    
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Negotiate '):
        return jsonify({'error': 'GSSAPI authentication token required'}), 401, {'WWW-Authenticate': 'Negotiate'}
        
    # Extract the GSSAPI token from the Authorization header
    gssapi_token = auth_header[10:]  # Remove 'Negotiate ' prefix
        
    # Make request to backend GSSAPI authenticate endpoint
    auth_data = {
        'gssapi_token': gssapi_token
    }
        
    print(f"GSSAPI Auth: Sending to backend: {auth_data}")
        
    try:
        # Use injected client instead of direct requests
        # Note: This would require adding a GSSAPI authenticate method to the client
        # For now, we'll use the HTTP client directly for this specific endpoint
        response = g.client.http.post('/api/v1/auth/gssapi/authenticate', json_data=auth_data)
        
        print(f"GSSAPI Auth: Backend response success: {response.is_success}")
        print(f"GSSAPI Auth: Backend response: {response.message}")
        
        if response.is_success:
            # Set session cookies for the authenticated user
            session['access_token'] = response.data.get('access_token')
            session['user'] = response.data.get('user')
            session['is_admin'] = response.data.get('user', {}).get('is_admin')
            
            print(f"GSSAPI Auth: Session set - access_token: {bool(session.get('access_token'))}, user: {bool(session.get('user'))}, is_admin: {session.get('is_admin')}")
            
            # Redirect to dashboard on successful authentication
            flash('GSSAPI authentication successful!', 'success')
            return redirect(url_for('dashboard.dashboard'))
        else:
            print(f"GSSAPI Auth: Backend error: {response.message}")
            flash(response.message, 'error')
            return redirect(url_for('auth.login'))
    except Exception as e:
        print(f"GSSAPI Auth: Exception: {e}")
        flash(f'GSSAPI authentication failed: {str(e)}', 'error')
        return redirect(url_for('auth.login'))


# The end.
