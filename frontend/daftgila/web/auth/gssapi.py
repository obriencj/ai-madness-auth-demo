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

import requests
from flask import Blueprint, request, redirect, url_for, flash, session, jsonify

# Import shared utilities
from ..utils import BACKEND_URL, extract_api_data

# Create GSSAPI blueprint
gssapi_bp = Blueprint('gssapi', __name__, url_prefix='/gssapi')

@gssapi_bp.route('/login')
def gssapi_login():
    """GSSAPI login page"""
    # Check if GSSAPI is enabled in configuration
    try:
        config_response = requests.get(f'{BACKEND_URL}/api/v1/auth/config')
        config = extract_api_data(config_response, 'config', default={})
        if not config.get('auth', {}).get('gssapi_enabled', True):
            flash('GSSAPI authentication is currently disabled', 'error')
            return redirect(url_for('auth.login'))
    except requests.RequestException:
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
        
    response = requests.post(
        f'{BACKEND_URL}/api/v1/auth/gssapi/authenticate',
        json=auth_data
    )
        
    print(f"GSSAPI Auth: Backend response status: {response.status_code}")
    print(f"GSSAPI Auth: Backend response: {response.text}")
        
    data = extract_api_data(response)
    if data:
        # Set session cookies for the authenticated user
        session['access_token'] = data.get('access_token')
        session['user'] = data.get('user')
        session['is_admin'] = data.get('user', {}).get('is_admin')
        
        print(f"GSSAPI Auth: Session set - access_token: {bool(session.get('access_token'))}, user: {bool(session.get('user'))}, is_admin: {session.get('is_admin')}")
        
        # Redirect to dashboard on successful authentication
        flash('GSSAPI authentication successful!', 'success')
        return redirect(url_for('dashboard.dashboard'))
    else:
        error_message = extract_api_data(response, 'error', default='GSSAPI authentication failed')
        print(f"GSSAPI Auth: Backend error: {error_message}")
        flash(error_message, 'error')
        return redirect(url_for('auth.login'))

# The end.
