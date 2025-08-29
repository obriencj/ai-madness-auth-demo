"""
Authentication blueprint for the Daft Gila web frontend.

This module handles all authentication-related routes including:
- User login/logout
- OAuth authentication flow
- GSSAPI authentication
- User registration
- Session validation

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import requests
from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify

# Import shared utilities
from .utils import BACKEND_URL, extract_api_data

# Create auth blueprint
auth_bp = Blueprint('auth', __name__)

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'access_token' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'access_token' not in session:
            return redirect(url_for('auth.login'))
        if not session.get('is_admin'):
            flash('Admin privileges required', 'error')
            return redirect(url_for('dashboard.dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# JWT token validation
def validate_jwt_token():
    """Validate JWT token and return user data"""
    if 'access_token' not in session:
        return None
    
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.get(f'{BACKEND_URL}/api/v1/auth/validate', headers=headers)
        
        if response.status_code == 200:
            data = extract_api_data(response)
            if data:
                return data.get('user')
        return None
    except requests.RequestException:
        return None

@auth_bp.route('/')
def index():
    """Main landing page - redirect to login"""
    return redirect(url_for('auth.login'))

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('login.html')
        
        try:
            response = requests.post(
                f'{BACKEND_URL}/api/v1/auth/login',
                json={'username': username, 'password': password}
            )
            
            if response.status_code == 200:
                data = extract_api_data(response)
                if data:
                    session['access_token'] = data.get('access_token')
                    session['user'] = data.get('user')
                    session['is_admin'] = data.get('user', {}).get('is_admin')
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard.dashboard'))
                else:
                    flash('Invalid credentials', 'error')
            else:
                error_message = extract_api_data(response, 'error', default='Login failed')
                flash(error_message, 'error')
        except requests.RequestException:
            flash('Connection error', 'error')
    
    # Get configuration to check if OAuth and GSSAPI are enabled
    config = {}
    try:
        config_response = requests.get(f'{BACKEND_URL}/api/v1/auth/config')
        config = extract_api_data(config_response, 'config', default={})
        print(f"Login: Loaded configuration with OAuth enabled: {config.get('auth', {}).get('oauth_enabled', True)}")
        print(f"Login: Loaded configuration with GSSAPI enabled: {config.get('auth', {}).get('gssapi_enabled', True)}")
        if config.get('auth', {}).get('oauth_enabled', True) and config.get('oauth_providers'):
            print(f"Login: Found {len(config['oauth_providers'])} OAuth providers in config")
        if config.get('auth', {}).get('gssapi_enabled', True) and config.get('gssapi_realms'):
            print(f"Login: Found {len(config['gssapi_realms'])} GSSAPI realms in config")
        else:
            print(f"Login: GSSAPI realms in config: {config.get('gssapi_realms', [])}")
    except requests.RequestException as e:
        print(f"Login: Connection error loading configuration: {e}")
        pass  # Use default values if config service is unavailable
    
    return render_template('login.html', config=config)

@auth_bp.route('/api/validate-session')
def validate_session():
    """AJAX endpoint to validate JWT session"""
    if 'access_token' not in session:
        return jsonify({'valid': False, 'message': 'No session found'}), 401
    
    user = validate_jwt_token()
    if user:
        return jsonify({
            'valid': True, 
            'user': user,
            'message': 'Session is valid'
        }), 200
    else:
        return jsonify({
            'valid': False, 
            'message': 'Session has expired'
        }), 401

@auth_bp.route('/logout')
def logout():
    """User logout"""
    if 'access_token' in session:
        try:
            headers = {'Authorization': f'Bearer {session["access_token"]}'}
            requests.post(f'{BACKEND_URL}/api/v1/auth/logout', headers=headers)
        except requests.RequestException:
            pass
    
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([username, email, password, confirm_password]):
            flash('All fields are required', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
        
        try:
            response = requests.post(
                f'{BACKEND_URL}/api/v1/auth/register',
                json={
                    'username': username,
                    'email': email,
                    'password': password
                }
            )
            
            if response.status_code == 201:
                data = extract_api_data(response)
                session['access_token'] = data.get('access_token')
                session['user'] = data.get('user')
                session['is_admin'] = data.get('user', {}).get('is_admin')
                flash('Registration successful!', 'success')
                return redirect(url_for('dashboard.dashboard'))
            else:
                error_message = extract_api_data(response, 'error', default='Unknown error')
                flash(f'Registration error: {error_message}', 'error')
        except requests.RequestException:
            flash('Connection error', 'error')
    
    # Get configuration to check if registration is allowed and get OAuth providers
    config = {}
    try:
        config_response = requests.get(f'{BACKEND_URL}/api/v1/auth/config')
        config = extract_api_data(config_response, 'config', default={})
        print(f"Register: Loaded configuration with OAuth enabled: {config.get('auth', {}).get('oauth_enabled', True)}")
        print(f"Register: Loaded configuration with GSSAPI enabled: {config.get('auth', {}).get('gssapi_enabled', True)}")
        if config.get('auth', {}).get('oauth_enabled', True) and config.get('oauth_providers'):
            print(f"Register: Found {len(config['oauth_providers'])} OAuth providers in config")
        if config.get('auth', {}).get('gssapi_enabled', True) and config.get('gssapi_realms'):
            print(f"Register: Found {len(config['gssapi_realms'])} GSSAPI realms in config")
        else:
            print(f"Register: GSSAPI realms in config: {config.get('gssapi_realms', [])}")
    except requests.RequestException as e:
        print(f"Register: Connection error loading configuration: {e}")
        pass  # Use default values if config service is unavailable
    
    return render_template('register.html', config=config)

@auth_bp.route('/gssapi/login')
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

@auth_bp.route('/oauth/<provider>/login')
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
    redirect_uri = url_for('auth.oauth_callback', provider=provider, _external=True)
    
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

@auth_bp.route('/oauth/<provider>/callback')
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
    redirect_uri = url_for('auth.oauth_callback', provider=provider, _external=True)
    
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
