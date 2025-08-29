"""
Authentication package for the Daft Gila web frontend.

This package organizes authentication functionality into logical modules:
- Core authentication (login, logout, session validation, user registration)
- OAuth authentication flow
- GSSAPI authentication

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import requests
from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify

# Import shared utilities
from ..utils import BACKEND_URL, extract_api_data

from .oauth import oauth_bp
from .gssapi import gssapi_bp

# Create core auth blueprint
auth_bp = Blueprint('auth', __name__)
auth_bp.register_blueprint(oauth_bp)
auth_bp.register_blueprint(gssapi_bp)

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
        print(f"Register: Found {len(config['oauth_providers'])} OAuth providers in config")
        if config.get('auth', {}).get('gssapi_enabled', True) and config.get('gssapi_realms'):
            print(f"Register: Found {len(config['gssapi_realms'])} GSSAPI realms in config")
        else:
            print(f"Register: GSSAPI realms in config: {config.get('gssapi_realms', [])}")
    except requests.RequestException as e:
        print(f"Register: Connection error loading configuration: {e}")
        pass  # Use default values if config service is unavailable
    
    return render_template('register.html', config=config)


# The end.
