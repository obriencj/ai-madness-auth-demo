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

from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, g

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
        # Use injected client instead of direct requests
        response = g.client.auth.get_account_info()
        
        if response.is_success:
            return response.data.get('user')
        return None
    except Exception:
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
            # Use injected client instead of direct requests
            response = g.client.auth.login(username, password)
            
            if response.is_success:
                session['access_token'] = response.data.get('access_token')
                session['user'] = response.data.get('user')
                session['is_admin'] = response.data.get('user', {}).get('is_admin')
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard.dashboard'))
            else:
                flash(response.message, 'error')
        except Exception as e:
            flash(f'Connection error: {str(e)}', 'error')
    
    # Get configuration to check if registration is allowed and get OAuth providers
    config = {}
    try:
        # Use injected client instead of direct requests
        config_response = g.client.test()
        if config_response.is_success:
            # Fetch public configuration using the DaftGila client
            public_config_response = g.client.config.get_public()
            if public_config_response.is_success:
                config = public_config_response.data.get('config', {})
        print(f"Login: Loaded configuration with OAuth enabled: {config.get('oauth', {}).get('enabled', False)}")
        print(f"Login: Loaded configuration with GSSAPI enabled: {config.get('gssapi', {}).get('enabled', False)}")
    except Exception as e:
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
            # Use injected client instead of direct requests
            g.client.auth.logout()
        except Exception:
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
            # Use injected client instead of direct requests
            response = g.client.auth.register(username, email, password)
            
            if response.is_success:
                session['access_token'] = response.data.get('access_token')
                session['user'] = response.data.get('user')
                session['is_admin'] = response.data.get('user', {}).get('is_admin')
                flash('Registration successful!', 'success')
                return redirect(url_for('dashboard.dashboard'))
            else:
                flash(f'Registration error: {response.message}', 'error')
        except Exception as e:
            flash(f'Connection error: {str(e)}', 'error')
    
    # Get configuration to check if registration is allowed and get OAuth providers
    config = {}
    try:
        # Use injected client instead of direct requests
        config_response = g.client.test()
        if config_response.is_success:
            # Fetch public configuration using the DaftGila client
            public_config_response = g.client.config.get_public()
            if public_config_response.is_success:
                config = public_config_response.data.get('config', {})
        print(f"Register: Loaded configuration with OAuth enabled: {config.get('oauth', {}).get('enabled', False)}")
        print(f"Register: Found {len(config.get('oauth', {}).get('providers', []))} OAuth providers in config")
        if config.get('gssapi', {}).get('enabled', False) and config.get('gssapi', {}).get('realms'):
            print(f"Register: Found {len(config['gssapi']['realms'])} GSSAPI realms in config")
        else:
            print(f"Register: GSSAPI realms in config: {config.get('gssapi', {}).get('realms', [])}")
    except Exception as e:
        print(f"Register: Connection error loading configuration: {e}")
        pass  # Use default values if config service is unavailable
    
    return render_template('register.html', config=config)


# The end.
