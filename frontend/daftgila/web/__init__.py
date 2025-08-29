"""
Frontend Flask application for the Gilla Auth Demo.

This module provides the frontend web interface for user authentication and management.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import os
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')

BACKEND_URL = os.getenv('BACKEND_URL', 'http://localhost:5000')

def extract_api_data(response, *keys, default=None):
    """
    Extract data from an API response with success checking and data extraction.
    
    This helper function handles the common pattern of:
    1. Getting JSON from response
    2. Checking success value
    3. Extracting data dict from response
    4. Getting specific values from the data dict
    
    Args:
        response: The requests.Response object from an API call
        *keys: Variable number of keys to extract from the data dict
        default: Default value to return if any step fails
        
    Returns:
        - If no keys provided: The entire data dict
        - If one key provided: The value for that key
        - If multiple keys provided: A tuple of values for those keys
        - If any step fails: The default value (or None if not specified)
        
    Examples:
        # Get entire data dict
        data = extract_api_data(response)
        
        # Get single value
        users = extract_api_data(response, 'users', default=[])
        
        # Get multiple values
        users, count = extract_api_data(response, 'users', 'total_count', default=([], 0))
    """
    try:
        if response.status_code != 200:
            return default
            
        response_data = response.json()
        if not response_data.get('success'):
            return default
            
        data = response_data.get('data', {})
        
        if not keys:
            return data
            
        if len(keys) == 1:
            return data.get(keys[0], default)
            
        # Multiple keys - return tuple
        return tuple(data.get(key, default) for key in keys)
        
    except (ValueError, KeyError, AttributeError):
        return default


@app.context_processor
def inject_user():
    """Inject user information into all templates"""
    if 'access_token' in session:
        # Use session data for template context to avoid circular imports
        return {
            'current_user': session.get('user'), 
            'is_authenticated': True
        }
    
    return {'current_user': None, 'is_authenticated': False}

# OAuth Provider Display Configuration
OAUTH_PROVIDER_DISPLAY = {
    'google': {
        'name': 'Google',
        'color': '#4285f4',
        'icon': 'fab fa-google'
    },
    'github': {
        'name': 'GitHub',
        'color': '#333',
        'icon': 'fab fa-github'
    }
}

def validate_jwt_token():
    """Validate JWT token with backend and return user info if valid"""
    if 'access_token' not in session:
        return None
    
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.get(f'{BACKEND_URL}/api/v1/auth/me', headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            # Update session with fresh user data
            session['user'] = data['user']
            session['is_admin'] = data['user']['is_admin']
            return data['user']
        else:
            # Token is invalid or expired
            print(f"JWT validation failed: {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"JWT validation error: {e}")
        return None


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'access_token' not in session:
            return redirect(url_for('login'))
        
        # Validate JWT token with backend
        user = validate_jwt_token()
        if not user:
            # Clear invalid session
            session.clear()
            flash('Your session has expired. Please log in again.', 'error')
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'access_token' not in session:
            print("Admin required: No access token in session")
            return redirect(url_for('login'))
        
        # Validate JWT token with backend
        user = validate_jwt_token()
        if not user:
            # Clear invalid session
            session.clear()
            flash('Your session has expired. Please log in again.', 'error')
            return redirect(url_for('login'))
        
        if not user.get('is_admin'):
            print(f"Admin required: User is not admin. User: {user}")
            flash('Admin privileges required', 'error')
            return redirect(url_for('dashboard'))
        
        print(f"Admin required: User is admin, proceeding")
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'access_token' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        try:
            response = requests.post(
                f'{BACKEND_URL}/api/v1/auth/login',
                json={'username': username, 'password': password}
            )
            
            if response.status_code == 200:
                data = response.json()
                session['access_token'] = data['access_token']
                session['user'] = data['user']
                session['is_admin'] = data['user']['is_admin']
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials', 'error')
        except requests.RequestException:
            flash('Connection error', 'error')
    
    # Get configuration to check if registration is allowed and get OAuth providers
    config = {}
    try:
        config_response = requests.get(f'{BACKEND_URL}/api/v1/auth/config')
        if config_response.status_code == 200:
            config_response_data = config_response.json()
            config = config_response_data.get('data', {}).get('config', {}) if config_response_data.get('success') else {}
            print(f"Login: Loaded configuration with OAuth enabled: {config.get('auth', {}).get('oauth_enabled', True)}")
            print(f"Login: Loaded configuration with GSSAPI enabled: {config.get('auth', {}).get('gssapi_enabled', True)}")
            if config.get('auth', {}).get('oauth_enabled', True) and config.get('oauth_providers'):
                print(f"Login: Found {len(config['oauth_providers'])} OAuth providers in config")
            if config.get('auth', {}).get('gssapi_enabled', True) and config.get('gssapi_realms'):
                print(f"Login: Found {len(config['gssapi_realms'])} GSSAPI realms in config")
            else:
                print(f"Login: GSSAPI realms in config: {config.get('gssapi_realms', [])}")
        else:
            print(f"Login: Failed to load configuration, status: {config_response.status_code}")
    except requests.RequestException as e:
        print(f"Login: Connection error loading configuration: {e}")
        pass  # Use default values if config service is unavailable
    
    return render_template('login.html', config=config)

@app.route('/api/validate-session')
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


@app.route('/logout')
def logout():
    if 'access_token' in session:
        try:
            headers = {'Authorization': f'Bearer {session["access_token"]}'}
            requests.post(f'{BACKEND_URL}/api/v1/auth/logout', headers=headers)
        except requests.RequestException:
            pass
    
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/admin')
@admin_required
def admin():
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

@app.route('/hello')
@login_required
def hello():
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.get(f'{BACKEND_URL}/api/v1/hello', headers=headers)
        
        message = extract_api_data(response, 'message', default='Hello World')
    except requests.RequestException:
        message = 'Connection error'
    
    return render_template('hello.html', message=message)

@app.route('/api/users', methods=['POST'])
@admin_required
def create_user():
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
    
    return redirect(url_for('admin'))


@app.route('/api/users/<int:user_id>', methods=['POST'])
@admin_required
def update_user(user_id):
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
    
    return redirect(url_for('admin'))


@app.route('/api/users/<int:user_id>/oauth-accounts/<int:oauth_account_id>/remove', methods=['POST'])
@admin_required
def admin_remove_user_oauth_account(user_id, oauth_account_id):
    """Admin remove OAuth account from a user"""
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
    
    return redirect(url_for('admin'))


@app.route('/admin/oauth-providers')
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
            return redirect(url_for('admin'))
    except requests.RequestException:
        flash('Connection error', 'error')
        return redirect(url_for('admin'))


@app.route('/admin/oauth-providers/create', methods=['POST'])
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
    
    return redirect(url_for('oauth_providers'))


@app.route('/admin/oauth-providers/<int:provider_id>/update', methods=['POST'])
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
    
    return redirect(url_for('oauth_providers'))


@app.route('/admin/oauth-providers/<int:provider_id>/delete', methods=['POST'])
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
    
    return redirect(url_for('oauth_providers'))


@app.route('/admin/sessions')
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
            return redirect(url_for('admin'))
    except requests.RequestException:
        flash('Connection error', 'error')
        return redirect(url_for('admin'))


@app.route('/admin/config')
@admin_required
def config_management():
    """Configuration management page"""
    return render_template('config.html')


@app.route('/admin/sessions/<int:session_id>/expire', methods=['POST'])
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


@app.route('/admin/sessions/expire-all', methods=['POST'])
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


# GSSAPI Routes
@app.route('/gssapi/login')
def gssapi_login():
    """ GSSAPI login page """
    # Check if GSSAPI is enabled in configuration
    try:
        config_response = requests.get(f'{BACKEND_URL}/api/v1/auth/config')
        if config_response.status_code == 200:
            config_response_data = config_response.json()
            config = config_response_data.get('data', {}).get('config', {}) if config_response_data.get('success') else {}
            if not config.get('auth', {}).get('gssapi_enabled', True):
                flash('GSSAPI authentication is currently disabled', 'error')
                return redirect(url_for('login'))
        else:
            flash('Failed to load configuration', 'error')
            return redirect(url_for('login'))
    except requests.RequestException:
        flash('Connection error', 'error')
        return redirect(url_for('login'))
    
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
            return redirect(url_for('dashboard'))
        else:
            error_message = extract_api_data(response, 'error', default='GSSAPI authentication failed')
            print(f"GSSAPI Auth: Backend error: {error_message}")
            flash(error_message, 'error')
            return redirect(url_for('login'))
    
# GSSAPI Admin Routes
@app.route('/admin/gssapi-realms')
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
            return redirect(url_for('admin'))
    except requests.RequestException:
        flash('Connection error', 'error')
        return redirect(url_for('admin'))


@app.route('/admin/gssapi-realms/create', methods=['POST'])
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
            return redirect(url_for('gssapi_realms'))
    
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
    
    return redirect(url_for('gssapi_realms'))


@app.route('/admin/gssapi-realms/<int:realm_id>/update', methods=['POST'])
@admin_required
def update_gssapi_realm(realm_id):
    """Update GSSAPI realm"""
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
            return redirect(url_for('gssapi_realms'))
    
    data = {
        'name': request.form.get('name'),
        'realm': request.form.get('realm'),
        'kdc_hosts': request.form.get('kdc_hosts').split(',') if request.form.get('kdc_hosts') else [],
        'admin_server': request.form.get('admin_server') or None,
        'service_principal': request.form.get('service_principal'),
        'default_realm': request.form.get('default_realm') == 'on',
        'is_active': request.form.get('is_active') == 'on'
    }
    
    # Only include keytab_data if new file was uploaded
    if keytab_data:
        data['keytab_data'] = keytab_data
    
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
    
    return redirect(url_for('gssapi_realms'))


@app.route('/admin/gssapi-realms/<int:realm_id>/delete', methods=['POST'])
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
    
    return redirect(url_for('gssapi_realms'))


# OAuth Routes
@app.route('/oauth/<provider>/login')
def oauth_login(provider):
    """Initiate OAuth login flow"""
    # Check if OAuth is enabled in configuration
    try:
        config_response = requests.get(f'{BACKEND_URL}/api/v1/auth/config')
        if config_response.status_code == 200:
            config = config_response.json().get('config', {})
            if not config.get('auth', {}).get('oauth_enabled', True):
                flash('OAuth authentication is currently disabled', 'error')
                return redirect(url_for('login'))
            
            # Check if provider exists in configuration
            oauth_providers = config.get('oauth_providers', [])
            provider_names = [p['name'] for p in oauth_providers]
            if provider not in provider_names:
                flash('Unsupported OAuth provider', 'error')
                return redirect(url_for('login'))
        else:
            flash('Failed to load configuration', 'error')
            return redirect(url_for('login'))
    except requests.RequestException:
        flash('Connection error', 'error')
        return redirect(url_for('login'))
    
    # Build redirect URI for OAuth callback
    redirect_uri = url_for('oauth_callback', provider=provider, _external=True)
    
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
            return redirect(url_for('login'))
    except requests.RequestException:
        flash('Connection error', 'error')
        return redirect(url_for('login'))


@app.route('/oauth/<provider>/callback')
def oauth_callback(provider):
    """Handle OAuth callback"""
    # Check if OAuth is enabled in configuration
    try:
        config_response = requests.get(f'{BACKEND_URL}/api/v1/auth/config')
        if config_response.status_code == 200:
            config = config_response.json().get('config', {})
            if not config.get('auth', {}).get('oauth_enabled', True):
                flash('OAuth authentication is currently disabled', 'error')
                return redirect(url_for('login'))
            
            # Check if provider exists in configuration
            oauth_providers = config.get('oauth_providers', [])
            provider_names = [p['name'] for p in oauth_providers]
            if provider not in provider_names:
                flash('Unsupported OAuth provider', 'error')
                return redirect(url_for('login'))
        else:
            flash('Failed to load configuration', 'error')
            return redirect(url_for('login'))
    except requests.RequestException:
        flash('Connection error', 'error')
        return redirect(url_for('login'))
    
    code = request.args.get('code')
    error = request.args.get('error')
    
    if error:
        flash(f'OAuth error: {error}', 'error')
        return redirect(url_for('login'))
    
    if not code:
        flash('Missing authorization code', 'error')
        return redirect(url_for('login'))
    
    # Build redirect URI for OAuth callback
    redirect_uri = url_for('oauth_callback', provider=provider, _external=True)
    
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
            return redirect(url_for('dashboard'))
        else:
            error_message = extract_api_data(response, 'error', default='Unknown error')
            flash(f'OAuth error: {error_message}', 'error')
            return redirect(url_for('login'))
    except requests.RequestException:
        flash('Connection error', 'error')
        return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
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
                return redirect(url_for('dashboard'))
            else:
                error_message = extract_api_data(response, 'error', default='Unknown error')
                flash(f'Registration error: {error_message}', 'error')
        except requests.RequestException:
            flash('Connection error', 'error')
    
    # Get configuration to check if registration is allowed and get OAuth providers
    config = {}
    try:
        config_response = requests.get(f'{BACKEND_URL}/api/v1/auth/config')
        if config_response.status_code == 200:
            config_response_data = config_response.json()
            config = config_response_data.get('data', {}).get('config', {}) if config_response_data.get('success') else {}
            print(f"Register: Loaded configuration with OAuth enabled: {config.get('auth', {}).get('oauth_enabled', True)}")
            print(f"Register: Loaded configuration with GSSAPI enabled: {config.get('auth', {}).get('gssapi_enabled', True)}")
            if config.get('auth', {}).get('oauth_enabled', True) and config.get('oauth_providers'):
                print(f"Register: Found {len(config['oauth_providers'])} OAuth providers in config")
            if config.get('auth', {}).get('gssapi_enabled', True) and config.get('gssapi_realms'):
                print(f"Register: Found {len(config['gssapi_realms'])} GSSAPI realms in config")
            else:
                print(f"Register: GSSAPI realms in config: {config.get('gssapi_realms', [])}")
        else:
            print(f"Register: Failed to load configuration, status: {config_response.status_code}")
    except requests.RequestException as e:
        print(f"Register: Connection error loading configuration: {e}")
        pass  # Use default values if config service is unavailable
    
    return render_template('register.html', config=config)


@app.route('/account')
@login_required
def account():
    """User account management page"""
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        
        # Get user account information
        response = requests.get(
            f'{BACKEND_URL}/api/v1/auth/account',
            headers=headers
        )
        
        account_data = extract_api_data(response)
        if account_data:
            # Get available OAuth providers for linking from public config
            available_providers = []
            try:
                config_response = requests.get(f'{BACKEND_URL}/api/v1/auth/config')
                config = extract_api_data(config_response, 'config', default={})
                if config.get('auth', {}).get('oauth_enabled', True):
                    oauth_providers = config.get('oauth_providers', [])
                    # Filter out providers that are already connected
                    connected_providers = {acc['provider'] for acc in account_data.get('user', {}).get('oauth_accounts', [])}
                    available_providers = [p for p in oauth_providers if p['name'] not in connected_providers]
                    print(f"Account: Found {len(available_providers)} available OAuth providers for linking")
            except requests.RequestException as e:
                print(f"Account: Connection error loading configuration: {e}")
                # Fallback to empty list if config service is unavailable
            
            return render_template('account.html', 
                                account=account_data.get('user', {}),
                                available_oauth_providers=available_providers)
        else:
            flash('Failed to load account information', 'error')
            return redirect(url_for('dashboard'))
    except requests.RequestException:
        flash('Connection error', 'error')
        return redirect(url_for('dashboard'))


@app.route('/account/update', methods=['POST'])
@login_required
def update_account():
    """Update user account information"""
    data = {
        'email': request.form.get('email')
    }
    
    password = request.form.get('password')
    if password:
        data['password'] = password
    
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.put(
            f'{BACKEND_URL}/api/v1/auth/account',
            json=data, headers=headers
        )
        
        if response.status_code == 200:
            flash('Account updated successfully', 'success')
            # Update session data
            session['user']['email'] = data['email']
        else:
            error_message = extract_api_data(response, 'error', default='Unknown error')
            flash(f'Error: {error_message}', 'error')
    except requests.RequestException:
        flash('Connection error', 'error')
    
    return redirect(url_for('account'))


@app.route('/account/oauth/<int:oauth_account_id>/remove', methods=['POST'])
@login_required
def remove_oauth_account(oauth_account_id):
    """Remove OAuth account from user"""
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.delete(
            f'{BACKEND_URL}/api/v1/auth/account/oauth/{oauth_account_id}',
            headers=headers
        )
        
        if response.status_code == 200:
            flash('OAuth account removed successfully', 'success')
        else:
            error_message = extract_api_data(response, 'error', default='Unknown error')
            flash(f'Error: {error_message}', 'error')
    except requests.RequestException:
        flash('Connection error', 'error')
    
    return redirect(url_for('account'))


@app.route('/account/oauth/link/<provider>')
@login_required
def link_oauth_account(provider):
    """Initiate OAuth account linking for logged-in user"""
    try:
        # Check if OAuth is enabled and provider exists using public config
        config_response = requests.get(f'{BACKEND_URL}/api/v1/auth/config')
        if config_response.status_code == 200:
            config_response_data = config_response.json()
            config = config_response_data.get('data', {}).get('config', {}) if config_response_data.get('success') else {}
            if not config.get('auth', {}).get('oauth_enabled', True):
                flash('OAuth authentication is currently disabled', 'error')
                return redirect(url_for('account'))
            
            # Check if provider exists in configuration
            oauth_providers = config.get('oauth_providers', [])
            provider_names = [p['name'] for p in oauth_providers]
            if provider not in provider_names:
                flash('OAuth provider not available', 'error')
                return redirect(url_for('account'))
        else:
            flash('Failed to load configuration', 'error')
            return redirect(url_for('account'))
        
        # Check if user already has this provider connected
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        account_response = requests.get(f'{BACKEND_URL}/api/v1/auth/account', headers=headers)
        if account_response.status_code == 200:
            account_data = account_response.json()
            connected_providers = {acc['provider'] for acc in account_data['user']['oauth_accounts']}
            if provider in connected_providers:
                flash(f'You already have {provider.title()} connected to your account', 'info')
                return redirect(url_for('account'))
        
        # Build redirect URI for OAuth linking callback
        redirect_uri = url_for('link_oauth_callback', provider=provider, _external=True)
        
        # Initiate OAuth linking
        response = requests.get(
            f'{BACKEND_URL}/api/v1/auth/oauth/{provider}/authorize',
            params={'redirect_uri': redirect_uri}
        )
        
        auth_data = extract_api_data(response)
        if auth_data:
            return redirect(auth_data.get('authorization_url'))
        else:
            flash('Failed to initiate OAuth linking', 'error')
            return redirect(url_for('account'))
    except requests.RequestException:
        flash('Connection error', 'error')
        return redirect(url_for('account'))


@app.route('/account/oauth/link/<provider>/callback')
@login_required
def link_oauth_callback(provider):
    """Handle OAuth linking callback"""
    code = request.args.get('code')
    error = request.args.get('error')
    
    if error:
        flash(f'OAuth linking error: {error}', 'error')
        return redirect(url_for('account'))
    
    if not code:
        flash('Missing authorization code', 'error')
        return redirect(url_for('account'))
    
    # Build redirect URI for OAuth linking callback
    redirect_uri = url_for('link_oauth_callback', provider=provider, _external=True)
    
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.get(
            f'{BACKEND_URL}/api/v1/auth/oauth/{provider}/link',
            params={'code': code, 'redirect_uri': redirect_uri},
            headers=headers
        )
        
        if response.status_code == 200:
            flash(f'Successfully linked {provider.title()} to your account!', 'success')
        else:
            error_message = extract_api_data(response, 'error', default='Unknown error')
            flash(f'OAuth linking error: {error_message}', 'error')
    except requests.RequestException:
        flash('Connection error', 'error')
    
    return redirect(url_for('account'))


# Application entry point for Gunicorn
# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=8000, debug=True)

# The end.
