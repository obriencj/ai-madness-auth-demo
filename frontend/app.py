"""
Frontend Flask application for the Gilla Auth Demo.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0

This module provides the frontend web interface for user authentication and management.
"""

import os
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')

BACKEND_URL = os.getenv('BACKEND_URL', 'http://localhost:5000')


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
    
    # Get OAuth providers from backend
    try:
        response = requests.get(f'{BACKEND_URL}/api/v1/auth/oauth/providers')
        if response.status_code == 200:
            oauth_providers = response.json()['providers']
            # Filter to only show active providers (backend should already do this, but double-check)
            oauth_providers = [p for p in oauth_providers if p.get('name')]
            print(f"Login: Loaded {len(oauth_providers)} active OAuth providers: {[p['name'] for p in oauth_providers]}")
        else:
            oauth_providers = []
            print(f"Login: Failed to load OAuth providers, status: {response.status_code}")
    except requests.RequestException as e:
        oauth_providers = []
        print(f"Login: Connection error loading OAuth providers: {e}")
    
    # Get configuration to check if registration is allowed
    config = {}
    try:
        config_response = requests.get(f'{BACKEND_URL}/api/v1/auth/config')
        if config_response.status_code == 200:
            config = config_response.json().get('config', {})
    except requests.RequestException:
        pass  # Use default values if config service is unavailable
    
    return render_template('login.html', oauth_providers=oauth_providers, config=config)

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
        print(f"Admin route: Making request to {BACKEND_URL}/api/v1/users")
        response = requests.get(f'{BACKEND_URL}/api/v1/users', headers=headers)
        print(f"Admin route: Response status: {response.status_code}")
        
        if response.status_code == 200:
            users = response.json()['users']
            print(f"Admin route: Loaded {len(users)} users")
            
            # Fetch OAuth account information for each user
            for user in users:
                try:
                    oauth_response = requests.get(
                        f'{BACKEND_URL}/api/v1/users/{user["id"]}/oauth-accounts',
                        headers=headers
                    )
                    if oauth_response.status_code == 200:
                        oauth_data = oauth_response.json()
                        user['oauth_accounts'] = oauth_data['oauth_accounts']
                    else:
                        user['oauth_accounts'] = []
                except requests.RequestException:
                    user['oauth_accounts'] = []
                    print(f"Failed to fetch OAuth accounts for user {user['id']}")
        else:
            users = []
            error_msg = f'Failed to load users: {response.status_code}'
            if response.status_code != 500:
                try:
                    error_data = response.json()
                    error_msg += f' - {error_data.get("error", "Unknown error")}'
                except:
                    pass
            flash(error_msg, 'error')
            print(f"Admin route: {error_msg}")
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
        
        if response.status_code == 200:
            message = response.json()['message']
        else:
            message = f'Error fetching message: {response.status_code}'
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
            error_data = response.json()
            flash(f'Error: {error_data.get("error", "Unknown error")}', 'error')
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
            f'{BACKEND_URL}/api/v1/users/{user_id}',
            json=data, headers=headers
        )
        
        if response.status_code == 200:
            flash('User updated successfully', 'success')
        else:
            error_data = response.json()
            flash(f'Error: {error_data.get("error", "Unknown error")}', 'error')
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
            f'{BACKEND_URL}/api/v1/users/{user_id}/oauth-accounts/{oauth_account_id}',
            headers=headers
        )
        
        if response.status_code == 200:
            flash('OAuth account removed successfully', 'success')
        else:
            error_data = response.json()
            flash(f'Error: {error_data.get("error", "Unknown error")}', 'error')
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
        
        if response.status_code == 200:
            providers_data = response.json()
            return render_template('oauth_providers.html', providers=providers_data['providers'])
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
            error_data = response.json()
            flash(f'Error: {error_data.get("error", "Unknown error")}', 'error')
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
            error_data = response.json()
            flash(f'Error: {error_data.get("error", "Unknown error")}', 'error')
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
            error_data = response.json()
            flash(f'Error: {error_data.get("error", "Unknown error")}', 'error')
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
        
        if response.status_code == 200:
            sessions_data = response.json()
            return render_template('jwt_sessions.html', sessions=sessions_data['sessions'])
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
            error_data = response.json()
            return jsonify({'error': error_data.get("error", "Unknown error")}), 400
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
            error_data = response.json()
            return jsonify({'error': error_data.get("error", "Unknown error")}), 400
    except requests.RequestException:
        return jsonify({'error': 'Connection error'}), 500


# OAuth Routes
@app.route('/oauth/<provider>/login')
def oauth_login(provider):
    """Initiate OAuth login flow"""
    # Check if provider exists and is active
    try:
        response = requests.get(f'{BACKEND_URL}/api/v1/auth/oauth/providers')
        if response.status_code == 200:
            providers = response.json()['providers']
            provider_names = [p['name'] for p in providers]
            if provider not in provider_names:
                flash('Unsupported OAuth provider', 'error')
                return redirect(url_for('login'))
        else:
            flash('Failed to load OAuth providers', 'error')
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
        
        if response.status_code == 200:
            auth_data = response.json()
            return redirect(auth_data['authorization_url'])
        else:
            flash('Failed to initiate OAuth login', 'error')
            return redirect(url_for('login'))
    except requests.RequestException:
        flash('Connection error', 'error')
        return redirect(url_for('login'))


@app.route('/oauth/<provider>/callback')
def oauth_callback(provider):
    """Handle OAuth callback"""
    # Check if provider exists and is active
    try:
        response = requests.get(f'{BACKEND_URL}/api/v1/auth/oauth/providers')
        if response.status_code == 200:
            providers = response.json()['providers']
            provider_names = [p['name'] for p in providers]
            if provider not in provider_names:
                flash('Unsupported OAuth provider', 'error')
                return redirect(url_for('login'))
        else:
            flash('Failed to load OAuth providers', 'error')
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
        
        if response.status_code == 200:
            data = response.json()
            session['access_token'] = data['access_token']
            session['user'] = data['user']
            session['is_admin'] = data['user']['is_admin']
            flash(f'Login successful with {provider.title()}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            error_data = response.json()
            flash(f'OAuth error: {error_data.get("error", "Unknown error")}', 'error')
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
                data = response.json()
                session['access_token'] = data['access_token']
                session['user'] = data['user']
                session['is_admin'] = data['user']['is_admin']
                flash('Registration successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                error_data = response.json()
                flash(f'Registration error: {error_data.get("error", "Unknown error")}', 'error')
        except requests.RequestException:
            flash('Connection error', 'error')
    
    # Get OAuth providers from backend
    try:
        response = requests.get(f'{BACKEND_URL}/api/v1/auth/oauth/providers')
        if response.status_code == 200:
            oauth_providers = response.json()['providers']
            # Filter to only show active providers (backend should already do this, but double-check)
            oauth_providers = [p for p in oauth_providers if p.get('name')]
            print(f"Register: Loaded {len(oauth_providers)} active OAuth providers: {[p['name'] for p in oauth_providers]}")
        else:
            oauth_providers = []
            print(f"Register: Failed to load OAuth providers, status: {response.status_code}")
    except requests.RequestException as e:
        oauth_providers = []
        print(f"Register: Connection error loading OAuth providers: {e}")
    
    # Get configuration to check if registration is allowed
    config = {}
    try:
        config_response = requests.get(f'{BACKEND_URL}/api/v1/auth/config')
        if config_response.status_code == 200:
            config = config_response.json().get('config', {})
    except requests.RequestException:
        pass  # Use default values if config service is unavailable
    
    return render_template('register.html', oauth_providers=oauth_providers, config=config)


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
        
        if response.status_code == 200:
            account_data = response.json()
            
            # Get available OAuth providers for linking
            oauth_response = requests.get(f'{BACKEND_URL}/api/v1/auth/oauth/providers')
            if oauth_response.status_code == 200:
                available_providers = oauth_response.json()['providers']
                # Filter out providers that are already connected
                connected_providers = {acc['provider'] for acc in account_data['user']['oauth_accounts']}
                available_providers = [p for p in available_providers if p['name'] not in connected_providers]
            else:
                available_providers = []
            
            return render_template('account.html', 
                                account=account_data['user'],
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
            error_data = response.json()
            flash(f'Error: {error_data.get("error", "Unknown error")}', 'error')
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
            error_data = response.json()
            flash(f'Error: {error_data.get("error", "Unknown error")}', 'error')
    except requests.RequestException:
        flash('Connection error', 'error')
    
    return redirect(url_for('account'))


@app.route('/account/oauth/link/<provider>')
@login_required
def link_oauth_account(provider):
    """Initiate OAuth account linking for logged-in user"""
    try:
        # Check if provider exists and is active
        oauth_response = requests.get(f'{BACKEND_URL}/api/v1/auth/oauth/providers')
        if oauth_response.status_code == 200:
            providers = oauth_response.json()['providers']
            provider_names = [p['name'] for p in providers]
            if provider not in provider_names:
                flash('OAuth provider not available', 'error')
                return redirect(url_for('account'))
        else:
            flash('Failed to load OAuth providers', 'error')
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
        
        if response.status_code == 200:
            auth_data = response.json()
            return redirect(auth_data['authorization_url'])
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
            error_data = response.json()
            flash(f'OAuth linking error: {error_data.get("error", "Unknown error")}', 'error')
    except requests.RequestException:
        flash('Connection error', 'error')
    
    return redirect(url_for('account'))


# Application entry point for Gunicorn
# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=8000, debug=True)

# The end.
