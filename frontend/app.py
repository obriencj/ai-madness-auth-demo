import os
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')

BACKEND_URL = os.getenv('BACKEND_URL', 'http://localhost:5000')

# OAuth Configuration
OAUTH_PROVIDERS = {
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

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'access_token' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'access_token' not in session:
            print("Admin required: No access token in session")
            return redirect(url_for('login'))
        if not session.get('is_admin'):
            print(f"Admin required: User is not admin. Session: {session}")
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
    
    return render_template('login.html', oauth_providers=OAUTH_PROVIDERS)

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


# OAuth Routes
@app.route('/oauth/<provider>/login')
def oauth_login(provider):
    """Initiate OAuth login flow"""
    if provider not in OAUTH_PROVIDERS:
        flash('Unsupported OAuth provider', 'error')
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
    if provider not in OAUTH_PROVIDERS:
        flash('Unsupported OAuth provider', 'error')
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
            flash(f'Login successful with {OAUTH_PROVIDERS[provider]["name"]}!', 'success')
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
    
    return render_template('register.html', oauth_providers=OAUTH_PROVIDERS)


# Application entry point for Gunicorn
# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=8000, debug=True)
