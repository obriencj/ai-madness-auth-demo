"""
Demo application showcasing the authentication service integration.

This application demonstrates how to integrate with the standalone auth service
and provides a simple hello world endpoint with authentication.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Cursor AI (Claude Sonnet 4)
"""

import os
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'demo-secret-key-change-in-production')

# Configuration
AUTH_SERVICE_URL = os.getenv('AUTH_SERVICE_URL', 'http://localhost:5000')


def validate_jwt_token():
    """Validate JWT token with auth service and return user info if valid."""
    if 'access_token' not in session:
        return None
    
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.get(f'{AUTH_SERVICE_URL}/api/v1/me', headers=headers)
        
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
    """Decorator to require authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'access_token' not in session:
            return redirect(url_for('login'))
        
        # Validate JWT token with auth service
        user = validate_jwt_token()
        if not user:
            # Clear invalid session
            session.clear()
            flash('Your session has expired. Please log in again.', 'error')
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function


@app.context_processor
def inject_user():
    """Inject user information into all templates."""
    if 'access_token' in session:
        return {
            'current_user': session.get('user'), 
            'is_authenticated': True
        }
    return {'current_user': None, 'is_authenticated': False}


@app.route('/')
def index():
    """Demo application home page."""
    if 'access_token' in session:
        return redirect(url_for('hello'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page - redirects to auth service."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        try:
            response = requests.post(
                f'{AUTH_SERVICE_URL}/api/v1/auth/login',
                json={'username': username, 'password': password}
            )
            
            if response.status_code == 200:
                data = response.json()
                session['access_token'] = data['access_token']
                session['user'] = data['user']
                session['is_admin'] = data['user']['is_admin']
                flash('Login successful!', 'success')
                return redirect(url_for('hello'))
            else:
                flash('Invalid credentials', 'error')
        except requests.RequestException:
            flash('Connection error to auth service', 'error')
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Logout user."""
    if 'access_token' in session:
        try:
            headers = {'Authorization': f'Bearer {session["access_token"]}'}
            requests.post(f'{AUTH_SERVICE_URL}/api/v1/auth/logout', headers=headers)
        except requests.RequestException:
            pass  # Continue with logout even if auth service is unavailable
    
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/hello')
@login_required
def hello():
    """Protected hello world page."""
    return render_template('hello.html')


@app.route('/api/hello')
@login_required
def api_hello():
    """Protected hello world API endpoint."""
    return jsonify({
        'message': 'Hello from Demo App!',
        'user': session.get('user'),
        'timestamp': '2024-01-01T00:00:00Z'
    })


@app.route('/admin')
@login_required
def admin():
    """Admin dashboard - redirects to auth service admin."""
    if not session.get('is_admin'):
        flash('Admin privileges required', 'error')
        return redirect(url_for('hello'))
    
    # Redirect to auth service admin interface
    return redirect(f'{AUTH_SERVICE_URL}/admin')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)

# The end.
