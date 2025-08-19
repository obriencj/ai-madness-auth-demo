import os
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')

BACKEND_URL = os.getenv('BACKEND_URL', 'http://localhost/api/v1')

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
            return redirect(url_for('login'))
        if not session.get('is_admin'):
            flash('Admin privileges required', 'error')
            return redirect(url_for('dashboard'))
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
            response = requests.post(f'{BACKEND_URL}/auth/login', 
                                   json={'username': username, 'password': password})
            
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
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'access_token' in session:
        try:
            headers = {'Authorization': f'Bearer {session["access_token"]}'}
            requests.post(f'{BACKEND_URL}/auth/logout', headers=headers)
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
        response = requests.get(f'{BACKEND_URL}/users', headers=headers)
        
        if response.status_code == 200:
            users = response.json()['users']
        else:
            users = []
            flash('Failed to load users', 'error')
    except requests.RequestException:
        users = []
        flash('Connection error', 'error')
    
    return render_template('admin.html', users=users)

@app.route('/hello')
@login_required
def hello():
    try:
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.get(f'{BACKEND_URL}/hello', headers=headers)
        
        if response.status_code == 200:
            message = response.json()['message']
        else:
            message = 'Error fetching message'
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
        response = requests.post(f'{BACKEND_URL}/register', 
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
        response = requests.put(f'{BACKEND_URL}/users/{user_id}', 
                              json=data, headers=headers)
        
        if response.status_code == 200:
            flash('User updated successfully', 'success')
        else:
            error_data = response.json()
            flash(f'Error: {error_data.get("error", "Unknown error")}', 'error')
    except requests.RequestException:
        flash('Connection error', 'error')
    
    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
