"""
Dashboard blueprint for the Daft Gila web frontend.

This module handles general user routes including:
- User dashboard
- Simple hello endpoint
- General user-facing pages

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import requests
from flask import Blueprint, render_template, session, redirect, url_for

# Import shared utilities
from .utils import BACKEND_URL, extract_api_data

# Create dashboard blueprint
dashboard_bp = Blueprint('dashboard', __name__)

# Import decorators from auth blueprint
from .auth import login_required

@dashboard_bp.route('/dashboard')
@login_required
def dashboard():
    """User dashboard page"""
    if 'user' not in session:
        return redirect(url_for('auth.login'))
    
    user = session['user']
    return render_template('dashboard.html', user=user)

@dashboard_bp.route('/hello')
def hello():
    """Simple hello endpoint for testing"""
    try:
        response = requests.get(f'{BACKEND_URL}/api/v1/hello')
        message = extract_api_data(response, 'message', default='Hello from frontend!')
        return render_template('hello.html', message=message)
    except requests.RequestException:
        return render_template('hello.html', message='Hello from frontend! (Backend unavailable)')

# The end.
