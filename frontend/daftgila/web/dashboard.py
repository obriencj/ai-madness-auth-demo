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

from flask import Blueprint, render_template, session, redirect, url_for, g

# Create dashboard blueprint
dashboard_bp = Blueprint('dashboard', __name__)

# Import decorators from auth package
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
        # Use injected client instead of direct requests
        response = g.client.hello()
        if response.is_success:
            message = response.message
        else:
            message = 'Hello from frontend! (Backend error)'
        return render_template('hello.html', message=message)
    except Exception:
        return render_template('hello.html', message='Hello from frontend! (Backend unavailable)')

# The end.
