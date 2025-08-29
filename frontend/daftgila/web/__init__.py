"""
Main application factory for the Daft Gila web frontend.

This module creates and configures the Flask application and registers
all blueprints for the different functional areas of the application.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import os
from flask import Flask, session

def create_app():
    """Create and configure the Flask application"""
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    
    # Register blueprints
    from .auth import auth_bp
    from .admin import admin_bp
    from .user import user_bp
    from .dashboard import dashboard_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(dashboard_bp)
    
    return app


app = create_app()


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


# The end.
