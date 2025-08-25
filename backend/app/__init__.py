"""
Simplified Flask application using the Authentication Engine.

This app demonstrates the new modular authentication system.
"""

import os
from flask import Flask
from flask_jwt_extended import JWTManager
from auth_engine import AuthEngine, AuthConfig

# Import the existing database instance and models
from .model import db, User, OAuthProvider, OAuthAccount, JWTSession


def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Basic Flask configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Set database URI
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
        'DATABASE_URL',
        'postgresql://auth_user:auth_password@localhost:5432/auth_demo'
    )
    
    # Initialize database first
    db.init_app(app)
    
    # Initialize JWT
    jwt = JWTManager()
    jwt.init_app(app)
    
    # Set up model references for the auth engine
    app.user_model = User
    app.oauth_provider_model = OAuthProvider
    app.oauth_account_model = OAuthAccount
    app.session_model = JWTSession
    
    # Configure authentication engine
    auth_config = AuthConfig({
        'providers': ['password', 'oauth_google', 'oauth_github'],
        'session_store': 'redis',
        'jwt_expiry': '1h',
        'enable_admin': True,
        'enable_oauth': True,
        'enable_session_tracking': True,
        'permissions': ['read', 'write', 'admin']
    })
    
    # Initialize the authentication engine
    auth_engine = AuthEngine(app, auth_config)
    
    # Store auth engine in app context for easy access
    app.auth_engine = auth_engine
    
    # Add only the /hello endpoint as requested
    @app.route('/api/v1/hello', methods=['GET'])
    @auth_engine.require_auth()
    def hello():
        """Protected endpoint requiring authentication."""
        return {'message': 'hello world'}, 200
    
    return app


# Create the application instance
app = create_app()


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)


# The end.
