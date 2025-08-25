"""
Database models for the Auth Demo application.

This module contains all SQLAlchemy model definitions and database-related functionality.
"""

import bcrypt
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Initialize SQLAlchemy instance (will be configured in app.py)
db = SQLAlchemy()


class User(db.Model):
    """User model for authentication and account management."""
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)  # Made nullable for OAuth users
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        """Hash and set user password."""
        self.password_hash = bcrypt.hashpw(
            password.encode('utf-8'), bcrypt.gensalt()
        ).decode('utf-8')

    def check_password(self, password):
        """Verify user password against stored hash."""
        if not self.password_hash:
            return False
        return bcrypt.checkpw(
            password.encode('utf-8'), self.password_hash.encode('utf-8')
        )

    def __repr__(self):
        return f'<User {self.username}>'


class OAuthProvider(db.Model):
    """OAuth provider configuration model."""
    __tablename__ = 'oauth_provider'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    client_id = db.Column(db.String(255), nullable=False)
    client_secret = db.Column(db.String(255), nullable=False)
    authorize_url = db.Column(db.String(500), nullable=False)
    token_url = db.Column(db.String(500), nullable=False)
    userinfo_url = db.Column(db.String(500), nullable=False)
    scope = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self):
        return f'<OAuthProvider {self.name}>'


class OAuthAccount(db.Model):
    """OAuth account linking model."""
    __tablename__ = 'oauth_account'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    provider_id = db.Column(
        db.Integer, db.ForeignKey('oauth_provider.id'), nullable=False
    )
    provider_user_id = db.Column(db.String(255), nullable=False)
    access_token = db.Column(db.Text)
    refresh_token = db.Column(db.Text)
    token_expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    # Relationships
    user = db.relationship('User', backref='oauth_accounts')
    provider = db.relationship('OAuthProvider')

    # Constraints
    __table_args__ = (
        db.UniqueConstraint('provider_id', 'provider_user_id'),
    )

    def __repr__(self):
        return f'<OAuthAccount {self.provider.name}:{self.provider_user_id}>'


class JWTSession(db.Model):
    """JWT session tracking model for admin session management."""
    __tablename__ = 'jwt_session'
    
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(255), unique=True, nullable=False)  # JWT ID
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    auth_method = db.Column(db.String(50), nullable=False)  # 'password', 'oauth_google', etc.
    ip_address = db.Column(db.String(45), nullable=True)  # IPv4 or IPv6
    user_agent = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    user = db.relationship('User', backref='jwt_sessions')

    def __repr__(self):
        return f'<JWTSession {self.jti} for {self.user.username}>'

    @property
    def is_expired(self):
        """Check if the session has expired."""
        return datetime.utcnow() > self.expires_at

    @property
    def auth_method_display(self):
        """Get a human-readable authentication method name."""
        if self.auth_method == 'password':
            return 'Password'
        elif self.auth_method.startswith('oauth_'):
            provider = self.auth_method.replace('oauth_', '').title()
            return f'OAuth ({provider})'
        else:
            return self.auth_method.title()






