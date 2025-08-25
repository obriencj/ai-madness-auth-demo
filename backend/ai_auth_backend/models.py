"""
Database models for the AI Auth Backend.

This module contains all SQLAlchemy model definitions and database-related 
functionality.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Cursor AI (Claude Sonnet 4)
"""

import bcrypt
from flask_sqlalchemy import SQLAlchemy
from typing import List

# Initialize SQLAlchemy instance (will be configured in app.py)
db = SQLAlchemy()


class User(db.Model):
    """User model for authentication and account management."""
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(
        db.String(255), nullable=True
    )  # Made nullable for OAuth users
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(
        db.DateTime, default=db.func.current_timestamp()
    )
    updated_at = db.Column(
        db.DateTime, 
        default=db.func.current_timestamp(), 
        onupdate=db.func.current_timestamp()
    )

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

    def has_permission(self, permission: str) -> bool:
        """Check if user has specific permission."""
        if permission == 'admin':
            return self.is_admin
        # Add more permission logic here as needed
        return True

    def get_permissions(self) -> List[str]:
        """Get list of user permissions."""
        permissions = ['read', 'write']
        if self.is_admin:
            permissions.append('admin')
        return permissions

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
    updated_at = db.Column(
        db.DateTime, 
        default=db.func.current_timestamp(), 
        onupdate=db.func.current_timestamp()
    )

    # Relationships
    user = db.relationship('User', backref='oauth_accounts')
    provider = db.relationship('OAuthProvider')

    # Constraints
    __table_args__ = (
        db.UniqueConstraint('provider_id', 'provider_user_id'),
    )

    def __repr__(self):
        return f'<OAuthAccount {self.user.username}@{self.provider.name}>'


class JWTSession(db.Model):
    """JWT session tracking model."""
    __tablename__ = 'jwt_session'
    
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(255), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    auth_method = db.Column(
        db.String(50), nullable=False
    )  # 'password', 'oauth_google', etc.
    ip_address = db.Column(db.String(45))  # IPv6 compatible
    user_agent = db.Column(db.Text)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(
        db.DateTime, 
        default=db.func.current_timestamp(), 
        onupdate=db.func.current_timestamp()
    )

    # Relationships
    user = db.relationship('User', backref='jwt_sessions')

    def __repr__(self):
        return f'<JWTSession {self.jti}>'


class Webhook(db.Model):
    """Webhook model for event notifications."""
    __tablename__ = 'webhook'
    
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    events = db.Column(
        db.JSON, nullable=False, default=[]
    )  # ['user.created', 'user.updated', etc.]
    secret = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(
        db.DateTime, 
        default=db.func.current_timestamp(), 
        onupdate=db.func.current_timestamp()
    )

    def __repr__(self):
        return f'<Webhook {self.url}>'


class AuditLog(db.Model):
    """Audit log model for compliance and tracking."""
    __tablename__ = 'audit_log'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id'), nullable=True
    )
    action = db.Column(
        db.String(100), nullable=False
    )  # 'user.login', 'user.created', etc.
    resource_type = db.Column(
        db.String(50)
    )  # 'user', 'oauth_provider', etc.
    resource_id = db.Column(
        db.String(255)
    )  # ID of the affected resource
    details = db.Column(db.JSON)  # Additional details about the action
    ip_address = db.Column(db.String(45))  # IPv6 compatible
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    # Relationships
    user = db.relationship('User', backref='audit_logs')

    def __repr__(self):
        return f'<AuditLog {self.action} by {self.user_id}>'


# The end.
