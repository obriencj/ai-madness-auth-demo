"""
Database models for the Auth Demo application.

This module contains all SQLAlchemy model definitions and database-related functionality.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import bcrypt
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from sqlalchemy import CheckConstraint, Index

# Initialize SQLAlchemy instance (will be configured in app.py)
db = SQLAlchemy()


class User(db.Model):
    """User model for authentication and account management."""
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=True)  # Made nullable for OAuth users
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp(), nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)
    login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)

    # Database constraints
    __table_args__ = (
        CheckConstraint('length(username) >= 3', name='username_min_length'),
        CheckConstraint('length(username) <= 80', name='username_max_length'),
        CheckConstraint('login_attempts >= 0', name='login_attempts_non_negative'),
        Index('idx_user_active_admin', 'is_active', 'is_admin'),
        Index('idx_user_created_at', 'created_at'),
        Index('idx_user_last_login', 'last_login_at'),
    )

    def set_password(self, password):
        """Hash and set user password."""
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
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

    @property
    def has_password(self):
        """Check if user has a password set."""
        return self.password_hash is not None

    @property
    def is_locked(self):
        """Check if user account is locked."""
        if not self.locked_until:
            return False
        return datetime.utcnow() < self.locked_until

    def increment_login_attempts(self):
        """Increment failed login attempts and lock account if threshold exceeded."""
        self.login_attempts += 1
        if self.login_attempts >= 5:  # Lock after 5 failed attempts
            self.locked_until = datetime.utcnow() + timedelta(minutes=30)

    def reset_login_attempts(self):
        """Reset failed login attempts and unlock account."""
        self.login_attempts = 0
        self.locked_until = None
        self.last_login_at = datetime.utcnow()

    def __repr__(self):
        return f'<User {self.username}>'


class OAuthProvider(db.Model):
    """OAuth provider configuration model."""
    __tablename__ = 'oauth_provider'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False, index=True)
    client_id = db.Column(db.String(255), nullable=False)
    client_secret = db.Column(db.String(255), nullable=False)
    authorize_url = db.Column(db.String(500), nullable=False)
    token_url = db.Column(db.String(500), nullable=False)
    userinfo_url = db.Column(db.String(500), nullable=False)
    scope = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)  # Soft delete
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp(), nullable=False)
    deleted_at = db.Column(db.DateTime, nullable=True)
    deleted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    # Relationships
    deleted_by_user = db.relationship('User', foreign_keys=[deleted_by])

    # Database constraints
    __table_args__ = (
        CheckConstraint('length(name) >= 2', name='provider_name_min_length'),
        CheckConstraint('length(name) <= 50', name='provider_name_max_length'),
        CheckConstraint('length(client_id) >= 1', name='client_id_min_length'),
        CheckConstraint('length(scope) >= 1', name='scope_min_length'),
        Index('idx_oauth_provider_active_name', 'is_active', 'name'),
        Index('idx_oauth_provider_created_at', 'created_at'),
    )

    def soft_delete(self, deleted_by_user_id):
        """Soft delete the provider."""
        self.is_deleted = True
        self.is_active = False
        self.deleted_at = datetime.utcnow()
        self.deleted_by = deleted_by_user_id

    def restore(self):
        """Restore a soft-deleted provider."""
        self.is_deleted = False
        self.deleted_at = None
        self.deleted_by = None

    def __repr__(self):
        return f'<OAuthProvider {self.name}>'


class OAuthAccount(db.Model):
    """OAuth account linking model."""
    __tablename__ = 'oauth_account'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, index=True)
    provider_id = db.Column(
        db.Integer, db.ForeignKey('oauth_provider.id', ondelete='CASCADE'), nullable=False, index=True
    )
    provider_user_id = db.Column(db.String(255), nullable=False, index=True)
    access_token = db.Column(db.Text, nullable=True)
    refresh_token = db.Column(db.Text, nullable=True)
    token_expires_at = db.Column(db.DateTime, nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp(), nullable=False)
    last_used_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    user = db.relationship('User', backref='oauth_accounts')
    provider = db.relationship('OAuthProvider')

    # Constraints
    __table_args__ = (
        db.UniqueConstraint('provider_id', 'provider_user_id', name='uq_oauth_provider_user'),
        CheckConstraint('length(provider_user_id) >= 1', name='provider_user_id_min_length'),
        Index('idx_oauth_account_user_provider', 'user_id', 'provider_id'),
        Index('idx_oauth_account_expires', 'token_expires_at'),
        Index('idx_oauth_account_last_used', 'last_used_at'),
    )

    @property
    def is_expired(self):
        """Check if the OAuth token has expired."""
        if not self.token_expires_at:
            return False
        return datetime.utcnow() > self.token_expires_at

    def update_last_used(self):
        """Update the last used timestamp."""
        self.last_used_at = datetime.utcnow()

    def __repr__(self):
        return f'<OAuthAccount {self.provider.name}:{self.provider_user_id}>'


class JWTSession(db.Model):
    """JWT session tracking model for admin session management."""
    __tablename__ = 'jwt_session'
    
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(255), unique=True, nullable=False, index=True)  # JWT ID
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, index=True)
    auth_method = db.Column(db.String(50), nullable=False, index=True)  # 'password', 'oauth_google', etc.
    ip_address = db.Column(db.String(45), nullable=True, index=True)  # IPv4 or IPv6
    user_agent = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    last_activity_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    user = db.relationship('User', backref='jwt_sessions')

    # Database constraints
    __table_args__ = (
        CheckConstraint('length(jti) >= 32', name='jti_min_length'),
        CheckConstraint('expires_at > created_at', name='expires_after_created'),
        CheckConstraint('last_activity_at >= created_at', name='last_activity_after_created'),
        Index('idx_jwt_session_user_active', 'user_id', 'is_active'),
        Index('idx_jwt_session_expires_active', 'expires_at', 'is_active'),
        Index('idx_jwt_session_method_created', 'auth_method', 'created_at'),
    )

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

    def update_activity(self):
        """Update the last activity timestamp."""
        self.last_activity_at = datetime.utcnow()


class GSSAPIRealm(db.Model):
    """GSSAPI/Kerberos realm configuration model."""
    __tablename__ = 'gssapi_realm'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False, index=True)
    realm = db.Column(db.String(255), nullable=False, index=True)
    kdc_hosts = db.Column(db.ARRAY(db.String), nullable=False)  # Array of KDC hostnames
    admin_server = db.Column(db.String(255), nullable=True)  # Admin server hostname
    service_principal = db.Column(db.String(255), nullable=False, index=True)  # Service principal (e.g., HTTP/hostname@REALM.COM)
    encrypted_keytab = db.Column(db.LargeBinary, nullable=False)  # Encrypted keytab data
    keytab_encryption_iv = db.Column(db.LargeBinary, nullable=False)  # Initialization vector for AES encryption
    keytab_encryption_salt = db.Column(db.LargeBinary, nullable=False)  # Salt for key derivation
    default_realm = db.Column(db.Boolean, default=False, nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)  # Soft delete
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp(), nullable=False)
    deleted_at = db.Column(db.DateTime, nullable=True)
    deleted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    # Relationships
    deleted_by_user = db.relationship('User', foreign_keys=[deleted_by])

    # Database constraints
    __table_args__ = (
        CheckConstraint('length(name) >= 2', name='realm_name_min_length'),
        CheckConstraint('length(name) <= 100', name='realm_name_max_length'),
        CheckConstraint('length(realm) >= 3', name='realm_domain_min_length'),
        CheckConstraint('array_length(kdc_hosts, 1) > 0', name='kdc_hosts_not_empty'),
        Index('idx_gssapi_realm_active_default', 'is_active', 'default_realm'),
        Index('idx_gssapi_realm_created_at', 'created_at'),
    )

    def soft_delete(self, deleted_by_user_id):
        """Soft delete the realm."""
        self.is_deleted = True
        self.is_active = False
        self.default_realm = False
        self.deleted_at = datetime.utcnow()
        self.deleted_by = deleted_by_user_id

    def restore(self):
        """Restore a soft-deleted realm."""
        self.is_deleted = False
        self.deleted_at = None
        self.deleted_by = None

    def __repr__(self):
        return f'<GSSAPIRealm {self.name}:{self.realm}>'


class GSSAPIAccount(db.Model):
    """GSSAPI account linking model."""
    __tablename__ = 'gssapi_account'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, index=True)
    realm_id = db.Column(db.Integer, db.ForeignKey('gssapi_realm.id', ondelete='CASCADE'), nullable=False, index=True)
    principal_name = db.Column(db.String(255), nullable=False, index=True)  # Full Kerberos principal
    service_principal = db.Column(db.String(255), nullable=True)  # Service principal if applicable
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp(), nullable=False)
    last_used_at = db.Column(db.DateTime, nullable=True, index=True)

    # Relationships
    user = db.relationship('User', backref='gssapi_accounts')
    realm = db.relationship('GSSAPIRealm')

    # Constraints
    __table_args__ = (
        db.UniqueConstraint('realm_id', 'principal_name', name='uq_gssapi_realm_principal'),
        CheckConstraint('length(principal_name) >= 3', name='principal_name_min_length'),
        Index('idx_gssapi_account_user_realm', 'user_id', 'realm_id'),
        Index('idx_gssapi_account_principal', 'principal_name'),
    )

    def update_last_used(self):
        """Update the last used timestamp."""
        self.last_used_at = datetime.utcnow()

    def __repr__(self):
        return f'<GSSAPIAccount {self.principal_name}@{self.realm.realm}>'


class AppConfigVersion(db.Model):
    """Application configuration version model."""
    __tablename__ = 'app_config_version'
    
    id = db.Column(db.Integer, primary_key=True)
    version = db.Column(db.Integer, nullable=False, index=True)
    config_data = db.Column(db.JSON, nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=False, nullable=False, index=True)
    activated_at = db.Column(db.DateTime, nullable=True, index=True)
    activated_by = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True, index=True)
    
    # Relationships
    creator = db.relationship('User', foreign_keys=[created_by], backref='created_configs')
    activator = db.relationship('User', foreign_keys=[activated_by], backref='activated_configs')

    # Database constraints
    __table_args__ = (
        CheckConstraint('version > 0', name='version_positive'),
        Index('idx_app_config_version_created', 'version', 'created_at'),
    )

    def __repr__(self):
        return f'<AppConfigVersion {self.version} {"(active)" if self.is_active else ""}>'

    @property
    def is_current(self):
        """Check if this is the currently active configuration."""
        return self.is_active


class AuditLog(db.Model):
    """Audit logging model for administrative actions."""
    __tablename__ = 'audit_log'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True, index=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    resource_type = db.Column(db.String(50), nullable=False, index=True)
    resource_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.JSON, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Relationships
    user = db.relationship('User', backref='audit_logs')

    # Database constraints
    __table_args__ = (
        CheckConstraint('length(action) >= 3', name='action_min_length'),
        CheckConstraint('length(action) <= 100', name='action_max_length'),
        CheckConstraint('length(resource_type) >= 2', name='resource_type_min_length'),
        CheckConstraint('length(resource_type) <= 50', name='resource_type_max_length'),
        Index('idx_audit_log_user_action', 'user_id', 'action'),
        Index('idx_audit_log_resource', 'resource_type', 'resource_id'),
        Index('idx_audit_log_created_at', 'created_at'),
    )

    def __repr__(self):
        return f'<AuditLog {self.action} on {self.resource_type} by {self.user_id}>'


# The end.






