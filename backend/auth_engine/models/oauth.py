"""
Concrete OAuth model implementations.
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

from ..core.models import AbstractOAuthProvider, AbstractOAuthAccount

db = SQLAlchemy()


class OAuthProvider(db.Model, AbstractOAuthProvider):
    """Concrete OAuth provider model implementation."""
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


class OAuthAccount(db.Model, AbstractOAuthAccount):
    """Concrete OAuth account model implementation."""
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


# The end.
