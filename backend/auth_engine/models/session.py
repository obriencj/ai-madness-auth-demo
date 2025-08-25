"""
Concrete JWT session model implementation.
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class JWTSession(db.Model):
    """Concrete JWT session model implementation."""
    __tablename__ = 'jwt_session'
    
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(255), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    auth_method = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    user = db.relationship('User', backref='jwt_sessions')
    
    def __repr__(self):
        return f'<JWTSession {self.jti} for {self.user.username}>'
    
    @property
    def is_expired(self) -> bool:
        """Check if the session has expired."""
        return datetime.utcnow() > self.expires_at
    
    @property
    def auth_method_display(self) -> str:
        """Get a human-readable authentication method name."""
        if self.auth_method == 'password':
            return 'Password'
        elif self.auth_method.startswith('oauth_'):
            provider = self.auth_method.replace('oauth_', '').title()
            return f'OAuth ({provider})'
        else:
            return self.auth_method.title()


# The end.
