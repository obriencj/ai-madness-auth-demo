"""
Concrete User model implementation.
"""

import bcrypt
from flask_sqlalchemy import SQLAlchemy
from typing import List

from ..core.models import AbstractUser

db = SQLAlchemy()


class User(db.Model, AbstractUser):
    """Concrete User model implementation."""
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    
    def set_password(self, password: str):
        """Hash and set user password."""
        self.password_hash = bcrypt.hashpw(
            password.encode('utf-8'), 
            bcrypt.gensalt()
        ).decode('utf-8')
    
    def check_password(self, password: str) -> bool:
        """Verify user password against stored hash."""
        if not self.password_hash:
            return False
        return bcrypt.checkpw(
            password.encode('utf-8'), 
            self.password_hash.encode('utf-8')
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


# The end.
