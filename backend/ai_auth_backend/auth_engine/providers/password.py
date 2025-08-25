"""
Password authentication provider.
"""

from typing import Dict, Any
from .base import BaseProvider
from ..exceptions import AuthError


class PasswordProvider(BaseProvider):
    """Password-based authentication provider."""
    
    def authenticate(self, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """Authenticate user with username and password."""
        username = credentials.get('username')
        password = credentials.get('password')
        
        if not username or not password:
            raise AuthError("Username and password are required")
        
        return self.auth_service.authenticate_with_password(username, password)
    
    def get_name(self) -> str:
        """Get provider name."""
        return 'password'
    
    def is_enabled(self) -> bool:
        """Check if provider is enabled."""
        return True


# The end.
