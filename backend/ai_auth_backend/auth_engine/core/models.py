"""
Abstract model interfaces for the Authentication Engine.
"""

from abc import ABC, abstractmethod
from typing import Any, Optional, List
from datetime import datetime


class AbstractUser(ABC):
    """Abstract user interface that can be extended by applications."""
    
    @property
    @abstractmethod
    def id(self) -> Any:
        """Get user ID."""
        pass
    
    @property
    @abstractmethod
    def username(self) -> str:
        """Get username."""
        pass
    
    @property
    @abstractmethod
    def email(self) -> str:
        """Get email address."""
        pass
    
    @property
    @abstractmethod
    def is_active(self) -> bool:
        """Check if user is active."""
        pass
    
    @abstractmethod
    def has_permission(self, permission: str) -> bool:
        """Check if user has specific permission."""
        pass
    
    @abstractmethod
    def get_permissions(self) -> List[str]:
        """Get list of user permissions."""
        pass
    
    @abstractmethod
    def check_password(self, password: str) -> bool:
        """Check if password matches user's password."""
        pass
    
    @abstractmethod
    def set_password(self, password: str):
        """Set user's password."""
        pass


class AbstractOAuthProvider(ABC):
    """Abstract OAuth provider interface."""
    
    @property
    @abstractmethod
    def id(self) -> Any:
        """Get provider ID."""
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Get provider name."""
        pass
    
    @property
    @abstractmethod
    def client_id(self) -> str:
        """Get OAuth client ID."""
        pass
    
    @property
    @abstractmethod
    def client_secret(self) -> str:
        """Get OAuth client secret."""
        pass
    
    @property
    @abstractmethod
    def authorize_url(self) -> str:
        """Get OAuth authorization URL."""
        pass
    
    @property
    @abstractmethod
    def token_url(self) -> str:
        """Get OAuth token URL."""
        pass
    
    @property
    @abstractmethod
    def userinfo_url(self) -> str:
        """Get OAuth user info URL."""
        pass
    
    @property
    @abstractmethod
    def scope(self) -> str:
        """Get OAuth scope."""
        pass
    
    @property
    @abstractmethod
    def is_active(self) -> bool:
        """Check if provider is active."""
        pass


class AbstractOAuthAccount(ABC):
    """Abstract OAuth account interface."""
    
    @property
    @abstractmethod
    def id(self) -> Any:
        """Get account ID."""
        pass
    
    @property
    @abstractmethod
    def user_id(self) -> Any:
        """Get associated user ID."""
        pass
    
    @property
    @abstractmethod
    def provider_id(self) -> Any:
        """Get associated provider ID."""
        pass
    
    @property
    @abstractmethod
    def provider_user_id(self) -> str:
        """Get provider's user ID."""
        pass
    
    @property
    @abstractmethod
    def access_token(self) -> Optional[str]:
        """Get OAuth access token."""
        pass
    
    @property
    @abstractmethod
    def refresh_token(self) -> Optional[str]:
        """Get OAuth refresh token."""
        pass
    
    @property
    @abstractmethod
    def created_at(self) -> datetime:
        """Get creation timestamp."""
        pass
    
    @property
    @abstractmethod
    def updated_at(self) -> datetime:
        """Get last update timestamp."""
        pass


class AbstractJWTSession(ABC):
    """Abstract JWT session interface."""
    
    @property
    @abstractmethod
    def id(self) -> Any:
        """Get session ID."""
        pass
    
    @property
    @abstractmethod
    def jti(self) -> str:
        """Get JWT ID."""
        pass
    
    @property
    @abstractmethod
    def user_id(self) -> Any:
        """Get associated user ID."""
        pass
    
    @property
    @abstractmethod
    def auth_method(self) -> str:
        """Get authentication method."""
        pass
    
    @property
    @abstractmethod
    def ip_address(self) -> Optional[str]:
        """Get client IP address."""
        pass
    
    @property
    @abstractmethod
    def user_agent(self) -> Optional[str]:
        """Get client user agent."""
        pass
    
    @property
    @abstractmethod
    def created_at(self) -> datetime:
        """Get creation timestamp."""
        pass
    
    @property
    @abstractmethod
    def expires_at(self) -> datetime:
        """Get expiration timestamp."""
        pass
    
    @property
    @abstractmethod
    def is_active(self) -> bool:
        """Check if session is active."""
        pass
    
    @property
    @abstractmethod
    def is_expired(self) -> bool:
        """Check if session has expired."""
        pass


# The end.
