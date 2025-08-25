"""
Base provider interface for authentication providers.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any


class BaseProvider(ABC):
    """Base class for all authentication providers."""
    
    def __init__(self, auth_service):
        """Initialize provider with authentication service."""
        self.auth_service = auth_service
    
    @abstractmethod
    def authenticate(self, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """Authenticate user with provided credentials."""
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """Get provider name."""
        pass
    
    @abstractmethod
    def is_enabled(self) -> bool:
        """Check if provider is enabled."""
        pass


# The end.
