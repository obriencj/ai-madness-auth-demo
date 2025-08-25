"""
Provider registry for managing authentication providers.
"""

from typing import Dict, Any, Optional
from .base import BaseProvider


class ProviderRegistry:
    """Registry for authentication providers."""
    
    def __init__(self):
        """Initialize provider registry."""
        self._providers: Dict[str, BaseProvider] = {}
    
    def register(self, name: str, provider: BaseProvider):
        """Register a provider with the registry."""
        self._providers[name] = provider
    
    def get(self, name: str) -> Optional[BaseProvider]:
        """Get provider by name."""
        return self._providers.get(name)
    
    def list_providers(self) -> Dict[str, BaseProvider]:
        """Get all registered providers."""
        return self._providers.copy()
    
    def list_enabled_providers(self) -> Dict[str, BaseProvider]:
        """Get all enabled providers."""
        return {
            name: provider 
            for name, provider in self._providers.items() 
            if provider.is_enabled()
        }
    
    def unregister(self, name: str):
        """Unregister a provider."""
        if name in self._providers:
            del self._providers[name]
    
    def clear(self):
        """Clear all providers."""
        self._providers.clear()


# The end.
