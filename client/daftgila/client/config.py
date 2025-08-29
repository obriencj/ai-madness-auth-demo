"""
Configuration Client

This module provides configuration management functionality for the DaftGila client.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

from typing import Dict, Any, Optional
from .http import HTTPClient
from .response import APIResponse
from .exceptions import ValidationError


class ConfigClient:
    """
    Client for configuration management operations.
    
    This class handles system configuration operations including:
    - Configuration retrieval and updates
    - Version management
    - Cache management
    - Public configuration access
    """
    
    def __init__(self, http_client: HTTPClient):
        """
        Initialize the configuration client.
        
        Args:
            http_client: HTTP client instance for making requests
        """
        self.http = http_client
    
    def get_active(self) -> APIResponse:
        """
        Get the currently active configuration.
        
        Returns:
            APIResponse with active configuration
        """
        return self.http.get('/api/v1/config/active')
    
    def update(self, config_data: Dict[str, Any]) -> APIResponse:
        """
        Update the system configuration.
        
        Args:
            config_data: Configuration data to update
            
        Returns:
            APIResponse with update result
            
        Raises:
            ValidationError: If config_data is empty
        """
        if not config_data:
            raise ValidationError("Configuration data is required")
        
        return self.http.put('/api/v1/config/update', json_data=config_data)
    
    def get_versions(self) -> APIResponse:
        """
        Get all configuration versions.
        
        Returns:
            APIResponse with list of configuration versions
        """
        return self.http.get('/api/v1/config/versions')
    
    def get_version(self, version_id: int) -> APIResponse:
        """
        Get a specific configuration version.
        
        Args:
            version_id: ID of the configuration version
            
        Returns:
            APIResponse with configuration version data
            
        Raises:
            ValidationError: If version_id is invalid
        """
        if not version_id or version_id <= 0:
            raise ValidationError("Valid version ID is required", "version_id", version_id)
        
        return self.http.get(f'/api/v1/config/versions/{version_id}')
    
    def activate_version(self, version_id: int) -> APIResponse:
        """
        Activate a specific configuration version.
        
        Args:
            version_id: ID of the configuration version to activate
            
        Returns:
            APIResponse with activation result
            
        Raises:
            ValidationError: If version_id is invalid
        """
        if not version_id or version_id <= 0:
            raise ValidationError("Valid version ID is required", "version_id", version_id)
        
        return self.http.post(f'/api/v1/config/versions/{version_id}/activate')
    
    def delete_version(self, version_id: int) -> APIResponse:
        """
        Delete a specific configuration version.
        
        Args:
            version_id: ID of the configuration version to delete
            
        Returns:
            APIResponse with deletion result
            
        Raises:
            ValidationError: If version_id is invalid
        """
        if not version_id or version_id <= 0:
            raise ValidationError("Valid version ID is required", "version_id", version_id)
        
        return self.http.delete(f'/api/v1/config/versions/{version_id}')
    
    def refresh_cache(self) -> APIResponse:
        """
        Refresh the configuration cache.
        
        Returns:
            APIResponse with cache refresh result
        """
        return self.http.post('/api/v1/config/cache/refresh')
    
    def get_cache_status(self) -> APIResponse:
        """
        Get the configuration cache status.
        
        Returns:
            APIResponse with cache status information
        """
        return self.http.get('/api/v1/config/cache/status')
    
    def get_public(self) -> APIResponse:
        """
        Get public configuration information.
        
        Returns:
            APIResponse with public configuration data
        """
        return self.http.get('/api/v1/config/public')


# The end.
