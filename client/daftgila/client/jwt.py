"""
JWT Client

This module provides JWT token management functionality for the DaftGila client.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

from typing import Dict, Any, Optional
from .http import HTTPClient
from .response import APIResponse
from .exceptions import ValidationError


class JWTClient:
    """
    Client for JWT token management operations.
    
    This class handles JWT token operations including:
    - Token validation
    - Token refresh
    - Session management
    """
    
    def __init__(self, http_client: HTTPClient):
        """
        Initialize the JWT client.
        
        Args:
            http_client: HTTP client instance for making requests
        """
        self.http = http_client
    
    def validate(self) -> APIResponse:
        """
        Validate the current JWT token.
        
        Returns:
            APIResponse with validation result
            
        Raises:
            ValidationError: If no active session exists
        """
        if 'Authorization' not in self.http.default_headers:
            raise ValidationError("Authentication required to validate JWT token")
        
        return self.http.get('/api/v1/jwt/validate')
    
    def refresh(self) -> APIResponse:
        """
        Refresh the current JWT access token.
        
        Returns:
            APIResponse with new token
            
        Raises:
            ValidationError: If no active session exists
        """
        if 'Authorization' not in self.http.default_headers:
            raise ValidationError("Authentication required to refresh JWT token")
        
        response = self.http.post('/api/v1/jwt/refresh')
        
        # Update auth header if refresh successful
        if response.is_success and 'access_token' in response.data:
            self.http.set_auth_header(response.data['access_token'])
        
        return response


# The end.
