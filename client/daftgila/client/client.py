"""
Main DaftGila Client

This module provides the main client class that unifies all API operations.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

from typing import Optional, Dict, Any
from .http import HTTPClient
from .auth import AuthClient
from .admin import AdminClient
from .gssapi import GSSAPIClient
from .jwt import JWTClient
from .config import ConfigClient
from .response import APIResponse
from .exceptions import DaftGilaClientError


class DaftGilaClient:
    """
    Main client for the DaftGila authentication platform API.
    
    This class provides a unified interface for all API operations including:
    - Authentication (login, logout, registration)
    - User management (admin operations)
    - OAuth provider management
    - GSSAPI realm management
    - General API endpoints
    
    The client automatically handles:
    - HTTP requests and responses
    - Authentication headers
    - Response parsing and validation
    - Error handling
    """
    
    def __init__(self, base_url: str, timeout: float = 30.0, 
                 verify_ssl: bool = True, default_headers: Optional[Dict[str, str]] = None):
        """
        Initialize the DaftGila client.
        
        Args:
            base_url: Base URL for the API (e.g., "http://localhost:5000")
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            default_headers: Default headers to include in all requests
        """
        # Initialize HTTP client
        self.http = HTTPClient(
            base_url=base_url,
            timeout=timeout,
            verify_ssl=verify_ssl,
            default_headers=default_headers or {}
        )
        
        # Initialize specialized clients
        self.auth = AuthClient(self.http)
        self.admin = AdminClient(self.http)
        self.gssapi = GSSAPIClient(self.http)
        self.jwt = JWTClient(self.http)
        self.config = ConfigClient(self.http)
        
        # Store configuration
        self.base_url = base_url
        self.timeout = timeout
        self.verify_ssl = verify_ssl
    
    # General API Methods
    
    def test(self) -> APIResponse:
        """
        Test API connectivity.
        
        Returns:
            APIResponse with test result
        """
        return self.http.get('/api/v1/test')
    
    def hello(self) -> APIResponse:
        """
        Access the protected hello endpoint.
        
        Returns:
            APIResponse with hello message
            
        Note:
            This endpoint requires authentication.
        """
        return self.http.get('/api/v1/hello')
    
    # Authentication State Management
    
    def is_authenticated(self) -> bool:
        """
        Check if the client is currently authenticated.
        
        Returns:
            True if authenticated, False otherwise
        """
        return 'Authorization' in self.http.default_headers
    
    def get_auth_token(self) -> Optional[str]:
        """
        Get the current authentication token.
        
        Returns:
            JWT token if authenticated, None otherwise
        """
        auth_header = self.http.default_headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            return auth_header[7:]  # Remove 'Bearer ' prefix
        return None
    
    def set_auth_token(self, token: str) -> None:
        """
        Set the authentication token manually.
        
        Args:
            token: JWT token to use for authentication
        """
        self.http.set_auth_header(token)
    
    def clear_auth_token(self) -> None:
        """Clear the current authentication token."""
        self.http.clear_auth_header()
    
    # Configuration Methods
    
    def update_timeout(self, timeout: float) -> None:
        """
        Update the request timeout.
        
        Args:
            timeout: New timeout value in seconds
        """
        if timeout <= 0:
            raise ValueError("Timeout must be positive")
        self.timeout = timeout
        self.http.timeout = timeout
    
    def update_ssl_verification(self, verify_ssl: bool) -> None:
        """
        Update SSL verification setting.
        
        Args:
            verify_ssl: Whether to verify SSL certificates
        """
        self.verify_ssl = verify_ssl
        self.http.verify_ssl = verify_ssl
        self.http.session.verify = verify_ssl
    
    def add_default_header(self, key: str, value: str) -> None:
        """
        Add a default header for all requests.
        
        Args:
            key: Header name
            value: Header value
        """
        self.http.default_headers[key] = value
    
    def remove_default_header(self, key: str) -> None:
        """
        Remove a default header.
        
        Args:
            key: Header name to remove
        """
        self.http.default_headers.pop(key, None)
    
    def get_default_headers(self) -> Dict[str, str]:
        """
        Get all default headers.
        
        Returns:
            Dictionary of default headers
        """
        return self.http.default_headers.copy()
    
    # Context Manager Support
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
    
    def close(self) -> None:
        """Close the client and clean up resources."""
        self.http.close()
    
    # Utility Methods
    
    def get_api_info(self) -> Dict[str, Any]:
        """
        Get information about the API and client configuration.
        
        Returns:
            Dictionary with API and client information
        """
        return {
            'base_url': self.base_url,
            'timeout': self.timeout,
            'verify_ssl': self.verify_ssl,
            'is_authenticated': self.is_authenticated(),
            'default_headers': self.get_default_headers(),
            'auth_token_present': bool(self.get_auth_token())
        }
    
    def ping(self) -> bool:
        """
        Simple connectivity test.
        
        Returns:
            True if API is reachable, False otherwise
        """
        try:
            response = self.test()
            return response.is_success
        except Exception:
            return False
    
    def health_check(self) -> Dict[str, Any]:
        """
        Comprehensive health check of the API.
        
        Returns:
            Dictionary with health check results
        """
        health_status = {
            'connectivity': False,
            'authentication_required': False,
            'timestamp': None
        }
        
        try:
            # Test basic connectivity
            test_response = self.test()
            health_status['connectivity'] = test_response.is_success
            
            # Test authenticated endpoint
            try:
                hello_response = self.hello()
                health_status['authentication_required'] = True
            except Exception:
                # Expected if not authenticated
                pass
            
            health_status['timestamp'] = test_response.data.get('timestamp') if test_response.data else None
            
        except Exception as e:
            health_status['error'] = str(e)
        
        return health_status


# The end.
