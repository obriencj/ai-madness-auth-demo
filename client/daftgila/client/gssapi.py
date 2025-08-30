"""
GSSAPI Client

This module provides GSSAPI/Kerberos authentication functionality for the DaftGila client.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

from typing import Dict, Any, Optional
from .http import HTTPClient
from .response import APIResponse
from .exceptions import ValidationError


class GSSAPIClient:
    """
    Client for GSSAPI/Kerberos authentication operations.
    
    This class handles enterprise-grade Kerberos authentication including:
    - GSSAPI authentication flows
    - Negotiation protocols
    - Realm management
    - Account management
    """
    
    def __init__(self, http_client: HTTPClient):
        """
        Initialize the GSSAPI client.
        
        Args:
            http_client: HTTP client instance for making requests
        """
        self.http = http_client
    
    def authenticate(self, token: str, realm: Optional[str] = None) -> APIResponse:
        """
        Authenticate using GSSAPI/Kerberos.
        
        Args:
            token: GSSAPI authentication token
            realm: Optional Kerberos realm name
            
        Returns:
            APIResponse with authentication result
            
        Raises:
            ValidationError: If token is invalid
        """
        if not token or not token.strip():
            raise ValidationError("GSSAPI token is required", "token", token)
        
        data = {'token': token.strip()}
        if realm:
            data['realm'] = realm.strip()
        
        response = self.http.post('/api/v1/auth/gssapi/authenticate', json_data=data)
        
        # If authentication successful, set the auth header for future requests
        if response.is_success and 'access_token' in response.data:
            self.http.set_auth_header(response.data['access_token'])
        
        return response
    
    def negotiate(self, realm: Optional[str] = None) -> APIResponse:
        """
        Initiate GSSAPI negotiation.
        
        Args:
            realm: Optional Kerberos realm name
            
        Returns:
            APIResponse with negotiation data
        """
        params = {}
        if realm:
            params['realm'] = realm.strip()
        
        return self.http.get('/api/v1/auth/gssapi/negotiate', params=params)
    
    def negotiate_post(self, token: str, realm: Optional[str] = None) -> APIResponse:
        """
        Complete GSSAPI negotiation with POST.
        
        Args:
            token: GSSAPI negotiation token
            realm: Optional Kerberos realm name
            
        Returns:
            APIResponse with negotiation result
            
        Raises:
            ValidationError: If token is invalid
        """
        if not token or not token.strip():
            raise ValidationError("GSSAPI token is required", "token", token)
        
        data = {'token': token.strip()}
        if realm:
            data['realm'] = realm.strip()
        
        return self.http.post('/api/v1/auth/gssapi/negotiate', json_data=data)
    
    def get_realms(self) -> APIResponse:
        """
        Get available GSSAPI realms.
        
        Returns:
            APIResponse with list of GSSAPI realms
        """
        return self.http.get('/api/v1/auth/gssapi/realms')
    
    def get_accounts(self) -> APIResponse:
        """
        Get GSSAPI accounts for the current user.
        
        Returns:
            APIResponse with list of GSSAPI accounts
            
        Raises:
            ValidationError: If no active session exists
        """
        if 'Authorization' not in self.http.default_headers:
            raise ValidationError("Authentication required to get GSSAPI accounts")
        
        return self.http.get('/api/v1/auth/gssapi/accounts')


# The end.
