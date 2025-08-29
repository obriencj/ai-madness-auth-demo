"""
Authentication Client

This module provides authentication-related functionality for the DaftGila client.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

from typing import Dict, Any, Optional
from .http import HTTPClient
from .response import APIResponse
from .exceptions import ValidationError


class AuthClient:
    """
    Client for authentication operations.
    
    This class handles user authentication including:
    - User login with username/password
    - User logout and session cleanup
    - User self-registration
    - OAuth authentication flows
    """
    
    def __init__(self, http_client: HTTPClient):
        """
        Initialize the authentication client.
        
        Args:
            http_client: HTTP client instance for making requests
        """
        self.http = http_client
    
    def login(self, username: str, password: str) -> APIResponse:
        """
        Authenticate a user with username and password.
        
        Args:
            username: User's username
            password: User's password
            
        Returns:
            APIResponse with authentication result
            
        Raises:
            ValidationError: If username or password is invalid
        """
        if not username or not username.strip():
            raise ValidationError("Username is required", "username", username)
        if not password:
            raise ValidationError("Password is required", "password")
        
        data = {
            'username': username.strip(),
            'password': password
        }
        
        response = self.http.post('/api/v1/auth/login', json_data=data)
        
        # If login successful, set the auth header for future requests
        if response.is_success and 'access_token' in response.data:
            self.http.set_auth_header(response.data['access_token'])
        
        return response
    
    def logout(self) -> APIResponse:
        """
        Logout the current user and clear authentication.
        
        Returns:
            APIResponse with logout result
        """
        # Get the current JWT token from headers
        auth_header = self.http.default_headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return APIResponse(
                success=False,
                message="No active session to logout",
                status_code=400
            )
        
        # Extract JTI from token for logout
        # Note: This is a simplified approach - in a real implementation,
        # you might want to decode the JWT to get the JTI
        data = {'jti': 'placeholder'}  # The backend will handle this
        
        response = self.http.post('/api/v1/auth/logout', json_data=data)
        
        # Clear auth header regardless of response
        self.http.clear_auth_header()
        
        return response
    
    def is_authenticated(self) -> bool:
        """
        Check if the client is currently authenticated.
        
        Returns:
            True if authenticated, False otherwise
        """
        return 'Authorization' in self.http.default_headers
    
    def register(self, username: str, email: str, password: str) -> APIResponse:
        """
        Register a new user account.
        
        Args:
            username: Desired username
            email: User's email address
            password: Desired password
            
        Returns:
            APIResponse with registration result
            
        Raises:
            ValidationError: If any required fields are invalid
        """
        if not username or not username.strip():
            raise ValidationError("Username is required", "username", username)
        if not email or not email.strip():
            raise ValidationError("Email is required", "email", email)
        if not password:
            raise ValidationError("Password is required", "password")
        
        # Basic validation
        if len(username.strip()) < 3:
            raise ValidationError("Username must be at least 3 characters", "username", username)
        if len(password) < 6:
            raise ValidationError("Password must be at least 6 characters", "password")
        if '@' not in email or '.' not in email:
            raise ValidationError("Invalid email format", "email", email)
        
        data = {
            'username': username.strip(),
            'email': email.strip(),
            'password': password
        }
        
        return self.http.post('/api/v1/auth/register', json_data=data)
    
    def get_oauth_providers(self) -> APIResponse:
        """
        Get available OAuth providers for authentication.
        
        Returns:
            APIResponse with OAuth provider information
        """
        return self.http.get('/api/v1/auth/oauth/providers')
    
    def oauth_authorize(self, provider: str, redirect_uri: str) -> str:
        """
        Get OAuth authorization URL for a provider.
        
        Args:
            provider: OAuth provider name (e.g., 'google', 'github')
            redirect_uri: Redirect URI for OAuth callback
            
        Returns:
            OAuth authorization URL
            
        Raises:
            ValidationError: If provider or redirect_uri is invalid
        """
        if not provider or not provider.strip():
            raise ValidationError("Provider is required", "provider", provider)
        if not redirect_uri or not redirect_uri.strip():
            raise ValidationError("Redirect URI is required", "redirect_uri", redirect_uri)
        
        # Build the OAuth authorization URL
        base_url = self.http.base_url
        auth_url = f"{base_url}/api/v1/auth/oauth/{provider}/authorize"
        
        # Add query parameters
        params = {
            'redirect_uri': redirect_uri,
            'response_type': 'code'
        }
        
        # Convert params to query string
        query_string = '&'.join([f"{k}={v}" for k, v in params.items()])
        return f"{auth_url}?{query_string}"
    
    def oauth_callback(self, provider: str, code: str, redirect_uri: str) -> APIResponse:
        """
        Complete OAuth authentication with authorization code.
        
        Args:
            provider: OAuth provider name
            code: Authorization code from OAuth provider
            redirect_uri: Redirect URI used in authorization
            
        Returns:
            APIResponse with OAuth authentication result
            
        Raises:
            ValidationError: If any required fields are invalid
        """
        if not provider or not provider.strip():
            raise ValidationError("Provider is required", "provider", provider)
        if not code or not code.strip():
            raise ValidationError("Authorization code is required", "code", code)
        if not redirect_uri or not redirect_uri.strip():
            raise ValidationError("Redirect URI is required", "redirect_uri", redirect_uri)
        
        data = {
            'provider': provider.strip(),
            'code': code.strip(),
            'redirect_uri': redirect_uri.strip()
        }
        
        response = self.http.post('/api/v1/auth/oauth/callback', json_data=data)
        
        # If OAuth successful, set the auth header for future requests
        if response.is_success and 'access_token' in response.data:
            self.http.set_auth_header(response.data['access_token'])
        
        return response
    
    def get_account_info(self) -> APIResponse:
        """
        Get current user account information.
        
        Returns:
            APIResponse with user account data
        """
        return self.http.get('/api/v1/auth/account')
    
    def update_account(self, **kwargs) -> APIResponse:
        """
        Update current user account information.
        
        Args:
            **kwargs: Fields to update (email, password, etc.)
            
        Returns:
            APIResponse with update result
        """
        if not kwargs:
            raise ValidationError("No fields specified for update")
        
        return self.http.put('/api/v1/auth/account', json_data=kwargs)
    
    def remove_oauth_account(self, oauth_account_id: int) -> APIResponse:
        """
        Remove an OAuth account link from current user.
        
        Args:
            oauth_account_id: ID of the OAuth account to remove
            
        Returns:
            APIResponse with removal result
            
        Raises:
            ValidationError: If oauth_account_id is invalid
        """
        if not oauth_account_id or oauth_account_id <= 0:
            raise ValidationError("Valid OAuth account ID is required", "oauth_account_id", oauth_account_id)
        
        return self.http.delete(f'/api/v1/auth/account/oauth/{oauth_account_id}')
    
    # JWT Session Management Methods (User-specific)
    
    def get_user_sessions(self) -> APIResponse:
        """
        Get all active JWT sessions for the current user.
        
        Returns:
            APIResponse with list of user's active JWT sessions
            
        Raises:
            ValidationError: If no active session exists
        """
        if not self.is_authenticated():
            raise ValidationError("No active session to get sessions")
        
        return self.http.get('/api/v1/auth/sessions')
    
    def expire_user_session(self, session_id: int) -> APIResponse:
        """
        Expire a specific JWT session for the current user.
        
        Args:
            session_id: ID of the JWT session to expire
            
        Returns:
            APIResponse with expiration result
            
        Raises:
            ValidationError: If session_id is invalid or no active session exists
        """
        if not self.is_authenticated():
            raise ValidationError("No active session to expire sessions")
        if not session_id or session_id <= 0:
            raise ValidationError("Valid session ID is required", "session_id", session_id)
        
        return self.http.delete(f'/api/v1/auth/sessions/{session_id}')
    
    def expire_all_user_sessions(self) -> APIResponse:
        """
        Expire all active JWT sessions for the current user.
        
        Returns:
            APIResponse with expiration result
            
        Raises:
            ValidationError: If no active session exists
        """
        if not self.is_authenticated():
            raise ValidationError("No active session to expire sessions")
        
        return self.http.post('/api/v1/auth/sessions/expire-all')


# The end.
