"""
Admin Client

This module provides administrative functionality for the DaftGila client.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

from typing import Dict, Any, Optional, List
from .http import HTTPClient
from .response import APIResponse
from .exceptions import ValidationError


class AdminClient:
    """
    Client for administrative operations.
    
    This class handles administrative tasks including:
    - User management (create, read, update, delete)
    - OAuth provider management
    - GSSAPI realm management
    - System configuration
    """
    
    def __init__(self, http_client: HTTPClient):
        """
        Initialize the admin client.
        
        Args:
            http_client: HTTP client instance for making requests
        """
        self.http = http_client
    
    # User Management Methods
    
    def get_users(self) -> APIResponse:
        """
        Get all users in the system.
        
        Returns:
            APIResponse with list of users
        """
        return self.http.get('/api/v1/admin/users')
    
    def create_user(self, username: str, email: str, password: str, 
                   is_admin: bool = False, is_active: bool = True) -> APIResponse:
        """
        Create a new user account.
        
        Args:
            username: Username for the new account
            email: Email address for the new account
            password: Password for the new account
            is_admin: Whether the user should have admin privileges
            is_active: Whether the user account should be active
            
        Returns:
            APIResponse with creation result
            
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
            'password': password,
            'is_admin': bool(is_admin),
            'is_active': bool(is_active)
        }
        
        return self.http.post('/api/v1/admin/users', json_data=data)
    
    def update_user(self, user_id: int, **kwargs) -> APIResponse:
        """
        Update an existing user account.
        
        Args:
            user_id: ID of the user to update
            **kwargs: Fields to update (email, is_admin, is_active, password)
            
        Returns:
            APIResponse with update result
            
        Raises:
            ValidationError: If user_id is invalid
        """
        if not user_id or user_id <= 0:
            raise ValidationError("Valid user ID is required", "user_id", user_id)
        
        if not kwargs:
            raise ValidationError("No fields specified for update")
        
        # Validate email if provided
        if 'email' in kwargs:
            email = kwargs['email']
            if not email or not email.strip() or '@' not in email or '.' not in email:
                raise ValidationError("Invalid email format", "email", email)
            kwargs['email'] = email.strip()
        
        # Validate boolean fields
        if 'is_admin' in kwargs:
            kwargs['is_admin'] = bool(kwargs['is_admin'])
        if 'is_active' in kwargs:
            kwargs['is_active'] = bool(kwargs['is_active'])
        
        return self.http.put(f'/api/v1/admin/users/{user_id}', json_data=kwargs)
    
    def delete_user(self, user_id: int) -> APIResponse:
        """
        Delete a user account.
        
        Args:
            user_id: ID of the user to delete
            
        Returns:
            APIResponse with deletion result
            
        Raises:
            ValidationError: If user_id is invalid
        """
        if not user_id or user_id <= 0:
            raise ValidationError("Valid user ID is required", "user_id", user_id)
        
        return self.http.delete(f'/api/v1/admin/users/{user_id}')
    
    def get_user_oauth_accounts(self, user_id: int) -> APIResponse:
        """
        Get OAuth accounts linked to a specific user.
        
        Args:
            user_id: ID of the user
            
        Returns:
            APIResponse with OAuth account information
            
        Raises:
            ValidationError: If user_id is invalid
        """
        if not user_id or user_id <= 0:
            raise ValidationError("Valid user ID is required", "user_id", user_id)
        
        return self.http.get(f'/api/v1/admin/users/{user_id}/oauth-accounts')
    
    # OAuth Provider Management Methods
    
    def get_oauth_providers(self) -> APIResponse:
        """
        Get all OAuth providers configured in the system.
        
        Returns:
            APIResponse with list of OAuth providers
        """
        return self.http.get('/api/v1/admin/oauth-providers')
    
    def create_oauth_provider(self, name: str, client_id: str, client_secret: str,
                             authorize_url: str, token_url: str, userinfo_url: str,
                             scope: str = "read profile") -> APIResponse:
        """
        Create a new OAuth provider configuration.
        
        Args:
            name: Provider name (e.g., 'google', 'github')
            client_id: OAuth client ID
            client_secret: OAuth client secret
            authorize_url: OAuth authorization URL
            token_url: OAuth token exchange URL
            userinfo_url: OAuth user info URL
            scope: OAuth scope (default: "read profile")
            
        Returns:
            APIResponse with creation result
            
        Raises:
            ValidationError: If any required fields are invalid
        """
        if not name or not name.strip():
            raise ValidationError("Provider name is required", "name", name)
        if not client_id or not client_id.strip():
            raise ValidationError("Client ID is required", "client_id", client_id)
        if not client_secret or not client_secret.strip():
            raise ValidationError("Client secret is required", "client_secret", client_secret)
        if not authorize_url or not authorize_url.strip():
            raise ValidationError("Authorization URL is required", "authorize_url", authorize_url)
        if not token_url or not token_url.strip():
            raise ValidationError("Token URL is required", "token_url", token_url)
        if not userinfo_url or not userinfo_url.strip():
            raise ValidationError("User info URL is required", "userinfo_url", userinfo_url)
        
        data = {
            'name': name.strip(),
            'client_id': client_id.strip(),
            'client_secret': client_secret.strip(),
            'authorize_url': authorize_url.strip(),
            'token_url': token_url.strip(),
            'userinfo_url': userinfo_url.strip(),
            'scope': scope.strip()
        }
        
        return self.http.post('/api/v1/admin/oauth-providers', json_data=data)
    
    def update_oauth_provider(self, provider_id: int, **kwargs) -> APIResponse:
        """
        Update an existing OAuth provider configuration.
        
        Args:
            provider_id: ID of the OAuth provider to update
            **kwargs: Fields to update
            
        Returns:
            APIResponse with update result
            
        Raises:
            ValidationError: If provider_id is invalid
        """
        if not provider_id or provider_id <= 0:
            raise ValidationError("Valid provider ID is required", "provider_id", provider_id)
        
        if not kwargs:
            raise ValidationError("No fields specified for update")
        
        # Strip whitespace from string fields
        for key, value in kwargs.items():
            if isinstance(value, str):
                kwargs[key] = value.strip()
        
        return self.http.put(f'/api/v1/admin/oauth-providers/{provider_id}', json_data=kwargs)
    
    def delete_oauth_provider(self, provider_id: int) -> APIResponse:
        """
        Delete an OAuth provider configuration.
        
        Args:
            provider_id: ID of the OAuth provider to delete
            
        Returns:
            APIResponse with deletion result
            
        Raises:
            ValidationError: If provider_id is invalid
        """
        if not provider_id or provider_id <= 0:
            raise ValidationError("Valid provider ID is required", "provider_id", provider_id)
        
        return self.http.delete(f'/api/v1/admin/oauth-providers/{provider_id}')
    
    # GSSAPI Realm Management Methods
    
    def get_gssapi_realms(self) -> APIResponse:
        """
        Get all GSSAPI realms configured in the system.
        
        Returns:
            APIResponse with list of GSSAPI realms
        """
        return self.http.get('/api/v1/admin/gssapi-realms')
    
    def create_gssapi_realm(self, name: str, keytab_data: str, 
                           description: Optional[str] = None) -> APIResponse:
        """
        Create a new GSSAPI realm configuration.
        
        Args:
            name: Realm name
            keytab_data: Base64-encoded keytab data
            description: Optional realm description
            
        Returns:
            APIResponse with creation result
            
        Raises:
            ValidationError: If required fields are invalid
        """
        if not name or not name.strip():
            raise ValidationError("Realm name is required", "name", name)
        if not keytab_data or not keytab_data.strip():
            raise ValidationError("Keytab data is required", "keytab_data", keytab_data)
        
        data = {
            'name': name.strip(),
            'keytab_data': keytab_data.strip()
        }
        if description:
            data['description'] = description.strip()
        
        return self.http.post('/api/v1/admin/gssapi-realms', json_data=data)
    
    def update_gssapi_realm(self, realm_id: int, **kwargs) -> APIResponse:
        """
        Update an existing GSSAPI realm configuration.
        
        Args:
            realm_id: ID of the GSSAPI realm to update
            **kwargs: Fields to update
            
        Returns:
            APIResponse with update result
            
        Raises:
            ValidationError: If realm_id is invalid
        """
        if not realm_id or realm_id <= 0:
            raise ValidationError("Valid realm ID is required", "realm_id", realm_id)
        
        if not kwargs:
            raise ValidationError("No fields specified for update")
        
        # Strip whitespace from string fields
        for key, value in kwargs.items():
            if isinstance(value, str):
                kwargs[key] = value.strip()
        
        return self.http.put(f'/api/v1/admin/gssapi-realms/{realm_id}', json_data=kwargs)
    
    def delete_gssapi_realm(self, realm_id: int) -> APIResponse:
        """
        Delete a GSSAPI realm configuration.
        
        Args:
            realm_id: ID of the GSSAPI realm to delete
            
        Returns:
            APIResponse with deletion result
            
        Raises:
            ValidationError: If realm_id is invalid
        """
        if not realm_id or realm_id <= 0:
            raise ValidationError("Valid realm ID is required", "realm_id", realm_id)
        
        return self.http.delete(f'/api/v1/admin/gssapi-realms/{realm_id}')
    
    # JWT Session Management Methods
    
    def get_jwt_sessions(self) -> APIResponse:
        """
        Get all active JWT sessions in the system (admin only).
        
        Returns:
            APIResponse with list of active JWT sessions
        """
        return self.http.get('/api/v1/admin/sessions')
    
    def expire_jwt_session(self, session_id: int) -> APIResponse:
        """
        Expire a specific JWT session (admin only).
        
        Args:
            session_id: ID of the JWT session to expire
            
        Returns:
            APIResponse with expiration result
            
        Raises:
            ValidationError: If session_id is invalid
        """
        if not session_id or session_id <= 0:
            raise ValidationError("Valid session ID is required", "session_id", session_id)
        
        return self.http.post(f'/api/v1/admin/sessions/{session_id}/expire')
    
    def expire_all_jwt_sessions(self) -> APIResponse:
        """
        Expire all active JWT sessions in the system (admin only).
        
        Returns:
            APIResponse with expiration result
        """
        return self.http.post('/api/v1/admin/sessions/expire-all')


# The end.
