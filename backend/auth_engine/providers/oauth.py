"""
OAuth authentication provider.
"""

import requests
from typing import Dict, Any, Optional
from .base import BaseProvider
from ..exceptions import AuthError, ProviderError


class OAuthProvider(BaseProvider):
    """OAuth-based authentication provider."""
    
    def __init__(self, provider_name: str, auth_service):
        """Initialize OAuth provider."""
        super().__init__(auth_service)
        self.provider_name = provider_name
        self.config = self._get_provider_config()
    
    def authenticate(self, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """Authenticate user with OAuth code."""
        code = credentials.get('code')
        redirect_uri = credentials.get('redirect_uri')
        
        if not code:
            raise AuthError("OAuth authorization code is required")
        
        if not redirect_uri:
            raise AuthError("OAuth redirect URI is required")
        
        # Exchange code for token
        token_data = self._exchange_code_for_token(code, redirect_uri)
        
        # Get user info from provider
        user_info = self._get_user_info(token_data['access_token'])
        
        # Authenticate with user info
        return self.auth_service.authenticate_with_oauth(
            self.provider_name, user_info
        )
    
    def get_authorization_url(self, redirect_uri: str) -> str:
        """Get OAuth authorization URL."""
        if not self.config:
            raise ProviderError(f"Provider '{self.provider_name}' not configured")
        
        params = {
            'client_id': self.config['client_id'],
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': self.config['scope']
        }
        
        param_str = '&'.join([f'{k}={v}' for k, v in params.items()])
        return f"{self.config['authorize_url']}?{param_str}"
    
    def _get_provider_config(self) -> Optional[Dict[str, Any]]:
        """Get OAuth provider configuration from database."""
        from flask import current_app
        
        # This would typically query the database for provider config
        # For now, return None to indicate not configured
        return None
    
    def _exchange_code_for_token(self, code: str, redirect_uri: str) -> Dict[str, Any]:
        """Exchange authorization code for access token."""
        if not self.config:
            raise ProviderError(f"Provider '{self.provider_name}' not configured")
        
        try:
            response = requests.post(self.config['token_url'], data={
                'client_id': self.config['client_id'],
                'client_secret': self.config['client_secret'],
                'code': code,
                'grant_type': 'authorization_code',
                'redirect_uri': redirect_uri
            })
            
            if response.status_code == 200:
                return response.json()
            else:
                raise ProviderError(f"Token exchange failed: {response.status_code}")
        except Exception as e:
            raise ProviderError(f"Token exchange error: {str(e)}")
    
    def _get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information from OAuth provider."""
        if not self.config:
            raise ProviderError(f"Provider '{self.provider_name}' not configured")
        
        try:
            headers = {'Authorization': f'Bearer {access_token}'}
            
            # Add provider-specific headers
            if self.provider_name == 'github':
                headers['Accept'] = 'application/vnd.github.v3+json'
            
            response = requests.get(self.config['userinfo_url'], headers=headers)
            
            if response.status_code == 200:
                return response.json()
            else:
                raise ProviderError(f"Failed to get user info: {response.status_code}")
        except Exception as e:
            raise ProviderError(f"Error getting user info: {str(e)}")
    
    def get_name(self) -> str:
        """Get provider name."""
        return f'oauth_{self.provider_name}'
    
    def is_enabled(self) -> bool:
        """Check if provider is enabled."""
        return self.config is not None and self.config.get('is_active', False)


# The end.
