"""
Configuration management for the Authentication Engine.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Cursor AI (Claude Sonnet 4)
"""

import os
from typing import List, Optional


class AuthConfig:
    """Configuration class for authentication settings."""
    
    def __init__(self, config_dict: Optional[dict] = None):
        """Initialize configuration with defaults or provided values."""
        # Default configuration
        self.providers = ['password']
        self.session_store = 'memory'  # 'memory' or 'redis'
        self.jwt_expiry = '1h'
        self.jwt_secret_key = os.getenv('JWT_SECRET_KEY', 'dev-jwt-secret')
        self.database_url = os.getenv('DATABASE_URL', 'sqlite:///auth.db')
        self.redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
        self.enable_admin = False
        self.enable_oauth = False
        self.enable_session_tracking = True
        self.permissions = ['read', 'write']
        
        # Override with provided configuration
        if config_dict:
            for key, value in config_dict.items():
                if hasattr(self, key):
                    setattr(self, key, value)
    
    def get_provider_config(self, provider_name: str) -> dict:
        """Get configuration for a specific provider."""
        if provider_name == 'password':
            return {
                'enabled': 'password' in self.providers,
                'min_password_length': 8,
                'require_special_chars': True
            }
        elif provider_name.startswith('oauth_'):
            oauth_provider = provider_name.replace('oauth_', '')
            return {
                'enabled': provider_name in self.providers,
                'client_id': os.getenv(f'{oauth_provider.upper()}_CLIENT_ID'),
                'client_secret': os.getenv(f'{oauth_provider.upper()}_CLIENT_SECRET'),
                'redirect_uri': os.getenv(f'{oauth_provider.upper()}_REDIRECT_URI')
            }
        return {}
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of errors."""
        errors = []
        
        if not self.providers:
            errors.append("At least one authentication provider must be configured")
        
        if self.session_store == 'redis' and not self.redis_url:
            errors.append("Redis URL must be configured when using Redis session store")
        
        if not self.jwt_secret_key or self.jwt_secret_key == 'dev-jwt-secret':
            errors.append("JWT secret key should be changed in production")
        
        return errors


# The end.
