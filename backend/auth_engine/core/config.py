"""
Configuration management for the Authentication Engine.
"""

import os
from typing import Dict, Any, List, Optional
from datetime import timedelta
from ..exceptions import ConfigurationError


class AuthConfig:
    """Configuration class for the Authentication Engine."""
    
    def __init__(self, config_dict: Optional[Dict[str, Any]] = None):
        """Initialize configuration with defaults or provided config."""
        self._config = config_dict or {}
        self._validate_config()
    
    @property
    def providers(self) -> List[str]:
        """Get list of enabled authentication providers."""
        return self._config.get('providers', ['password'])
    
    @property
    def session_store(self) -> str:
        """Get session store type."""
        return self._config.get('session_store', 'memory')
    
    @property
    def jwt_expiry(self) -> timedelta:
        """Get JWT token expiry time."""
        expiry_str = self._config.get('jwt_expiry', '1h')
        return self._parse_timedelta(expiry_str)
    
    @property
    def jwt_secret_key(self) -> str:
        """Get JWT secret key."""
        return self._config.get('jwt_secret_key') or os.getenv(
            'JWT_SECRET_KEY', 
            'your-super-secret-jwt-key-change-in-production'
        )
    
    @property
    def database_url(self) -> str:
        """Get database URL."""
        return self._config.get('database_url') or os.getenv(
            'DATABASE_URL',
            'postgresql://auth_user:auth_password@localhost:5432/auth_demo'
        )
    
    @property
    def redis_url(self) -> str:
        """Get Redis URL for session storage."""
        return self._config.get('redis_url') or os.getenv(
            'REDIS_URL', 
            'redis://localhost:6379'
        )
    
    @property
    def user_model(self) -> str:
        """Get custom user model class name."""
        return self._config.get('user_model', 'User')
    
    @property
    def enable_admin(self) -> bool:
        """Check if admin functionality is enabled."""
        return self._config.get('enable_admin', True)
    
    @property
    def enable_oauth(self) -> bool:
        """Check if OAuth functionality is enabled."""
        return self._config.get('enable_oauth', True)
    
    @property
    def enable_session_tracking(self) -> bool:
        """Check if session tracking is enabled."""
        return self._config.get('enable_session_tracking', True)
    
    @property
    def hooks(self) -> Dict[str, str]:
        """Get custom hooks configuration."""
        return self._config.get('hooks', {})
    
    @property
    def permissions(self) -> List[str]:
        """Get available permissions."""
        return self._config.get('permissions', ['read', 'write', 'admin'])
    
    def _validate_config(self):
        """Validate configuration values."""
        if not isinstance(self.providers, list):
            raise ConfigurationError("providers must be a list")
        
        if self.session_store not in ['memory', 'redis', 'database']:
            raise ConfigurationError(
                "session_store must be one of: memory, redis, database"
            )
    
    def _parse_timedelta(self, time_str: str) -> timedelta:
        """Parse time string into timedelta."""
        if not time_str:
            return timedelta(hours=1)
        
        # Simple parsing for common formats
        if time_str.endswith('h'):
            hours = int(time_str[:-1])
            return timedelta(hours=hours)
        elif time_str.endswith('m'):
            minutes = int(time_str[:-1])
            return timedelta(minutes=minutes)
        elif time_str.endswith('d'):
            days = int(time_str[:-1])
            return timedelta(days=days)
        else:
            # Default to hours
            try:
                hours = int(time_str)
                return timedelta(hours=hours)
            except ValueError:
                return timedelta(hours=1)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key."""
        return self._config.get(key, default)
    
    def set(self, key: str, value: Any):
        """Set configuration value."""
        self._config[key] = value
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return self._config.copy()


# The end.
