"""
Main Authentication Engine class.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Cursor AI (Claude Sonnet 4)
"""

from typing import Dict, Any, Optional
from flask import Flask
from flask_cors import CORS

from .config import AuthConfig
from .services import AuthenticationService, UserService, SessionService
from ..providers import ProviderRegistry
from ..exceptions import ConfigurationError


class AuthEngine:
    """Main authentication engine that orchestrates the entire system."""
    
    def __init__(self, app: Flask, config: Optional[AuthConfig] = None):
        """Initialize the authentication engine."""
        self.app = app
        self.config = config or AuthConfig()
        self.provider_registry = ProviderRegistry()
        self.services = {}
        
        self._validate_config()
        self._setup_app()
        self._initialize_services()
        self._register_providers()
        self._setup_blueprints()
    
    def _validate_config(self):
        """Validate engine configuration."""
        if not self.config.providers:
            raise ConfigurationError("At least one provider must be configured")
    
    def _setup_app(self):
        """Setup Flask app with authentication configuration."""
        # Configure database (only if not already set)
        if 'SQLALCHEMY_DATABASE_URI' not in self.app.config:
            self.app.config['SQLALCHEMY_DATABASE_URI'] = self.config.database_url
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        
        # Configure JWT
        self.app.config['JWT_SECRET_KEY'] = self.config.jwt_secret_key
        self.app.config['JWT_ACCESS_TOKEN_EXPIRES'] = self.config.jwt_expiry
        self.app.config['JWT_ALGORITHM'] = 'HS256'
        self.app.config['JWT_TOKEN_LOCATION'] = ['headers']
        self.app.config['JWT_HEADER_NAME'] = 'Authorization'
        self.app.config['JWT_HEADER_TYPE'] = 'Bearer'
        
        # Enable CORS
        CORS(self.app)
        
        # Store config in app context
        self.app.auth_config = self.config
    
    def _initialize_services(self):
        """Initialize service layer."""
        # Get model classes from app
        user_model = getattr(self.app, 'user_model', None)
        oauth_account_model = getattr(self.app, 'oauth_account_model', None)
        session_model = getattr(self.app, 'session_model', None)
        
        if not user_model:
            raise ConfigurationError("User model not configured in app")
        
        # Get database instance from app
        db = getattr(self.app, 'db', None)
        if not db:
            raise ConfigurationError("Database instance not configured in app")
        
        # Initialize services
        self.services['user'] = UserService(user_model, oauth_account_model, db)
        self.services['session'] = SessionService(
            session_model, 
            db,
            self._get_redis_client()
        )
        self.services['auth'] = AuthenticationService(
            self.services['user'],
            self.services['session']
        )
        
        # Store services in app context
        self.app.auth_services = self.services
    
    def _get_redis_client(self):
        """Get Redis client if configured."""
        if self.config.session_store == 'redis':
            try:
                import redis
                return redis.from_url(self.config.redis_url)
            except ImportError:
                self.app.logger.warning("Redis not available, using memory storage")
                return None
        return None
    
    def _register_providers(self):
        """Register configured authentication providers."""
        for provider_name in self.config.providers:
            try:
                provider = self.provider_registry.get_provider(provider_name)
                if provider:
                    provider.register(self.app)
            except Exception as e:
                self.app.logger.error(f"Failed to register provider {provider_name}: {e}")
    
    def _setup_blueprints(self):
        """Setup Flask blueprints for authentication routes."""
        from ..api import auth_bp, oauth_bp, admin_bp
        
        self.app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
        self.app.register_blueprint(oauth_bp, url_prefix='/api/v1/auth/oauth')
        self.app.register_blueprint(admin_bp, url_prefix='/api/v1/admin')
    
    def require_auth(self):
        """Decorator to require authentication."""
        from ..middleware import auth_required
        return auth_required
    
    def require_permission(self, permission: str):
        """Decorator to require specific permission."""
        from ..middleware import permission_required
        return permission_required(permission)
    
    def get_current_user(self):
        """Get current authenticated user."""
        from flask_jwt_extended import get_jwt_identity
        from flask import current_app
        
        username = get_jwt_identity()
        if username:
            return self.services['user'].get_user_by_username(username)
        return None
    
    def get_user_service(self):
        """Get user service instance."""
        return self.services['user']
    
    def get_session_service(self):
        """Get session service instance."""
        return self.services['session']
    
    def get_auth_service(self):
        """Get authentication service instance."""
        return self.services['auth']


# The end.
