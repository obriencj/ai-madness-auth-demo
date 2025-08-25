"""
Main Authentication Engine class.
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
        
        # Initialize services
        self.services['user'] = UserService(user_model, oauth_account_model)
        self.services['session'] = SessionService(
            session_model, 
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
            if provider_name == 'password':
                self.provider_registry.register('password', self._create_password_provider())
            elif provider_name.startswith('oauth_'):
                oauth_provider = provider_name.replace('oauth_', '')
                self.provider_registry.register(
                    provider_name, 
                    self._create_oauth_provider(oauth_provider)
                )
    
    def _create_password_provider(self):
        """Create password authentication provider."""
        from ..providers.password import PasswordProvider
        return PasswordProvider(self.services['auth'])
    
    def _create_oauth_provider(self, provider_name: str):
        """Create OAuth authentication provider."""
        from ..providers.oauth import OAuthProvider
        return OAuthProvider(provider_name, self.services['auth'])
    
    def _setup_blueprints(self):
        """Setup and register authentication blueprints."""
        from ..api import create_auth_blueprint, create_oauth_blueprint
        
        # Register core auth blueprint
        auth_bp = create_auth_blueprint(self.services['auth'])
        self.app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
        
        # Register OAuth blueprint if enabled
        if self.config.enable_oauth:
            oauth_bp = create_oauth_blueprint(self.services['auth'])
            self.app.register_blueprint(oauth_bp, url_prefix='/api/v1/auth/oauth')
        
        # Register admin blueprint if enabled
        if self.config.enable_admin:
            from ..api import create_admin_blueprint
            admin_bp = create_admin_blueprint(self.services)
            self.app.register_blueprint(admin_bp, url_prefix='/api/v1/admin')
    
    def get_service(self, service_name: str):
        """Get service by name."""
        return self.services.get(service_name)
    
    def get_provider(self, provider_name: str):
        """Get provider by name."""
        return self.provider_registry.get(provider_name)
    
    def authenticate(self, provider: str, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """Authenticate using specified provider."""
        auth_provider = self.get_provider(provider)
        if not auth_provider:
            raise ConfigurationError(f"Provider '{provider}' not found")
        
        return auth_provider.authenticate(credentials)
    
    def get_current_user(self):
        """Get current authenticated user."""
        from flask_jwt_extended import get_jwt_identity
        username = get_jwt_identity()
        if username:
            return self.services['user'].get_user_by_username(username)
        return None
    
    def require_auth(self, permission: Optional[str] = None):
        """Decorator to require authentication and optionally specific permission."""
        from flask_jwt_extended import jwt_required
        from functools import wraps
        
        def decorator(f):
            @wraps(f)
            @jwt_required()
            def decorated_function(*args, **kwargs):
                user = self.get_current_user()
                if not user:
                    return {'error': 'User not found'}, 404
                
                if permission:
                    self.services['user'].require_permission(user, permission)
                
                return f(*args, **kwargs)
            return decorated_function
        return decorator


# The end.
