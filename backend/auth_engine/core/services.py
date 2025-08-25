"""
Service layer for the Authentication Engine.
"""

from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from flask import current_app, request
from flask_jwt_extended import create_access_token, decode_token

from ..exceptions import AuthError, UserNotFound, PermissionDenied


class AuthenticationService:
    """Service for handling authentication operations."""
    
    def __init__(self, user_service, session_service):
        self.user_service = user_service
        self.session_service = session_service
    
    def authenticate_with_password(self, username: str, password: str) -> Dict[str, Any]:
        """Authenticate user with username and password."""
        user = self.user_service.get_user_by_username(username)
        
        if not user or not user.is_active:
            raise AuthError("Invalid credentials")
        
        if not user.check_password(password):
            raise AuthError("Invalid credentials")
        
        return self._create_auth_result(user, 'password')
    
    def authenticate_with_oauth(self, provider: str, user_info: Dict[str, Any]) -> Dict[str, Any]:
        """Authenticate user with OAuth provider."""
        # Find or create user based on OAuth info
        user = self.user_service.find_or_create_oauth_user(provider, user_info)
        
        if not user or not user.is_active:
            raise AuthError("User account is inactive")
        
        return self._create_auth_result(user, f'oauth_{provider}')
    
    def _create_auth_result(self, user, auth_method: str) -> Dict[str, Any]:
        """Create authentication result with JWT token and session."""
        # Create JWT token
        access_token = create_access_token(identity=user.username)
        
        # Get JTI from token
        token_data = decode_token(access_token)
        jti = token_data['jti']
        
        # Create session record
        self.session_service.create_session(
            jti=jti,
            user_id=user.id,
            auth_method=auth_method,
            ip_address=self._get_client_ip(),
            user_agent=request.headers.get('User-Agent')
        )
        
        return {
            'access_token': access_token,
            'user': self.user_service.serialize_user(user)
        }
    
    def logout(self, jti: str):
        """Logout user by expiring their session."""
        self.session_service.expire_session(jti)
    
    def _get_client_ip(self) -> str:
        """Get client IP address."""
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        else:
            return request.remote_addr


class UserService:
    """Service for handling user operations."""
    
    def __init__(self, user_model, oauth_account_model):
        self.user_model = user_model
        self.oauth_account_model = oauth_account_model
        # Get the database instance from the user model
        self.db = user_model.__table__.metadata.bind
    
    def get_user_by_id(self, user_id: Any) -> Optional[Any]:
        """Get user by ID."""
        return self.user_model.query.get(user_id)
    
    def get_user_by_username(self, username: str) -> Optional[Any]:
        """Get user by username."""
        return self.user_model.query.filter_by(username=username).first()
    
    def get_user_by_email(self, email: str) -> Optional[Any]:
        """Get user by email."""
        return self.user_model.query.filter_by(email=email).first()
    
    def create_user(self, user_data: Dict[str, Any]) -> Any:
        """Create new user."""
        user = self.user_model(**user_data)
        self.db.session.add(user)
        self.db.session.commit()
        return user
    
    def update_user(self, user_id: Any, user_data: Dict[str, Any]) -> Any:
        """Update existing user."""
        user = self.get_user_by_id(user_id)
        if not user:
            raise UserNotFound(f"User with ID {user_id} not found")
        
        for key, value in user_data.items():
            if hasattr(user, key):
                setattr(user, key, value)
        
        self.db.session.commit()
        return user
    
    def delete_user(self, user_id: Any):
        """Delete user."""
        user = self.get_user_by_id(user_id)
        if not user:
            raise UserNotFound(f"User with ID {user_id} not found")
        
        self.db.session.delete(user)
        self.db.session.commit()
    
    def find_or_create_oauth_user(self, provider: str, user_info: Dict[str, Any]) -> Any:
        """Find existing user or create new one from OAuth data."""
        # Try to find existing OAuth account
        oauth_account = self._find_oauth_account(provider, user_info)
        if oauth_account:
            return oauth_account.user
        
        # Try to find user by email
        email = user_info.get('email')
        if email:
            user = self.get_user_by_email(email)
            if user:
                return user
        
        # Create new user
        return self._create_oauth_user(provider, user_info)
    
    def _find_oauth_account(self, provider: str, user_info: Dict[str, Any]) -> Optional[Any]:
        """Find OAuth account by provider and user info."""
        provider_user_id = str(user_info.get('id', user_info.get('sub', '')))
        return self.oauth_account_model.query.filter_by(
            provider_name=provider,
            provider_user_id=provider_user_id
        ).first()
    
    def _create_oauth_user(self, provider: str, user_info: Dict[str, Any]) -> Any:
        """Create new user from OAuth data."""
        username = self._generate_unique_username(user_info)
        email = user_info.get('email', f"{username}@{provider}.oauth")
        
        user_data = {
            'username': username,
            'email': email,
            'is_active': True
        }
        
        return self.create_user(user_data)
    
    def _generate_unique_username(self, user_info: Dict[str, Any]) -> str:
        """Generate unique username from OAuth user info."""
        base_username = user_info.get('login', user_info.get('name', 'user'))
        base_username = ''.join(c for c in base_username if c.isalnum() or c in '._-')
        
        counter = 1
        username = base_username
        while self.get_user_by_username(username):
            username = f"{base_username}{counter}"
            counter += 1
        
        return username
    
    def serialize_user(self, user: Any) -> Dict[str, Any]:
        """Serialize user object to dictionary."""
        return {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_active': user.is_active,
            'permissions': user.get_permissions()
        }
    
    def check_permission(self, user: Any, permission: str) -> bool:
        """Check if user has specific permission."""
        return user.has_permission(permission)
    
    def require_permission(self, user: Any, permission: str):
        """Require user to have specific permission."""
        if not self.check_permission(user, permission):
            raise PermissionDenied(f"Permission '{permission}' required")


class SessionService:
    """Service for handling session operations."""
    
    def __init__(self, session_model, redis_client=None):
        self.session_model = session_model
        self.redis_client = redis_client
        # Get the database instance from the session model
        self.db = session_model.__table__.metadata.bind
    
    def create_session(self, jti: str, user_id: Any, auth_method: str, 
                      ip_address: Optional[str] = None, 
                      user_agent: Optional[str] = None) -> Any:
        """Create new JWT session."""
        expires_at = datetime.utcnow() + timedelta(hours=1)
        
        session = self.session_model(
            jti=jti,
            user_id=user_id,
            auth_method=auth_method,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expires_at,
            is_active=True
        )
        
        self.db.session.add(session)
        self.db.session.commit()
        
        return session
    
    def get_session_by_jti(self, jti: str) -> Optional[Any]:
        """Get session by JTI."""
        return self.session_model.query.filter_by(jti=jti).first()
    
    def expire_session(self, jti: str):
        """Expire session by JTI."""
        session = self.get_session_by_jti(jti)
        if session:
            session.is_active = False
            self.db.session.commit()
            
            # Add to blacklist if Redis is available
            if self.redis_client:
                self.redis_client.setex(jti, 3600, "true")
    
    def get_active_sessions(self, user_id: Optional[Any] = None) -> List[Any]:
        """Get active sessions, optionally filtered by user."""
        query = self.session_model.query.filter(
            self.session_model.is_active == True,
            self.session_model.expires_at > datetime.utcnow()
        )
        
        if user_id:
            query = query.filter(self.session_model.user_id == user_id)
        
        return query.order_by(self.session_model.created_at.desc()).all()
    
    def expire_all_sessions(self, user_id: Optional[Any] = None) -> int:
        """Expire all active sessions, optionally filtered by user."""
        sessions = self.get_active_sessions(user_id)
        
        for session in sessions:
            session.is_active = False
            if self.redis_client:
                self.redis_client.setex(session.jti, 3600, "true")
        
        self.db.session.commit()
        return len(sessions)


# The end.
