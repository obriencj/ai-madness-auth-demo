"""
Service layer for the Authentication Engine.
"""

from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from flask import request, g
from flask_jwt_extended import create_access_token, decode_token

from ..exceptions import AuthError, UserNotFound, PermissionDenied
from ..middleware.tenant import get_current_tenant, log_audit_event


class AuthenticationService:
    """Service for handling authentication operations."""
    
    def __init__(self, user_service, session_service):
        self.user_service = user_service
        self.session_service = session_service
    
    def authenticate_with_password(self, username: str, password: str) -> Dict[str, Any]:
        """Authenticate user with username and password."""
        tenant = get_current_tenant()
        user = self.user_service.get_user_by_username(username, tenant.id)
        
        if not user or not user.is_active:
            log_audit_event('user.login.failed', 'user', username, 
                          {'reason': 'invalid_credentials'})
            raise AuthError("Invalid credentials")
        
        if not user.check_password(password):
            log_audit_event('user.login.failed', 'user', user.id, 
                          {'reason': 'invalid_password'})
            raise AuthError("Invalid credentials")
        
        # Log successful login
        log_audit_event('user.login.success', 'user', user.id)
        
        return self._create_auth_result(user, 'password')
    
    def authenticate_with_oauth(self, provider: str, user_info: Dict[str, Any]) -> Dict[str, Any]:
        """Authenticate user with OAuth provider."""
        tenant = get_current_tenant()
        
        # Find or create user based on OAuth info
        user = self.user_service.find_or_create_oauth_user(provider, user_info, tenant.id)
        
        if not user or not user.is_active:
            log_audit_event('user.oauth.login.failed', 'user', user.id if user else None, 
                          {'provider': provider, 'reason': 'inactive_user'})
            raise AuthError("User account is inactive")
        
        # Log successful OAuth login
        log_audit_event('user.oauth.login.success', 'user', user.id, 
                       {'provider': provider})
        
        return self._create_auth_result(user, f'oauth_{provider}')
    
    def _create_auth_result(self, user, auth_method: str) -> Dict[str, Any]:
        """Create authentication result with JWT token and session."""
        # Create JWT token
        access_token = create_access_token(identity=user.username)
        
        # Get JTI from token
        token_data = decode_token(access_token)
        jti = token_data['jti']
        
        # Create session record
        tenant = get_current_tenant()
        self.session_service.create_session(
            jti=jti,
            user_id=user.id,
            auth_method=auth_method,
            ip_address=self._get_client_ip(),
            user_agent=request.headers.get('User-Agent'),
            tenant_id=tenant.id
        )
        
        return {
            'access_token': access_token,
            'user': self.user_service.serialize_user(user)
        }
    
    def logout(self, jti: str):
        """Logout user by expiring their session."""
        tenant = get_current_tenant()
        session = self.session_service.get_session_by_jti(jti, tenant.id)
        if session:
            log_audit_event('user.logout', 'user', session.user_id)
        
        self.session_service.expire_session(jti, tenant.id)
    
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
    
    def __init__(self, user_model, oauth_account_model, db):
        self.user_model = user_model
        self.oauth_account_model = oauth_account_model
        self.db = db
    
    def get_user_by_id(self, user_id: Any, tenant_id: int) -> Optional[Any]:
        """Get user by ID within tenant."""
        return self.user_model.query.filter_by(
            id=user_id, tenant_id=tenant_id
        ).first()
    
    def get_user_by_username(self, username: str, tenant_id: int) -> Optional[Any]:
        """Get user by username within tenant."""
        return self.user_model.query.filter_by(
            username=username, tenant_id=tenant_id
        ).first()
    
    def get_user_by_email(self, email: str, tenant_id: int) -> Optional[Any]:
        """Get user by email within tenant."""
        return self.user_model.query.filter_by(
            email=email, tenant_id=tenant_id
        ).first()
    
    def create_user(self, user_data: Dict[str, Any], tenant_id: int) -> Any:
        """Create new user within tenant."""
        user_data['tenant_id'] = tenant_id
        user = self.user_model(**user_data)
        self.db.session.add(user)
        self.db.session.commit()
        
        log_audit_event('user.created', 'user', user.id, user_data)
        return user
    
    def update_user(self, user_id: Any, user_data: Dict[str, Any], tenant_id: int) -> Any:
        """Update existing user within tenant."""
        user = self.get_user_by_id(user_id, tenant_id)
        if not user:
            raise UserNotFound(f"User with ID {user_id} not found")
        
        for key, value in user_data.items():
            if hasattr(user, key):
                setattr(user, key, value)
        
        self.db.session.commit()
        
        log_audit_event('user.updated', 'user', user.id, user_data)
        return user
    
    def delete_user(self, user_id: Any, tenant_id: int):
        """Delete user within tenant."""
        user = self.get_user_by_id(user_id, tenant_id)
        if not user:
            raise UserNotFound(f"User with ID {user_id} not found")
        
        self.db.session.delete(user)
        self.db.session.commit()
        
        log_audit_event('user.deleted', 'user', user_id)
    
    def find_or_create_oauth_user(self, provider: str, user_info: Dict[str, Any], tenant_id: int) -> Any:
        """Find existing user or create new one from OAuth data within tenant."""
        # Try to find existing OAuth account
        oauth_account = self._find_oauth_account(provider, user_info, tenant_id)
        if oauth_account:
            return oauth_account.user
        
        # Try to find user by email
        email = user_info.get('email')
        if email:
            user = self.get_user_by_email(email, tenant_id)
            if user:
                return user
        
        # Create new user
        return self._create_oauth_user(provider, user_info, tenant_id)
    
    def _find_oauth_account(self, provider: str, user_info: Dict[str, Any], tenant_id: int) -> Optional[Any]:
        """Find OAuth account by provider and user info within tenant."""
        provider_user_id = str(user_info.get('id', user_info.get('sub', '')))
        return self.oauth_account_model.query.filter_by(
            provider_name=provider,
            provider_user_id=provider_user_id,
            tenant_id=tenant_id
        ).first()
    
    def _create_oauth_user(self, provider: str, user_info: Dict[str, Any], tenant_id: int) -> Any:
        """Create new user from OAuth data within tenant."""
        username = self._generate_unique_username(user_info, tenant_id)
        email = user_info.get('email', f"{username}@{provider}.oauth")
        
        user_data = {
            'username': username,
            'email': email,
            'is_active': True
        }
        
        return self.create_user(user_data, tenant_id)
    
    def _generate_unique_username(self, user_info: Dict[str, Any], tenant_id: int) -> str:
        """Generate unique username from OAuth user info within tenant."""
        base_username = user_info.get('login', user_info.get('name', 'user'))
        base_username = ''.join(c for c in base_username if c.isalnum() or c in '._-')
        
        counter = 1
        username = base_username
        while self.get_user_by_username(username, tenant_id):
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
            'is_admin': user.is_admin,
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
    
    def __init__(self, session_model, db, redis_client=None):
        self.session_model = session_model
        self.db = db
        self.redis_client = redis_client
    
    def create_session(self, jti: str, user_id: Any, auth_method: str, 
                      ip_address: Optional[str] = None, 
                      user_agent: Optional[str] = None,
                      tenant_id: int = None) -> Any:
        """Create new JWT session within tenant."""
        expires_at = datetime.utcnow() + timedelta(hours=1)
        
        session = self.session_model(
            jti=jti,
            user_id=user_id,
            auth_method=auth_method,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expires_at,
            is_active=True,
            tenant_id=tenant_id
        )
        
        self.db.session.add(session)
        self.db.session.commit()
        
        return session
    
    def get_session_by_jti(self, jti: str, tenant_id: int) -> Optional[Any]:
        """Get session by JTI within tenant."""
        return self.session_model.query.filter_by(
            jti=jti, tenant_id=tenant_id
        ).first()
    
    def expire_session(self, jti: str, tenant_id: int):
        """Expire session by JTI within tenant."""
        session = self.get_session_by_jti(jti, tenant_id)
        if session:
            session.is_active = False
            self.db.session.commit()
            
            # Add to blacklist if Redis is available
            if self.redis_client:
                self.redis_client.setex(jti, 3600, "true")
    
    def get_active_sessions(self, user_id: Optional[Any] = None, tenant_id: int = None) -> List[Any]:
        """Get active sessions within tenant, optionally filtered by user."""
        query = self.session_model.query.filter(
            self.session_model.is_active.is_(True),
            self.session_model.expires_at > datetime.utcnow(),
            self.session_model.tenant_id == tenant_id
        )
        
        if user_id:
            query = query.filter(self.session_model.user_id == user_id)
        
        return query.order_by(self.session_model.created_at.desc()).all()
    
    def expire_all_sessions(self, user_id: Optional[Any] = None, tenant_id: int = None) -> int:
        """Expire all active sessions within tenant, optionally filtered by user."""
        sessions = self.get_active_sessions(user_id, tenant_id)
        
        for session in sessions:
            session.is_active = False
            if self.redis_client:
                self.redis_client.setex(session.jti, 3600, "true")
        
        self.db.session.commit()
        return len(sessions)


# The end.
