"""
Tenant isolation and API key authentication middleware.
"""

from functools import wraps
from flask import request, jsonify, current_app, g


def get_tenant_from_request():
    """Extract tenant from request headers or domain."""
    # Try to get tenant from API key header
    api_key = request.headers.get('X-API-Key')
    if api_key:
        from ..models import Tenant
        tenant = Tenant.query.filter_by(
            api_key=api_key, is_active=True
        ).first()
        if tenant:
            return tenant
    
    # Try to get tenant from domain
    domain = request.headers.get('Host', '').split(':')[0]
    if domain:
        from ..models import Tenant
        tenant = Tenant.query.filter_by(
            domain=domain, is_active=True
        ).first()
        if tenant:
            return tenant
    
    # Return default tenant if no specific tenant found
    from ..models import Tenant
    return Tenant.query.filter_by(name='default').first()


def require_api_key(f):
    """Decorator to require API key authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        from ..models import Tenant
        tenant = Tenant.query.filter_by(
            api_key=api_key, is_active=True
        ).first()
        
        if not tenant:
            return jsonify({'error': 'Invalid API key'}), 401
        
        # Store tenant in request context
        g.current_tenant = tenant
        return f(*args, **kwargs)
    return decorated_function


def tenant_required(f):
    """Decorator to require tenant context."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        tenant = get_tenant_from_request()
        if not tenant:
            return jsonify({'error': 'Tenant not found'}), 404
        
        # Store tenant in request context
        g.current_tenant = tenant
        return f(*args, **kwargs)
    return decorated_function


def get_current_tenant():
    """Get current tenant from request context."""
    return getattr(g, 'current_tenant', None)


def log_audit_event(action, resource_type=None, resource_id=None,
                    details=None, user_id=None):
    """Log audit event for current tenant."""
    tenant = get_current_tenant()
    if not tenant:
        return
    
    from ..models import AuditLog
    
    audit_log = AuditLog(
        tenant_id=tenant.id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        details=details or {},
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    
    current_app.db.session.add(audit_log)
    current_app.db.session.commit()


# The end.
