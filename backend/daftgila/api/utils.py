"""
Utility functions shared across the Auth Demo application.

This module contains common utility functions that are used by multiple
modules to avoid code duplication.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

from functools import wraps
from flask import request
from .model import User


def generate_unique_username(base_username):
    """
    Generate a unique username from a base username.
    
    Args:
        base_username (str): The base username to make unique
        
    Returns:
        str: A unique username that doesn't exist in the database
    """
    # Clean the base username to only allow alphanumeric characters and some special chars
    clean_username = ''.join(c for c in base_username if c.isalnum() or c in '._-')
    
    counter = 1
    username = clean_username
    
    # Keep trying until we find a unique username
    while User.query.filter_by(username=username).first():
        username = f"{clean_username}{counter}"
        counter += 1
    
    return username


def get_provider_color(provider_name):
    """
    Get display color for OAuth provider.
    
    Args:
        provider_name (str): The name of the OAuth provider
        
    Returns:
        str: Hex color code for the provider
    """
    colors = {
        'google': '#4285f4',
        'github': '#333',
        'facebook': '#1877f2',
        'twitter': '#1da1f2',
        'linkedin': '#0077b5',
        'microsoft': '#00a4ef'
    }
    return colors.get(provider_name.lower(), '#6c757d')


def admin_required(f):
    """
    Decorator to require admin privileges for an endpoint.
    
    Args:
        f: The function to decorate
        
    Returns:
        The decorated function
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from .jwt import get_jwt_identity
        
        current_username = get_jwt_identity()
        current_user = User.query.filter_by(username=current_username).first()
        
        if not current_user or not current_user.is_admin:
            return error_response('Admin privileges required', 403)
        
        return f(*args, **kwargs)
    return decorated_function


def admin_required_with_audit(action, resource_type=None):
    """
    Decorator to require admin privileges and automatically log actions.
    
    Args:
        action (str): The action being performed (from AuditActions)
        resource_type (str, optional): The type of resource being acted upon
        
    Returns:
        The decorated function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from .jwt import get_jwt_identity
            from .audit import log_action, AuditActions
            
            current_username = get_jwt_identity()
            current_user = User.query.filter_by(username=current_username).first()
            
            if not current_user or not current_user.is_admin:
                return error_response('Admin privileges required', 403)
            
            # Execute the function
            result = f(*args, **kwargs)
            
            # Log the action if it was successful (status code < 400)
            if hasattr(result, '__getitem__') and len(result) >= 2:
                status_code = result[1]
                if status_code < 400:
                    # Extract resource ID from kwargs if available
                    resource_id = kwargs.get('user_id') or kwargs.get('provider_id') or kwargs.get('realm_id') or kwargs.get('session_id') or kwargs.get('version_id')
                    
                    log_action(
                        user_id=current_user.id,
                        action=action,
                        resource_type=resource_type or 'system',
                        resource_id=resource_id,
                        details={
                            'endpoint': request.endpoint,
                            'method': request.method,
                            'ip_address': _get_client_ip(),
                            'user_agent': request.headers.get('User-Agent')
                        }
                    )
            
            return result
        return decorated_function
    return decorator


def get_current_user():
    """
    Get the current authenticated user from JWT token.
    
    Returns:
        User: The current user object, or None if not authenticated
    """
    from .jwt import get_jwt_identity
    
    current_username = get_jwt_identity()
    if not current_username:
        return None
    
    return User.query.filter_by(username=current_username).first()


def validate_required_fields(data, required_fields):
    """
    Validate that required fields are present in request data.
    
    Args:
        data (dict): The request data to validate
        required_fields (list): List of required field names
        
    Returns:
        tuple: (is_valid, error_message) where is_valid is boolean
    """
    if not data:
        return False, 'Request data is required'
    
    missing_fields = [field for field in required_fields if not data.get(field)]
    if missing_fields:
        return False, f'Missing required fields: {", ".join(missing_fields)}'
    
    return True, None


def validate_email_format(email):
    """
    Basic email format validation.
    
    Args:
        email (str): Email address to validate
        
    Returns:
        bool: True if email format is valid
    """
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_username_format(username):
    """
    Validate username format (alphanumeric, dots, underscores, hyphens only).
    
    Args:
        username (str): Username to validate
        
    Returns:
        bool: True if username format is valid
    """
    import re
    pattern = r'^[a-zA-Z0-9._-]+$'
    return re.match(pattern, username) is not None


def format_user_response(user):
    """
    Format user data for API response.
    
    Args:
        user (User): User object to format
        
    Returns:
        dict: Formatted user data
    """
    return {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'is_admin': user.is_admin,
        'is_active': user.is_active,
        'created_at': user.created_at.isoformat() if hasattr(user, 'created_at') and user.created_at else None,
        'updated_at': user.updated_at.isoformat() if hasattr(user, 'updated_at') and user.updated_at else None,
        'last_login_at': user.last_login_at.isoformat() if hasattr(user, 'last_login_at') and user.last_login_at else None
    }


def format_oauth_provider_response(provider):
    """
    Format OAuth provider data for API response.
    
    Args:
        provider (OAuthProvider): OAuth provider object to format
        
    Returns:
        dict: Formatted provider data
    """
    return {
        'id': provider.id,
        'name': provider.name,
        'client_id': provider.client_id,
        'client_secret': '***' if provider.client_secret else None,
        'authorize_url': provider.authorize_url,
        'token_url': provider.token_url,
        'userinfo_url': provider.userinfo_url,
        'scope': provider.scope,
        'is_active': provider.is_active,
        'is_deleted': getattr(provider, 'is_deleted', False),
        'created_at': provider.created_at.isoformat() if provider.created_at else None,
        'updated_at': provider.updated_at.isoformat() if hasattr(provider, 'updated_at') and provider.updated_at else None
    }


def format_gssapi_realm_response(realm):
    """
    Format GSSAPI realm data for API response.
    
    Args:
        realm (GSSAPIRealm): GSSAPI realm object to format
        
    Returns:
        dict: Formatted realm data
    """
    return {
        'id': realm.id,
        'name': realm.name,
        'realm': realm.realm,
        'kdc_hosts': realm.kdc_hosts,
        'admin_server': realm.admin_server,
        'service_principal': realm.service_principal,
        'default_realm': realm.default_realm,
        'is_active': realm.is_active,
        'is_deleted': getattr(realm, 'is_deleted', False),
        'created_at': realm.created_at.isoformat() if realm.created_at else None,
        'updated_at': realm.updated_at.isoformat() if hasattr(realm, 'updated_at') and realm.updated_at else None
    }


def success_response(message, data=None, status_code=200):
    """
    Create a standardized success response.
    
    Args:
        message (str): Success message
        data (dict, optional): Response data
        status_code (int): HTTP status code
        
    Returns:
        tuple: (response, status_code)
    """
    response = {'message': message}
    if data:
        response.update(data)
    return jsonify(response), status_code


def error_response(error_message, status_code=400, details=None):
    """
    Create a standardized error response.
    
    Args:
        error_message (str): Error message
        status_code (int): HTTP status code
        details (dict, optional): Additional error details
        
    Returns:
        tuple: (response, status_code)
    """
    response = {'error': error_message}
    if details:
        response['details'] = details
    return jsonify(response), status_code


def _get_client_ip():
    """Get the client's IP address, handling proxy headers."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr


# The end.
