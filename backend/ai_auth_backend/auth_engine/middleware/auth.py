"""
Authentication middleware for the Authentication Engine.
"""

from functools import wraps
from flask import request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt

from ..exceptions import AuthError, PermissionDenied


def auth_required(f):
    """Decorator to require authentication."""
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except AuthError as e:
            return jsonify({'error': str(e)}), 401
        except Exception as e:
            return jsonify({'error': 'Authentication failed'}), 401
    return decorated_function


def permission_required(permission: str):
    """Decorator to require specific permission."""
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            try:
                username = get_jwt_identity()
                if not username:
                    return jsonify({'error': 'User not found'}), 404
                
                # Get user service from app context
                user_service = current_app.auth_services['user']
                user = user_service.get_user_by_username(username)
                
                if not user:
                    return jsonify({'error': 'User not found'}), 404
                
                # Check permission
                if not user_service.check_permission(user, permission):
                    raise PermissionDenied(f"Permission '{permission}' required")
                
                return f(*args, **kwargs)
            except PermissionDenied as e:
                return jsonify({'error': str(e)}), 403
            except AuthError as e:
                return jsonify({'error': str(e)}), 401
            except Exception as e:
                return jsonify({'error': 'Permission check failed'}), 403
        return decorated_function
    return decorator


def admin_required(f):
    """Decorator to require admin privileges."""
    return permission_required('admin')(f)


# The end.
