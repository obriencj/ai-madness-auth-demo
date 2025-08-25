"""
Authentication Engine - A reusable authentication system for Flask applications.

This package provides a modular, configurable authentication system that can be
easily integrated into any Flask application.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Cursor AI (Claude Sonnet 4)
"""

from .core import AuthEngine, AuthConfig
from .providers import ProviderRegistry
from .middleware import auth_required, permission_required
from .exceptions import AuthError, PermissionDenied, UserNotFound

__version__ = "1.0.0"
__all__ = [
    'AuthEngine',
    'AuthConfig', 
    'ProviderRegistry',
    'auth_required',
    'permission_required',
    'AuthError',
    'PermissionDenied',
    'UserNotFound'
]

# The end.
