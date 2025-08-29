"""
Authentication package for the Daft Gila web frontend.

This package organizes authentication functionality into logical modules:
- Core authentication (login, logout, session validation)
- OAuth authentication flow
- GSSAPI authentication

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

from .core import auth_bp
from .oauth import oauth_bp
from .gssapi import gssapi_bp

# Export the main auth blueprint for registration
__all__ = ['auth_bp', 'oauth_bp', 'gssapi_bp']

# The end.
