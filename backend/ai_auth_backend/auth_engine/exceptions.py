"""
Custom exceptions for the Authentication Engine.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Cursor AI (Claude Sonnet 4)
"""


class AuthError(Exception):
    """Base exception for authentication errors."""
    pass


class UserNotFound(AuthError):
    """Raised when a user cannot be found."""
    pass


class PermissionDenied(AuthError):
    """Raised when a user lacks required permissions."""
    pass


class ConfigurationError(AuthError):
    """Raised when there's a configuration error."""
    pass


class ValidationError(AuthError):
    """Raised when input validation fails."""
    pass


class OAuthError(AuthError):
    """Raised when OAuth operations fail."""
    pass


# The end.
