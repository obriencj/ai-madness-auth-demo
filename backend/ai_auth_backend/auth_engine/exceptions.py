"""
Custom exceptions for the Authentication Engine.
"""


class AuthError(Exception):
    """Base exception for authentication errors."""
    pass


class PermissionDenied(AuthError):
    """Raised when a user doesn't have required permissions."""
    pass


class UserNotFound(AuthError):
    """Raised when a user cannot be found."""
    pass


class ProviderError(AuthError):
    """Raised when an authentication provider encounters an error."""
    pass


class ConfigurationError(AuthError):
    """Raised when there's a configuration error."""
    pass


class SessionError(AuthError):
    """Raised when there's a session-related error."""
    pass


# The end.
