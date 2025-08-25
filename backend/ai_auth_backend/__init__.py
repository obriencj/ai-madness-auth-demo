"""
AI Auth Backend - A self-hosted, open-source authentication service.

This package provides a complete authentication service with user management,
OAuth integration, and JWT authentication.
"""

from .app import create_app, app

__version__ = "0.1.0"
__author__ = "AI Madness Team"
__email__ = "team@ai-madness.com"

__all__ = ["create_app", "app"]

# The end.
