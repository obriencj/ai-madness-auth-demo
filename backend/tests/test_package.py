"""
Test package structure and imports.
"""

from ai_auth_backend import create_app, app
from ai_auth_backend.models import db, User


def test_package_imports():
    """Test that the package can be imported correctly."""
    assert create_app is not None
    assert app is not None
    assert db is not None
    assert User is not None


def test_app_creation():
    """Test that the Flask app can be created."""
    test_app = create_app()
    assert test_app is not None
    assert test_app.config['SECRET_KEY'] is not None


def test_models_available():
    """Test that all models are available."""
    from ai_auth_backend.models import (
        User, OAuthProvider, OAuthAccount, JWTSession, Webhook, AuditLog
    )
    assert User is not None
    assert OAuthProvider is not None
    assert OAuthAccount is not None
    assert JWTSession is not None
    assert Webhook is not None
    assert AuditLog is not None


# The end.
