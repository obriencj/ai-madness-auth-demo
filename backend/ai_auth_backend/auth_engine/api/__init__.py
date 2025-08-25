"""
API blueprints for the Authentication Engine.
"""

from .auth import create_auth_blueprint
from .oauth import create_oauth_blueprint
from .admin import create_admin_blueprint

__all__ = [
    'create_auth_blueprint',
    'create_oauth_blueprint', 
    'create_admin_blueprint'
]

# The end.
