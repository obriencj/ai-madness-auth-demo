"""
WSGI entry point for production deployment.
"""

from ai_auth_backend.app import create_app

app = create_app()

if __name__ == "__main__":
    app.run()

# The end.
