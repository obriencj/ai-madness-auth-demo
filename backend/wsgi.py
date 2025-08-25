"""
WSGI entry point for production deployment.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Cursor AI (Claude Sonnet 4)
"""

from ai_auth_backend.app import create_app

app = create_app()

if __name__ == "__main__":
    app.run()

# The end.
