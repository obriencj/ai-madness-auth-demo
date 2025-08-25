"""
Command-line interface for the AI Auth Backend.
"""

import click
import os
from .app import create_app
from .models import db, User


@click.group()
def cli():
    """AI Auth Backend - Command Line Interface."""
    pass


@cli.command()
@click.option('--host', default='0.0.0.0', help='Host to bind to')
@click.option('--port', default=5000, help='Port to bind to')
@click.option('--debug', is_flag=True, help='Enable debug mode')
@click.option('--workers', default=4, help='Number of Gunicorn workers')
def run(host, port, debug, workers):
    """Run the authentication service."""
    if debug:
        # Development mode with Flask
        app = create_app()
        app.run(debug=True, host=host, port=port)
    else:
        # Production mode with Gunicorn
        os.environ['FLASK_APP'] = 'ai_auth_backend.app:app'
        os.environ['FLASK_ENV'] = 'production'
        
        import gunicorn.app.base
        
        class StandaloneApplication(gunicorn.app.base.BaseApplication):
            def __init__(self, app, options=None):
                self.options = options or {}
                self.application = app
                super().__init__()
            
            def load_config(self):
                for key, value in self.options.items():
                    self.cfg.set(key.lower(), value)
            
            def load(self):
                return self.application
        
        options = {
            'bind': f'{host}:{port}',
            'workers': workers,
            'worker_class': 'sync',
            'timeout': 120,
            'keepalive': 2,
            'max_requests': 1000,
            'max_requests_jitter': 100,
            'preload_app': True,
        }
        
        StandaloneApplication(create_app(), options).run()


@cli.command()
@click.option('--username', required=True, help='Admin username')
@click.option('--email', required=True, help='Admin email')
@click.option('--password', required=True, help='Admin password')
def create_admin(username, email, password):
    """Create an admin user."""
    app = create_app()
    
    with app.app_context():
        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            click.echo(f"User '{username}' already exists!")
            return
        
        # Create new admin user
        user = User(
            username=username,
            email=email,
            is_admin=True,
            is_active=True
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        click.echo(f"Admin user '{username}' created successfully!")


@cli.command()
@click.option('--username', required=True, help='Username to check')
def check_user(username):
    """Check if a user exists and show their details."""
    app = create_app()
    
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if user:
            click.echo(f"User: {user.username}")
            click.echo(f"Email: {user.email}")
            click.echo(f"Admin: {user.is_admin}")
            click.echo(f"Active: {user.is_active}")
            click.echo(f"Created: {user.created_at}")
        else:
            click.echo(f"User '{username}' not found!")


@cli.command()
def init_db():
    """Initialize the database tables."""
    app = create_app()
    
    with app.app_context():
        db.create_all()
        click.echo("Database tables created successfully!")


@cli.command()
def health_check():
    """Perform a health check on the service."""
    app = create_app()
    
    with app.app_context():
        try:
            # Test database connection
            db.session.execute('SELECT 1')
            click.echo("✅ Database: OK")
        except Exception as e:
            click.echo(f"❌ Database: ERROR - {e}")
            return
        
        try:
            # Test Redis connection (if configured)
            redis_url = app.config.get('REDIS_URL')
            if redis_url:
                import redis
                r = redis.from_url(redis_url)
                r.ping()
                click.echo("✅ Redis: OK")
            else:
                click.echo("⚠️  Redis: Not configured")
        except Exception as e:
            click.echo(f"❌ Redis: ERROR - {e}")
        
        click.echo("✅ Health check completed!")


def main():
    """Main entry point for the CLI."""
    cli()


if __name__ == '__main__':
    main()

# The end.
