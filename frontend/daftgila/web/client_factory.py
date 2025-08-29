"""
Client Factory for DaftGila API

This module provides a factory function to create configured DaftGilaClient
instances for use in Flask routes.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""


import os
from typing import Optional
from daftgila.client import DaftGilaClient


def create_api_client(access_token: Optional[str] = None) -> DaftGilaClient:
    """
    Create a configured DaftGilaClient instance.
    
    Args:
        access_token: Optional JWT token for authenticated requests
        
    Returns:
        Configured DaftGilaClient instance
    """
    # Get backend URL from environment
    backend_url = os.environ.get('BACKEND_URL', 'http://localhost:5000')
    
    # Create client with default configuration
    client = DaftGilaClient(
        base_url=backend_url,
        timeout=30.0,
        verify_ssl=True,
        default_headers={
            'User-Agent': 'DaftGila-Web/1.0'
        }
    )
    
    # Set authentication token if provided
    if access_token:
        client.set_auth_token(access_token)
    
    return client


def get_client_from_session(session) -> DaftGilaClient:
    """
    Create a client instance configured with session data.
    
    Args:
        session: Flask session object
        
    Returns:
        Configured DaftGilaClient instance
    """
    access_token = session.get('access_token')
    return create_api_client(access_token)


# The end.
