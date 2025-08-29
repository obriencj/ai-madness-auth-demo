"""
Utility functions shared across the Auth Demo application.

This module contains common utility functions that are used by multiple
modules to avoid code duplication.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

from .model import User


def generate_unique_username(base_username):
    """
    Generate a unique username from a base username.
    
    Args:
        base_username (str): The base username to make unique
        
    Returns:
        str: A unique username that doesn't exist in the database
    """
    # Clean the base username to only allow alphanumeric characters and some special chars
    clean_username = ''.join(c for c in base_username if c.isalnum() or c in '._-')
    
    counter = 1
    username = clean_username
    
    # Keep trying until we find a unique username
    while User.query.filter_by(username=username).first():
        username = f"{clean_username}{counter}"
        counter += 1
    
    return username


def get_provider_color(provider_name):
    """
    Get display color for OAuth provider.
    
    Args:
        provider_name (str): The name of the OAuth provider
        
    Returns:
        str: Hex color code for the provider
    """
    colors = {
        'google': '#4285f4',
        'github': '#333',
        'facebook': '#1877f2',
        'twitter': '#1da1f2',
        'linkedin': '#0077b5',
        'microsoft': '#00a4ef'
    }
    return colors.get(provider_name.lower(), '#6c757d')


# The end.
