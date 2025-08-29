"""
Shared utilities for the Daft Gila web frontend.

This module contains common functions and utilities used across
multiple blueprints to avoid code duplication.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import os

# Configuration
BACKEND_URL = os.environ.get('BACKEND_URL', 'http://localhost:5000')

def extract_api_data(response, *keys, default=None):
    """
    Extract data from an API response with success checking and data extraction.
    
    This helper function handles the common pattern of:
    1. Getting JSON from response
    2. Checking success value
    3. Extracting data dict from response
    4. Getting specific values from the data dict
    
    Args:
        response: The requests.Response object from an API call
        *keys: Variable number of keys to extract from the data dict
        default: Default value to return if any step fails
        
    Returns:
        - If no keys provided: The entire data dict
        - If one key provided: The value for that key
        - If multiple keys provided: A tuple of values for those keys
        - If any step fails: The default value (or None if not specified)
        
    Examples:
        # Get entire data dict
        data = extract_api_data(response)
        
        # Get single value
        users = extract_api_data(response, 'users', default=[])
        
        # Get multiple values
        users, count = extract_api_data(response, 'users', 'total_count', default=([], 0))
    """

    # print(f"extract_api_data: {response}")

    try:
        if response.status_code != 200:
            return default

        response_data = response.json()
        # print(f"response_data: {response_data}")

        if not response_data.get('success'):
            return default
            
        data = response_data.get('data', {})
        
        if not keys:
            return data
            
        if len(keys) == 1:
            return data.get(keys[0], default)
            
        # Multiple keys - return tuple
        return tuple(data.get(key, default) for key in keys)
        
    except (ValueError, KeyError, AttributeError):
        return default

# The end.
