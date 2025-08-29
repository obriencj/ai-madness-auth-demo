"""
DaftGila Client Module

Object-oriented requests wrapper for the DaftGila API.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

from .client import DaftGilaClient
from .exceptions import DaftGilaClientError, AuthenticationError, APIError
from .response import APIResponse

__all__ = [
    'DaftGilaClient',
    'DaftGilaClientError', 
    'AuthenticationError',
    'APIError',
    'APIResponse'
]

# The end.
