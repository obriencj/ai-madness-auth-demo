"""
API Response Models

This module defines the response models used by the DaftGila client.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

from typing import Any, Dict, Optional, Union
from dataclasses import dataclass


@dataclass
class APIResponse:
    """
    Standard API response wrapper.
    
    This class provides a consistent interface for all API responses,
    handling both successful and error responses from the DaftGila API.
    """
    
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    status_code: int = 200
    
    def __post_init__(self):
        """Validate response data after initialization."""
        if self.success and self.status_code >= 400:
            raise ValueError("Successful responses should not have error status codes")
        if not self.success and self.status_code < 400:
            raise ValueError("Error responses should have error status codes")
    
    @property
    def is_success(self) -> bool:
        """Check if the response indicates success."""
        return self.success and self.status_code < 400
    
    @property
    def is_error(self) -> bool:
        """Check if the response indicates an error."""
        return not self.success or self.status_code >= 400
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a value from the response data.
        
        Args:
            key: The key to retrieve from the data dictionary
            default: Default value if key doesn't exist
            
        Returns:
            The value for the key or the default value
        """
        if self.data is None:
            return default
        return self.data.get(key, default)
    
    def __getitem__(self, key: str) -> Any:
        """
        Access response data using dictionary-style access.
        
        Args:
            key: The key to retrieve from the data dictionary
            
        Returns:
            The value for the key
            
        Raises:
            KeyError: If the key doesn't exist in the data
        """
        if self.data is None:
            raise KeyError(f"Response has no data")
        return self.data[key]
    
    def __contains__(self, key: str) -> bool:
        """
        Check if a key exists in the response data.
        
        Args:
            key: The key to check
            
        Returns:
            True if the key exists, False otherwise
        """
        return self.data is not None and key in self.data
    
    def __str__(self) -> str:
        """String representation of the response."""
        status = "SUCCESS" if self.is_success else "ERROR"
        return f"APIResponse({status}, {self.status_code}): {self.message}"
    
    def __repr__(self) -> str:
        """Detailed string representation of the response."""
        return (f"APIResponse(success={self.success}, message='{self.message}', "
                f"data={self.data}, status_code={self.status_code})")


def create_success_response(message: str, data: Optional[Dict[str, Any]] = None, 
                          status_code: int = 200) -> APIResponse:
    """
    Create a success response.
    
    Args:
        message: Success message
        data: Optional response data
        status_code: HTTP status code (default: 200)
        
    Returns:
        APIResponse instance
    """
    return APIResponse(
        success=True,
        message=message,
        data=data,
        status_code=status_code
    )


def create_error_response(message: str, status_code: int = 400, 
                        data: Optional[Dict[str, Any]] = None) -> APIResponse:
    """
    Create an error response.
    
    Args:
        message: Error message
        status_code: HTTP status code (default: 400)
        data: Optional error data
        
    Returns:
        APIResponse instance
    """
    return APIResponse(
        success=False,
        message=message,
        data=data,
        status_code=status_code
    )


# The end.
