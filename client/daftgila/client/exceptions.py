"""
Custom Exceptions

This module defines custom exception classes for the DaftGila client.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

from typing import Optional, Dict, Any


class DaftGilaClientError(Exception):
    """
    Base exception class for all DaftGila client errors.
    
    This exception is raised when there's an error in the client
    that's not related to the API response itself.
    """
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize the exception.
        
        Args:
            message: Error message
            details: Optional additional error details
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}
    
    def __str__(self) -> str:
        """String representation of the exception."""
        if self.details:
            return f"{self.message} - Details: {self.details}"
        return self.message


class AuthenticationError(DaftGilaClientError):
    """
    Exception raised when authentication fails.
    
    This exception is raised when the client cannot authenticate
    with the API, such as invalid credentials or expired tokens.
    """
    
    def __init__(self, message: str = "Authentication failed", 
                 details: Optional[Dict[str, Any]] = None):
        """
        Initialize the authentication error.
        
        Args:
            message: Error message
            details: Optional additional error details
        """
        super().__init__(message, details)


class APIError(DaftGilaClientError):
    """
    Exception raised when the API returns an error response.
    
    This exception is raised when the API returns a non-success
    response, such as validation errors or server errors.
    """
    
    def __init__(self, message: str, status_code: int, 
                 response_data: Optional[Dict[str, Any]] = None):
        """
        Initialize the API error.
        
        Args:
            message: Error message from the API
            status_code: HTTP status code from the API
            response_data: Optional full response data from the API
        """
        super().__init__(message, {"status_code": status_code, "response_data": response_data})
        self.status_code = status_code
        self.response_data = response_data
    
    def __str__(self) -> str:
        """String representation of the API error."""
        return f"API Error ({self.status_code}): {self.message}"


class ValidationError(DaftGilaClientError):
    """
    Exception raised when input validation fails.
    
    This exception is raised when the client validates input
    parameters before sending them to the API.
    """
    
    def __init__(self, message: str, field: Optional[str] = None, 
                 value: Optional[Any] = None):
        """
        Initialize the validation error.
        
        Args:
            message: Validation error message
            field: Optional field name that failed validation
            value: Optional value that failed validation
        """
        details = {}
        if field is not None:
            details["field"] = field
        if value is not None:
            details["value"] = value
        
        super().__init__(message, details)
        self.field = field
        self.value = value


class ConnectionError(DaftGilaClientError):
    """
    Exception raised when there's a connection error.
    
    This exception is raised when the client cannot connect
    to the API server, such as network issues or server unavailability.
    """
    
    def __init__(self, message: str = "Connection failed", 
                 original_error: Optional[Exception] = None):
        """
        Initialize the connection error.
        
        Args:
            message: Error message
            original_error: Optional original exception that caused the connection error
        """
        details = {}
        if original_error is not None:
            details["original_error"] = str(original_error)
        
        super().__init__(message, details)
        self.original_error = original_error


class TimeoutError(DaftGilaClientError):
    """
    Exception raised when a request times out.
    
    This exception is raised when a request to the API
    takes longer than the configured timeout.
    """
    
    def __init__(self, message: str = "Request timed out", 
                 timeout_seconds: Optional[float] = None):
        """
        Initialize the timeout error.
        
        Args:
            message: Error message
            timeout_seconds: Optional timeout value in seconds
        """
        details = {}
        if timeout_seconds is not None:
            details["timeout_seconds"] = timeout_seconds
        
        super().__init__(message, details)
        self.timeout_seconds = timeout_seconds


# The end.
