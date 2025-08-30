"""
HTTP Client Base

This module provides the base HTTP client functionality for the DaftGila client.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import json
import requests
from typing import Any, Dict, Optional, Union
from urllib.parse import urljoin

from .response import APIResponse, create_success_response, create_error_response
from .exceptions import (
    DaftGilaClientError, APIError, ConnectionError, 
    TimeoutError, ValidationError
)


class HTTPClient:
    """
    Base HTTP client for making requests to the DaftGila API.
    
    This class handles the low-level HTTP operations including:
    - Request preparation and execution
    - Response parsing and validation
    - Error handling and exception raising
    - Header management
    """
    
    def __init__(self, base_url: str, timeout: float = 30.0, 
                 verify_ssl: bool = True, default_headers: Optional[Dict[str, str]] = None):
        """
        Initialize the HTTP client.
        
        Args:
            base_url: Base URL for the API (e.g., "http://localhost:5000")
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            default_headers: Default headers to include in all requests
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.default_headers = default_headers or {}
        self.session = requests.Session()
        
        # Configure session
        self.session.verify = verify_ssl
        self.session.headers.update(self.default_headers)
    
    def _build_url(self, endpoint: str) -> str:
        """
        Build full URL from endpoint.
        
        Args:
            endpoint: API endpoint (e.g., "/api/v1/auth/login")
            
        Returns:
            Full URL combining base_url and endpoint
        """
        if endpoint.startswith('http'):
            return endpoint
        return urljoin(f"{self.base_url}/", endpoint.lstrip('/'))
    
    def _prepare_headers(self, headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Prepare headers for the request.
        
        Args:
            headers: Additional headers to include
            
        Returns:
            Combined headers dictionary
        """
        request_headers = self.default_headers.copy()
        if headers:
            request_headers.update(headers)
        return request_headers
    
    def _parse_response(self, response: requests.Response) -> APIResponse:
        """
        Parse the HTTP response into an APIResponse object.
        
        Args:
            response: The requests.Response object
            
        Returns:
            APIResponse object with parsed data
            
        Raises:
            APIError: If the response indicates an error
        """
        try:
            # Try to parse JSON response
            if response.headers.get('content-type', '').startswith('application/json'):
                response_data = response.json()
            else:
                response_data = None
            
            # Check if response indicates success
            if response.status_code < 400:
                # Success response
                if response_data and isinstance(response_data, dict):
                    success = response_data.get('success', True)
                    message = response_data.get('message', 'Request successful')
                    data = response_data.get('data')
                else:
                    success = True
                    message = response.reason or 'Request successful'
                    data = response_data
                
                return create_success_response(message, data, response.status_code)
            else:
                # Error response
                if response_data and isinstance(response_data, dict):
                    message = response_data.get('error', response_data.get('message', response.reason))
                    data = response_data
                else:
                    message = response.reason or f'HTTP {response.status_code}'
                    data = response_data
                
                return create_error_response(message, response.status_code, data)
                
        except (ValueError, json.JSONDecodeError) as e:
            # Non-JSON response
            message = response.reason or f'HTTP {response.status_code}'
            return create_error_response(message, response.status_code, {'raw_response': response.text})
    
    def _handle_request_exception(self, e: Exception, operation: str) -> None:
        """
        Handle request exceptions and raise appropriate custom exceptions.
        
        Args:
            e: The original exception
            operation: Description of the operation being performed
            
        Raises:
            ConnectionError: For connection-related errors
            TimeoutError: For timeout errors
            DaftGilaClientError: For other request errors
        """
        if isinstance(e, requests.exceptions.Timeout):
            raise TimeoutError(f"{operation} timed out", self.timeout)
        elif isinstance(e, requests.exceptions.ConnectionError):
            raise ConnectionError(f"{operation} failed", e)
        elif isinstance(e, requests.exceptions.RequestException):
            raise DaftGilaClientError(f"{operation} failed: {str(e)}")
        else:
            raise DaftGilaClientError(f"Unexpected error during {operation}: {str(e)}")
    
    def get(self, endpoint: str, headers: Optional[Dict[str, str]] = None, 
            params: Optional[Dict[str, Any]] = None) -> APIResponse:
        """
        Make a GET request to the API.
        
        Args:
            endpoint: API endpoint
            headers: Optional additional headers
            params: Optional query parameters
            
        Returns:
            APIResponse object
            
        Raises:
            ConnectionError: If connection fails
            TimeoutError: If request times out
            DaftGilaClientError: For other errors
        """
        url = self._build_url(endpoint)
        request_headers = self._prepare_headers(headers)
        
        try:
            response = self.session.get(
                url, 
                headers=request_headers, 
                params=params, 
                timeout=self.timeout
            )
            return self._parse_response(response)
        except Exception as e:
            self._handle_request_exception(e, f"GET request to {endpoint}")
    
    def post(self, endpoint: str, data: Optional[Dict[str, Any]] = None, 
             json_data: Optional[Dict[str, Any]] = None, 
             headers: Optional[Dict[str, str]] = None) -> APIResponse:
        """
        Make a POST request to the API.
        
        Args:
            endpoint: API endpoint
            data: Optional form data
            json_data: Optional JSON data
            headers: Optional additional headers
            
        Returns:
            APIResponse object
            
        Raises:
            ConnectionError: If connection fails
            TimeoutError: If request times out
            DaftGilaClientError: For other errors
        """
        url = self._build_url(endpoint)
        request_headers = self._prepare_headers(headers)
        
        try:
            response = self.session.post(
                url, 
                data=data, 
                json=json_data, 
                headers=request_headers, 
                timeout=self.timeout
            )
            return self._parse_response(response)
        except Exception as e:
            self._handle_request_exception(e, f"POST request to {endpoint}")
    
    def put(self, endpoint: str, data: Optional[Dict[str, Any]] = None, 
            json_data: Optional[Dict[str, Any]] = None, 
            headers: Optional[Dict[str, str]] = None) -> APIResponse:
        """
        Make a PUT request to the API.
        
        Args:
            endpoint: API endpoint
            data: Optional form data
            json_data: Optional JSON data
            headers: Optional additional headers
            
        Returns:
            APIResponse object
            
        Raises:
            ConnectionError: If connection fails
            TimeoutError: If request times out
            DaftGilaClientError: For other errors
        """
        url = self._build_url(endpoint)
        request_headers = self._prepare_headers(headers)
        
        try:
            response = self.session.put(
                url, 
                data=data, 
                json=json_data, 
                headers=request_headers, 
                timeout=self.timeout
            )
            return self._parse_response(response)
        except Exception as e:
            self._handle_request_exception(e, f"PUT request to {endpoint}")
    
    def delete(self, endpoint: str, headers: Optional[Dict[str, str]] = None) -> APIResponse:
        """
        Make a DELETE request to the API.
        
        Args:
            endpoint: API endpoint
            headers: Optional additional headers
            
        Returns:
            APIResponse object
            
        Raises:
            ConnectionError: If connection fails
            TimeoutError: If request times out
            DaftGilaClientError: For other errors
        """
        url = self._build_url(endpoint)
        request_headers = self._prepare_headers(headers)
        
        try:
            response = self.session.delete(
                url, 
                headers=request_headers, 
                timeout=self.timeout
            )
            return self._parse_response(response)
        except Exception as e:
            self._handle_request_exception(e, f"DELETE request to {endpoint}")
    
    def set_auth_header(self, token: str) -> None:
        """
        Set the Authorization header for authenticated requests.
        
        Args:
            token: JWT token to include in Authorization header
        """
        self.default_headers['Authorization'] = f'Bearer {token}'
    
    def clear_auth_header(self) -> None:
        """Clear the Authorization header."""
        self.default_headers.pop('Authorization', None)
    
    def close(self) -> None:
        """Close the HTTP session."""
        self.session.close()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


# The end.
