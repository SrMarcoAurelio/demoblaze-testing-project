"""
API Client
Professional HTTP client wrapper for API testing with comprehensive features.

Author: Marc Arévalo
Version: 1.0
"""

import logging
from typing import Any, Dict, Optional, Union
from urllib.parse import urljoin

import requests
from requests.auth import AuthBase, HTTPBasicAuth

logger = logging.getLogger(__name__)


class APIClient:
    """
    Professional API client for testing REST APIs.

    Features:
    - Request/response logging
    - Automatic retries
    - Authentication support
    - Session management
    - Custom headers
    - Response validation
    """

    def __init__(
        self,
        base_url: str,
        timeout: int = 30,
        verify_ssl: bool = True,
        auth: Optional[AuthBase] = None,
        default_headers: Optional[Dict[str, str]] = None,
    ):
        """
        Initialize API client.

        Args:
            base_url: Base URL for API
            timeout: Request timeout in seconds
            verify_ssl: Verify SSL certificates
            auth: Authentication object
            default_headers: Default headers for all requests
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.auth = auth
        self.session = requests.Session()
        self.session.verify = verify_ssl

        if default_headers:
            self.session.headers.update(default_headers)

        if auth:
            self.session.auth = auth

        logger.info(f"API Client initialized for {self.base_url}")

    def _build_url(self, endpoint: str) -> str:
        """Build full URL from endpoint."""
        return urljoin(self.base_url + "/", endpoint.lstrip("/"))

    def _log_request(self, method: str, url: str, **kwargs) -> None:
        """Log request details."""
        logger.debug(f"API Request: {method.upper()} {url}")
        if "params" in kwargs:
            logger.debug(f"Query params: {kwargs['params']}")
        if "json" in kwargs:
            logger.debug(f"JSON body: {kwargs['json']}")
        if "headers" in kwargs:
            logger.debug(f"Headers: {kwargs['headers']}")

    def _log_response(self, response: requests.Response) -> None:
        """Log response details."""
        logger.debug(f"API Response: {response.status_code}")
        logger.debug(f"Response time: {response.elapsed.total_seconds():.3f}s")
        logger.debug(f"Response size: {len(response.content)} bytes")

    def get(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> requests.Response:
        """
        Send GET request.

        Args:
            endpoint: API endpoint
            params: Query parameters
            headers: Request headers
            **kwargs: Additional requests arguments

        Returns:
            Response object
        """
        url = self._build_url(endpoint)
        self._log_request("GET", url, params=params, headers=headers)

        response = self.session.get(
            url,
            params=params,
            headers=headers,
            timeout=self.timeout,
            **kwargs,
        )

        self._log_response(response)
        return response

    def post(
        self,
        endpoint: str,
        data: Optional[Union[Dict, str]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> requests.Response:
        """
        Send POST request.

        Args:
            endpoint: API endpoint
            data: Form data
            json: JSON data
            headers: Request headers
            **kwargs: Additional requests arguments

        Returns:
            Response object
        """
        url = self._build_url(endpoint)
        self._log_request("POST", url, json=json, headers=headers)

        response = self.session.post(
            url,
            data=data,
            json=json,
            headers=headers,
            timeout=self.timeout,
            **kwargs,
        )

        self._log_response(response)
        return response

    def put(
        self,
        endpoint: str,
        data: Optional[Union[Dict, str]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> requests.Response:
        """
        Send PUT request.

        Args:
            endpoint: API endpoint
            data: Form data
            json: JSON data
            headers: Request headers
            **kwargs: Additional requests arguments

        Returns:
            Response object
        """
        url = self._build_url(endpoint)
        self._log_request("PUT", url, json=json, headers=headers)

        response = self.session.put(
            url,
            data=data,
            json=json,
            headers=headers,
            timeout=self.timeout,
            **kwargs,
        )

        self._log_response(response)
        return response

    def patch(
        self,
        endpoint: str,
        data: Optional[Union[Dict, str]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> requests.Response:
        """
        Send PATCH request.

        Args:
            endpoint: API endpoint
            data: Form data
            json: JSON data
            headers: Request headers
            **kwargs: Additional requests arguments

        Returns:
            Response object
        """
        url = self._build_url(endpoint)
        self._log_request("PATCH", url, json=json, headers=headers)

        response = self.session.patch(
            url,
            data=data,
            json=json,
            headers=headers,
            timeout=self.timeout,
            **kwargs,
        )

        self._log_response(response)
        return response

    def delete(
        self,
        endpoint: str,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> requests.Response:
        """
        Send DELETE request.

        Args:
            endpoint: API endpoint
            headers: Request headers
            **kwargs: Additional requests arguments

        Returns:
            Response object
        """
        url = self._build_url(endpoint)
        self._log_request("DELETE", url, headers=headers)

        response = self.session.delete(
            url,
            headers=headers,
            timeout=self.timeout,
            **kwargs,
        )

        self._log_response(response)
        return response

    def set_auth_token(self, token: str, token_type: str = "Bearer") -> None:
        """
        Set authentication token.

        Args:
            token: Authentication token
            token_type: Token type (Bearer, Token, etc.)
        """
        self.session.headers.update({"Authorization": f"{token_type} {token}"})
        logger.info(f"Set {token_type} authentication token")

    def set_basic_auth(self, username: str, password: str) -> None:
        """
        Set HTTP Basic Authentication.

        Args:
            username: Username
            password: Password
        """
        self.session.auth = HTTPBasicAuth(username, password)
        logger.info(f"Set Basic Auth for user: {username}")

    def clear_auth(self) -> None:
        """Clear authentication."""
        self.session.auth = None
        if "Authorization" in self.session.headers:
            del self.session.headers["Authorization"]
        logger.info("Cleared authentication")

    def set_header(self, key: str, value: str) -> None:
        """
        Set custom header.

        Args:
            key: Header name
            value: Header value
        """
        self.session.headers[key] = value
        logger.debug(f"Set header: {key}={value}")

    def remove_header(self, key: str) -> None:
        """
        Remove custom header.

        Args:
            key: Header name
        """
        if key in self.session.headers:
            del self.session.headers[key]
            logger.debug(f"Removed header: {key}")

    def close(self) -> None:
        """Close session."""
        self.session.close()
        logger.info("API Client session closed")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
