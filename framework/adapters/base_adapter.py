"""
Application Adapter - Universal Test Automation Framework
Author: Marc Arévalo
Version: 1.0

Abstract base class defining the interface for application-specific adapters.
Each web application to be tested must implement this interface.

This is the KEY to universality: all application-specific details are isolated
in adapters, keeping the core framework completely generic.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional


class AuthenticationMethod(Enum):
    """Supported authentication methods."""

    MODAL = "modal"  # Login via modal dialog
    PAGE = "page"  # Login via dedicated page
    BASIC_AUTH = "basic"  # HTTP Basic Authentication
    OAUTH = "oauth"  # OAuth2 flow
    SSO = "sso"  # Single Sign-On
    NONE = "none"  # No authentication required


class ApplicationAdapter(ABC):
    """
    Abstract adapter defining the interface for application-specific implementations.

    Each application adapter encapsulates:
    - URL patterns and routing
    - Authentication mechanisms
    - Page structure and navigation
    - Application-specific behaviors

    Example implementation:
        class MyAppAdapter(ApplicationAdapter):
            def get_base_url(self) -> str:
                return "https://myapp.com"

            def get_authentication_method(self) -> AuthenticationMethod:
                return AuthenticationMethod.PAGE

            # ... implement other methods
    """

    @abstractmethod
    def get_base_url(self) -> str:
        """
        Return the application's base URL.

        Returns:
            Base URL without trailing slash

        Example:
            return "https://www.example.com"
        """
        pass

    @abstractmethod
    def get_url_patterns(self) -> Dict[str, str]:
        """
        Return URL patterns for different pages/resources.

        Use {param} syntax for dynamic values.

        Returns:
            Dict mapping page types to URL patterns

        Example:
            return {
                "product": "/products/{id}",
                "category": "/category?cat={category}",
                "search": "/search?q={query}",
                "user_profile": "/users/{username}"
            }
        """
        pass

    @abstractmethod
    def get_authentication_method(self) -> AuthenticationMethod:
        """
        Return the authentication method used by the application.

        Returns:
            AuthenticationMethod enum value

        Example:
            return AuthenticationMethod.MODAL
        """
        pass

    @abstractmethod
    def get_navigation_structure(self) -> Dict[str, Any]:
        """
        Return the navigation structure of the application.

        Returns:
            Dict describing navigation elements and their relationships

        Example:
            return {
                "header": {
                    "home": {"text": "Home", "url": "/"},
                    "products": {"text": "Products", "url": "/products"},
                    "login": {"text": "Login", "type": "button"}
                },
                "footer": {
                    "about": {"text": "About", "url": "/about"}
                }
            }
        """
        pass

    @abstractmethod
    def discover_page_structure(self, page_type: str) -> Dict[str, Any]:
        """
        Discover the structure of a specific page type.

        This method should use the DiscoveryEngine to automatically
        identify forms, inputs, buttons, and other interactive elements.

        Args:
            page_type: Type of page to discover (e.g., "login", "product", "checkout")

        Returns:
            Dict describing the discovered page structure

        Example:
            return {
                "forms": [
                    {
                        "id": "loginForm",
                        "inputs": [
                            {"name": "username", "type": "text"},
                            {"name": "password", "type": "password"}
                        ],
                        "buttons": [
                            {"text": "Log in", "type": "submit"}
                        ]
                    }
                ],
                "links": [...],
                "navigation": [...]
            }
        """
        pass

    def get_page_identifiers(self) -> Dict[str, str]:
        """
        Return identifiers for different page types.

        Optional method with default empty implementation.
        Used to identify which page the application is currently on.

        Returns:
            Dict mapping page types to identifying URL patterns or elements

        Example:
            return {
                "home": "/",
                "product": "/prod.html",
                "cart": "/cart.html",
                "checkout": "/checkout"
            }
        """
        return {}

    def get_timeout_recommendations(self) -> Dict[str, int]:
        """
        Return recommended timeout values for this application.

        Optional method with sensible defaults.

        Returns:
            Dict with timeout values in seconds

        Example:
            return {
                "default": 10,
                "short": 5,
                "medium": 15,
                "long": 30,
                "ajax": 20
            }
        """
        return {"default": 10, "short": 5, "medium": 15, "long": 30}

    def get_special_behaviors(self) -> Dict[str, Any]:
        """
        Return any special behaviors or quirks of the application.

        Optional method for documenting application-specific behaviors
        that tests need to handle.

        Returns:
            Dict describing special behaviors

        Example:
            return {
                "uses_ajax_navigation": True,
                "has_custom_alerts": True,
                "requires_javascript": True,
                "uses_frames": False,
                "has_captcha": False
            }
        """
        return {
            "uses_ajax_navigation": False,
            "has_custom_alerts": False,
            "requires_javascript": True,
            "uses_frames": False,
            "has_captcha": False,
        }

    def get_test_users(self) -> Dict[str, Dict[str, str]]:
        """
        Return test user credentials for this application.

        Optional method. Should read from environment variables for security.

        Returns:
            Dict mapping user types to credentials

        Example:
            import os
            return {
                "valid": {
                    "username": os.getenv("TEST_USERNAME", ""),
                    "password": os.getenv("TEST_PASSWORD", "")
                },
                "admin": {
                    "username": os.getenv("ADMIN_USERNAME", ""),
                    "password": os.getenv("ADMIN_PASSWORD", "")
                }
            }
        """
        return {}

    def validate_configuration(self) -> List[str]:
        """
        Validate that the adapter is properly configured.

        Returns:
            List of validation error messages (empty if valid)

        Example:
            errors = []
            if not self.get_base_url():
                errors.append("Base URL is not configured")
            if not self.get_test_users().get("valid"):
                errors.append("Valid test user is not configured")
            return errors
        """
        errors = []

        if not self.get_base_url():
            errors.append("Base URL is required")

        if not self.get_url_patterns():
            errors.append("URL patterns are required")

        if self.get_authentication_method() not in AuthenticationMethod:
            errors.append("Invalid authentication method")

        return errors

    def __str__(self) -> str:
        """String representation for debugging."""
        return (
            f"{self.__class__.__name__}("
            f"base_url={self.get_base_url()}, "
            f"auth={self.get_authentication_method().value})"
        )

    def __repr__(self) -> str:
        """Detailed representation."""
        return (
            f"{self.__class__.__name__}("
            f"base_url='{self.get_base_url()}', "
            f"auth_method={self.get_authentication_method()}, "
            f"url_patterns={len(self.get_url_patterns())} patterns)"
        )
