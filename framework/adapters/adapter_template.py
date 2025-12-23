"""
Application Adapter Template - Universal Test Automation Framework
Author: Marc Arévalo
Version: 1.0

Generic template for creating application-specific adapters.
Copy this file and implement methods for YOUR application.

NO SPECIFIC APPLICATION EXAMPLES - This is a professional template.
"""

import os
from typing import Any, Dict, List

from selenium.webdriver.common.by import By

from .base_adapter import ApplicationAdapter, AuthenticationMethod


class YourAppAdapter(ApplicationAdapter):
    """
    Template adapter for YOUR application.

    Replace 'YourApp' with your actual application name.
    Implement all abstract methods for your specific application.

    This template provides structure - YOU provide the details.
    """

    def __init__(self):
        """Initialize your application adapter."""
        super().__init__()

    def get_base_url(self) -> str:
        """
        Return YOUR application's base URL.

        Should read from environment variable for flexibility.

        Returns:
            Base URL without trailing slash

        Example implementation:
            return os.getenv("BASE_URL", "https://your-app.com")
        """
        return os.getenv("BASE_URL", "")

    def get_url_patterns(self) -> Dict[str, str]:
        """
        Return URL patterns for YOUR application's pages.

        Use {param} syntax for dynamic values.

        Returns:
            Dict mapping page types to URL patterns

        Example implementation:
            return {
                "home": "/",
                "login": "/login",
                "user_profile": "/users/{username}",
                "item_detail": "/items/{id}",
                "search": "/search?q={query}"
            }
        """
        return {
            "home": "/",
            # Add your URL patterns here
        }

    def get_authentication_method(self) -> AuthenticationMethod:
        """
        Return YOUR application's authentication method.

        Returns:
            AuthenticationMethod enum value

        Options:
            - AuthenticationMethod.MODAL (login via popup/modal)
            - AuthenticationMethod.PAGE (login via dedicated page)
            - AuthenticationMethod.OAUTH (OAuth2 flow)
            - AuthenticationMethod.SSO (Single Sign-On)
            - AuthenticationMethod.BASIC_AUTH (HTTP Basic Auth)
            - AuthenticationMethod.NONE (no authentication)

        Example implementation:
            return AuthenticationMethod.PAGE
        """
        return AuthenticationMethod.NONE

    def get_navigation_structure(self) -> Dict[str, Any]:
        """
        Return YOUR application's navigation structure.

        Document main navigation elements and their selectors.

        Returns:
            Dict describing navigation elements

        Example implementation:
            return {
                "header": {
                    "home": {
                        "text": "Home",
                        "selector": (By.ID, "home-link"),
                        "url": "/"
                    },
                    "login": {
                        "text": "Login",
                        "selector": (By.ID, "login-button"),
                        "type": "page"
                    }
                },
                "footer": {
                    "about": {
                        "text": "About",
                        "url": "/about"
                    }
                }
            }
        """
        return {
            "header": {},
            "footer": {},
            # Add your navigation structure here
        }

    def discover_page_structure(self, page_type: str) -> Dict[str, Any]:
        """
        Discover or define structure for YOUR application's page types.

        Can use DiscoveryEngine for automatic discovery or
        return known structure for predictable pages.

        Args:
            page_type: Type of page (e.g., "login", "checkout", "profile")

        Returns:
            Dict describing page structure

        Example implementation:
            structures = {
                "login": {
                    "form_id": "login-form",
                    "fields": {
                        "username": {"id": "username", "type": "text"},
                        "password": {"id": "password", "type": "password"}
                    },
                    "submit_button": {"id": "submit"}
                }
            }
            return structures.get(page_type, {})
        """
        return {}

    def get_page_identifiers(self) -> Dict[str, str]:
        """
        Return identifiers for YOUR application's page types.

        Used to identify which page the browser is currently on.

        Returns:
            Dict mapping page types to URL identifiers

        Example implementation:
            return {
                "home": "/",
                "login": "/login",
                "dashboard": "/dashboard"
            }
        """
        return {}

    def get_timeout_recommendations(self) -> Dict[str, int]:
        """
        Return recommended timeout values for YOUR application.

        Adjust based on your application's performance characteristics.

        Returns:
            Dict with timeout values in seconds

        Example implementation:
            return {
                "default": 15,  # Your app is slow
                "short": 5,
                "medium": 20,
                "long": 40,
                "ajax": 25  # Heavy AJAX usage
            }
        """
        return {
            "default": 10,
            "short": 5,
            "medium": 15,
            "long": 30,
        }

    def get_special_behaviors(self) -> Dict[str, Any]:
        """
        Document any special behaviors of YOUR application.

        Helps tests handle application-specific quirks.

        Returns:
            Dict describing special behaviors

        Example implementation:
            return {
                "uses_ajax_navigation": True,
                "has_custom_alerts": False,
                "requires_javascript": True,
                "uses_frames": False,
                "has_captcha": True,
                "uses_hash_routing": False,
                "modal_based_forms": True
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
        Return test user credentials for YOUR application.

        SECURITY: ALWAYS read from environment variables.
        NEVER hardcode credentials in code!

        Returns:
            Dict mapping user types to credentials

        Example implementation:
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

        Environment Variables:
            TEST_USERNAME - Valid test username
            TEST_PASSWORD - Valid test password
            ADMIN_USERNAME - Admin username (if applicable)
            ADMIN_PASSWORD - Admin password (if applicable)
        """
        return {
            "valid": {
                "username": os.getenv("TEST_USERNAME", ""),
                "password": os.getenv("TEST_PASSWORD", ""),
            }
        }

    def validate_configuration(self) -> List[str]:
        """
        Validate that YOUR adapter is properly configured.

        Override to add application-specific validation.

        Returns:
            List of validation error messages (empty if valid)

        Example implementation:
            errors = super().validate_configuration()

            # Add your validations
            if not self.get_test_users().get("valid", {}).get("username"):
                errors.append("TEST_USERNAME not configured")

            if not self.get_base_url():
                errors.append("BASE_URL not configured")

            return errors
        """
        errors = super().validate_configuration()

        # Add application-specific validations here
        test_users = self.get_test_users()
        valid_user = test_users.get("valid", {})

        if not valid_user.get("username"):
            errors.append(
                "Valid test username not configured. "
                "Set TEST_USERNAME environment variable."
            )

        if not valid_user.get("password"):
            errors.append(
                "Valid test password not configured. "
                "Set TEST_PASSWORD environment variable."
            )

        return errors

    def __str__(self) -> str:
        """String representation."""
        return f"YourAppAdapter(base_url={self.get_base_url()})"

    def __repr__(self) -> str:
        """Detailed representation."""
        return (
            f"YourAppAdapter("
            f"base_url='{self.get_base_url()}', "
            f"auth={self.get_authentication_method().value})"
        )


# Example: How to use your adapter in tests
"""
# In conftest.py:
@pytest.fixture
def app_adapter():
    from framework.adapters.your_app_adapter import YourAppAdapter
    return YourAppAdapter()

# In tests:
def test_something(browser, app_adapter):
    browser.get(app_adapter.get_base_url())
    test_users = app_adapter.get_test_users()
    # ... use adapter to get application-specific details
"""
