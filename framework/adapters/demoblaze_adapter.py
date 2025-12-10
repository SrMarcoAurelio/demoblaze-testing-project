"""
Demoblaze Application Adapter - Universal Test Automation Framework
Author: Marc Arévalo
Version: 1.0

Application-specific adapter for Demoblaze (https://www.demoblaze.com/).

This adapter encapsulates ALL Demoblaze-specific details:
- URL patterns
- Authentication method (modal-based)
- Page identifiers
- Test credentials
- Special behaviors

This demonstrates how to adapt the universal framework to a specific application.
"""

import os
from typing import Any, Dict, List

from selenium.webdriver.common.by import By

from framework.adapters.base_adapter import (
    ApplicationAdapter,
    AuthenticationMethod,
)


class DemoblazeAdapter(ApplicationAdapter):
    """
    Adapter for Demoblaze e-commerce demo application.

    Implements the ApplicationAdapter interface with Demoblaze-specific details.

    Example:
        adapter = DemoblazeAdapter()
        print(adapter.get_base_url())
        # Output: https://www.demoblaze.com

        patterns = adapter.get_url_patterns()
        product_url = patterns["product"].format(id="1")
        # Output: prod.html?idp_=1
    """

    def __init__(self):
        """Initialize Demoblaze adapter."""
        super().__init__()

    def get_base_url(self) -> str:
        """
        Return Demoblaze base URL.

        Can be overridden via BASE_URL environment variable.

        Returns:
            Base URL for Demoblaze
        """
        return os.getenv("BASE_URL", "https://www.demoblaze.com")

    def get_url_patterns(self) -> Dict[str, str]:
        """
        Return URL patterns for Demoblaze pages.

        Returns:
            Dict mapping page types to URL patterns
        """
        return {
            "home": "/",
            "product": "/prod.html?idp_={id}",
            "cart": "/cart.html",
            "category": "/#?cat={category}",  # Demoblaze uses hash routing
        }

    def get_authentication_method(self) -> AuthenticationMethod:
        """
        Return Demoblaze authentication method.

        Demoblaze uses modal dialog for login.

        Returns:
            AuthenticationMethod.MODAL
        """
        return AuthenticationMethod.MODAL

    def get_navigation_structure(self) -> Dict[str, Any]:
        """
        Return Demoblaze navigation structure.

        Returns:
            Dict describing navigation elements
        """
        return {
            "header": {
                "home": {
                    "text": "Home",
                    "selector": (By.LINK_TEXT, "Home"),
                    "url": "/",
                },
                "contact": {
                    "text": "Contact",
                    "selector": (By.LINK_TEXT, "Contact"),
                    "type": "modal",
                },
                "about_us": {
                    "text": "About us",
                    "selector": (By.LINK_TEXT, "About us"),
                    "type": "modal",
                },
                "cart": {
                    "text": "Cart",
                    "selector": (By.ID, "cartur"),
                    "url": "/cart.html",
                },
                "login": {
                    "text": "Log in",
                    "selector": (By.ID, "login2"),
                    "type": "modal",
                },
                "signup": {
                    "text": "Sign up",
                    "selector": (By.ID, "signin2"),
                    "type": "modal",
                },
            },
            "categories": {
                "phones": {
                    "text": "Phones",
                    "selector": (By.LINK_TEXT, "Phones"),
                },
                "laptops": {
                    "text": "Laptops",
                    "selector": (By.LINK_TEXT, "Laptops"),
                },
                "monitors": {
                    "text": "Monitors",
                    "selector": (By.LINK_TEXT, "Monitors"),
                },
            },
            "footer": {
                "about": {"text": "About Us", "heading": True},
                "contact": {"text": "Get in Touch", "heading": True},
            },
        }

    def discover_page_structure(self, page_type: str) -> Dict[str, Any]:
        """
        Discover structure of Demoblaze page types.

        This method would use DiscoveryEngine to automatically map page structure.

        Args:
            page_type: Type of page (e.g., "login", "product", "cart")

        Returns:
            Dict with discovered page structure

        Note:
            In production, this would use DiscoveryEngine.
            For now, returns known structure.
        """
        # Known structures for Demoblaze pages
        structures = {
            "login": {
                "modal_id": "logInModal",
                "form_fields": {
                    "username": {"id": "loginusername", "type": "text"},
                    "password": {"id": "loginpassword", "type": "password"},
                },
                "buttons": {
                    "submit": {
                        "selector": "button[onclick='logIn()']",
                        "text": "Log in",
                    },
                    "close": {"class": "close", "text": "×"},
                },
            },
            "signup": {
                "modal_id": "signInModal",
                "form_fields": {
                    "username": {"id": "sign-username", "type": "text"},
                    "password": {"id": "sign-password", "type": "password"},
                },
                "buttons": {
                    "submit": {
                        "selector": "button[onclick='register()']",
                        "text": "Sign up",
                    },
                    "close": {"class": "close", "text": "×"},
                },
            },
            "product": {
                "elements": {
                    "title": {"class": "name"},
                    "price": {"class": "price-container"},
                    "description": {"id": "more-information"},
                    "add_to_cart": {"selector": "a[onclick='addToCart(...)']"},
                }
            },
            "cart": {
                "elements": {
                    "table": {"class": "table"},
                    "total": {"id": "totalp"},
                    "place_order": {
                        "selector": "button[data-target='#orderModal']"
                    },
                    "delete_buttons": {"class": "btn-danger"},
                }
            },
            "checkout": {
                "modal_id": "orderModal",
                "form_fields": {
                    "name": {"id": "name", "type": "text"},
                    "country": {"id": "country", "type": "text"},
                    "city": {"id": "city", "type": "text"},
                    "credit_card": {"id": "card", "type": "text"},
                    "month": {"id": "month", "type": "text"},
                    "year": {"id": "year", "type": "text"},
                },
                "buttons": {
                    "purchase": {
                        "selector": "button[onclick='purchaseOrder()']"
                    },
                    "close": {"class": "close"},
                },
            },
        }

        return structures.get(page_type, {})

    def get_page_identifiers(self) -> Dict[str, str]:
        """
        Return page identifiers for Demoblaze.

        Returns:
            Dict mapping page types to URL identifiers
        """
        return {
            "home": "index.html",
            "product": "prod.html",
            "cart": "cart.html",
        }

    def get_timeout_recommendations(self) -> Dict[str, int]:
        """
        Return recommended timeout values for Demoblaze.

        Demoblaze is fast, so shorter timeouts are appropriate.

        Returns:
            Dict with timeout values in seconds
        """
        return {
            "default": 10,
            "short": 5,
            "medium": 15,
            "long": 30,
            "ajax": 10,  # Demoblaze uses AJAX for many operations
        }

    def get_special_behaviors(self) -> Dict[str, Any]:
        """
        Return special behaviors of Demoblaze.

        Returns:
            Dict describing special behaviors
        """
        return {
            "uses_ajax_navigation": True,  # Product selection uses AJAX
            "has_custom_alerts": True,  # Uses JavaScript alert() for notifications
            "requires_javascript": True,  # Heavy JavaScript usage
            "uses_frames": False,
            "has_captcha": False,
            "uses_hash_routing": True,  # Uses # for some navigation
            "modal_based_forms": True,  # Login/Signup/Purchase use modals
            "alert_confirms_actions": True,  # Adding to cart shows alert
        }

    def get_test_users(self) -> Dict[str, Dict[str, str]]:
        """
        Return test user credentials for Demoblaze.

        SECURITY: Reads from environment variables.
        Never hardcode credentials in code!

        Returns:
            Dict mapping user types to credentials

        Environment Variables:
            TEST_USERNAME - Valid test username
            TEST_PASSWORD - Valid test password
        """
        return {
            "valid": {
                "username": os.getenv("TEST_USERNAME", ""),
                "password": os.getenv("TEST_PASSWORD", ""),
            },
            # For invalid user tests, we can use hardcoded values
            # since these are intentionally non-existent accounts
            "invalid_username": {
                "username": "nonexistent_user_99999",
                "password": "anypassword",
            },
            "invalid_password": {
                "username": os.getenv("TEST_USERNAME", ""),
                "password": "wrongpassword123",
            },
        }

    def validate_configuration(self) -> List[str]:
        """
        Validate Demoblaze adapter configuration.

        Returns:
            List of validation errors (empty if valid)
        """
        errors = super().validate_configuration()

        # Check if test credentials are configured
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

    def get_product_examples(self) -> Dict[str, Any]:
        """
        Return example product data for Demoblaze.

        Useful for testing product-related functionality.

        Returns:
            Dict with example product information
        """
        return {
            "phones": [
                "Samsung galaxy s6",
                "Nokia lumia 1520",
                "Nexus 6",
                "Samsung galaxy s7",
                "Iphone 6 32gb",
                "Sony xperia z5",
                "HTC One M9",
            ],
            "laptops": [
                "Sony vaio i5",
                "Sony vaio i7",
                "MacBook air",
                "Dell i7 8gb",
                "2017 Dell 15.6 Inch",
                "MacBook Pro",
            ],
            "monitors": ["Apple monitor 24", "ASUS Full HD"],
        }

    def get_purchase_data_template(self) -> Dict[str, str]:
        """
        Return template for purchase form data.

        Returns:
            Dict with field names and example values
        """
        return {
            "name": "Test User",
            "country": "Test Country",
            "city": "Test City",
            "credit_card": "4111111111111111",  # Test card number
            "month": "12",
            "year": "2025",
        }

    def __str__(self) -> str:
        """String representation."""
        return f"DemoblazeAdapter(base_url={self.get_base_url()})"

    def __repr__(self) -> str:
        """Detailed representation."""
        return (
            f"DemoblazeAdapter("
            f"base_url='{self.get_base_url()}', "
            f"auth={self.get_authentication_method().value}, "
            f"url_patterns={len(self.get_url_patterns())} patterns)"
        )


if __name__ == "__main__":
    """
    Demonstrate Demoblaze adapter usage.

    Run: python -m framework.adapters.demoblaze_adapter
    """
    print("=" * 70)
    print("DEMOBLAZE ADAPTER - CONFIGURATION")
    print("=" * 70)

    adapter = DemoblazeAdapter()

    print(f"\nBase URL: {adapter.get_base_url()}")
    print(
        f"Authentication Method: {adapter.get_authentication_method().value}"
    )

    print(f"\nURL Patterns:")
    for page_type, pattern in adapter.get_url_patterns().items():
        print(f"  {page_type}: {pattern}")

    print(f"\nTimeouts:")
    for timeout_type, value in adapter.get_timeout_recommendations().items():
        print(f"  {timeout_type}: {value}s")

    print(f"\nSpecial Behaviors:")
    for behavior, enabled in adapter.get_special_behaviors().items():
        print(f"  {behavior}: {enabled}")

    # Validate configuration
    errors = adapter.validate_configuration()
    if errors:
        print(f"\n⚠️  Configuration Errors:")
        for error in errors:
            print(f"  - {error}")
    else:
        print(f"\n✓ Configuration is valid")

    print("\n" + "=" * 70)
    print("To set credentials: export TEST_USERNAME='your_username'")
    print("                    export TEST_PASSWORD='your_password'")
    print("=" * 70)
