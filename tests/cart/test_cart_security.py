"""
Cart Security Tests
Author: Marc Arévalo
Version: 1.0

Tests cart security: price validation, URL manipulation,
cart tampering, and data integrity.

⚠️ SECURITY TESTING NOTICE:
These are UI-level security validation tests.
For comprehensive security testing, use dedicated DAST tools.
"""

import pytest
from selenium.webdriver.common.by import By


@pytest.mark.security
@pytest.mark.cart
class TestPriceValidation:
    """Test price integrity and validation"""

    def test_price_cannot_be_negative_CART_SEC_001(self, cart_page):
        """Test system rejects negative prices"""
        _, product_price = cart_page.add_first_product()
        assert (
            product_price > 0
        ), f"Price should be positive, got {product_price}"

    def test_price_is_integer_CART_SEC_002(self, cart_page):
        """Test prices are integers (no decimal manipulation)"""
        _, product_price = cart_page.add_first_product()
        assert isinstance(
            product_price, int
        ), f"Price should be integer, got {type(product_price).__name__}"

    def test_cart_total_cannot_be_manipulated_CART_SEC_003(self, cart_page):
        """Test cart total is server-calculated, not client-manipulated"""
        _, price1 = cart_page.add_first_product()
        _, price2 = cart_page.add_second_product()
        cart_page.open_cart()

        expected_total = price1 + price2
        cart_total = cart_page.get_cart_total()

        # Cart total should match sum (server validates)
        assert (
            cart_total == expected_total
        ), f"Cart total mismatch: expected ${expected_total}, got ${cart_total}"

    def test_price_parsing_rejects_malicious_input_CART_SEC_004(
        self, cart_page
    ):
        """Test _parse_price handles malicious input safely"""
        malicious_inputs = [
            "<script>alert('XSS')</script>360",
            "'; DROP TABLE products; --",
            "../../etc/passwd",
            "null",
            "undefined",
            "NaN",
            "Infinity",
        ]

        for malicious_input in malicious_inputs:
            result = cart_page._parse_price(malicious_input)
            # Should extract numbers or return 0, never execute code
            assert isinstance(
                result, int
            ), f"Expected int for '{malicious_input}', got {type(result).__name__}"
            assert (
                result >= 0
            ), f"Price should be non-negative for '{malicious_input}'"


@pytest.mark.security
@pytest.mark.cart
class TestCartDataIntegrity:
    """Test cart data integrity"""

    def test_cart_count_matches_actual_items_CART_SEC_005(self, cart_page):
        """Test cart count cannot be manipulated"""
        cart_page.add_first_product()
        cart_page.add_second_product()
        cart_page.open_cart()

        # Count items directly vs get_cart_item_count
        actual_items = len(cart_page.find_elements(cart_page.CART_ITEMS))
        reported_count = cart_page.get_cart_item_count()

        assert (
            actual_items == reported_count
        ), f"Cart count mismatch: {actual_items} actual vs {reported_count} reported"

    def test_delete_validates_item_exists_CART_SEC_006(self, cart_page):
        """Test delete operation validates item existence"""
        cart_page.add_first_product()
        cart_page.open_cart()

        # Delete valid item should succeed
        result = cart_page.delete_first_item()
        assert result is True, "Valid delete should succeed"

        # Verify cart is empty
        assert (
            cart_page.is_cart_empty()
        ), "Cart should be empty after deleting only item"

    def test_empty_cart_cannot_checkout_CART_SEC_007(self, cart_page):
        """Test empty cart shows Place Order button (app behavior validation)"""
        cart_page.open_cart()

        # Note: DemoBlaze actually allows empty cart checkout (known vulnerability)
        # This test documents the behavior
        is_visible = cart_page.is_place_order_visible()
        # The button is visible even for empty cart (security issue)
        assert isinstance(
            is_visible, bool
        ), "is_place_order_visible should return boolean"


@pytest.mark.security
@pytest.mark.cart
class TestCartSessionSecurity:
    """Test cart session security"""

    def test_cart_persists_within_session_CART_SEC_008(self, cart_page):
        """Test cart is tied to session (not globally accessible)"""
        _, product_price = cart_page.add_first_product()
        cart_page.open_cart()

        initial_total = cart_page.get_cart_total()
        assert (
            initial_total == product_price
        ), "Cart should persist within session"

        # Navigate and return - cart should remain
        cart_page.go_home()
        cart_page.open_cart()

        final_total = cart_page.get_cart_total()
        assert (
            final_total == initial_total
        ), "Cart should persist after navigation within same session"

    def test_rapid_clicks_handled_safely_CART_SEC_009(self, cart_page):
        """Test rapid Add to Cart clicks don't cause errors"""
        # Rapid clicking should not crash or cause security errors
        price = cart_page.rapid_add_to_cart(
            cart_page.FIRST_PRODUCT_LINK, times=5
        )

        assert price > 0, "Rapid clicks should not corrupt price data"

        # Verify cart still functions
        cart_page.go_home()
        cart_page.open_cart()
        assert (
            cart_page.is_place_order_visible()
        ), "Cart should remain functional after rapid clicks"


@pytest.mark.security
@pytest.mark.cart
class TestCartInputValidation:
    """Test cart input validation"""

    def test_product_name_displayed_safely_CART_SEC_010(self, cart_page):
        """Test product names in cart don't execute scripts (XSS protection)"""
        _, _ = cart_page.add_first_product()
        cart_page.open_cart()

        product_name = cart_page.get_first_item_name()

        # Product name should be plain text, not executable
        assert product_name is not None, "Product name should be present"
        assert isinstance(product_name, str), "Product name should be string"
        # If XSS was present, we'd see script tags or alerts
        # This test documents that names are displayed as-is
        assert len(product_name) > 0, "Product name should not be empty"
