"""
Cart Business Logic Tests
Author: Marc Arévalo
Version: 1.0

Tests cart business rules: price calculations, cart persistence,
product limits, total accuracy, and timing requirements.
"""

import pytest
from selenium.webdriver.common.by import By


@pytest.mark.business
@pytest.mark.cart
class TestPriceParsing:
    """Test price parsing logic"""

    def test_parse_price_with_dollar_sign_CART_BR_001(self, cart_page):
        """Test _parse_price handles dollar sign"""
        result = cart_page._parse_price("$360")
        assert result == 360, f"Expected 360, got {result}"

    def test_parse_price_without_dollar_sign_CART_BR_002(self, cart_page):
        """Test _parse_price handles plain numbers"""
        result = cart_page._parse_price("790")
        assert result == 790, f"Expected 790, got {result}"

    def test_parse_price_with_extra_text_CART_BR_003(self, cart_page):
        """Test _parse_price ignores extra text"""
        result = cart_page._parse_price("360 *includes tax")
        assert result == 360, f"Expected 360, got {result}"

    def test_parse_price_empty_string_CART_BR_004(self, cart_page):
        """Test _parse_price handles empty string"""
        result = cart_page._parse_price("")
        assert result == 0, f"Expected 0 for empty string, got {result}"

    def test_parse_price_no_numbers_CART_BR_005(self, cart_page):
        """Test _parse_price handles string with no numbers"""
        result = cart_page._parse_price("Price not available")
        assert result == 0, f"Expected 0 for non-numeric string, got {result}"


@pytest.mark.business
@pytest.mark.cart
class TestCartTotalAccuracy:
    """Test cart total calculation accuracy"""

    def test_cart_total_matches_sum_single_product_CART_BR_006(
        self, cart_page
    ):
        """Test cart total equals product price for single item"""
        _, product_price = cart_page.add_first_product()
        cart_page.open_cart()

        cart_total = cart_page.get_cart_total()
        assert (
            cart_total == product_price
        ), f"Cart total ${cart_total} should equal product price ${product_price}"

    def test_cart_total_matches_sum_two_products_CART_BR_007(self, cart_page):
        """Test cart total equals sum of two products"""
        _, price1 = cart_page.add_first_product()
        _, price2 = cart_page.add_second_product()
        cart_page.open_cart()

        expected_total = price1 + price2
        cart_total = cart_page.get_cart_total()
        assert (
            cart_total == expected_total
        ), f"Cart total ${cart_total} should equal ${expected_total} (${price1} + ${price2})"

    def test_cart_total_updates_after_deletion_CART_BR_008(self, cart_page):
        """Test cart total recalculates after deleting item"""
        _, price1 = cart_page.add_first_product()
        _, price2 = cart_page.add_second_product()
        cart_page.open_cart()

        cart_page.delete_first_item()
        cart_page.driver.refresh()
        cart_page.wait_for_element_visible(cart_page.PLACE_ORDER_BUTTON)

        new_total = cart_page.get_cart_total()
        assert (
            new_total == price2
        ), f"After deleting first item, total should be ${price2}, got ${new_total}"


@pytest.mark.business
@pytest.mark.cart
class TestCartWaitOperations:
    """Test cart wait and synchronization operations"""

    def test_wait_for_cart_to_update_success_CART_BR_009(self, cart_page):
        """Test wait_for_cart_to_update with expected count"""
        cart_page.add_first_product()
        cart_page.open_cart()

        result = cart_page.wait_for_cart_to_update(expected_count=1, timeout=5)
        assert (
            result is True
        ), "wait_for_cart_to_update should return True when count matches"

    def test_wait_for_cart_to_update_timeout_CART_BR_010(self, cart_page):
        """Test wait_for_cart_to_update times out with wrong count"""
        cart_page.add_first_product()
        cart_page.open_cart()

        result = cart_page.wait_for_cart_to_update(
            expected_count=99, timeout=2
        )
        assert (
            result is False
        ), "wait_for_cart_to_update should return False on timeout"

    def test_cart_total_waits_for_update_CART_BR_011(self, cart_page):
        """Test get_cart_total waits for total to be calculated"""
        cart_page.add_first_product()
        cart_page.open_cart()

        # Should wait and return valid total, not 0
        cart_total = cart_page.get_cart_total(timeout=10)
        assert (
            cart_total > 0
        ), f"Cart total should be calculated, got ${cart_total}"


@pytest.mark.business
@pytest.mark.cart
@pytest.mark.performance
class TestCartPerformance:
    """Test cart performance requirements"""

    def test_cart_total_calculation_time_CART_BR_012(self, cart_page):
        """Test cart total calculation completes in reasonable time"""
        cart_page.add_first_product()
        cart_page.open_cart()

        calculation_time = cart_page.measure_cart_total_calculation_time()
        assert (
            calculation_time < 5.0
        ), f"Cart total calculation took {calculation_time:.2f}s, expected < 5s"

    def test_rapid_add_to_cart_handling_CART_BR_013(self, cart_page):
        """Test rapid clicking Add to Cart (duplicate handling)"""
        price = cart_page.rapid_add_to_cart(
            cart_page.FIRST_PRODUCT_LINK, times=3
        )

        assert price > 0, f"Product price should be positive, got {price}"
        # Note: We can't verify exact cart count as it depends on app behavior
        # Some apps add multiple instances, some prevent duplicates


@pytest.mark.business
@pytest.mark.cart
class TestCartPersistence:
    """Test cart state persistence"""

    def test_cart_persists_after_navigation_CART_BR_014(self, cart_page):
        """Test cart contents persist after navigating away and back"""
        _, product_price = cart_page.add_first_product()
        cart_page.open_cart()
        initial_count = cart_page.get_cart_item_count()

        # Navigate away and back
        cart_page.go_home()
        cart_page.open_cart()

        final_count = cart_page.get_cart_item_count()
        assert (
            final_count == initial_count
        ), f"Cart count changed after navigation: {initial_count} -> {final_count}"

        final_total = cart_page.get_cart_total()
        assert (
            final_total == product_price
        ), f"Cart total changed after navigation: ${product_price} -> ${final_total}"

    def test_delete_from_multi_item_cart_CART_BR_015(self, cart_page):
        """Test deleting one item from cart with multiple items"""
        cart_page.add_first_product()
        cart_page.add_second_product()
        custom_locator = (By.XPATH, "(//a[@class='hrefch'])[3]")
        cart_page.add_product_to_cart(custom_locator)

        cart_page.open_cart()
        initial_count = cart_page.get_cart_item_count()
        assert (
            initial_count == 3
        ), f"Expected 3 items initially, got {initial_count}"

        cart_page.delete_first_item()
        final_count = cart_page.get_cart_item_count()
        assert (
            final_count == 2
        ), f"Expected 2 items after deletion, got {final_count}"
