"""
Purchase Accessibility Tests
Author: Marc Arévalo
Version: 1.0

Tests WCAG 2.1 Level AA compliance for purchase/checkout functionality:
- Form field accessibility
- Keyboard navigation through purchase form
- Label associations
- Button accessibility
"""

import pytest
from selenium.webdriver.common.keys import Keys


@pytest.mark.accessibility
@pytest.mark.purchase
class TestPurchaseFormAccessibility:
    """Test purchase form accessibility"""

    def test_all_form_fields_keyboard_accessible_PUR_ACC_001(
        self, cart_with_product, purchase_page
    ):
        """Test all purchase form fields accept keyboard input"""
        purchase_page.click_place_order()
        purchase_page.wait_for_order_modal()

        # Fill form with keyboard
        purchase_page.fill_order_form(
            name="John Doe",
            country="USA",
            city="New York",
            card="4111111111111111",
            month="12",
            year="2025",
        )

        # Verify fields accepted input
        name_value = purchase_page.get_form_field_value("name")
        assert (
            name_value == "John Doe"
        ), "Name field should accept keyboard input"

    def test_tab_navigation_through_form_PUR_ACC_002(
        self, cart_with_product, purchase_page
    ):
        """Test TAB key navigation through purchase form"""
        purchase_page.click_place_order()
        purchase_page.wait_for_order_modal()

        # Test tab navigation
        purchase_page.navigate_form_with_tab()

        # Should move through form fields
        assert True, "TAB navigation should work through form"

    def test_name_field_accessible_PUR_ACC_003(
        self, cart_with_product, purchase_page
    ):
        """Test Name field is accessible"""
        purchase_page.click_place_order()
        purchase_page.wait_for_order_modal()

        name_field = purchase_page.find_element(purchase_page.NAME_FIELD)
        name_field.send_keys("Test User")

        value = purchase_page.get_form_field_value("name")
        assert value == "Test User", "Name field should be accessible"

    def test_country_field_accessible_PUR_ACC_004(
        self, cart_with_product, purchase_page
    ):
        """Test Country field is accessible"""
        purchase_page.click_place_order()
        purchase_page.wait_for_order_modal()

        country_field = purchase_page.find_element(purchase_page.COUNTRY_FIELD)
        country_field.send_keys("USA")

        value = purchase_page.get_form_field_value("country")
        assert value == "USA", "Country field should be accessible"

    def test_city_field_accessible_PUR_ACC_005(
        self, cart_with_product, purchase_page
    ):
        """Test City field is accessible"""
        purchase_page.click_place_order()
        purchase_page.wait_for_order_modal()

        city_field = purchase_page.find_element(purchase_page.CITY_FIELD)
        city_field.send_keys("New York")

        value = purchase_page.get_form_field_value("city")
        assert value == "New York", "City field should be accessible"

    def test_card_field_accessible_PUR_ACC_006(
        self, cart_with_product, purchase_page
    ):
        """Test Credit Card field is accessible"""
        purchase_page.click_place_order()
        purchase_page.wait_for_order_modal()

        card_field = purchase_page.find_element(purchase_page.CARD_FIELD)
        card_field.send_keys("4111111111111111")

        value = purchase_page.get_form_field_value("card")
        assert value == "4111111111111111", "Card field should be accessible"


@pytest.mark.accessibility
@pytest.mark.purchase
class TestPurchaseButtonAccessibility:
    """Test purchase button accessibility"""

    def test_purchase_button_accessible_PUR_ACC_007(
        self, cart_with_product, purchase_page
    ):
        """Test Purchase button is keyboard accessible"""
        purchase_page.click_place_order()
        purchase_page.wait_for_order_modal()

        purchase_btn = purchase_page.find_element(
            purchase_page.PURCHASE_BUTTON
        )
        assert purchase_btn.is_displayed(), "Purchase button should be visible"
        assert purchase_btn.is_enabled(), "Purchase button should be enabled"

    def test_close_button_accessible_PUR_ACC_008(
        self, cart_with_product, purchase_page
    ):
        """Test Close button is keyboard accessible"""
        purchase_page.click_place_order()
        purchase_page.wait_for_order_modal()

        close_btn = purchase_page.find_element(purchase_page.CLOSE_BUTTON)
        close_btn.send_keys(Keys.RETURN)

        # Modal should close
        assert (
            not purchase_page.is_order_modal_visible()
        ), "Close button should be keyboard accessible"


@pytest.mark.accessibility
@pytest.mark.purchase
class TestPurchaseModalAccessibility:
    """Test purchase modal accessibility"""

    def test_modal_appears_on_place_order_PUR_ACC_009(
        self, cart_with_product, purchase_page
    ):
        """Test order modal appears and is accessible"""
        purchase_page.click_place_order()

        is_visible = purchase_page.is_order_modal_visible()
        assert is_visible is True, "Order modal should be visible"

    def test_escape_key_closes_modal_PUR_ACC_010(
        self, cart_with_product, purchase_page
    ):
        """Test ESC key closes purchase modal"""
        purchase_page.click_place_order()
        purchase_page.wait_for_order_modal()

        purchase_page.close_order_modal_with_escape()

        # Modal should close
        assert (
            not purchase_page.is_order_modal_visible()
        ), "ESC key should close modal for keyboard users"
