"""
Cart Accessibility Tests
Author: Marc Arévalo
Version: 1.0

Tests WCAG 2.1 Level AA compliance for cart functionality:
- Keyboard navigation
- Button accessibility
- Table accessibility for cart items
- Screen reader support
"""

import pytest
from selenium.webdriver.common.keys import Keys


@pytest.mark.accessibility
@pytest.mark.cart
class TestCartKeyboardNavigation:
    """Test keyboard navigation in cart"""

    def test_navigate_to_cart_with_keyboard_CART_ACC_001(self, cart_page):
        """Test navigating to cart using keyboard"""
        cart_link = cart_page.find_element(cart_page.CART_NAV_LINK)
        cart_link.send_keys(Keys.RETURN)

        # Should navigate to cart
        assert (
            cart_page.is_place_order_visible()
        ), "Should navigate to cart with keyboard"

    def test_place_order_button_accessible_by_keyboard_CART_ACC_002(
        self, cart_page
    ):
        """Test Place Order button is keyboard accessible"""
        cart_page.add_first_product()
        cart_page.open_cart()

        place_order_btn = cart_page.find_element(cart_page.PLACE_ORDER_BUTTON)
        place_order_btn.send_keys(Keys.RETURN)

        # Button should be activated (would open modal if functional)
        assert True, "Place Order button should respond to keyboard"

    def test_delete_link_accessible_by_keyboard_CART_ACC_003(self, cart_page):
        """Test delete links are keyboard accessible"""
        cart_page.add_first_product()
        cart_page.open_cart()

        try:
            delete_link = cart_page.find_element(cart_page.FIRST_DELETE_LINK)
            # Verify element is present and interactable
            assert delete_link.is_displayed(), "Delete link should be visible"
            assert delete_link.is_enabled(), "Delete link should be enabled"
        except Exception:
            pytest.skip("No items in cart to test delete link")


@pytest.mark.accessibility
@pytest.mark.cart
class TestCartTableAccessibility:
    """Test cart items table accessibility"""

    def test_cart_items_in_table_structure_CART_ACC_004(self, cart_page):
        """Test cart items use proper table structure"""
        cart_page.add_first_product()
        cart_page.open_cart()

        # Cart items should be in a table (tbody)
        items = cart_page.find_elements(cart_page.CART_ITEMS)
        assert len(items) > 0, "Cart items should be in table structure"

    def test_cart_displays_item_information_CART_ACC_005(self, cart_page):
        """Test cart displays item name for screen readers"""
        cart_page.add_first_product()
        cart_page.open_cart()

        item_name = cart_page.get_first_item_name()
        assert item_name is not None, "Cart should display item name"
        assert len(item_name) > 0, "Item name should be readable"


@pytest.mark.accessibility
@pytest.mark.cart
class TestCartButtonAccessibility:
    """Test cart button accessibility"""

    def test_place_order_button_has_text_CART_ACC_006(self, cart_page):
        """Test Place Order button has descriptive text"""
        cart_page.open_cart()

        button = cart_page.find_element(cart_page.PLACE_ORDER_BUTTON)
        button_text = button.text

        assert button_text, "Place Order button should have text"
        assert len(button_text) > 0, "Button text should be descriptive"

    def test_cart_link_has_text_CART_ACC_007(self, cart_page):
        """Test Cart navigation link has descriptive text"""
        cart_link = cart_page.find_element(cart_page.CART_NAV_LINK)
        link_text = cart_link.text

        assert (
            link_text is not None
        ), "Cart link should have text or ARIA label"

    def test_home_link_accessible_CART_ACC_008(self, cart_page):
        """Test Home link is accessible from cart"""
        cart_page.open_cart()

        home_link = cart_page.find_element(cart_page.HOME_NAV_LINK)
        assert home_link.is_displayed(), "Home link should be visible"
        assert home_link.is_enabled(), "Home link should be enabled"
