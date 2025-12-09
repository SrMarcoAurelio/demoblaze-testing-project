"""
Cart Functional Tests
Author: Marc Arévalo
Version: 1.0

Tests basic cart functionality: add products, view cart, delete items, checkout.
"""

import pytest
from selenium.webdriver.common.by import By


@pytest.mark.functional
@pytest.mark.cart
class TestCartNavigation:
    """Test cart navigation functionality"""

    def test_open_cart_page_CART_FN_001(self, cart_page):
        """Test navigating to cart page"""
        result = cart_page.open_cart()
        assert result is True, "Failed to open cart page"
        assert (
            cart_page.is_place_order_visible()
        ), "Place Order button not visible"

    def test_navigate_home_from_cart_CART_FN_002(self, cart_page):
        """Test navigating back to home from cart"""
        cart_page.open_cart()
        result = cart_page.go_home()
        assert result is True, "Failed to navigate to home"

    def test_cart_page_displays_place_order_button_CART_FN_003(
        self, cart_page
    ):
        """Test Place Order button is visible on cart page"""
        cart_page.open_cart()
        assert (
            cart_page.is_place_order_visible()
        ), "Place Order button not visible"


@pytest.mark.functional
@pytest.mark.cart
class TestAddProductsToCart:
    """Test adding products to cart"""

    def test_add_first_product_to_cart_CART_FN_004(self, cart_page):
        """Test adding first product to cart"""
        product_name, product_price = cart_page.add_first_product()

        assert product_name, "Product name is empty"
        assert product_price > 0, f"Invalid product price: {product_price}"
        assert isinstance(product_name, str), "Product name should be string"
        assert isinstance(
            product_price, int
        ), "Product price should be integer"

    def test_add_second_product_to_cart_CART_FN_005(self, cart_page):
        """Test adding second product to cart"""
        product_name, product_price = cart_page.add_second_product()

        assert product_name, "Product name is empty"
        assert product_price > 0, f"Invalid product price: {product_price}"

    def test_add_product_with_custom_locator_CART_FN_006(self, cart_page):
        """Test adding product using custom locator"""
        custom_locator = (By.XPATH, "(//a[@class='hrefch'])[3]")
        product_name, product_price = cart_page.add_product_to_cart(
            custom_locator
        )

        assert product_name, "Product name is empty"
        assert product_price > 0, f"Invalid product price: {product_price}"

    def test_add_product_from_laptops_category_CART_FN_007(self, cart_page):
        """Test adding product from specific category"""
        product_name, product_price = cart_page.add_product_from_category(
            cart_page.CATEGORY_LAPTOPS_LINK, "Sony vaio i5"
        )

        assert (
            product_name == "Sony vaio i5"
        ), f"Expected 'Sony vaio i5', got '{product_name}'"
        assert product_price > 0, f"Invalid product price: {product_price}"

    def test_add_multiple_products_CART_FN_008(self, cart_page):
        """Test adding multiple different products to cart"""
        product1_name, product1_price = cart_page.add_first_product()
        product2_name, product2_price = cart_page.add_second_product()

        assert product1_name != product2_name, "Products should be different"
        cart_page.open_cart()
        item_count = cart_page.get_cart_item_count()
        assert item_count == 2, f"Expected 2 items in cart, got {item_count}"


@pytest.mark.functional
@pytest.mark.cart
class TestCartItemOperations:
    """Test cart item operations"""

    def test_get_cart_item_count_empty_cart_CART_FN_009(self, cart_page):
        """Test getting item count from empty cart"""
        cart_page.open_cart()
        count = cart_page.get_cart_item_count()
        assert count == 0, f"Expected 0 items in empty cart, got {count}"

    def test_get_cart_item_count_with_products_CART_FN_010(self, cart_page):
        """Test getting item count after adding products"""
        cart_page.add_first_product()
        cart_page.open_cart()
        count = cart_page.get_cart_item_count()
        assert count == 1, f"Expected 1 item in cart, got {count}"

    def test_is_cart_empty_returns_true_CART_FN_011(self, cart_page):
        """Test is_cart_empty returns True for empty cart"""
        cart_page.open_cart()
        assert cart_page.is_cart_empty() is True, "Cart should be empty"

    def test_is_cart_empty_returns_false_CART_FN_012(self, cart_page):
        """Test is_cart_empty returns False when cart has items"""
        cart_page.add_first_product()
        cart_page.open_cart()
        assert cart_page.is_cart_empty() is False, "Cart should not be empty"

    def test_get_first_item_name_CART_FN_013(self, cart_page):
        """Test getting first item name from cart"""
        product_name, _ = cart_page.add_first_product()
        cart_page.open_cart()
        first_item = cart_page.get_first_item_name()
        assert (
            first_item == product_name
        ), f"Expected '{product_name}', got '{first_item}'"

    def test_get_first_item_name_empty_cart_CART_FN_014(self, cart_page):
        """Test get_first_item_name returns None for empty cart"""
        cart_page.open_cart()
        first_item = cart_page.get_first_item_name()
        assert first_item is None, "Expected None for empty cart"


@pytest.mark.functional
@pytest.mark.cart
class TestDeleteCartItems:
    """Test deleting items from cart"""

    def test_delete_first_item_from_cart_CART_FN_015(self, cart_page):
        """Test deleting first item from cart"""
        cart_page.add_first_product()
        cart_page.add_second_product()
        cart_page.open_cart()

        initial_count = cart_page.get_cart_item_count()
        result = cart_page.delete_first_item()

        assert result is True, "Failed to delete first item"
        final_count = cart_page.get_cart_item_count()
        assert (
            final_count == initial_count - 1
        ), f"Expected {initial_count - 1} items, got {final_count}"

    def test_delete_all_items_from_cart_CART_FN_016(self, cart_page):
        """Test deleting all items from cart"""
        cart_page.add_first_product()
        cart_page.add_second_product()
        cart_page.open_cart()

        result = cart_page.delete_all_items()
        assert result is True, "Failed to delete all items"
        assert (
            cart_page.is_cart_empty()
        ), "Cart should be empty after deleting all items"


@pytest.mark.functional
@pytest.mark.cart
class TestCartTotal:
    """Test cart total calculation"""

    def test_get_cart_total_single_product_CART_FN_017(self, cart_page):
        """Test cart total with single product"""
        _, product_price = cart_page.add_first_product()
        cart_page.open_cart()

        cart_total = cart_page.get_cart_total()
        assert (
            cart_total == product_price
        ), f"Expected total ${product_price}, got ${cart_total}"

    def test_get_cart_total_multiple_products_CART_FN_018(self, cart_page):
        """Test cart total with multiple products"""
        _, price1 = cart_page.add_first_product()
        _, price2 = cart_page.add_second_product()
        cart_page.open_cart()

        expected_total = price1 + price2
        cart_total = cart_page.get_cart_total()
        assert (
            cart_total == expected_total
        ), f"Expected total ${expected_total}, got ${cart_total}"

    def test_get_cart_total_empty_cart_CART_FN_019(self, cart_page):
        """Test cart total for empty cart"""
        cart_page.open_cart()
        cart_total = cart_page.get_cart_total()
        assert (
            cart_total == 0
        ), f"Expected total $0 for empty cart, got ${cart_total}"


@pytest.mark.functional
@pytest.mark.cart
class TestPlaceOrder:
    """Test place order functionality"""

    def test_click_place_order_button_CART_FN_020(self, cart_page):
        """Test clicking Place Order button"""
        cart_page.add_first_product()
        cart_page.open_cart()

        result = cart_page.click_place_order()
        assert result is True, "Failed to click Place Order button"
