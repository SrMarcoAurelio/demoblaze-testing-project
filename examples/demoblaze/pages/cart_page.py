"""
Cart Page Object Model - TEMPLATE
Author: Marc Arevalo
Version: 6.0

IMPORTANT: This is a TEMPLATE/EXAMPLE for shopping cart page object.
The locators shown here are EXAMPLES and MUST be adapted to YOUR application's
actual element IDs, classes, and structure.

This template demonstrates:
- Shopping cart operations
- Add to cart functionality
- Cart item management
- Cart total calculation
- Product removal from cart

ADAPTATION REQUIRED:
1. Update ALL locators to match your application's elements
2. Modify methods if your cart flow differs (quantities, variants, etc.)
3. Consider loading locators from config/locators.json
4. Test thoroughly with YOUR application

For applications with different cart patterns (session-based, quantity selectors,
product variants, guest checkout, etc.), use this as inspiration but create
appropriate implementations.
"""

import re
import time
from typing import Optional, Tuple

from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait

from pages.base_page import BasePage


class CartPage(BasePage):
    """
    TEMPLATE Page Object for Shopping Cart functionality.

    This template demonstrates a basic shopping cart pattern.
    Adapt all locators and logic to match YOUR application.

    Handles:
    - Cart navigation
    - Adding products to cart
    - Viewing cart contents
    - Removing items from cart
    - Cart total calculation

    IMPORTANT: All locators below are EXAMPLES and must be replaced
    with your application's actual element locators.
    """

    # ========================================================================
    # NAVIGATION LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    CART_NAV_LINK = (By.ID, "cart-link")  # EXAMPLE - adapt to your app
    HOME_NAV_LINK = (By.XPATH, "//a[contains(text(), 'Home')]")  # EXAMPLE

    # ========================================================================
    # CART CONTENT LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    CART_ITEMS = (By.XPATH, "//tbody[@id='cart-items']/tr")  # EXAMPLE
    FIRST_ITEM_NAME = (
        By.XPATH,
        "//tbody[@id='cart-items']/tr[1]/td[2]",
    )  # EXAMPLE
    FIRST_ITEM_PRICE = (
        By.XPATH,
        "//tbody[@id='cart-items']/tr[1]/td[3]",
    )  # EXAMPLE
    FIRST_DELETE_LINK = (By.XPATH, "(//a[text()='Delete'])[1]")  # EXAMPLE
    SECOND_DELETE_LINK = (By.XPATH, "(//a[text()='Delete'])[2]")  # EXAMPLE

    CART_TOTAL_PRICE = (By.ID, "total-price")  # EXAMPLE - adapt to your app

    PLACE_ORDER_BUTTON = (
        By.XPATH,
        "//button[text()='Place Order']",
    )  # EXAMPLE

    # ========================================================================
    # PRODUCT CATALOG LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    FIRST_PRODUCT_LINK = (
        By.XPATH,
        "(//a[@class='product-link'])[1]",
    )  # EXAMPLE
    SECOND_PRODUCT_LINK = (
        By.XPATH,
        "(//a[@class='product-link'])[2]",
    )  # EXAMPLE
    PRODUCT_NAME_HEADER = (By.TAG_NAME, "h2")  # EXAMPLE
    PRODUCT_PRICE_HEADER = (By.TAG_NAME, "h3")  # EXAMPLE
    ADD_TO_CART_BUTTON = (By.XPATH, "//a[text()='Add to cart']")  # EXAMPLE

    CATEGORY_LAPTOPS_LINK = (By.XPATH, "//a[text()='Laptops']")  # EXAMPLE

    # ========================================================================
    # CART METHODS - Adapt to your application's workflow
    # ========================================================================

    def open_cart(self) -> bool:
        """
        Navigate to cart page.

        TEMPLATE METHOD - Adapt to your application's cart navigation.

        Returns:
            True if cart page opened successfully

        Example:
            >>> cart_page.open_cart()
            >>> assert cart_page.get_cart_item_count() > 0
        """
        self.click(self.CART_NAV_LINK)
        self.wait_for_element_visible(self.PLACE_ORDER_BUTTON)
        self.logger.info("Opened cart page")
        return True

    def go_home(self) -> bool:
        """
        Navigate to home page.

        TEMPLATE METHOD - Adapt to your application.

        Returns:
            True if navigation successful
        """
        self.click(self.HOME_NAV_LINK)
        self.wait_for_element_visible(self.FIRST_PRODUCT_LINK)
        return True

    def add_product_to_cart(
        self, product_locator: Optional[Tuple[str, str]] = None
    ) -> Tuple[str, int]:
        """
        Add a product to cart and return to home page.

        TEMPLATE METHOD - Adapt to your application's add-to-cart flow.
        Your app may have different steps (no alert, quantity selector, etc.).

        Args:
            product_locator: Locator for product link (defaults to first product)

        Returns:
            Tuple of (product_name, product_price)

        Example:
            >>> name, price = cart_page.add_product_to_cart()
            >>> cart_page.open_cart()
            >>> assert cart_page.get_first_item_name() == name
        """
        if product_locator is None:
            product_locator = self.FIRST_PRODUCT_LINK

        product_link = self.wait_for_element_clickable(product_locator)
        product_name_elem = self.find_element(product_locator)
        product_name = product_name_elem.text
        product_link.click()

        self.wait_for_element_visible(self.PRODUCT_PRICE_HEADER)

        price_element = self.find_element(self.PRODUCT_PRICE_HEADER)
        price_text = price_element.text
        price = self._parse_price(price_text)

        add_to_cart_btn = self.wait_for_element_clickable(
            self.ADD_TO_CART_BUTTON
        )
        add_to_cart_btn.click()

        # Check for alert (some apps show confirmation alert)
        self.get_alert_text(timeout=5)

        self.go_home()

        self.logger.info(f"Added product '{product_name}' to cart (${price})")
        return (product_name, price)

    def add_first_product(self) -> Tuple[str, int]:
        """
        Add first product to cart.

        TEMPLATE METHOD - Convenience wrapper for add_product_to_cart.

        Returns:
            Tuple of (product_name, product_price)
        """
        return self.add_product_to_cart(self.FIRST_PRODUCT_LINK)

    def add_second_product(self) -> Tuple[str, int]:
        """
        Add second product to cart.

        TEMPLATE METHOD - Convenience wrapper for add_product_to_cart.

        Returns:
            Tuple of (product_name, product_price)
        """
        return self.add_product_to_cart(self.SECOND_PRODUCT_LINK)

    def add_product_from_category(
        self, category_locator: Tuple[str, str], product_name: str
    ) -> Tuple[str, int]:
        """
        Add product from specific category.

        TEMPLATE METHOD - Adapt to your application's category navigation.

        Args:
            category_locator: Locator for category link
            product_name: Name of product to add

        Returns:
            Tuple of (product_name, product_price)

        Example:
            >>> category_loc = (By.LINK_TEXT, "Electronics")
            >>> name, price = cart_page.add_product_from_category(category_loc, "iPhone")
        """
        self.click(category_locator)
        self.waiter.wait_for_page_load(timeout=3)

        product_link = self.wait_for_element_clickable(
            (By.LINK_TEXT, product_name)
        )
        product_link.click()

        price_element = self.wait_for_element_visible(
            self.PRODUCT_PRICE_HEADER
        )
        price = self._parse_price(price_element.text)

        add_to_cart_btn = self.wait_for_element_clickable(
            self.ADD_TO_CART_BUTTON
        )
        add_to_cart_btn.click()

        self.get_alert_text(timeout=5)

        self.logger.info(f"Added '{product_name}' from category (${price})")
        return (product_name, price)

    def rapid_add_to_cart(
        self, product_locator: Tuple[str, str], times: int = 3
    ) -> int:
        """
        Rapidly click Add to Cart multiple times.

        TEMPLATE METHOD - Used for testing duplicate handling.
        Adapt to your application's duplicate prevention mechanism.

        Args:
            product_locator: Locator for product link
            times: Number of times to click

        Returns:
            Product price

        Example:
            >>> price = cart_page.rapid_add_to_cart(cart_page.FIRST_PRODUCT_LINK, 3)
            >>> # Test that app handles duplicates correctly
        """
        self.click(product_locator)
        self.wait_for_element_visible(self.PRODUCT_PRICE_HEADER)

        price_element = self.find_element(self.PRODUCT_PRICE_HEADER)
        price = self._parse_price(price_element.text)

        add_to_cart_btn = self.wait_for_element_clickable(
            self.ADD_TO_CART_BUTTON
        )

        for i in range(times):
            add_to_cart_btn.click()
            alert_text = self.get_alert_text(timeout=2)
            if alert_text:
                self.logger.info(f"Click {i+1}: {alert_text}")

        return price

    # ========================================================================
    # CART QUERY METHODS
    # ========================================================================

    def get_cart_item_count(self) -> int:
        """
        Get number of items in cart.

        TEMPLATE METHOD - Adapt to your application's cart structure.

        Returns:
            Number of items in cart

        Example:
            >>> count = cart_page.get_cart_item_count()
            >>> assert count > 0
        """
        try:
            items = self.find_elements(self.CART_ITEMS)
            count = len(items)
            self.logger.info(f"Cart has {count} items")
            return count
        except NoSuchElementException:
            return 0

    def get_cart_total(self, timeout: int = 10) -> int:
        """
        Get cart total price.

        TEMPLATE METHOD - Adapt to your application's total calculation display.
        Waits for total to update before returning.

        Args:
            timeout: Maximum time to wait for total to update

        Returns:
            Cart total as integer

        Example:
            >>> total = cart_page.get_cart_total()
            >>> assert total > 0
        """
        try:
            total_element = self.wait_for_element_visible(
                self.CART_TOTAL_PRICE, timeout=timeout
            )

            # Wait for total to populate (not empty)
            WebDriverWait(self.driver, timeout).until(
                lambda d: d.find_element(*self.CART_TOTAL_PRICE).text.strip()
                != ""
            )

            total_text = total_element.text
            total = self._parse_price(total_text)

            self.logger.info(f"Cart total: ${total}")
            return total

        except TimeoutException:
            self.logger.warning("Cart total did not update in time")
            return 0

    def get_first_item_name(self) -> Optional[str]:
        """
        Get name of first item in cart.

        TEMPLATE METHOD - Adapt to your application.

        Returns:
            Item name or None if not found
        """
        try:
            item_name = self.wait_for_element_visible(self.FIRST_ITEM_NAME)
            return item_name.text
        except Exception:
            return None

    def is_cart_empty(self) -> bool:
        """
        Check if cart is empty.

        TEMPLATE METHOD - Adapt to your application's empty cart indicator.

        Returns:
            True if cart is empty

        Example:
            >>> cart_page.delete_all_items()
            >>> assert cart_page.is_cart_empty()
        """
        count = self.get_cart_item_count()
        return count == 0

    # ========================================================================
    # CART MODIFICATION METHODS
    # ========================================================================

    def delete_first_item(self) -> bool:
        """
        Delete first item from cart.

        TEMPLATE METHOD - Adapt to your application's item removal mechanism.

        Returns:
            True if deletion successful

        Example:
            >>> initial_count = cart_page.get_cart_item_count()
            >>> cart_page.delete_first_item()
            >>> assert cart_page.get_cart_item_count() == initial_count - 1
        """
        initial_count = self.get_cart_item_count()

        delete_link = self.find_element(self.FIRST_DELETE_LINK)
        delete_link.click()

        try:
            WebDriverWait(self.driver, 10).until(
                lambda d: len(d.find_elements(*self.CART_ITEMS))
                < initial_count
            )
            self.logger.info("Deleted first item from cart")
            return True
        except TimeoutException:
            self.logger.warning("Item deletion timeout")
            return False

    def delete_all_items(self) -> bool:
        """
        Delete all items from cart.

        TEMPLATE METHOD - Adapt to your application.
        Some apps may have a "Clear Cart" button instead.

        Returns:
            True if all items deleted

        Example:
            >>> cart_page.delete_all_items()
            >>> assert cart_page.is_cart_empty()
        """
        initial_count = self.get_cart_item_count()

        for i in range(initial_count):
            self.delete_first_item()
            self.logger.info(f"Deleted item {i+1}/{initial_count}")

        self.logger.info("Deleted all items from cart")
        return True

    # ========================================================================
    # CHECKOUT METHODS
    # ========================================================================

    def click_place_order(self) -> bool:
        """
        Click Place Order button to open checkout modal/page.

        TEMPLATE METHOD - Adapt to your application's checkout flow.

        Returns:
            True if button clicked successfully

        Example:
            >>> cart_page.open_cart()
            >>> cart_page.click_place_order()
            >>> # Proceed with checkout...
        """
        place_order_btn = self.wait_for_element_clickable(
            self.PLACE_ORDER_BUTTON
        )
        place_order_btn.click()
        self.logger.info("Clicked Place Order button")
        return True

    def is_place_order_visible(self) -> bool:
        """
        Check if Place Order button is visible.

        TEMPLATE METHOD - Adapt to your application.

        Returns:
            True if button is visible
        """
        try:
            btn = self.find_element(self.PLACE_ORDER_BUTTON)
            return btn.is_displayed()
        except Exception:
            return False

    # ========================================================================
    # HELPER METHODS
    # ========================================================================

    def _parse_price(self, price_str: str) -> int:
        """
        Parse price from string.

        TEMPLATE METHOD - Adapt to your application's price format.

        Args:
            price_str: Price string (e.g., "$360", "360 *includes tax")

        Returns:
            Price as integer

        Example:
            "$360" -> 360
            "360 *includes tax" -> 360
            "€25.50" -> 25
        """
        match = re.search(r"\d+", price_str)
        if match:
            return int(match.group(0))
        return 0

    def wait_for_cart_to_update(
        self, expected_count: int, timeout: int = 10
    ) -> bool:
        """
        Wait for cart to have expected number of items.

        TEMPLATE METHOD - Useful for async cart updates.

        Args:
            expected_count: Expected number of items
            timeout: Maximum time to wait

        Returns:
            True if cart updated to expected count

        Example:
            >>> cart_page.add_first_product()
            >>> assert cart_page.wait_for_cart_to_update(expected_count=1)
        """
        try:
            WebDriverWait(self.driver, timeout).until(
                lambda d: len(d.find_elements(*self.CART_ITEMS))
                == expected_count
            )
            return True
        except TimeoutException:
            return False

    def measure_cart_total_calculation_time(self) -> float:
        """
        Measure how long it takes for cart total to be calculated.

        TEMPLATE METHOD - Performance testing utility.

        Returns:
            Calculation time in seconds

        Example:
            >>> calc_time = cart_page.measure_cart_total_calculation_time()
            >>> assert calc_time < 2.0  # Should be fast
        """
        start_time = time.time()
        total = self.get_cart_total(timeout=5)
        calculation_time = time.time() - start_time

        self.logger.info(
            f"Cart total calculated in {calculation_time:.2f} seconds"
        )
        return calculation_time


# ============================================================================
# USAGE EXAMPLE - How to adapt this template to your application
# ============================================================================
"""
EXAMPLE ADAPTATION:

1. Update locators to match your application:
   CART_NAV_LINK = (By.ID, "your-cart-button-id")
   CART_ITEMS = (By.CSS_SELECTOR, "your-cart-items-selector")
   # ... etc

2. If your app uses quantity selectors:
   QUANTITY_INPUT = (By.CSS_SELECTOR, ".quantity-input")

   def update_item_quantity(self, item_index: int, quantity: int):
       locator = (By.XPATH, f"(//input[@class='quantity-input'])[{item_index}]")
       quantity_input = self.find_element(locator)
       quantity_input.clear()
       quantity_input.send_keys(str(quantity))

3. If your app has product variants (size, color, etc.):
   def add_product_with_variant(self, product_locator, size: str, color: str):
       self.click(product_locator)
       self.select_option(self.SIZE_DROPDOWN, size)
       self.select_option(self.COLOR_DROPDOWN, color)
       self.click(self.ADD_TO_CART_BUTTON)

4. If your app has a "Clear Cart" button:
   CLEAR_CART_BUTTON = (By.ID, "clear-cart")

   def clear_cart(self):
       self.click(self.CLEAR_CART_BUTTON)
       # Confirm if there's a confirmation dialog
       self.accept_alert()

5. If your app tracks cart in session/header badge:
   CART_BADGE = (By.CSS_SELECTOR, ".cart-badge")

   def get_cart_badge_count(self):
       badge = self.find_element(self.CART_BADGE)
       return int(badge.text)

6. Use discovery-based element finding:
   from framework.core import ElementFinder

   def open_cart(self):
       cart_btn = self.finder.find_by_text("Cart", tag="button")
       if cart_btn:
           self.interactor.click(cart_btn)
"""
