"""
Cart Page Object Model
Author: Marc Arévalo
Version: 2.0

This page object models Shopping Cart functionality.
Contains all locators and actions related to cart operations.
Universal and reusable across any web application with shopping cart features.
"""

from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from pages.base_page import BasePage
import logging
import time
import re

class CartPage(BasePage):
    """Cart Page Object - handles all cart-related operations"""


    CART_NAV_LINK = (By.ID, "cartur")
    HOME_NAV_LINK = (By.XPATH, "//a[contains(text(), 'Home')]")

    CART_ITEMS = (By.XPATH, "//tbody[@id='tbodyid']/tr")
    FIRST_ITEM_NAME = (By.XPATH, "//tbody[@id='tbodyid']/tr[1]/td[2]")
    FIRST_ITEM_PRICE = (By.XPATH, "//tbody[@id='tbodyid']/tr[1]/td[3]")
    FIRST_DELETE_LINK = (By.XPATH, "(//a[text()='Delete'])[1]")
    SECOND_DELETE_LINK = (By.XPATH, "(//a[text()='Delete'])[2]")

    CART_TOTAL_PRICE = (By.ID, "totalp")

    PLACE_ORDER_BUTTON = (By.XPATH, "//button[text()='Place Order']")

    FIRST_PRODUCT_LINK = (By.XPATH, "(//a[@class='hrefch'])[1]")
    SECOND_PRODUCT_LINK = (By.XPATH, "(//a[@class='hrefch'])[2]")
    PRODUCT_NAME_HEADER = (By.TAG_NAME, "h2")
    PRODUCT_PRICE_HEADER = (By.TAG_NAME, "h3")
    ADD_TO_CART_BUTTON = (By.XPATH, "//a[text()='Add to cart']")

    CATEGORY_LAPTOPS_LINK = (By.XPATH, "//a[text()='Laptops']")


    def open_cart(self):
        """Navigate to cart page"""
        self.click(self.CART_NAV_LINK)
        self.wait_for_element_visible(self.PLACE_ORDER_BUTTON)
        self.logger.info("Opened cart page")
        return True

    def go_home(self):
        """Navigate to home page"""
        self.click(self.HOME_NAV_LINK)
        self.wait_for_element_visible(self.FIRST_PRODUCT_LINK)
        return True


    def add_product_to_cart(self, product_locator=None):
        """
        Add a product to cart and return to home page
        Returns: (product_name, product_price)
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

        add_to_cart_btn = self.wait_for_element_clickable(self.ADD_TO_CART_BUTTON)
        add_to_cart_btn.click()

        self.get_alert_text(timeout=5)

        self.go_home()

        self.logger.info(f"Added product '{product_name}' to cart (${price})")
        return (product_name, price)

    def add_first_product(self):
        """Add first product to cart"""
        return self.add_product_to_cart(self.FIRST_PRODUCT_LINK)

    def add_second_product(self):
        """Add second product to cart"""
        return self.add_product_to_cart(self.SECOND_PRODUCT_LINK)

    def add_product_from_category(self, category_locator, product_name):
        """Add product from specific category"""
        self.click(category_locator)
        time.sleep(1)

        product_link = self.wait_for_element_clickable((By.LINK_TEXT, product_name))
        product_link.click()

        price_element = self.wait_for_element_visible(self.PRODUCT_PRICE_HEADER)
        price = self._parse_price(price_element.text)

        add_to_cart_btn = self.wait_for_element_clickable(self.ADD_TO_CART_BUTTON)
        add_to_cart_btn.click()

        self.get_alert_text(timeout=5)

        self.logger.info(f"Added '{product_name}' from category (${price})")
        return (product_name, price)

    def rapid_add_to_cart(self, product_locator, times=3):
        """
        Rapidly click Add to Cart multiple times
        Used for testing duplicate handling
        """
        self.click(product_locator)
        self.wait_for_element_visible(self.PRODUCT_PRICE_HEADER)

        price_element = self.find_element(self.PRODUCT_PRICE_HEADER)
        price = self._parse_price(price_element.text)

        add_to_cart_btn = self.wait_for_element_clickable(self.ADD_TO_CART_BUTTON)

        for i in range(times):
            add_to_cart_btn.click()
            alert_text = self.get_alert_text(timeout=2)
            if alert_text:
                self.logger.info(f"Click {i+1}: {alert_text}")

        return price


    def get_cart_item_count(self):
        """Get number of items in cart"""
        try:
            items = self.find_elements(self.CART_ITEMS)
            count = len(items)
            self.logger.info(f"Cart has {count} items")
            return count
        except NoSuchElementException:
            return 0

    def get_cart_total(self, timeout=10):
        """
        Get cart total price
        Waits for total to update before returning
        """
        try:
            total_element = self.wait_for_element_visible(self.CART_TOTAL_PRICE, timeout=timeout)

            WebDriverWait(self.driver, timeout).until(
                lambda d: d.find_element(*self.CART_TOTAL_PRICE).text.strip() != ""
            )

            total_text = total_element.text
            total = self._parse_price(total_text)

            self.logger.info(f"Cart total: ${total}")
            return total

        except TimeoutException:
            self.logger.warning("Cart total did not update in time")
            return 0

    def get_first_item_name(self):
        """Get name of first item in cart"""
        try:
            item_name = self.wait_for_element_visible(self.FIRST_ITEM_NAME)
            return item_name.text
        except:
            return None

    def is_cart_empty(self):
        """Check if cart is empty"""
        count = self.get_cart_item_count()
        return count == 0


    def delete_first_item(self):
        """Delete first item from cart"""
        initial_count = self.get_cart_item_count()

        delete_link = self.find_element(self.FIRST_DELETE_LINK)
        delete_link.click()

        try:
            WebDriverWait(self.driver, 10).until(
                lambda d: len(d.find_elements(*self.CART_ITEMS)) < initial_count
            )
            self.logger.info("Deleted first item from cart")
            return True
        except TimeoutException:
            self.logger.warning("Item deletion timeout")
            return False

    def delete_all_items(self):
        """Delete all items from cart"""
        initial_count = self.get_cart_item_count()

        for i in range(initial_count):
            self.delete_first_item()
            self.logger.info(f"Deleted item {i+1}/{initial_count}")

        self.logger.info("Deleted all items from cart")
        return True


    def click_place_order(self):
        """Click Place Order button to open checkout modal"""
        place_order_btn = self.wait_for_element_clickable(self.PLACE_ORDER_BUTTON)
        place_order_btn.click()
        self.logger.info("Clicked Place Order button")
        return True

    def is_place_order_visible(self):
        """Check if Place Order button is visible"""
        try:
            btn = self.find_element(self.PLACE_ORDER_BUTTON)
            return btn.is_displayed()
        except:
            return False


    def _parse_price(self, price_str):
        """
        Parse price from string
        Examples: "$360" -> 360, "360 *includes tax" -> 360
        """
        match = re.search(r'\d+', price_str)
        if match:
            return int(match.group(0))
        return 0

    def wait_for_cart_to_update(self, expected_count, timeout=10):
        """Wait for cart to have expected number of items"""
        try:
            WebDriverWait(self.driver, timeout).until(
                lambda d: len(d.find_elements(*self.CART_ITEMS)) == expected_count
            )
            return True
        except TimeoutException:
            return False

    def measure_cart_total_calculation_time(self):
        """Measure how long it takes for cart total to be calculated"""
        start_time = time.time()
        total = self.get_cart_total(timeout=5)
        calculation_time = time.time() - start_time

        self.logger.info(f"Cart total calculated in {calculation_time:.2f} seconds")
        return calculation_time
