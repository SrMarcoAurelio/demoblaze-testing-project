"""
ProductPage - Page Object Model for Product Detail Pages
Author: Marc Arévalo
Version: 2.0

This module provides a centralized interface for interacting with product detail pages.
Follows the Page Object Model (POM) design pattern for maintainable test automation.
Universal and reusable across any web application.
"""

import logging
import re
import time
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

import requests
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

from config import config
from pages.base_page import BasePage

logger = logging.getLogger(__name__)


class ProductPage(BasePage):
    """
    Page Object Model for Product Detail Pages

    Provides methods for:
    - Product navigation
    - Product information retrieval (name, price, description, image)
    - Add to cart operations
    - URL manipulation for security testing
    - Product validation across all catalog items
    """

    PRODUCT_LINKS = (By.CSS_SELECTOR, ".hrefch")
    PRODUCT_CARDS = (By.CSS_SELECTOR, ".card")
    FIRST_PRODUCT_LINK = (By.XPATH, "(//a[@class='hrefch'])[1]")
    SECOND_PRODUCT_LINK = (By.XPATH, "(//a[@class='hrefch'])[2]")

    PRODUCT_NAME = (By.CSS_SELECTOR, "h2.name")
    PRODUCT_PRICE = (By.CSS_SELECTOR, "h3.price-container")
    PRODUCT_DESCRIPTION = (By.CSS_SELECTOR, "#more")
    PRODUCT_IMAGE = (By.CSS_SELECTOR, ".item.active img")
    ADD_TO_CART_BUTTON = (By.CSS_SELECTOR, "a.btn.btn-success.btn-lg")

    HOME_LINK = (By.CSS_SELECTOR, "a.nav-link[href='index.html']")
    CART_LINK = (By.ID, "cartur")

    CATEGORY_PHONES = (By.LINK_TEXT, "Phones")
    CATEGORY_LAPTOPS = (By.LINK_TEXT, "Laptops")
    CATEGORY_MONITORS = (By.LINK_TEXT, "Monitors")

    NEXT_BUTTON = (By.ID, "next2")
    PREV_BUTTON = (By.ID, "prev2")

    def navigate_to_first_product(self) -> Tuple[bool, Optional[str]]:
        """
        Navigate from home page to the first product in the catalog
        Returns: (success, product_name)
        """
        try:
            self.driver.get(self.base_url)
            self.wait_for_page_load()

            self.wait_for_element_visible(self.PRODUCT_LINKS, timeout=10)
            time.sleep(1)

            first_product = self.find_element(self.FIRST_PRODUCT_LINK)
            product_name = first_product.text

            first_product.click()
            self.wait_for_page_load()
            time.sleep(2)

            return True, product_name
        except (TimeoutException, NoSuchElementException) as e:
            logger.error(f"Failed to navigate to first product: {e}")
            return False, None

    def navigate_to_product_by_index(
        self, index: int = 1
    ) -> Tuple[bool, Optional[str]]:
        """
        Navigate to a specific product by its index in the catalog
        Args:
            index: Product index (1-based)
        Returns: (success, product_name)
        """
        try:
            self.driver.get(self.base_url)
            self.wait_for_page_load()

            self.wait_for_element_visible(self.PRODUCT_LINKS, timeout=10)
            time.sleep(1)

            locator = (By.XPATH, f"(//a[@class='hrefch'])[{index}]")
            product_link = self.find_element(locator)
            product_name = product_link.text

            product_link.click()
            self.wait_for_page_load()
            time.sleep(2)

            return True, product_name
        except (TimeoutException, NoSuchElementException) as e:
            logger.error(f"Failed to navigate to product {index}: {e}")
            return False, None

    def navigate_to_product_by_url(self, product_id: Union[str, int]) -> bool:
        """
        Navigate directly to a product via URL manipulation
        Args:
            product_id: Product ID (can be string for security testing)
        Returns: bool - success status
        """
        try:
            url = f"{self.base_url}{config.PRODUCT_URL_PATTERN}".format(
                product_id=product_id
            )
            self.driver.get(url)
            self.wait_for_page_load()
            time.sleep(config.SLEEP_LONG)
            return True
        except Exception as e:
            logger.error(f"Failed to navigate to product ID {product_id}: {e}")
            return False

    def go_home(self) -> None:
        """Navigate back to home page"""
        home_link = self.find_element(self.HOME_LINK)
        home_link.click()
        self.wait_for_page_load()
        time.sleep(1)

    def go_back_browser(self) -> None:
        """Use browser back button"""
        self.driver.back()
        self.wait_for_page_load()
        time.sleep(1)

    def get_product_name(self, timeout: int = 10) -> Optional[str]:
        """
        Get product name from detail page
        Returns: str or None
        """
        try:
            element = self.wait_for_element_visible(
                self.PRODUCT_NAME, timeout=timeout
            )
            return element.text
        except TimeoutException:
            logger.warning("Product name not found")
            return None

    def get_product_price(self, timeout: int = 10) -> Optional[str]:
        """
        Get product price as string (e.g., "$790 *includes tax")
        Returns: str or None
        """
        try:
            element = self.wait_for_element_visible(
                self.PRODUCT_PRICE, timeout=timeout
            )
            return element.text
        except TimeoutException:
            logger.warning("Product price not found")
            return None

    def get_product_price_value(self, timeout: int = 10) -> Optional[int]:
        """
        Extract numeric price value from price string
        Returns: int or None
        """
        price_text = self.get_product_price(timeout=timeout)
        if price_text:
            match = re.search(r"\$(\d+)", price_text)
            if match:
                return int(match.group(1))
        return None

    def get_product_description(self, timeout: int = 10) -> Optional[str]:
        """
        Get product description text
        Returns: str or None
        """
        try:
            element = self.wait_for_element_visible(
                self.PRODUCT_DESCRIPTION, timeout=timeout
            )
            return element.text
        except TimeoutException:
            logger.warning("Product description not found")
            return None

    def get_product_image_src(self, timeout: int = 10) -> Optional[str]:
        """
        Get product image source URL
        Returns: str or None
        """
        try:
            element = self.wait_for_element_visible(
                self.PRODUCT_IMAGE, timeout=timeout
            )
            return element.get_attribute("src")
        except TimeoutException:
            logger.warning("Product image not found")
            return None

    def get_product_image_alt(self, timeout: int = 10) -> Optional[str]:
        """
        Get product image alt attribute for accessibility testing
        Returns: str or None
        """
        try:
            element = self.wait_for_element_visible(
                self.PRODUCT_IMAGE, timeout=timeout
            )
            return element.get_attribute("alt")
        except TimeoutException:
            logger.warning("Product image not found")
            return None

    def get_all_product_details(self, timeout: int = 10) -> Dict[str, Any]:
        """
        Extract all product details from the current product page
        Returns: dict with name, price, description, image_src, add_to_cart_present
        """
        details = {
            "name": self.get_product_name(timeout=timeout),
            "price": self.get_product_price(timeout=timeout),
            "price_value": self.get_product_price_value(timeout=timeout),
            "description": self.get_product_description(timeout=timeout),
            "image_src": self.get_product_image_src(timeout=timeout),
            "image_alt": self.get_product_image_alt(timeout=timeout),
            "add_to_cart_present": self.is_add_to_cart_visible(
                timeout=timeout
            ),
        }
        return details

    def is_add_to_cart_visible(self, timeout: int = 5) -> bool:
        """
        Check if Add to Cart button is visible
        Returns: bool
        """
        try:
            self.wait_for_element_visible(
                self.ADD_TO_CART_BUTTON, timeout=timeout
            )
            return True
        except TimeoutException:
            return False

    def click_add_to_cart(self) -> bool:
        """
        Click the Add to Cart button
        Returns: bool - success status
        """
        try:
            button = self.wait_for_element_clickable(
                self.ADD_TO_CART_BUTTON, timeout=10
            )
            button.click()
            return True
        except TimeoutException:
            logger.error("Add to Cart button not clickable")
            return False

    def add_to_cart_and_handle_alert(
        self, timeout: int = 5
    ) -> Tuple[bool, Optional[str]]:
        """
        Add product to cart and handle the alert
        Returns: (success, alert_text)
        """
        if not self.click_add_to_cart():
            return False, None

        alert_text = self.get_alert_text(timeout=timeout)
        return True, alert_text

    def add_product_to_cart_complete(
        self,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Complete flow: add to cart and return to home
        Returns: (success, product_name, alert_text)
        """
        product_name = self.get_product_name()
        success, alert_text = self.add_to_cart_and_handle_alert()

        if success:
            self.go_home()

        return success, product_name, alert_text

    def get_all_product_links_on_page(self) -> List[Any]:
        """
        Get all product links currently visible on the catalog page
        Returns: list of WebElement objects
        """
        try:
            self.driver.get(self.base_url)
            self.wait_for_page_load()
            time.sleep(1)

            products = self.find_elements(self.PRODUCT_LINKS)
            return products
        except Exception as e:
            logger.error(f"Failed to get product links: {e}")
            return []

    def get_product_count_on_page(self) -> int:
        """
        Count how many products are visible on current catalog page
        Returns: int
        """
        products = self.get_all_product_links_on_page()
        return len(products)

    def iterate_all_products(
        self, max_products: Optional[int] = None
    ) -> Generator[Tuple[int, str, Dict[str, Any]], None, None]:
        """
        Generator that yields (index, product_name, details) for each product
        Useful for validation tests across all products
        Args:
            max_products: Maximum number of products to check (None = all)
        Yields: (index, product_name, details_dict)
        """
        self.driver.get(self.base_url)
        self.wait_for_page_load()
        time.sleep(1)

        products = self.get_all_product_links_on_page()
        count = (
            len(products)
            if max_products is None
            else min(len(products), max_products)
        )

        for i in range(1, count + 1):
            success, product_name = self.navigate_to_product_by_index(i)

            if success and product_name:
                details = self.get_all_product_details()
                yield i, product_name, details

            self.driver.get(self.base_url)
            self.wait_for_page_load()
            time.sleep(1)

    def validate_product_data_completeness(self) -> Tuple[bool, List[str]]:
        """
        Validate that all essential product data is present
        Returns: (is_valid, missing_fields)
        """
        details = self.get_all_product_details()

        missing = []
        if not details["name"]:
            missing.append("name")
        if not details["price"]:
            missing.append("price")
        if not details["description"]:
            missing.append("description")
        if not details["image_src"]:
            missing.append("image")
        if not details["add_to_cart_present"]:
            missing.append("add_to_cart_button")

        is_valid = len(missing) == 0
        return is_valid, missing

    def validate_price_format(self) -> Tuple[bool, Optional[str]]:
        """
        Validate price follows expected format: "$XXX *includes tax"
        Returns: (is_valid, actual_price)
        """
        price = self.get_product_price()

        if not price:
            return False, None

        pattern = r"^\$\d+\s+\*includes tax$"
        is_valid = bool(re.match(pattern, price))

        return is_valid, price

    def verify_image_loads(
        self, timeout: int = 10
    ) -> Tuple[bool, Optional[int], Optional[str]]:
        """
        Verify product image loads successfully by checking HTTP status
        Returns: (loads_successfully, status_code, image_url)
        """
        image_url = self.get_product_image_src(timeout=timeout)

        if not image_url:
            return False, None, None

        try:
            response = requests.head(image_url, timeout=5)
            status_code = response.status_code
            loads_successfully = status_code == 200
            return loads_successfully, status_code, image_url
        except requests.RequestException as e:
            logger.error(f"Failed to verify image: {e}")
            return False, None, image_url

    def test_keyboard_navigation(self) -> Dict[str, bool]:
        """
        Test keyboard navigation on product page (Tab key)
        Returns: dict with navigation results
        """
        results = {
            "add_to_cart_focusable": False,
            "home_link_focusable": False,
            "tab_navigation_works": False,
        }

        try:
            actions = ActionChains(self.driver)

            for _ in range(10):
                actions.send_keys(Keys.TAB).perform()
                time.sleep(0.2)

                active_element = self.driver.switch_to.active_element
                tag_name = active_element.tag_name

                if tag_name == "a":
                    text = active_element.text
                    if "Add to cart" in text:
                        results["add_to_cart_focusable"] = True
                    if "Home" in text:
                        results["home_link_focusable"] = True

            results["tab_navigation_works"] = (
                results["add_to_cart_focusable"]
                or results["home_link_focusable"]
            )

        except Exception as e:
            logger.error(f"Keyboard navigation test failed: {e}")

        return results

    def measure_page_load_time(self) -> Dict[str, Any]:
        """
        Measure product detail page load time using Navigation Timing API
        Returns: dict with timing metrics (in seconds)
        """
        try:
            timing = self.driver.execute_script(
                """
                var timing = window.performance.timing;
                return {
                    navigationStart: timing.navigationStart,
                    domContentLoaded: timing.domContentLoadedEventEnd,
                    loadComplete: timing.loadEventEnd
                };
            """
            )

            nav_start = timing["navigationStart"]
            dom_loaded = timing["domContentLoaded"]
            load_complete = timing["loadComplete"]

            if nav_start and dom_loaded and load_complete:
                dom_load_time = (dom_loaded - nav_start) / 1000.0
                total_load_time = (load_complete - nav_start) / 1000.0

                return {
                    "dom_load_time": dom_load_time,
                    "total_load_time": total_load_time,
                    "success": True,
                }
        except Exception as e:
            logger.error(f"Failed to measure load time: {e}")

        return {
            "dom_load_time": None,
            "total_load_time": None,
            "success": False,
        }

    def get_current_product_id_from_url(self) -> Optional[str]:
        """
        Extract product ID from current URL
        Returns: str or None
        """
        current_url = self.driver.current_url
        match = re.search(r"idp_=([^&]+)", current_url)
        if match:
            return match.group(1)
        return None

    def check_for_sql_error_indicators(self) -> Tuple[bool, List[str]]:
        """
        Check page source for SQL error disclosure
        Returns: (has_error, error_indicators_found)
        """
        page_source = self.driver.page_source.lower()

        sql_error_patterns = [
            "sql syntax",
            "mysql",
            "postgresql",
            "sqlite",
            "database error",
            "odbc",
            "jdbc",
            "syntax error near",
            "unclosed quotation mark",
            "you have an error in your sql syntax",
        ]

        found_indicators = []
        for pattern in sql_error_patterns:
            if pattern in page_source:
                found_indicators.append(pattern)

        has_error = len(found_indicators) > 0
        return has_error, found_indicators

    def check_for_xss_execution(
        self, payload: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if XSS payload is reflected unescaped or executed
        Args:
            payload: XSS payload string
        Returns: (is_vulnerable, evidence)
        """
        page_source = self.driver.page_source

        if payload in page_source:
            return True, f"Payload reflected unescaped: {payload}"

        try:
            alert = self.driver.switch_to.alert
            alert_text = alert.text
            alert.accept()
            return True, f"Alert executed: {alert_text}"
        except Exception:
            # No alert present
            pass

        return False, None

    def check_security_headers(self) -> Dict[str, str]:
        """
        Check for security headers in HTTP response (requires network log access)
        Returns: dict with header presence
        """
        return {
            "note": "Security header checking requires network log access",
            "recommendation": "Use browser DevTools Protocol or proxy like mitmproxy",
        }

    def check_for_information_disclosure(self) -> Tuple[bool, List[str]]:
        """
        Check page source for information disclosure (comments, debug info, etc.)
        Returns: (has_disclosure, findings)
        """
        page_source = self.driver.page_source.lower()

        disclosure_patterns = [
            ("<!-- debug", "Debug comments"),
            ("password", "Password references"),
            ("api_key", "API key references"),
            ("secret", "Secret references"),
            ("admin", "Admin references"),
            ("todo", "TODO comments"),
            ("fixme", "FIXME comments"),
        ]

        findings = []
        for pattern, description in disclosure_patterns:
            if pattern in page_source:
                findings.append(description)

        has_disclosure = len(findings) > 0
        return has_disclosure, findings
