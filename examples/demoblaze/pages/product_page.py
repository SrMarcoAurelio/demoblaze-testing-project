"""
Product Page Object Model - TEMPLATE
Author: Marc Arevalo
Version: 6.0

IMPORTANT: This is a TEMPLATE/EXAMPLE for product detail page object.
The locators shown here are EXAMPLES and MUST be adapted to YOUR application's
actual element IDs, classes, and structure.

This template demonstrates:
- Product detail page navigation
- Product information retrieval
- Add to cart functionality
- Product validation and quality checks
- Security testing patterns
- Accessibility testing

ADAPTATION REQUIRED:
1. Update ALL locators to match your application's elements
2. Modify methods if your product page structure differs
3. Consider loading locators from config/locators.json
4. Test thoroughly with YOUR application

For applications with different product patterns (reviews, variants, related products,
image galleries, etc.), use this as inspiration but create appropriate implementations.
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

from .base_page import BasePage

logger = logging.getLogger(__name__)


class ProductPage(BasePage):
    """
    TEMPLATE Page Object for Product Detail Pages.

    This template demonstrates a product detail page pattern.
    Adapt all locators and logic to match YOUR application.

    Handles:
    - Product navigation
    - Product information retrieval (name, price, description, image)
    - Add to cart operations
    - Product validation across catalog items
    - Security and accessibility testing

    IMPORTANT: All locators below are EXAMPLES and must be replaced
    with your application's actual element locators.
    """

    # ========================================================================
    # CATALOG/LISTING LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    PRODUCT_LINKS = (By.CSS_SELECTOR, ".product-link")  # EXAMPLE
    PRODUCT_CARDS = (By.CSS_SELECTOR, ".product-card")  # EXAMPLE
    FIRST_PRODUCT_LINK = (
        By.XPATH,
        "(//a[@class='product-link'])[1]",
    )  # EXAMPLE
    SECOND_PRODUCT_LINK = (
        By.XPATH,
        "(//a[@class='product-link'])[2]",
    )  # EXAMPLE

    # ========================================================================
    # PRODUCT DETAIL LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    PRODUCT_NAME = (By.CSS_SELECTOR, "h2.product-name")  # EXAMPLE
    PRODUCT_PRICE = (By.CSS_SELECTOR, "h3.price-container")  # EXAMPLE
    PRODUCT_DESCRIPTION = (By.CSS_SELECTOR, "#product-description")  # EXAMPLE
    PRODUCT_IMAGE = (By.CSS_SELECTOR, ".product-image img")  # EXAMPLE
    ADD_TO_CART_BUTTON = (By.CSS_SELECTOR, "a.btn-add-to-cart")  # EXAMPLE

    # ========================================================================
    # NAVIGATION LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    HOME_LINK = (By.CSS_SELECTOR, "a.nav-link[href='index.html']")  # EXAMPLE
    CART_LINK = (By.ID, "cart-link")  # EXAMPLE

    # ========================================================================
    # CATEGORY LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    CATEGORY_PHONES = (By.LINK_TEXT, "Phones")  # EXAMPLE
    CATEGORY_LAPTOPS = (By.LINK_TEXT, "Laptops")  # EXAMPLE
    CATEGORY_MONITORS = (By.LINK_TEXT, "Monitors")  # EXAMPLE

    # ========================================================================
    # PAGINATION LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    NEXT_BUTTON = (By.ID, "next-page")  # EXAMPLE
    PREV_BUTTON = (By.ID, "prev-page")  # EXAMPLE

    # ========================================================================
    # PRODUCT NAVIGATION METHODS - Adapt to your application's workflow
    # ========================================================================

    def navigate_to_first_product(self) -> Tuple[bool, Optional[str]]:
        """
        Navigate from home page to the first product in the catalog.

        TEMPLATE METHOD - Adapt to your application's navigation.

        Returns:
            Tuple of (success, product_name)

        Example:
            >>> success, name = product_page.navigate_to_first_product()
            >>> assert success
            >>> assert product_page.get_product_name() == name
        """
        try:
            self.driver.get(self.base_url)
            self.wait_for_page_load()

            self.wait_for_element_visible(self.PRODUCT_LINKS, timeout=10)
            self.waiter.wait_for_page_load(timeout=3)

            first_product = self.find_element(self.FIRST_PRODUCT_LINK)
            product_name = first_product.text

            first_product.click()
            self.wait_for_page_load()
            self.waiter.wait_for_page_load(timeout=5)

            return True, product_name
        except (TimeoutException, NoSuchElementException) as e:
            logger.error(f"Failed to navigate to first product: {e}")
            return False, None

    def navigate_to_product_by_index(
        self, index: int = 1
    ) -> Tuple[bool, Optional[str]]:
        """
        Navigate to a specific product by its index in the catalog.

        TEMPLATE METHOD - Adapt to your application's catalog structure.

        Args:
            index: Product index (1-based)

        Returns:
            Tuple of (success, product_name)

        Example:
            >>> success, name = product_page.navigate_to_product_by_index(3)
            >>> assert success
        """
        try:
            self.driver.get(self.base_url)
            self.wait_for_page_load()

            self.wait_for_element_visible(self.PRODUCT_LINKS, timeout=10)
            self.waiter.wait_for_page_load(timeout=3)

            locator = (By.XPATH, f"(//a[@class='product-link'])[{index}]")
            product_link = self.find_element(locator)
            product_name = product_link.text

            product_link.click()
            self.wait_for_page_load()
            self.waiter.wait_for_page_load(timeout=5)

            return True, product_name
        except (TimeoutException, NoSuchElementException) as e:
            logger.error(f"Failed to navigate to product {index}: {e}")
            return False, None

    def navigate_to_product_by_url(self, product_id: Union[str, int]) -> bool:
        """
        Navigate directly to a product via URL manipulation.

        TEMPLATE METHOD - Adapt to YOUR application's URL structure.
        This method is useful for security testing (SQL injection in URL params).

        Args:
            product_id: Product ID (can be string for security testing)

        Returns:
            True if navigation successful

        Example:
            >>> product_page.navigate_to_product_by_url(123)
            >>> assert product_page.get_product_name() is not None

            >>> # Security testing
            >>> product_page.navigate_to_product_by_url("' OR '1'='1")
            >>> has_sql_error, _ = product_page.check_for_sql_error_indicators()
            >>> assert not has_sql_error
        """
        try:
            # EXAMPLE: Adapt to YOUR application's URL pattern
            # Common patterns: /product/123, /product?id=123, /p/123
            url = f"{self.base_url}/product?id={product_id}"
            self.driver.get(url)
            self.wait_for_page_load()
            self.waiter.wait_for_page_load(timeout=5)
            return True
        except Exception as e:
            logger.error(f"Failed to navigate to product ID {product_id}: {e}")
            return False

    def go_home(self) -> None:
        """
        Navigate back to home page.

        TEMPLATE METHOD - Adapt to your application.

        Example:
            >>> product_page.go_home()
            >>> assert catalog_page.are_products_displayed()
        """
        home_link = self.find_element(self.HOME_LINK)
        home_link.click()
        self.wait_for_page_load()
        self.waiter.wait_for_page_load(timeout=3)

    def go_back_browser(self) -> None:
        """
        Use browser back button.

        TEMPLATE METHOD - Standard browser navigation.

        Example:
            >>> product_page.navigate_to_first_product()
            >>> product_page.go_back_browser()
            >>> # Should be back on catalog page
        """
        self.driver.back()
        self.wait_for_page_load()
        self.waiter.wait_for_page_load(timeout=3)

    # ========================================================================
    # PRODUCT INFORMATION METHODS
    # ========================================================================

    def get_product_name(self, timeout: int = 10) -> Optional[str]:
        """
        Get product name from detail page.

        TEMPLATE METHOD - Adapt to your application's product name display.

        Args:
            timeout: Maximum time to wait

        Returns:
            Product name or None

        Example:
            >>> name = product_page.get_product_name()
            >>> assert name is not None
            >>> assert len(name) > 0
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
        Get product price as string (e.g., "$790 *includes tax").

        TEMPLATE METHOD - Adapt to your application's price display.

        Returns:
            Price string or None

        Example:
            >>> price = product_page.get_product_price()
            >>> assert "$" in price
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
        Extract numeric price value from price string.

        TEMPLATE METHOD - Adapt to your application's price format.

        Returns:
            Price as integer or None

        Example:
            >>> price_value = product_page.get_product_price_value()
            >>> assert price_value > 0
        """
        price_text = self.get_product_price(timeout=timeout)
        if price_text:
            # EXAMPLE: Extract "$790" -> 790
            # Adapt to YOUR application's format
            match = re.search(r"\$(\d+)", price_text)
            if match:
                return int(match.group(1))
        return None

    def get_product_description(self, timeout: int = 10) -> Optional[str]:
        """
        Get product description text.

        TEMPLATE METHOD - Adapt to your application.

        Returns:
            Description text or None

        Example:
            >>> desc = product_page.get_product_description()
            >>> assert desc is not None
            >>> assert len(desc) > 10
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
        Get product image source URL.

        TEMPLATE METHOD - Adapt to your application.

        Returns:
            Image URL or None

        Example:
            >>> img_src = product_page.get_product_image_src()
            >>> assert img_src is not None
            >>> assert img_src.startswith("http")
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
        Get product image alt attribute for accessibility testing.

        TEMPLATE METHOD - Accessibility testing utility.

        Returns:
            Alt text or None

        Example:
            >>> alt = product_page.get_product_image_alt()
            >>> assert alt is not None, "Image missing alt text (accessibility issue)"
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
        Extract all product details from the current product page.

        TEMPLATE METHOD - Convenience method for batch data extraction.

        Returns:
            Dict with name, price, description, image_src, add_to_cart_present

        Example:
            >>> details = product_page.get_all_product_details()
            >>> assert details["name"] is not None
            >>> assert details["price"] is not None
            >>> assert details["add_to_cart_present"]
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

    # ========================================================================
    # ADD TO CART METHODS
    # ========================================================================

    def is_add_to_cart_visible(self, timeout: int = 5) -> bool:
        """
        Check if Add to Cart button is visible.

        TEMPLATE METHOD - Adapt to your application.

        Returns:
            True if button is visible

        Example:
            >>> assert product_page.is_add_to_cart_visible()
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
        Click the Add to Cart button.

        TEMPLATE METHOD - Adapt to your application's cart mechanism.

        Returns:
            True if click successful

        Example:
            >>> success = product_page.click_add_to_cart()
            >>> assert success
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
        Add product to cart and handle the alert (if present).

        TEMPLATE METHOD - Adapt to your application's confirmation mechanism.
        Some apps show alert, some show toast, some redirect to cart.

        Returns:
            Tuple of (success, alert_text)

        Example:
            >>> success, alert = product_page.add_to_cart_and_handle_alert()
            >>> assert success
            >>> assert "added" in alert.lower()
        """
        if not self.click_add_to_cart():
            return False, None

        alert_text = self.get_alert_text(timeout=timeout)
        return True, alert_text

    def add_product_to_cart_complete(
        self,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Complete flow: add to cart and return to home.

        TEMPLATE METHOD - Full add-to-cart workflow.

        Returns:
            Tuple of (success, product_name, alert_text)

        Example:
            >>> success, name, alert = product_page.add_product_to_cart_complete()
            >>> assert success
            >>> product_page.open_cart()
            >>> # Verify product in cart
        """
        product_name = self.get_product_name()
        success, alert_text = self.add_to_cart_and_handle_alert()

        if success:
            self.go_home()

        return success, product_name, alert_text

    # ========================================================================
    # CATALOG QUERY METHODS
    # ========================================================================

    def get_all_product_links_on_page(self) -> List[Any]:
        """
        Get all product links currently visible on the catalog page.

        TEMPLATE METHOD - Catalog navigation utility.

        Returns:
            List of WebElement objects

        Example:
            >>> product_page.go_home()
            >>> links = product_page.get_all_product_links_on_page()
            >>> assert len(links) > 0
        """
        try:
            self.driver.get(self.base_url)
            self.wait_for_page_load()
            self.waiter.wait_for_page_load(timeout=3)

            products = self.find_elements(self.PRODUCT_LINKS)
            return products
        except Exception as e:
            logger.error(f"Failed to get product links: {e}")
            return []

    def get_product_count_on_page(self) -> int:
        """
        Count how many products are visible on current catalog page.

        TEMPLATE METHOD - Catalog query utility.

        Returns:
            Number of products

        Example:
            >>> count = product_page.get_product_count_on_page()
            >>> assert count > 0
        """
        products = self.get_all_product_links_on_page()
        return len(products)

    def iterate_all_products(
        self, max_products: Optional[int] = None
    ) -> Generator[Tuple[int, str, Dict[str, Any]], None, None]:
        """
        Generator that yields (index, product_name, details) for each product.

        TEMPLATE METHOD - Useful for validation tests across all products.

        Args:
            max_products: Maximum number of products to check (None = all)

        Yields:
            Tuple of (index, product_name, details_dict)

        Example:
            >>> for idx, name, details in product_page.iterate_all_products(max_products=5):
            ...     assert details["name"] is not None
            ...     assert details["price_value"] > 0
        """
        self.driver.get(self.base_url)
        self.wait_for_page_load()
        self.waiter.wait_for_page_load(timeout=3)

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
            self.waiter.wait_for_page_load(timeout=3)

    # ========================================================================
    # VALIDATION METHODS
    # ========================================================================

    def validate_product_data_completeness(self) -> Tuple[bool, List[str]]:
        """
        Validate that all essential product data is present.

        TEMPLATE METHOD - Data completeness validation.

        Returns:
            Tuple of (is_valid, missing_fields)

        Example:
            >>> is_valid, missing = product_page.validate_product_data_completeness()
            >>> assert is_valid, f"Missing fields: {missing}"
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
        Validate price follows expected format: "$XXX *includes tax".

        TEMPLATE METHOD - Adapt to YOUR application's price format.

        Returns:
            Tuple of (is_valid, actual_price)

        Example:
            >>> is_valid, price = product_page.validate_price_format()
            >>> assert is_valid, f"Invalid price format: {price}"
        """
        price = self.get_product_price()

        if not price:
            return False, None

        # EXAMPLE: "$790 *includes tax"
        # Adapt to YOUR application's format
        pattern = r"^\$\d+\s+\*includes tax$"
        is_valid = bool(re.match(pattern, price))

        return is_valid, price

    def verify_image_loads(
        self, timeout: int = 10
    ) -> Tuple[bool, Optional[int], Optional[str]]:
        """
        Verify product image loads successfully by checking HTTP status.

        TEMPLATE METHOD - HTTP validation utility.

        Returns:
            Tuple of (loads_successfully, status_code, image_url)

        Example:
            >>> loads, code, url = product_page.verify_image_loads()
            >>> assert loads, f"Image failed to load: {url} (status {code})"
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

    # ========================================================================
    # ACCESSIBILITY TESTING METHODS
    # ========================================================================

    def test_keyboard_navigation(self) -> Dict[str, bool]:
        """
        Test keyboard navigation on product page (Tab key).

        TEMPLATE METHOD - Accessibility testing utility.

        Returns:
            Dict with navigation results

        Example:
            >>> results = product_page.test_keyboard_navigation()
            >>> assert results["tab_navigation_works"]
        """
        results = {
            "add_to_cart_focusable": False,
            "home_link_focusable": False,
            "tab_navigation_works": False,
        }

        try:
            actions = ActionChains(self.driver)

            # Tab through elements
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

    # ========================================================================
    # PERFORMANCE MEASUREMENT METHODS
    # ========================================================================

    def measure_page_load_time(self) -> Dict[str, Any]:
        """
        Measure product detail page load time using Navigation Timing API.

        TEMPLATE METHOD - Performance testing utility.

        Returns:
            Dict with timing metrics (in seconds)

        Example:
            >>> timing = product_page.measure_page_load_time()
            >>> assert timing["total_load_time"] < 3.0
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
        Extract product ID from current URL.

        TEMPLATE METHOD - Adapt to YOUR application's URL structure.

        Returns:
            Product ID or None

        Example:
            >>> product_id = product_page.get_current_product_id_from_url()
            >>> assert product_id is not None
        """
        current_url = self.driver.current_url
        # EXAMPLE: Extract from "?id=123" or "/product/123"
        # Adapt to YOUR application's URL pattern
        match = re.search(r"id=([^&]+)", current_url)
        if match:
            return match.group(1)
        # Try path-based pattern
        match = re.search(r"/product/([^/?]+)", current_url)
        if match:
            return match.group(1)
        return None

    # ========================================================================
    # SECURITY TESTING METHODS
    # ========================================================================

    def check_for_sql_error_indicators(self) -> Tuple[bool, List[str]]:
        """
        Check page source for SQL error disclosure.

        TEMPLATE METHOD - Security testing utility.

        Returns:
            Tuple of (has_error, error_indicators_found)

        Example:
            >>> # Test SQL injection
            >>> product_page.navigate_to_product_by_url("' OR '1'='1")
            >>> has_error, indicators = product_page.check_for_sql_error_indicators()
            >>> assert not has_error, f"SQL errors exposed: {indicators}"
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
        Check if XSS payload is reflected unescaped or executed.

        TEMPLATE METHOD - Security testing utility.

        Args:
            payload: XSS payload string

        Returns:
            Tuple of (is_vulnerable, evidence)

        Example:
            >>> # This would typically be tested via URL params or form inputs
            >>> is_vuln, evidence = product_page.check_for_xss_execution("<script>alert('XSS')</script>")
            >>> assert not is_vuln, f"XSS vulnerability: {evidence}"
        """
        page_source = self.driver.page_source

        # Check if payload is reflected unescaped
        if payload in page_source:
            return True, f"Payload reflected unescaped: {payload}"

        # Check if alert was executed
        try:
            alert = self.driver.switch_to.alert
            alert_text = alert.text
            alert.accept()
            return True, f"Alert executed: {alert_text}"
        except Exception:
            pass

        return False, None

    def check_security_headers(self) -> Dict[str, str]:
        """
        Check for security headers in HTTP response.

        TEMPLATE METHOD - Note: Requires network log access or proxy.

        Returns:
            Dict with note about implementation

        Note:
            Security header checking requires network log access via
            Chrome DevTools Protocol or a proxy like mitmproxy.
        """
        return {
            "note": "Security header checking requires network log access",
            "recommendation": "Use browser DevTools Protocol or proxy like mitmproxy",
        }

    def check_for_information_disclosure(self) -> Tuple[bool, List[str]]:
        """
        Check page source for information disclosure (comments, debug info, etc.).

        TEMPLATE METHOD - Security testing utility.

        Returns:
            Tuple of (has_disclosure, findings)

        Example:
            >>> has_disclosure, findings = product_page.check_for_information_disclosure()
            >>> assert not has_disclosure, f"Information disclosure: {findings}"
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


# ============================================================================
# USAGE EXAMPLE - How to adapt this template to your application
# ============================================================================
"""
EXAMPLE ADAPTATION:

1. Update locators to match your application:
   PRODUCT_NAME = (By.CSS_SELECTOR, "your-product-name-selector")
   PRODUCT_PRICE = (By.CSS_SELECTOR, "your-price-selector")
   # ... etc

2. If your app has product variants (size, color, etc.):
   SIZE_DROPDOWN = (By.ID, "size-select")
   COLOR_DROPDOWN = (By.ID, "color-select")

   def select_variant(self, size: str, color: str):
       from selenium.webdriver.support.select import Select
       size_select = Select(self.find_element(self.SIZE_DROPDOWN))
       size_select.select_by_visible_text(size)
       color_select = Select(self.find_element(self.COLOR_DROPDOWN))
       color_select.select_by_visible_text(color)

3. If your app has product reviews:
   REVIEW_SECTION = (By.ID, "reviews")
   REVIEW_STARS = (By.CSS_SELECTOR, ".review-stars")

   def get_average_rating(self) -> Optional[float]:
       reviews = self.find_elements(self.REVIEW_STARS)
       # Parse and calculate average

4. If your app has related products:
   RELATED_PRODUCTS = (By.CSS_SELECTOR, ".related-product")

   def get_related_products(self) -> List[str]:
       related = self.find_elements(self.RELATED_PRODUCTS)
       return [r.text for r in related]

5. If your app has image gallery:
   IMAGE_THUMBNAILS = (By.CSS_SELECTOR, ".thumbnail")

   def click_thumbnail(self, index: int):
       thumbnails = self.find_elements(self.IMAGE_THUMBNAILS)
       if index < len(thumbnails):
           thumbnails[index].click()

6. Use discovery-based element finding:
   from framework.core import ElementFinder

   def get_product_name(self):
       name_element = self.finder.find_by_tag("h1", within=".product-details")
       if name_element:
           return name_element.text
"""
