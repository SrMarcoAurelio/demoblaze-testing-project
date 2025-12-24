"""
Catalog Page Object Model - TEMPLATE
Author: Marc Arevalo
Version: 6.0

IMPORTANT: This is a TEMPLATE/EXAMPLE for product catalog/listing page object.
The locators shown here are EXAMPLES and MUST be adapted to YOUR application's
actual element IDs, classes, and structure.

This template demonstrates:
- Product catalog browsing
- Category navigation and filtering
- Product listing and pagination
- Product data validation
- Accessibility testing patterns
- Performance measurement

ADAPTATION REQUIRED:
1. Update ALL locators to match your application's elements
2. Modify methods if your catalog structure differs
3. Consider loading locators from config/locators.json
4. Test thoroughly with YOUR application

For applications with different catalog patterns (search-based, filter dropdowns,
infinite scroll, grid/list view, etc.), use this as inspiration but create
appropriate implementations.
"""

import logging
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.remote.webelement import WebElement

from .base_page import BasePage

logger = logging.getLogger(__name__)


class CatalogPage(BasePage):
    """
    TEMPLATE Page Object for Product Catalog/Listing Pages.

    This template demonstrates a catalog with categories, products, and pagination.
    Adapt all locators and logic to match YOUR application.

    Handles:
    - Category navigation (Phones, Laptops, Monitors, etc.)
    - Product listing and information retrieval
    - Pagination (next, previous, boundary conditions)
    - Product validation (completeness, format, broken links)
    - Accessibility testing (keyboard navigation, ARIA, focus indicators)
    - Performance measurement (load time, category switch time)

    IMPORTANT: All locators below are EXAMPLES and must be replaced
    with your application's actual element locators.
    """

    # ========================================================================
    # NAVIGATION LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    HOME_LINK = (By.ID, "home-link")  # EXAMPLE - adapt to your app
    LOGO_LINK = (By.CSS_SELECTOR, ".navbar-brand")  # EXAMPLE

    # ========================================================================
    # CATEGORY LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    # If your app has category navigation:
    CATEGORIES_SECTION = (By.ID, "categories")  # EXAMPLE
    PHONES_CATEGORY = (By.LINK_TEXT, "Phones")  # EXAMPLE
    LAPTOPS_CATEGORY = (By.LINK_TEXT, "Laptops")  # EXAMPLE
    MONITORS_CATEGORY = (By.LINK_TEXT, "Monitors")  # EXAMPLE

    # Your app may use different category patterns:
    # CATEGORY_DROPDOWN = (By.ID, "category-select")
    # FILTER_CHECKBOXES = (By.CSS_SELECTOR, ".filter-checkbox")

    # ========================================================================
    # PRODUCT LISTING LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    PRODUCT_CARDS = (By.CSS_SELECTOR, ".product-card")  # EXAMPLE
    PRODUCT_TITLES = (By.CSS_SELECTOR, ".product-title a")  # EXAMPLE
    PRODUCT_PRICES = (By.CSS_SELECTOR, ".product-price")  # EXAMPLE
    PRODUCT_IMAGES = (By.CSS_SELECTOR, ".product-image")  # EXAMPLE
    PRODUCT_LINKS = (By.CSS_SELECTOR, ".product-link")  # EXAMPLE
    PRODUCT_DESCRIPTIONS = (By.CSS_SELECTOR, ".product-description")  # EXAMPLE

    # ========================================================================
    # PAGINATION LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    NEXT_BUTTON = (By.ID, "next-page")  # EXAMPLE
    PREV_BUTTON = (By.ID, "prev-page")  # EXAMPLE

    # ========================================================================
    # PRODUCT DETAIL LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    PRODUCT_DETAIL_NAME = (By.CSS_SELECTOR, "h2.product-name")  # EXAMPLE

    # ========================================================================
    # CATALOG NAVIGATION METHODS - Adapt to your application's workflow
    # ========================================================================

    def go_to_catalog(self) -> None:
        """
        Navigate to catalog/home page.

        TEMPLATE METHOD - Adapt to your application's catalog URL.

        Example:
            >>> catalog_page.go_to_catalog()
            >>> assert catalog_page.are_products_displayed()
        """
        self.driver.get(self.base_url)
        self.wait_for_page_load()
        self.waiter.wait_for_page_load(timeout=3)

    def click_home(self) -> None:
        """
        Click Home link to show all products.

        TEMPLATE METHOD - Adapt to your application.

        Example:
            >>> catalog_page.click_home()
            >>> assert catalog_page.get_product_count() > 0
        """
        home_link = self.wait_for_element_clickable(self.HOME_LINK, timeout=10)
        home_link.click()
        self.wait_for_page_load()
        self.waiter.wait_for_page_load(timeout=3)

    def click_logo(self) -> None:
        """
        Click logo to return to home.

        TEMPLATE METHOD - Adapt to your application.
        """
        logo = self.wait_for_element_clickable(self.LOGO_LINK, timeout=10)
        logo.click()
        self.wait_for_page_load()
        self.waiter.wait_for_page_load(timeout=3)

    # ========================================================================
    # CATEGORY NAVIGATION METHODS - Adapt to your application
    # ========================================================================

    def click_phones_category(self) -> bool:
        """
        Click Phones category link.

        TEMPLATE METHOD - Adapt to your application's categories.
        Your app may have different categories (Electronics, Clothing, Books, etc.).

        Returns:
            True if category clicked successfully

        Example:
            >>> catalog_page.click_phones_category()
            >>> products = catalog_page.get_all_product_names()
            >>> # Verify products are from Phones category
        """
        phones = self.wait_for_element_clickable(
            self.PHONES_CATEGORY, timeout=10
        )
        phones.click()
        self.waiter.wait_for_page_load(timeout=5)  # Wait for products to load
        return True

    def click_laptops_category(self) -> bool:
        """
        Click Laptops category link.

        TEMPLATE METHOD - Adapt to your application's categories.

        Returns:
            True if category clicked successfully
        """
        laptops = self.wait_for_element_clickable(
            self.LAPTOPS_CATEGORY, timeout=10
        )
        laptops.click()
        self.waiter.wait_for_page_load(timeout=5)
        return True

    def click_monitors_category(self) -> bool:
        """
        Click Monitors category link.

        TEMPLATE METHOD - Adapt to your application's categories.

        Returns:
            True if category clicked successfully
        """
        monitors = self.wait_for_element_clickable(
            self.MONITORS_CATEGORY, timeout=10
        )
        monitors.click()
        self.waiter.wait_for_page_load(timeout=5)
        return True

    def get_active_category(self) -> Optional[str]:
        """
        Get the currently active category.

        TEMPLATE METHOD - Adapt to your application's category indicator.
        This might be from URL, active CSS class, breadcrumb, etc.

        Returns:
            Category name or None

        Example:
            >>> catalog_page.click_phones_category()
            >>> assert catalog_page.get_active_category() == "phones"
        """
        try:
            current_url = self.driver.current_url
            # EXAMPLE: Parse from URL query parameter
            # Adapt to YOUR application's URL structure
            if "category=" in current_url:
                return current_url.split("category=")[1].split("&")[0]
            return "all"
        except Exception as e:
            logger.error(f"Failed to get active category: {e}")
            return None

    def is_category_active(self, category_name: str) -> bool:
        """
        Check if a category link has active state styling.

        TEMPLATE METHOD - Adapt to your application's active state indicator.

        Args:
            category_name: "Phones", "Laptops", "Monitors", etc.

        Returns:
            True if category is active

        Example:
            >>> catalog_page.click_phones_category()
            >>> assert catalog_page.is_category_active("Phones")
        """
        try:
            if category_name == "Phones":
                locator = self.PHONES_CATEGORY
            elif category_name == "Laptops":
                locator = self.LAPTOPS_CATEGORY
            elif category_name == "Monitors":
                locator = self.MONITORS_CATEGORY
            else:
                return False

            element = self.find_element(locator)
            classes = element.get_attribute("class") or ""

            # EXAMPLE: Check for "active" or "selected" class
            # Adapt to YOUR application's active state CSS
            return "active" in classes or "selected" in classes

        except NoSuchElementException:
            return False

    # ========================================================================
    # PRODUCT LISTING METHODS
    # ========================================================================

    def get_all_product_cards(self, timeout: int = 10) -> List[WebElement]:
        """
        Get all product cards currently displayed.

        TEMPLATE METHOD - Adapt to your application's product card structure.

        Args:
            timeout: Maximum time to wait for products

        Returns:
            List of WebElement objects

        Example:
            >>> cards = catalog_page.get_all_product_cards()
            >>> assert len(cards) > 0
        """
        try:
            self.wait_for_element_visible(self.PRODUCT_CARDS, timeout=timeout)
            cards = self.find_elements(self.PRODUCT_CARDS)
            return cards
        except TimeoutException:
            logger.warning("No product cards found")
            return []

    def get_product_count(self, timeout: int = 10) -> int:
        """
        Count how many products are currently displayed.

        TEMPLATE METHOD - Convenience wrapper for get_all_product_cards.

        Returns:
            Number of products

        Example:
            >>> count = catalog_page.get_product_count()
            >>> assert count > 0
        """
        cards = self.get_all_product_cards(timeout=timeout)
        return len(cards)

    def get_all_product_names(self, timeout: int = 10) -> List[str]:
        """
        Get all product names from current page.

        TEMPLATE METHOD - Adapt to your application's product name display.

        Returns:
            List of product names

        Example:
            >>> names = catalog_page.get_all_product_names()
            >>> assert "Samsung Galaxy S6" in names
        """
        try:
            self.wait_for_element_visible(self.PRODUCT_TITLES, timeout=timeout)
            titles = self.find_elements(self.PRODUCT_TITLES)
            return [title.text for title in titles if title.text]
        except TimeoutException:
            return []

    def get_all_product_prices(self, timeout: int = 10) -> List[str]:
        """
        Get all product prices from current page.

        TEMPLATE METHOD - Adapt to your application's price display.

        Returns:
            List of price strings

        Example:
            >>> prices = catalog_page.get_all_product_prices()
            >>> assert len(prices) > 0
        """
        try:
            self.wait_for_element_visible(self.PRODUCT_PRICES, timeout=timeout)
            prices = self.find_elements(self.PRODUCT_PRICES)
            return [price.text for price in prices if price.text]
        except TimeoutException:
            return []

    def get_all_product_images(self, timeout: int = 10) -> List[WebElement]:
        """
        Get all product image elements.

        TEMPLATE METHOD - Adapt to your application.

        Returns:
            List of image WebElement objects
        """
        try:
            self.wait_for_element_visible(self.PRODUCT_IMAGES, timeout=timeout)
            images = self.find_elements(self.PRODUCT_IMAGES)
            return images
        except TimeoutException:
            return []

    def get_all_product_links(self, timeout: int = 10) -> List[WebElement]:
        """
        Get all product clickable links.

        TEMPLATE METHOD - Adapt to your application.

        Returns:
            List of link WebElement objects
        """
        try:
            self.wait_for_element_visible(self.PRODUCT_LINKS, timeout=timeout)
            links = self.find_elements(self.PRODUCT_LINKS)
            return links
        except TimeoutException:
            return []

    def are_products_displayed(self, timeout: int = 10) -> bool:
        """
        Check if any products are visible on page.

        TEMPLATE METHOD - Convenience wrapper.

        Returns:
            True if products are displayed

        Example:
            >>> catalog_page.go_to_catalog()
            >>> assert catalog_page.are_products_displayed()
        """
        return self.get_product_count(timeout=timeout) > 0

    # ========================================================================
    # PRODUCT INTERACTION METHODS
    # ========================================================================

    def click_first_product(self) -> Tuple[bool, Optional[str]]:
        """
        Click on the first product link.

        TEMPLATE METHOD - Adapt to your application's navigation.

        Returns:
            Tuple of (success, product_name)

        Example:
            >>> success, name = catalog_page.click_first_product()
            >>> assert success
            >>> assert product_page.get_product_name() == name
        """
        try:
            links = self.get_all_product_links(timeout=10)
            if not links:
                return False, None

            first_link = links[0]
            product_name = first_link.text
            first_link.click()

            self.wait_for_page_load()
            self.waiter.wait_for_page_load(timeout=5)

            return True, product_name
        except Exception as e:
            logger.error(f"Failed to click first product: {e}")
            return False, None

    def click_product_by_index(self, index: int) -> Tuple[bool, Optional[str]]:
        """
        Click on a product by its index (0-based).

        TEMPLATE METHOD - Adapt to your application.

        Args:
            index: Product index (0 = first product)

        Returns:
            Tuple of (success, product_name)

        Example:
            >>> success, name = catalog_page.click_product_by_index(2)
            >>> assert success
        """
        try:
            links = self.get_all_product_links(timeout=10)
            if index >= len(links):
                return False, None

            target_link = links[index]
            product_name = target_link.text
            target_link.click()

            self.wait_for_page_load()
            self.waiter.wait_for_page_load(timeout=5)

            return True, product_name
        except Exception as e:
            logger.error(f"Failed to click product {index}: {e}")
            return False, None

    def is_on_product_detail_page(self, timeout: int = 5) -> bool:
        """
        Check if currently on a product detail page.

        TEMPLATE METHOD - Adapt to your application's URL structure.

        Returns:
            True if on product detail page

        Example:
            >>> catalog_page.click_first_product()
            >>> assert catalog_page.is_on_product_detail_page()
        """
        try:
            self.wait_for_element_visible(
                self.PRODUCT_DETAIL_NAME, timeout=timeout
            )
            # EXAMPLE: Check URL for product identifier
            # Adapt to YOUR application's URL structure
            current_url = self.driver.current_url
            return "product" in current_url or "item" in current_url
        except TimeoutException:
            return False

    # ========================================================================
    # PAGINATION METHODS - Adapt to your application
    # ========================================================================

    def is_next_button_visible(self, timeout: int = 5) -> bool:
        """
        Check if Next button is visible.

        TEMPLATE METHOD - Adapt to your application's pagination.

        Returns:
            True if Next button is visible
        """
        try:
            self.wait_for_element_visible(self.NEXT_BUTTON, timeout=timeout)
            return True
        except TimeoutException:
            return False

    def is_prev_button_visible(self, timeout: int = 5) -> bool:
        """
        Check if Previous button is visible.

        TEMPLATE METHOD - Adapt to your application's pagination.

        Returns:
            True if Previous button is visible
        """
        try:
            self.wait_for_element_visible(self.PREV_BUTTON, timeout=timeout)
            return True
        except TimeoutException:
            return False

    def is_next_button_enabled(self) -> bool:
        """
        Check if Next button is enabled (not disabled).

        TEMPLATE METHOD - Adapt to your application.

        Returns:
            True if Next button is enabled
        """
        try:
            button = self.find_element(self.NEXT_BUTTON)
            return button.is_displayed() and button.is_enabled()
        except NoSuchElementException:
            return False

    def is_prev_button_enabled(self) -> bool:
        """
        Check if Previous button is enabled.

        TEMPLATE METHOD - Adapt to your application.

        Returns:
            True if Previous button is enabled
        """
        try:
            button = self.find_element(self.PREV_BUTTON)
            return button.is_displayed() and button.is_enabled()
        except NoSuchElementException:
            return False

    def click_next_page(self) -> bool:
        """
        Click Next pagination button.

        TEMPLATE METHOD - Adapt to your application's pagination.

        Returns:
            True if pagination successful

        Example:
            >>> initial_products = catalog_page.get_all_product_names()
            >>> catalog_page.click_next_page()
            >>> next_products = catalog_page.get_all_product_names()
            >>> assert initial_products != next_products
        """
        try:
            next_btn = self.wait_for_element_clickable(
                self.NEXT_BUTTON, timeout=10
            )
            next_btn.click()
            self.waiter.wait_for_page_load(
                timeout=5
            )  # Wait for new products to load
            return True
        except TimeoutException:
            logger.warning("Next button not clickable")
            return False

    def click_prev_page(self) -> bool:
        """
        Click Previous pagination button.

        TEMPLATE METHOD - Adapt to your application's pagination.

        Returns:
            True if pagination successful
        """
        try:
            prev_btn = self.wait_for_element_clickable(
                self.PREV_BUTTON, timeout=10
            )
            prev_btn.click()
            self.waiter.wait_for_page_load(timeout=5)
            return True
        except TimeoutException:
            logger.warning("Previous button not clickable")
            return False

    # ========================================================================
    # PRODUCT VALIDATION METHODS
    # ========================================================================

    def validate_all_products_have_names(self) -> Tuple[bool, int]:
        """
        Validate that all displayed products have names.

        TEMPLATE METHOD - Product completeness validation.

        Returns:
            Tuple of (all_have_names, missing_count)

        Example:
            >>> all_valid, missing = catalog_page.validate_all_products_have_names()
            >>> assert all_valid, f"{missing} products missing names"
        """
        names = self.get_all_product_names()
        cards = self.get_all_product_cards()

        missing = len(cards) - len(names)
        all_have_names = missing == 0

        return all_have_names, missing

    def validate_all_products_have_prices(self) -> Tuple[bool, int]:
        """
        Validate that all displayed products have prices.

        TEMPLATE METHOD - Product completeness validation.

        Returns:
            Tuple of (all_have_prices, missing_count)
        """
        prices = self.get_all_product_prices()
        cards = self.get_all_product_cards()

        missing = len(cards) - len(prices)
        all_have_prices = missing == 0

        return all_have_prices, missing

    def validate_price_format(self, price_text: str) -> bool:
        """
        Validate price follows expected format: "$XXX" or "$XXX.XX".

        TEMPLATE METHOD - Adapt to your application's price format.

        Args:
            price_text: Price text to validate

        Returns:
            True if price format is valid

        Example:
            >>> prices = catalog_page.get_all_product_prices()
            >>> for price in prices:
            >>>     assert catalog_page.validate_price_format(price)
        """
        if not price_text:
            return False

        # EXAMPLE: US dollar format
        # Adapt to YOUR application's currency format (€, £, ¥, etc.)
        pattern = r"^\$\d+(\.\d{2})?$"
        return bool(re.match(pattern, price_text))

    def validate_all_prices_format(self) -> Tuple[bool, List[str]]:
        """
        Validate all prices follow correct format.

        TEMPLATE METHOD - Batch price validation.

        Returns:
            Tuple of (all_valid, invalid_prices)

        Example:
            >>> all_valid, invalid = catalog_page.validate_all_prices_format()
            >>> assert all_valid, f"Invalid prices: {invalid}"
        """
        prices = self.get_all_product_prices()
        invalid = []

        for price in prices:
            if not self.validate_price_format(price):
                invalid.append(price)

        all_valid = len(invalid) == 0
        return all_valid, invalid

    def validate_image_loads(
        self, image_url: str
    ) -> Tuple[bool, Optional[int]]:
        """
        Validate image URL loads successfully.

        TEMPLATE METHOD - HTTP validation utility.

        Args:
            image_url: Image URL to check

        Returns:
            Tuple of (loads, status_code)

        Example:
            >>> images = catalog_page.get_all_product_images()
            >>> for img in images:
            >>>     src = img.get_attribute("src")
            >>>     loads, code = catalog_page.validate_image_loads(src)
            >>>     assert loads, f"Image failed: {src}"
        """
        try:
            response = requests.head(image_url, timeout=5)
            status_code = response.status_code
            loads = status_code == 200
            return loads, status_code
        except requests.RequestException as e:
            logger.error(f"Image validation failed: {e}")
            return False, None

    def validate_all_images_load(
        self,
    ) -> Tuple[bool, List[Tuple[str, Optional[int]]]]:
        """
        Validate all product images load successfully.

        TEMPLATE METHOD - Batch image validation.

        Returns:
            Tuple of (all_load, failed_images)

        Example:
            >>> all_valid, failed = catalog_page.validate_all_images_load()
            >>> assert all_valid, f"{len(failed)} images failed to load"
        """
        images = self.get_all_product_images()
        failed = []

        for img in images:
            img_src = img.get_attribute("src")
            if img_src:
                loads, status = self.validate_image_loads(img_src)
                if not loads:
                    failed.append((img_src, status))

        all_load = len(failed) == 0
        return all_load, failed

    def validate_product_link_not_broken(
        self, link_url: str
    ) -> Tuple[bool, Optional[int]]:
        """
        Validate product link is not broken (returns 200).

        TEMPLATE METHOD - HTTP validation utility.

        Args:
            link_url: Product link URL

        Returns:
            Tuple of (is_valid, status_code)
        """
        try:
            response = requests.get(link_url, timeout=5)
            status_code = response.status_code
            is_valid = status_code == 200
            return is_valid, status_code
        except requests.RequestException as e:
            logger.error(f"Link validation failed: {e}")
            return False, None

    # ========================================================================
    # PERFORMANCE MEASUREMENT METHODS
    # ========================================================================

    def measure_catalog_load_time(self) -> Dict[str, Any]:
        """
        Measure catalog page load time using Navigation Timing API.

        TEMPLATE METHOD - Performance testing utility.

        Returns:
            Dict with timing metrics (in seconds)

        Example:
            >>> timing = catalog_page.measure_catalog_load_time()
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

    def measure_category_switch_time(
        self, category_method: Callable[[], bool]
    ) -> float:
        """
        Measure time to switch categories.

        TEMPLATE METHOD - Performance testing utility.

        Args:
            category_method: Method to call (e.g., self.click_phones_category)

        Returns:
            Time in seconds

        Example:
            >>> time_taken = catalog_page.measure_category_switch_time(
            ...     catalog_page.click_phones_category
            ... )
            >>> assert time_taken < 2.0
        """
        start_time = time.time()
        category_method()
        end_time = time.time()

        return end_time - start_time

    # ========================================================================
    # ACCESSIBILITY TESTING METHODS
    # ========================================================================

    def test_keyboard_navigation_categories(self) -> Dict[str, bool]:
        """
        Test keyboard navigation through category links.

        TEMPLATE METHOD - Accessibility testing utility.
        Adapt to YOUR application's keyboard navigation.

        Returns:
            Dict with navigation results

        Example:
            >>> results = catalog_page.test_keyboard_navigation_categories()
            >>> assert results["tab_navigation_works"]
        """
        results = {
            "phones_focusable": False,
            "laptops_focusable": False,
            "monitors_focusable": False,
            "tab_navigation_works": False,
        }

        try:
            categories = self.find_element(self.CATEGORIES_SECTION)
            categories.click()

            actions = ActionChains(self.driver)

            # Tab through elements
            for _ in range(10):
                actions.send_keys(Keys.TAB).perform()
                time.sleep(0.2)

                active_element = self.driver.switch_to.active_element
                text = active_element.text

                if "Phones" in text:
                    results["phones_focusable"] = True
                if "Laptops" in text:
                    results["laptops_focusable"] = True
                if "Monitors" in text:
                    results["monitors_focusable"] = True

            results["tab_navigation_works"] = any(
                [
                    results["phones_focusable"],
                    results["laptops_focusable"],
                    results["monitors_focusable"],
                ]
            )

        except Exception as e:
            logger.error(f"Keyboard navigation test failed: {e}")

        return results

    def check_category_aria_labels(self) -> Dict[str, bool]:
        """
        Check if category links have ARIA labels.

        TEMPLATE METHOD - Accessibility testing utility.

        Returns:
            Dict with ARIA label presence

        Example:
            >>> results = catalog_page.check_category_aria_labels()
            >>> assert all(results.values()), "Some categories missing ARIA labels"
        """
        results = {
            "phones_has_aria": False,
            "laptops_has_aria": False,
            "monitors_has_aria": False,
        }

        try:
            phones = self.find_element(self.PHONES_CATEGORY)
            laptops = self.find_element(self.LAPTOPS_CATEGORY)
            monitors = self.find_element(self.MONITORS_CATEGORY)

            results["phones_has_aria"] = bool(
                phones.get_attribute("aria-label")
            )
            results["laptops_has_aria"] = bool(
                laptops.get_attribute("aria-label")
            )
            results["monitors_has_aria"] = bool(
                monitors.get_attribute("aria-label")
            )

        except NoSuchElementException as e:
            logger.error(f"Category not found: {e}")

        return results

    def check_focus_indicators(self) -> Dict[str, bool]:
        """
        Check if focus indicators are visible on interactive elements.

        TEMPLATE METHOD - Accessibility testing utility.

        Returns:
            Dict with focus indicator status

        Example:
            >>> results = catalog_page.check_focus_indicators()
            >>> assert results["categories_have_focus"]
        """
        results = {
            "categories_have_focus": False,
            "products_have_focus": False,
        }

        try:
            phones = self.find_element(self.PHONES_CATEGORY)
            phones.click()

            has_outline = self.driver.execute_script(
                """
                var element = arguments[0];
                var styles = window.getComputedStyle(element, ':focus');
                return styles.outlineWidth !== '0px' && styles.outlineStyle !== 'none';
            """,
                phones,
            )

            results["categories_have_focus"] = has_outline

            links = self.get_all_product_links()
            if links:
                first_link = links[0]
                has_product_outline = self.driver.execute_script(
                    """
                    var element = arguments[0];
                    element.focus();
                    var styles = window.getComputedStyle(element, ':focus');
                    return styles.outlineWidth !== '0px' && styles.outlineStyle !== 'none';
                """,
                    first_link,
                )

                results["products_have_focus"] = has_product_outline

        except Exception as e:
            logger.error(f"Focus indicator check failed: {e}")

        return results

    def get_product_image_alt_texts(
        self,
    ) -> List[Tuple[Optional[str], Optional[str]]]:
        """
        Get alt text for all product images.

        TEMPLATE METHOD - Accessibility testing utility.

        Returns:
            List of (image_src, alt_text) tuples

        Example:
            >>> alt_data = catalog_page.get_product_image_alt_texts()
            >>> for src, alt in alt_data:
            >>>     assert alt, f"Image missing alt text: {src}"
        """
        images = self.get_all_product_images()
        alt_data = []

        for img in images:
            src = img.get_attribute("src")
            alt = img.get_attribute("alt")
            alt_data.append((src, alt))

        return alt_data

    def validate_all_images_have_alt_text(self) -> Tuple[bool, int]:
        """
        Validate all product images have alt text.

        TEMPLATE METHOD - Accessibility validation.

        Returns:
            Tuple of (all_have_alt, missing_count)

        Example:
            >>> all_valid, missing = catalog_page.validate_all_images_have_alt_text()
            >>> assert all_valid, f"{missing} images missing alt text"
        """
        alt_data = self.get_product_image_alt_texts()

        missing = 0
        for src, alt in alt_data:
            if not alt or alt.strip() == "":
                missing += 1

        all_have_alt = missing == 0
        return all_have_alt, missing

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
            >>> has_errors, indicators = catalog_page.check_for_sql_error_indicators()
            >>> assert not has_errors, f"SQL errors exposed: {indicators}"
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
        ]

        found_indicators = []
        for pattern in sql_error_patterns:
            if pattern in page_source:
                found_indicators.append(pattern)

        has_error = len(found_indicators) > 0
        return has_error, found_indicators

    def check_for_directory_listing(self) -> Tuple[bool, List[str]]:
        """
        Check for directory listing exposure.

        TEMPLATE METHOD - Security testing utility.

        Returns:
            Tuple of (has_listing, indicators_found)
        """
        page_source = self.driver.page_source.lower()

        listing_indicators = [
            "index of /",
            "parent directory",
            "directory listing",
            "last modified",
            "apache server at",
        ]

        found = []
        for indicator in listing_indicators:
            if indicator in page_source:
                found.append(indicator)

        has_listing = len(found) > 0
        return has_listing, found

    def check_for_verbose_errors(self) -> Tuple[bool, List[str]]:
        """
        Check for verbose error messages in page source.

        TEMPLATE METHOD - Security testing utility.

        Returns:
            Tuple of (has_verbose_errors, errors_found)
        """
        page_source = self.driver.page_source.lower()

        error_patterns = [
            "stack trace",
            "exception",
            "fatal error",
            "warning:",
            "notice:",
            "deprecated:",
            "parse error",
        ]

        found = []
        for pattern in error_patterns:
            if pattern in page_source:
                found.append(pattern)

        has_errors = len(found) > 0
        return has_errors, found


# ============================================================================
# USAGE EXAMPLE - How to adapt this template to your application
# ============================================================================
"""
EXAMPLE ADAPTATION:

1. Update locators to match your application:
   PRODUCT_CARDS = (By.CSS_SELECTOR, "your-product-card-selector")
   PRODUCT_TITLES = (By.CSS_SELECTOR, "your-title-selector")
   # ... etc

2. If your app uses dropdown filters instead of category links:
   CATEGORY_DROPDOWN = (By.ID, "category-select")

   def select_category(self, category_name: str):
       from selenium.webdriver.support.select import Select
       dropdown = Select(self.find_element(self.CATEGORY_DROPDOWN))
       dropdown.select_by_visible_text(category_name)

3. If your app has infinite scroll instead of pagination:
   def scroll_to_load_more(self, times: int = 3):
       for i in range(times):
           self.driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
           time.sleep(2)  # Wait for products to load

4. If your app has search functionality:
   SEARCH_INPUT = (By.ID, "search")
   SEARCH_BUTTON = (By.ID, "search-btn")

   def search_products(self, query: str):
       self.type(self.SEARCH_INPUT, query)
       self.click(self.SEARCH_BUTTON)
       self.wait_for_page_load()

5. If your app has grid/list view toggle:
   GRID_VIEW_BUTTON = (By.ID, "grid-view")
   LIST_VIEW_BUTTON = (By.ID, "list-view")

   def switch_to_grid_view(self):
       self.click(self.GRID_VIEW_BUTTON)

   def switch_to_list_view(self):
       self.click(self.LIST_VIEW_BUTTON)

6. Use discovery-based element finding:
   from framework.core import ElementFinder

   def click_category(self, category_name: str):
       category_link = self.finder.find_by_text(category_name, tag="a")
       if category_link:
           self.interactor.click(category_link)
"""
