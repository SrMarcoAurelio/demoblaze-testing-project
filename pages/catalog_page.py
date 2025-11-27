"""
CatalogPage - Page Object Model for Catalog/Home Page
Author: Marc Arévalo
Version: 1.0

This module provides a centralized interface for interacting with the catalog/home page.
Includes category navigation, product browsing, pagination, and accessibility features.
"""

import time
import logging
import re
import requests
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.action_chains import ActionChains
from pages.base_page import BasePage

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CatalogPage(BasePage):
    """
    Page Object Model for DemoBlaze Catalog/Home Page

    Provides methods for:
    - Category navigation (Phones, Laptops, Monitors, Home)
    - Product listing and information retrieval
    - Pagination (next, previous, boundary conditions)
    - Product validation (completeness, format, broken links)
    - Accessibility testing (keyboard navigation, ARIA, focus indicators)
    - Performance measurement (load time, category switch time)
    """

    # ============================================================================
    # LOCATORS
    # ============================================================================

    # Navigation
    HOME_LINK = (By.ID, "nava")
    LOGO_LINK = (By.CSS_SELECTOR, ".navbar-brand")

    # Categories
    CATEGORIES_SECTION = (By.ID, "cat")
    PHONES_CATEGORY = (By.LINK_TEXT, "Phones")
    LAPTOPS_CATEGORY = (By.LINK_TEXT, "Laptops")
    MONITORS_CATEGORY = (By.LINK_TEXT, "Monitors")

    # Products
    PRODUCT_CARDS = (By.CSS_SELECTOR, ".card")
    PRODUCT_TITLES = (By.CSS_SELECTOR, ".card-title a")
    PRODUCT_PRICES = (By.CSS_SELECTOR, ".card-block h5")
    PRODUCT_IMAGES = (By.CSS_SELECTOR, ".card-img-top")
    PRODUCT_LINKS = (By.CSS_SELECTOR, ".hrefch")
    PRODUCT_DESCRIPTIONS = (By.CSS_SELECTOR, ".card-block p")

    # Pagination
    NEXT_BUTTON = (By.ID, "next2")
    PREV_BUTTON = (By.ID, "prev2")

    # Product Details Page (for navigation verification)
    PRODUCT_DETAIL_NAME = (By.CSS_SELECTOR, "h2.name")

    # ============================================================================
    # NAVIGATION METHODS
    # ============================================================================

    def go_to_catalog(self):
        """Navigate to catalog/home page"""
        self.driver.get(self.base_url)
        self.wait_for_page_load()
        time.sleep(1)

    def click_home(self):
        """Click Home link to show all products"""
        home_link = self.wait_for_element_clickable(self.HOME_LINK, timeout=10)
        home_link.click()
        self.wait_for_page_load()
        time.sleep(1)

    def click_logo(self):
        """Click logo to return to home"""
        logo = self.wait_for_element_clickable(self.LOGO_LINK, timeout=10)
        logo.click()
        self.wait_for_page_load()
        time.sleep(1)

    # ============================================================================
    # CATEGORY NAVIGATION METHODS
    # ============================================================================

    def click_phones_category(self):
        """Click Phones category link"""
        phones = self.wait_for_element_clickable(self.PHONES_CATEGORY, timeout=10)
        phones.click()
        time.sleep(2)  # Wait for products to load
        return True

    def click_laptops_category(self):
        """Click Laptops category link"""
        laptops = self.wait_for_element_clickable(self.LAPTOPS_CATEGORY, timeout=10)
        laptops.click()
        time.sleep(2)
        return True

    def click_monitors_category(self):
        """Click Monitors category link"""
        monitors = self.wait_for_element_clickable(self.MONITORS_CATEGORY, timeout=10)
        monitors.click()
        time.sleep(2)
        return True

    def get_active_category(self):
        """
        Get the currently active category
        Returns: str or None
        """
        try:
            # Check URL for category parameter
            current_url = self.driver.current_url
            if "cat=" in current_url:
                return current_url.split("cat=")[1].split("&")[0]
            return "all"
        except Exception as e:
            logger.error(f"Failed to get active category: {e}")
            return None

    def is_category_active(self, category_name):
        """
        Check if a category link has active state styling
        Args:
            category_name: "Phones", "Laptops", or "Monitors"
        Returns: bool
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

            # Check for active styling
            return "active" in classes or "selected" in classes

        except NoSuchElementException:
            return False

    # ============================================================================
    # PRODUCT LISTING METHODS
    # ============================================================================

    def get_all_product_cards(self, timeout=10):
        """
        Get all product cards currently displayed
        Returns: list of WebElement
        """
        try:
            self.wait_for_element_visible(self.PRODUCT_CARDS, timeout=timeout)
            cards = self.find_elements(self.PRODUCT_CARDS)
            return cards
        except TimeoutException:
            logger.warning("No product cards found")
            return []

    def get_product_count(self, timeout=10):
        """
        Count how many products are currently displayed
        Returns: int
        """
        cards = self.get_all_product_cards(timeout=timeout)
        return len(cards)

    def get_all_product_names(self, timeout=10):
        """
        Get all product names from current page
        Returns: list of str
        """
        try:
            self.wait_for_element_visible(self.PRODUCT_TITLES, timeout=timeout)
            titles = self.find_elements(self.PRODUCT_TITLES)
            return [title.text for title in titles if title.text]
        except TimeoutException:
            return []

    def get_all_product_prices(self, timeout=10):
        """
        Get all product prices from current page
        Returns: list of str
        """
        try:
            self.wait_for_element_visible(self.PRODUCT_PRICES, timeout=timeout)
            prices = self.find_elements(self.PRODUCT_PRICES)
            return [price.text for price in prices if price.text]
        except TimeoutException:
            return []

    def get_all_product_images(self, timeout=10):
        """
        Get all product image elements
        Returns: list of WebElement
        """
        try:
            self.wait_for_element_visible(self.PRODUCT_IMAGES, timeout=timeout)
            images = self.find_elements(self.PRODUCT_IMAGES)
            return images
        except TimeoutException:
            return []

    def get_all_product_links(self, timeout=10):
        """
        Get all product clickable links
        Returns: list of WebElement
        """
        try:
            self.wait_for_element_visible(self.PRODUCT_LINKS, timeout=timeout)
            links = self.find_elements(self.PRODUCT_LINKS)
            return links
        except TimeoutException:
            return []

    def are_products_displayed(self, timeout=10):
        """
        Check if any products are visible on page
        Returns: bool
        """
        return self.get_product_count(timeout=timeout) > 0

    # ============================================================================
    # PRODUCT INTERACTION METHODS
    # ============================================================================

    def click_first_product(self):
        """
        Click on the first product link
        Returns: (success, product_name)
        """
        try:
            links = self.get_all_product_links(timeout=10)
            if not links:
                return False, None

            first_link = links[0]
            product_name = first_link.text
            first_link.click()

            self.wait_for_page_load()
            time.sleep(2)

            return True, product_name
        except Exception as e:
            logger.error(f"Failed to click first product: {e}")
            return False, None

    def click_product_by_index(self, index):
        """
        Click on a product by its index (0-based)
        Args:
            index: Product index (0 = first product)
        Returns: (success, product_name)
        """
        try:
            links = self.get_all_product_links(timeout=10)
            if index >= len(links):
                return False, None

            target_link = links[index]
            product_name = target_link.text
            target_link.click()

            self.wait_for_page_load()
            time.sleep(2)

            return True, product_name
        except Exception as e:
            logger.error(f"Failed to click product {index}: {e}")
            return False, None

    def is_on_product_detail_page(self, timeout=5):
        """
        Check if currently on a product detail page
        Returns: bool
        """
        try:
            self.wait_for_element_visible(self.PRODUCT_DETAIL_NAME, timeout=timeout)
            return "prod.html" in self.driver.current_url
        except TimeoutException:
            return False

    # ============================================================================
    # PAGINATION METHODS
    # ============================================================================

    def is_next_button_visible(self, timeout=5):
        """Check if Next button is visible"""
        try:
            self.wait_for_element_visible(self.NEXT_BUTTON, timeout=timeout)
            return True
        except TimeoutException:
            return False

    def is_prev_button_visible(self, timeout=5):
        """Check if Previous button is visible"""
        try:
            self.wait_for_element_visible(self.PREV_BUTTON, timeout=timeout)
            return True
        except TimeoutException:
            return False

    def is_next_button_enabled(self):
        """Check if Next button is enabled (not disabled)"""
        try:
            button = self.find_element(self.NEXT_BUTTON)
            return button.is_displayed() and button.is_enabled()
        except NoSuchElementException:
            return False

    def is_prev_button_enabled(self):
        """Check if Previous button is enabled"""
        try:
            button = self.find_element(self.PREV_BUTTON)
            return button.is_displayed() and button.is_enabled()
        except NoSuchElementException:
            return False

    def click_next_page(self):
        """
        Click Next pagination button
        Returns: bool - success status
        """
        try:
            next_btn = self.wait_for_element_clickable(self.NEXT_BUTTON, timeout=10)
            next_btn.click()
            time.sleep(2)  # Wait for new products to load
            return True
        except TimeoutException:
            logger.warning("Next button not clickable")
            return False

    def click_prev_page(self):
        """
        Click Previous pagination button
        Returns: bool - success status
        """
        try:
            prev_btn = self.wait_for_element_clickable(self.PREV_BUTTON, timeout=10)
            prev_btn.click()
            time.sleep(2)
            return True
        except TimeoutException:
            logger.warning("Previous button not clickable")
            return False

    # ============================================================================
    # VALIDATION METHODS
    # ============================================================================

    def validate_all_products_have_names(self):
        """
        Validate that all displayed products have names
        Returns: (all_have_names, missing_count)
        """
        names = self.get_all_product_names()
        cards = self.get_all_product_cards()

        missing = len(cards) - len(names)
        all_have_names = missing == 0

        return all_have_names, missing

    def validate_all_products_have_prices(self):
        """
        Validate that all displayed products have prices
        Returns: (all_have_prices, missing_count)
        """
        prices = self.get_all_product_prices()
        cards = self.get_all_product_cards()

        missing = len(cards) - len(prices)
        all_have_prices = missing == 0

        return all_have_prices, missing

    def validate_price_format(self, price_text):
        """
        Validate price follows expected format: "$XXX"
        Args:
            price_text: Price text to validate
        Returns: bool
        """
        if not price_text:
            return False

        # Expected format: "$790" or "$790.00"
        pattern = r'^\$\d+(\.\d{2})?$'
        return bool(re.match(pattern, price_text))

    def validate_all_prices_format(self):
        """
        Validate all prices follow correct format
        Returns: (all_valid, invalid_prices)
        """
        prices = self.get_all_product_prices()
        invalid = []

        for price in prices:
            if not self.validate_price_format(price):
                invalid.append(price)

        all_valid = len(invalid) == 0
        return all_valid, invalid

    def validate_image_loads(self, image_url):
        """
        Validate image URL loads successfully
        Args:
            image_url: Image URL to check
        Returns: (loads, status_code)
        """
        try:
            response = requests.head(image_url, timeout=5)
            status_code = response.status_code
            loads = status_code == 200
            return loads, status_code
        except requests.RequestException as e:
            logger.error(f"Image validation failed: {e}")
            return False, None

    def validate_all_images_load(self):
        """
        Validate all product images load successfully
        Returns: (all_load, failed_images)
        """
        images = self.get_all_product_images()
        failed = []

        for img in images:
            img_src = img.get_attribute('src')
            if img_src:
                loads, status = self.validate_image_loads(img_src)
                if not loads:
                    failed.append((img_src, status))

        all_load = len(failed) == 0
        return all_load, failed

    def validate_product_link_not_broken(self, link_url):
        """
        Validate product link is not broken (returns 200)
        Args:
            link_url: Product link URL
        Returns: (is_valid, status_code)
        """
        try:
            response = requests.get(link_url, timeout=5)
            status_code = response.status_code
            is_valid = status_code == 200
            return is_valid, status_code
        except requests.RequestException as e:
            logger.error(f"Link validation failed: {e}")
            return False, None

    # ============================================================================
    # PERFORMANCE MEASUREMENT METHODS
    # ============================================================================

    def measure_catalog_load_time(self):
        """
        Measure catalog page load time using Navigation Timing API
        Returns: dict with timing metrics (in seconds)
        """
        try:
            timing = self.driver.execute_script("""
                var timing = window.performance.timing;
                return {
                    navigationStart: timing.navigationStart,
                    domContentLoaded: timing.domContentLoadedEventEnd,
                    loadComplete: timing.loadEventEnd
                };
            """)

            nav_start = timing['navigationStart']
            dom_loaded = timing['domContentLoaded']
            load_complete = timing['loadComplete']

            if nav_start and dom_loaded and load_complete:
                dom_load_time = (dom_loaded - nav_start) / 1000.0
                total_load_time = (load_complete - nav_start) / 1000.0

                return {
                    'dom_load_time': dom_load_time,
                    'total_load_time': total_load_time,
                    'success': True
                }
        except Exception as e:
            logger.error(f"Failed to measure load time: {e}")

        return {
            'dom_load_time': None,
            'total_load_time': None,
            'success': False
        }

    def measure_category_switch_time(self, category_method):
        """
        Measure time to switch categories
        Args:
            category_method: Method to call (e.g., self.click_phones_category)
        Returns: float - time in seconds
        """
        start_time = time.time()
        category_method()
        end_time = time.time()

        return end_time - start_time

    # ============================================================================
    # ACCESSIBILITY METHODS
    # ============================================================================

    def test_keyboard_navigation_categories(self):
        """
        Test keyboard navigation through category links
        Returns: dict with navigation results
        """
        results = {
            'phones_focusable': False,
            'laptops_focusable': False,
            'monitors_focusable': False,
            'tab_navigation_works': False
        }

        try:
            # Click on categories section to start
            categories = self.find_element(self.CATEGORIES_SECTION)
            categories.click()

            actions = ActionChains(self.driver)

            # Try to Tab through categories
            for _ in range(10):
                actions.send_keys(Keys.TAB).perform()
                time.sleep(0.2)

                active_element = self.driver.switch_to.active_element
                text = active_element.text

                if 'Phones' in text:
                    results['phones_focusable'] = True
                if 'Laptops' in text:
                    results['laptops_focusable'] = True
                if 'Monitors' in text:
                    results['monitors_focusable'] = True

            results['tab_navigation_works'] = any([
                results['phones_focusable'],
                results['laptops_focusable'],
                results['monitors_focusable']
            ])

        except Exception as e:
            logger.error(f"Keyboard navigation test failed: {e}")

        return results

    def check_category_aria_labels(self):
        """
        Check if category links have ARIA labels
        Returns: dict with ARIA label presence
        """
        results = {
            'phones_has_aria': False,
            'laptops_has_aria': False,
            'monitors_has_aria': False
        }

        try:
            phones = self.find_element(self.PHONES_CATEGORY)
            laptops = self.find_element(self.LAPTOPS_CATEGORY)
            monitors = self.find_element(self.MONITORS_CATEGORY)

            results['phones_has_aria'] = bool(phones.get_attribute('aria-label'))
            results['laptops_has_aria'] = bool(laptops.get_attribute('aria-label'))
            results['monitors_has_aria'] = bool(monitors.get_attribute('aria-label'))

        except NoSuchElementException as e:
            logger.error(f"Category not found: {e}")

        return results

    def check_focus_indicators(self):
        """
        Check if focus indicators are visible on interactive elements
        Returns: dict with focus indicator status
        """
        results = {
            'categories_have_focus': False,
            'products_have_focus': False
        }

        try:
            # Check category link focus
            phones = self.find_element(self.PHONES_CATEGORY)
            phones.click()

            # Use JavaScript to check computed styles
            has_outline = self.driver.execute_script("""
                var element = arguments[0];
                var styles = window.getComputedStyle(element, ':focus');
                return styles.outlineWidth !== '0px' && styles.outlineStyle !== 'none';
            """, phones)

            results['categories_have_focus'] = has_outline

            # Check product link focus
            links = self.get_all_product_links()
            if links:
                first_link = links[0]
                has_product_outline = self.driver.execute_script("""
                    var element = arguments[0];
                    element.focus();
                    var styles = window.getComputedStyle(element, ':focus');
                    return styles.outlineWidth !== '0px' && styles.outlineStyle !== 'none';
                """, first_link)

                results['products_have_focus'] = has_product_outline

        except Exception as e:
            logger.error(f"Focus indicator check failed: {e}")

        return results

    def get_product_image_alt_texts(self):
        """
        Get alt text for all product images
        Returns: list of (image_src, alt_text) tuples
        """
        images = self.get_all_product_images()
        alt_data = []

        for img in images:
            src = img.get_attribute('src')
            alt = img.get_attribute('alt')
            alt_data.append((src, alt))

        return alt_data

    def validate_all_images_have_alt_text(self):
        """
        Validate all product images have alt text
        Returns: (all_have_alt, missing_count)
        """
        alt_data = self.get_product_image_alt_texts()

        missing = 0
        for src, alt in alt_data:
            if not alt or alt.strip() == "":
                missing += 1

        all_have_alt = missing == 0
        return all_have_alt, missing

    # ============================================================================
    # SECURITY TESTING METHODS
    # ============================================================================

    def check_for_sql_error_indicators(self):
        """
        Check page source for SQL error disclosure
        Returns: (has_error, error_indicators_found)
        """
        page_source = self.driver.page_source.lower()

        sql_error_patterns = [
            'sql syntax',
            'mysql',
            'postgresql',
            'sqlite',
            'database error',
            'odbc',
            'jdbc',
            'syntax error near',
            'unclosed quotation mark'
        ]

        found_indicators = []
        for pattern in sql_error_patterns:
            if pattern in page_source:
                found_indicators.append(pattern)

        has_error = len(found_indicators) > 0
        return has_error, found_indicators

    def check_for_directory_listing(self):
        """
        Check for directory listing exposure
        Returns: (has_listing, indicators_found)
        """
        page_source = self.driver.page_source.lower()

        listing_indicators = [
            'index of /',
            'parent directory',
            'directory listing',
            'last modified',
            'apache server at'
        ]

        found = []
        for indicator in listing_indicators:
            if indicator in page_source:
                found.append(indicator)

        has_listing = len(found) > 0
        return has_listing, found

    def check_for_verbose_errors(self):
        """
        Check for verbose error messages in page source
        Returns: (has_verbose_errors, errors_found)
        """
        page_source = self.driver.page_source.lower()

        error_patterns = [
            'stack trace',
            'exception',
            'fatal error',
            'warning:',
            'notice:',
            'deprecated:',
            'parse error'
        ]

        found = []
        for pattern in error_patterns:
            if pattern in page_source:
                found.append(pattern)

        has_errors = len(found) > 0
        return has_errors, found
