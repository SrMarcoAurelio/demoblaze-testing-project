"""
Wait Handler - Universal Test Automation Framework
Author: Marc Arévalo
Version: 1.0

Handles all wait strategies and synchronization logic.
Separated from BasePage to follow Single Responsibility Principle.

This class is UNIVERSAL - works with any web application.
NO SLEEP CALLS - Only proper Selenium waits.
"""

import logging
from typing import Any, Callable, Optional

from selenium.common.exceptions import (
    NoSuchElementException,
    StaleElementReferenceException,
    TimeoutException,
)
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


class WaitHandler:
    """
    Universal wait handler using Selenium explicit waits.

    Provides comprehensive wait strategies without using time.sleep().
    All waits are intelligent and based on actual element states.

    NO HARDCODED SLEEPS - Only condition-based waits.

    Example:
        wait_handler = WaitHandler(driver, default_timeout=10)
        wait_handler.wait_for_element_visible(By.ID, "login-button")
    """

    def __init__(
        self,
        driver: WebDriver,
        default_timeout: int = 10,
        poll_frequency: float = 0.5,
    ):
        """
        Initialize wait handler.

        Args:
            driver: Selenium WebDriver instance
            default_timeout: Default timeout in seconds
            poll_frequency: How often to check condition (seconds)
        """
        self.driver = driver
        self.default_timeout = default_timeout
        self.poll_frequency = poll_frequency
        self.logger = logging.getLogger(__name__)

    def wait_for_element_visible(
        self, by: By, value: str, timeout: Optional[int] = None
    ) -> Optional[WebElement]:
        """
        Wait until element is visible.

        Args:
            by: Selenium By locator type
            value: Locator value
            timeout: Custom timeout (uses default if not specified)

        Returns:
            WebElement if found and visible, None on timeout

        Example:
            element = wait_handler.wait_for_element_visible(By.ID, "modal")
        """
        timeout = timeout or self.default_timeout
        try:
            wait = WebDriverWait(
                self.driver, timeout, poll_frequency=self.poll_frequency
            )
            element = wait.until(EC.visibility_of_element_located((by, value)))
            self.logger.debug(f"✓ Element visible: {by}='{value}'")
            return element
        except TimeoutException:
            self.logger.debug(
                f"✗ Element not visible after {timeout}s: {by}='{value}'"
            )
            return None

    def wait_for_element_present(
        self, by: By, value: str, timeout: Optional[int] = None
    ) -> Optional[WebElement]:
        """
        Wait until element is present in DOM (may not be visible).

        Args:
            by: Selenium By locator type
            value: Locator value
            timeout: Custom timeout

        Returns:
            WebElement if found, None on timeout

        Example:
            element = wait_handler.wait_for_element_present(By.NAME, "username")
        """
        timeout = timeout or self.default_timeout
        try:
            wait = WebDriverWait(
                self.driver, timeout, poll_frequency=self.poll_frequency
            )
            element = wait.until(EC.presence_of_element_located((by, value)))
            self.logger.debug(f"✓ Element present: {by}='{value}'")
            return element
        except TimeoutException:
            self.logger.debug(
                f"✗ Element not present after {timeout}s: {by}='{value}'"
            )
            return None

    def wait_for_element_clickable(
        self, by: By, value: str, timeout: Optional[int] = None
    ) -> Optional[WebElement]:
        """
        Wait until element is clickable (visible and enabled).

        Args:
            by: Selenium By locator type
            value: Locator value
            timeout: Custom timeout

        Returns:
            WebElement if clickable, None on timeout

        Example:
            button = wait_handler.wait_for_element_clickable(By.ID, "submit")
        """
        timeout = timeout or self.default_timeout
        try:
            wait = WebDriverWait(
                self.driver, timeout, poll_frequency=self.poll_frequency
            )
            element = wait.until(EC.element_to_be_clickable((by, value)))
            self.logger.debug(f"✓ Element clickable: {by}='{value}'")
            return element
        except TimeoutException:
            self.logger.debug(
                f"✗ Element not clickable after {timeout}s: {by}='{value}'"
            )
            return None

    def wait_for_element_invisible(
        self, by: By, value: str, timeout: Optional[int] = None
    ) -> bool:
        """
        Wait until element is invisible or removed from DOM.

        Args:
            by: Selenium By locator type
            value: Locator value
            timeout: Custom timeout

        Returns:
            True if element became invisible, False on timeout

        Example:
            if wait_handler.wait_for_element_invisible(By.ID, "loading"):
                print("Loading indicator disappeared")
        """
        timeout = timeout or self.default_timeout
        try:
            wait = WebDriverWait(
                self.driver, timeout, poll_frequency=self.poll_frequency
            )
            wait.until(EC.invisibility_of_element_located((by, value)))
            self.logger.debug(f"✓ Element invisible: {by}='{value}'")
            return True
        except TimeoutException:
            self.logger.debug(
                f"✗ Element still visible after {timeout}s: {by}='{value}'"
            )
            return False

    def wait_for_text_present(
        self, by: By, value: str, text: str, timeout: Optional[int] = None
    ) -> bool:
        """
        Wait until element contains specific text.

        Args:
            by: Selenium By locator type
            value: Locator value
            text: Text to wait for
            timeout: Custom timeout

        Returns:
            True if text appeared, False on timeout

        Example:
            if wait_handler.wait_for_text_present(By.ID, "status", "Success"):
                print("Success message appeared")
        """
        timeout = timeout or self.default_timeout
        try:
            wait = WebDriverWait(
                self.driver, timeout, poll_frequency=self.poll_frequency
            )
            wait.until(EC.text_to_be_present_in_element((by, value), text))
            self.logger.debug(f"✓ Text present: '{text}' in {by}='{value}'")
            return True
        except TimeoutException:
            self.logger.debug(f"✗ Text not present after {timeout}s: '{text}'")
            return False

    def wait_for_alert(self, timeout: Optional[int] = None) -> Optional[Any]:
        """
        Wait for JavaScript alert to be present.

        Args:
            timeout: Custom timeout

        Returns:
            Alert object if present, None on timeout

        Example:
            alert = wait_handler.wait_for_alert()
            if alert:
                print(f"Alert text: {alert.text}")
        """
        timeout = timeout or self.default_timeout
        try:
            wait = WebDriverWait(
                self.driver, timeout, poll_frequency=self.poll_frequency
            )
            alert = wait.until(EC.alert_is_present())
            self.logger.debug("✓ Alert present")
            return alert
        except TimeoutException:
            self.logger.debug(f"✗ No alert after {timeout}s")
            return None

    def wait_for_url_contains(
        self, url_part: str, timeout: Optional[int] = None
    ) -> bool:
        """
        Wait until URL contains specific string.

        Args:
            url_part: String to wait for in URL
            timeout: Custom timeout

        Returns:
            True if URL contains string, False on timeout

        Example:
            if wait_handler.wait_for_url_contains("success"):
                print("Navigated to success page")
        """
        timeout = timeout or self.default_timeout
        try:
            wait = WebDriverWait(
                self.driver, timeout, poll_frequency=self.poll_frequency
            )
            wait.until(EC.url_contains(url_part))
            self.logger.debug(f"✓ URL contains: '{url_part}'")
            return True
        except TimeoutException:
            self.logger.debug(
                f"✗ URL does not contain '{url_part}' after {timeout}s"
            )
            return False

    def wait_for_url_to_be(
        self, url: str, timeout: Optional[int] = None
    ) -> bool:
        """
        Wait until URL equals specific value.

        Args:
            url: Exact URL to wait for
            timeout: Custom timeout

        Returns:
            True if URL matches, False on timeout

        Example:
            if wait_handler.wait_for_url_to_be("https://example.com/home"):
                print("At home page")
        """
        timeout = timeout or self.default_timeout
        try:
            wait = WebDriverWait(
                self.driver, timeout, poll_frequency=self.poll_frequency
            )
            wait.until(EC.url_to_be(url))
            self.logger.debug(f"✓ URL is: '{url}'")
            return True
        except TimeoutException:
            self.logger.debug(f"✗ URL is not '{url}' after {timeout}s")
            return False

    def wait_for_title_contains(
        self, title: str, timeout: Optional[int] = None
    ) -> bool:
        """
        Wait until page title contains specific string.

        Args:
            title: String to wait for in title
            timeout: Custom timeout

        Returns:
            True if title contains string, False on timeout

        Example:
            if wait_handler.wait_for_title_contains("Dashboard"):
                print("On dashboard page")
        """
        timeout = timeout or self.default_timeout
        try:
            wait = WebDriverWait(
                self.driver, timeout, poll_frequency=self.poll_frequency
            )
            wait.until(EC.title_contains(title))
            self.logger.debug(f"✓ Title contains: '{title}'")
            return True
        except TimeoutException:
            self.logger.debug(
                f"✗ Title does not contain '{title}' after {timeout}s"
            )
            return False

    def wait_for_element_attribute(
        self,
        by: By,
        value: str,
        attribute: str,
        attribute_value: str,
        timeout: Optional[int] = None,
    ) -> bool:
        """
        Wait until element's attribute has specific value.

        Args:
            by: Selenium By locator type
            value: Locator value
            attribute: Attribute name to check
            attribute_value: Expected attribute value
            timeout: Custom timeout

        Returns:
            True if attribute matches, False on timeout

        Example:
            # Wait until button becomes enabled
            if wait_handler.wait_for_element_attribute(
                By.ID, "submit", "disabled", "false"
            ):
                print("Button enabled")
        """
        timeout = timeout or self.default_timeout

        def check_attribute(driver):
            try:
                element = driver.find_element(by, value)
                return element.get_attribute(attribute) == attribute_value
            except (NoSuchElementException, StaleElementReferenceException):
                return False

        try:
            wait = WebDriverWait(
                self.driver, timeout, poll_frequency=self.poll_frequency
            )
            wait.until(check_attribute)
            self.logger.debug(
                f"✓ Attribute '{attribute}' = '{attribute_value}' for {by}='{value}'"
            )
            return True
        except TimeoutException:
            self.logger.debug(
                f"✗ Attribute condition not met after {timeout}s"
            )
            return False

    def wait_for_condition(
        self,
        condition: Callable[[WebDriver], bool],
        timeout: Optional[int] = None,
        error_message: str = "Condition not met",
    ) -> bool:
        """
        Wait for custom condition function.

        ADVANCED: Allows custom wait conditions for complex scenarios.

        Args:
            condition: Function that takes driver and returns bool
            timeout: Custom timeout
            error_message: Message to log on timeout

        Returns:
            True if condition met, False on timeout

        Example:
            def cart_has_items(driver):
                cart = driver.find_element(By.ID, "cart-count")
                return int(cart.text) > 0

            if wait_handler.wait_for_condition(cart_has_items):
                print("Cart has items")
        """
        timeout = timeout or self.default_timeout
        try:
            wait = WebDriverWait(
                self.driver, timeout, poll_frequency=self.poll_frequency
            )
            wait.until(condition)
            self.logger.debug(f"✓ Custom condition met")
            return True
        except TimeoutException:
            self.logger.debug(f"✗ {error_message} after {timeout}s")
            return False

    def wait_for_page_load(self, timeout: Optional[int] = None) -> bool:
        """
        Wait for page to finish loading (document ready state).

        Args:
            timeout: Custom timeout

        Returns:
            True if page loaded, False on timeout

        Example:
            wait_handler.wait_for_page_load()
        """
        timeout = timeout or self.default_timeout

        def page_loaded(driver):
            return (
                driver.execute_script("return document.readyState")
                == "complete"
            )

        return self.wait_for_condition(
            page_loaded, timeout, "Page did not finish loading"
        )

    def wait_for_ajax_complete(self, timeout: Optional[int] = None) -> bool:
        """
        Wait for jQuery AJAX calls to complete.

        Only works if application uses jQuery.

        Args:
            timeout: Custom timeout

        Returns:
            True if AJAX complete, False on timeout

        Example:
            wait_handler.wait_for_ajax_complete()
        """
        timeout = timeout or self.default_timeout

        def ajax_complete(driver):
            try:
                jquery_active = driver.execute_script(
                    "return jQuery.active == 0"
                )
                return jquery_active
            except:
                # jQuery not present
                return True

        return self.wait_for_condition(
            ajax_complete, timeout, "AJAX calls did not complete"
        )

    def wait_for_number_of_elements(
        self, by: By, value: str, count: int, timeout: Optional[int] = None
    ) -> bool:
        """
        Wait until specific number of elements are present.

        DISCOVERY METHOD: Useful for waiting for dynamic content.

        Args:
            by: Selenium By locator type
            value: Locator value
            count: Expected number of elements
            timeout: Custom timeout

        Returns:
            True if count matched, False on timeout

        Example:
            # Wait until 10 products are loaded
            if wait_handler.wait_for_number_of_elements(
                By.CLASS_NAME, "product", 10
            ):
                print("10 products loaded")
        """
        timeout = timeout or self.default_timeout

        def check_count(driver):
            elements = driver.find_elements(by, value)
            return len(elements) == count

        return self.wait_for_condition(
            check_count, timeout, f"Element count did not reach {count}"
        )

    def is_element_visible(self, by: By, value: str, timeout: int = 0) -> bool:
        """
        Check if element is visible (returns immediately or after short wait).

        Args:
            by: Selenium By locator type
            value: Locator value
            timeout: Short timeout (0 = immediate check)

        Returns:
            True if visible, False otherwise

        Example:
            if wait_handler.is_element_visible(By.ID, "error-msg"):
                print("Error visible")
        """
        if timeout == 0:
            try:
                element = self.driver.find_element(by, value)
                return element.is_displayed()
            except:
                return False
        else:
            return (
                self.wait_for_element_visible(by, value, timeout) is not None
            )

    def __str__(self) -> str:
        """String representation."""
        return f"WaitHandler(timeout={self.default_timeout}s)"

    def __repr__(self) -> str:
        """Detailed representation."""
        return (
            f"WaitHandler("
            f"driver={self.driver}, "
            f"timeout={self.default_timeout}, "
            f"poll={self.poll_frequency})"
        )
