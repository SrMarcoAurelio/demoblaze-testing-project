"""
Element Finder - Universal Test Automation Framework
Author: Marc Arévalo
Version: 1.0

Handles element discovery using multiple strategies.
Separated from BasePage to follow Single Responsibility Principle.

This class is UNIVERSAL - works with any web application.
"""

import logging
from typing import List, Optional, Tuple

from selenium.common.exceptions import (
    NoSuchElementException,
    StaleElementReferenceException,
    TimeoutException,
)
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.remote.webelement import WebElement


class ElementFinder:
    """
    Universal element finder using multiple locator strategies.

    Provides flexible element discovery with automatic fallback strategies.
    This class DISCOVERS elements rather than assuming their location.

    Example:
        finder = ElementFinder(driver)
        element = finder.find_element(By.ID, "username")
        elements = finder.find_elements(By.CLASS_NAME, "product")
    """

    def __init__(self, driver: WebDriver):
        """
        Initialize element finder.

        Args:
            driver: Selenium WebDriver instance
        """
        self.driver = driver
        self.logger = logging.getLogger(__name__)

    def find_element(
        self, by: By, value: str, context: Optional[WebElement] = None
    ) -> Optional[WebElement]:
        """
        Find a single element using specified locator strategy.

        Args:
            by: Selenium By locator type
            value: Locator value
            context: Optional parent element to search within

        Returns:
            WebElement if found, None otherwise

        Example:
            element = finder.find_element(By.ID, "login-button")
        """
        try:
            search_context = context if context else self.driver
            element = search_context.find_element(by, value)
            self.logger.debug(f"✓ Found element: {by}='{value}'")
            return element
        except NoSuchElementException:
            self.logger.debug(f"✗ Element not found: {by}='{value}'")
            return None
        except StaleElementReferenceException:
            self.logger.warning(f"⚠ Stale element: {by}='{value}'")
            return None

    def find_elements(
        self, by: By, value: str, context: Optional[WebElement] = None
    ) -> List[WebElement]:
        """
        Find all elements matching the specified locator.

        Args:
            by: Selenium By locator type
            value: Locator value
            context: Optional parent element to search within

        Returns:
            List of WebElements (empty if none found)

        Example:
            products = finder.find_elements(By.CLASS_NAME, "product-card")
        """
        try:
            search_context = context if context else self.driver
            elements = search_context.find_elements(by, value)
            self.logger.debug(
                f"✓ Found {len(elements)} elements: {by}='{value}'"
            )
            return elements
        except Exception as e:
            self.logger.warning(
                f"✗ Error finding elements {by}='{value}': {e}"
            )
            return []

    def find_element_with_fallback(
        self, locator_strategies: List[Tuple[By, str]]
    ) -> Optional[WebElement]:
        """
        Try multiple locator strategies until one succeeds.

        This is KEY to discovery-based testing: try multiple ways to find
        an element instead of assuming a specific locator.

        Args:
            locator_strategies: List of (By, value) tuples to try in order

        Returns:
            First WebElement found, or None if all strategies fail

        Example:
            element = finder.find_element_with_fallback([
                (By.ID, "submit-btn"),
                (By.NAME, "submit"),
                (By.XPATH, "//button[@type='submit']"),
                (By.CSS_SELECTOR, "button[type='submit']")
            ])
        """
        for by, value in locator_strategies:
            element = self.find_element(by, value)
            if element:
                self.logger.debug(f"✓ Fallback succeeded: {by}='{value}'")
                return element

        self.logger.warning(
            f"✗ All fallback strategies failed: {len(locator_strategies)} attempts"
        )
        return None

    def find_by_text(
        self,
        text: str,
        tag: str = "*",
        exact: bool = False,
        context: Optional[WebElement] = None,
    ) -> Optional[WebElement]:
        """
        Find element by its visible text content.

        DISCOVERY-BASED: Finds elements by what users see, not by implementation details.

        Args:
            text: Text to search for
            tag: HTML tag to search within (default: any tag)
            exact: If True, match exact text; if False, match partial text
            context: Optional parent element to search within

        Returns:
            WebElement if found, None otherwise

        Example:
            # Find button with text "Login"
            button = finder.find_by_text("Login", tag="button", exact=True)

            # Find any element containing "Welcome"
            welcome = finder.find_by_text("Welcome")
        """
        if exact:
            xpath = f"//{tag}[text()='{text}']"
        else:
            xpath = f"//{tag}[contains(text(), '{text}')]"

        return self.find_element(By.XPATH, xpath, context)

    def find_by_attribute(
        self, attribute: str, value: str, tag: str = "*"
    ) -> Optional[WebElement]:
        """
        Find element by any attribute.

        Args:
            attribute: Attribute name
            value: Attribute value
            tag: HTML tag to search (default: any tag)

        Returns:
            WebElement if found, None otherwise

        Example:
            link = finder.find_by_attribute("href", "/products")
            input_field = finder.find_by_attribute("placeholder", "Enter username")
        """
        xpath = f"//{tag}[@{attribute}='{value}']"
        return self.find_element(By.XPATH, xpath)

    def find_by_partial_attribute(
        self, attribute: str, value: str, tag: str = "*"
    ) -> Optional[WebElement]:
        """
        Find element by partial attribute match.

        Args:
            attribute: Attribute name
            value: Partial attribute value
            tag: HTML tag to search

        Returns:
            WebElement if found, None otherwise

        Example:
            button = finder.find_by_partial_attribute("class", "btn-primary")
        """
        xpath = f"//{tag}[contains(@{attribute}, '{value}')]"
        return self.find_element(By.XPATH, xpath)

    def find_clickable_elements(self) -> List[WebElement]:
        """
        Discover all clickable elements on the page.

        DISCOVERY METHOD: Identifies interactive elements automatically.

        Returns:
            List of clickable WebElements

        Example:
            clickable = finder.find_clickable_elements()
            for element in clickable:
                print(f"Clickable: {element.tag_name} - {element.text}")
        """
        clickable_selectors = [
            (By.TAG_NAME, "a"),
            (By.TAG_NAME, "button"),
            (By.CSS_SELECTOR, "input[type='button']"),
            (By.CSS_SELECTOR, "input[type='submit']"),
            (By.CSS_SELECTOR, "[onclick]"),
            (By.CSS_SELECTOR, "[role='button']"),
        ]

        all_clickable = []
        for by, value in clickable_selectors:
            elements = self.find_elements(by, value)
            all_clickable.extend(elements)

        self.logger.debug(f"✓ Found {len(all_clickable)} clickable elements")
        return all_clickable

    def find_input_elements(self) -> List[WebElement]:
        """
        Discover all input elements on the page.

        DISCOVERY METHOD: Identifies form inputs automatically.

        Returns:
            List of input WebElements

        Example:
            inputs = finder.find_input_elements()
            for input_elem in inputs:
                print(f"Input: {input_elem.get_attribute('name')}")
        """
        input_selectors = [
            (By.TAG_NAME, "input"),
            (By.TAG_NAME, "textarea"),
            (By.TAG_NAME, "select"),
        ]

        all_inputs = []
        for by, value in input_selectors:
            elements = self.find_elements(by, value)
            all_inputs.extend(elements)

        self.logger.debug(f"✓ Found {len(all_inputs)} input elements")
        return all_inputs

    def find_forms(self) -> List[WebElement]:
        """
        Discover all forms on the page.

        DISCOVERY METHOD: Identifies all form elements.

        Returns:
            List of form WebElements

        Example:
            forms = finder.find_forms()
            for form in forms:
                print(f"Form: {form.get_attribute('id')}")
        """
        forms = self.find_elements(By.TAG_NAME, "form")
        self.logger.debug(f"✓ Found {len(forms)} forms")
        return forms

    def find_links(self) -> List[WebElement]:
        """
        Discover all links on the page.

        DISCOVERY METHOD: Identifies all anchor elements.

        Returns:
            List of link WebElements

        Example:
            links = finder.find_links()
            for link in links:
                print(f"Link: {link.text} -> {link.get_attribute('href')}")
        """
        links = self.find_elements(By.TAG_NAME, "a")
        self.logger.debug(f"✓ Found {len(links)} links")
        return links

    def is_element_present(self, by: By, value: str) -> bool:
        """
        Check if element exists in the DOM (may not be visible).

        Args:
            by: Selenium By locator type
            value: Locator value

        Returns:
            True if element exists, False otherwise

        Example:
            if finder.is_element_present(By.ID, "error-message"):
                print("Error message exists")
        """
        return self.find_element(by, value) is not None

    def get_element_count(self, by: By, value: str) -> int:
        """
        Count how many elements match the locator.

        Args:
            by: Selenium By locator type
            value: Locator value

        Returns:
            Number of matching elements

        Example:
            product_count = finder.get_element_count(By.CLASS_NAME, "product")
        """
        elements = self.find_elements(by, value)
        return len(elements)

    def __str__(self) -> str:
        """String representation."""
        return f"ElementFinder(driver={self.driver.name if hasattr(self.driver, 'name') else 'WebDriver'})"

    def __repr__(self) -> str:
        """Detailed representation."""
        return f"ElementFinder(driver={self.driver})"
