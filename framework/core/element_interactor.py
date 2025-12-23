"""
Element Interactor - Universal Test Automation Framework
Author: Marc Arévalo
Version: 1.0

Handles all interactions with web elements (click, type, select, etc.).
Separated from BasePage to follow Single Responsibility Principle.

This class is UNIVERSAL - works with any web application.
"""

import logging
from typing import List, Optional

from selenium.common.exceptions import (
    ElementNotInteractableException,
    JavascriptException,
    StaleElementReferenceException,
)
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.support.ui import Select


class ElementInteractor:
    """
    Universal element interaction handler.

    Provides reliable methods for interacting with web elements.
    Handles common interaction failures with automatic retries.

    Example:
        interactor = ElementInteractor(driver)
        interactor.click(element)
        interactor.type(element, "Hello World")
    """

    def __init__(self, driver: WebDriver):
        """
        Initialize element interactor.

        Args:
            driver: Selenium WebDriver instance
        """
        self.driver = driver
        self.logger = logging.getLogger(__name__)

    def click(
        self, element: WebElement, force: bool = False, retry: int = 3
    ) -> bool:
        """
        Click an element with automatic retry on failure.

        Args:
            element: WebElement to click
            force: If True, use JavaScript click as fallback
            retry: Number of retry attempts

        Returns:
            True if click succeeded, False otherwise

        Example:
            success = interactor.click(button)
            if not success:
                print("Click failed")
        """
        for attempt in range(retry):
            try:
                element.click()
                self.logger.debug(f"✓ Clicked element (attempt {attempt + 1})")
                return True
            except (
                ElementNotInteractableException,
                StaleElementReferenceException,
            ) as e:
                self.logger.debug(
                    f"✗ Click failed (attempt {attempt + 1}): {e}"
                )
                if attempt == retry - 1 and force:
                    self.logger.debug("↻ Trying JavaScript click as fallback")
                    return self.click_with_js(element)

        self.logger.warning(f"✗ Click failed after {retry} attempts")
        return False

    def click_with_js(self, element: WebElement) -> bool:
        """
        Click element using JavaScript.

        Useful when standard click fails due to overlays or positioning issues.

        Args:
            element: WebElement to click

        Returns:
            True if successful, False otherwise

        Example:
            success = interactor.click_with_js(hidden_button)
        """
        try:
            self.driver.execute_script("arguments[0].click();", element)
            self.logger.debug("✓ JavaScript click succeeded")
            return True
        except JavascriptException as e:
            self.logger.warning(f"✗ JavaScript click failed: {e}")
            return False

    def type(
        self, element: WebElement, text: str, clear_first: bool = True
    ) -> bool:
        """
        Type text into an input element.

        Args:
            element: Input WebElement
            text: Text to type
            clear_first: If True, clear field before typing

        Returns:
            True if successful, False otherwise

        Example:
            interactor.type(username_field, "testuser")
        """
        try:
            if clear_first:
                element.clear()

            element.send_keys(text)
            self.logger.debug(f"✓ Typed text: '{text[:20]}...'")
            return True
        except Exception as e:
            self.logger.warning(f"✗ Type failed: {e}")
            return False

    def type_slowly(
        self,
        element: WebElement,
        text: str,
        delay: float = 0.1,
        clear_first: bool = True,
    ) -> bool:
        """
        Type text character by character with delay.

        Useful for fields with JavaScript validation or autocomplete.

        Args:
            element: Input WebElement
            text: Text to type
            delay: Delay between characters in seconds
            clear_first: If True, clear field first

        Returns:
            True if successful, False otherwise

        Example:
            interactor.type_slowly(search_field, "product", delay=0.2)
        """
        import time

        try:
            if clear_first:
                element.clear()

            for char in text:
                element.send_keys(char)
                time.sleep(delay)

            self.logger.debug(f"✓ Typed slowly: '{text}'")
            return True
        except Exception as e:
            self.logger.warning(f"✗ Slow type failed: {e}")
            return False

    def clear(self, element: WebElement) -> bool:
        """
        Clear an input element.

        Args:
            element: Input WebElement

        Returns:
            True if successful, False otherwise

        Example:
            interactor.clear(username_field)
        """
        try:
            element.clear()
            self.logger.debug("✓ Cleared element")
            return True
        except Exception as e:
            self.logger.warning(f"✗ Clear failed: {e}")
            return False

    def select_by_visible_text(self, element: WebElement, text: str) -> bool:
        """
        Select dropdown option by visible text.

        Args:
            element: Select WebElement
            text: Visible text of option to select

        Returns:
            True if successful, False otherwise

        Example:
            interactor.select_by_visible_text(country_dropdown, "Spain")
        """
        try:
            select = Select(element)
            select.select_by_visible_text(text)
            self.logger.debug(f"✓ Selected by text: '{text}'")
            return True
        except Exception as e:
            self.logger.warning(f"✗ Select by text failed: {e}")
            return False

    def select_by_value(self, element: WebElement, value: str) -> bool:
        """
        Select dropdown option by value attribute.

        Args:
            element: Select WebElement
            value: Value attribute of option to select

        Returns:
            True if successful, False otherwise

        Example:
            interactor.select_by_value(month_dropdown, "12")
        """
        try:
            select = Select(element)
            select.select_by_value(value)
            self.logger.debug(f"✓ Selected by value: '{value}'")
            return True
        except Exception as e:
            self.logger.warning(f"✗ Select by value failed: {e}")
            return False

    def select_by_index(self, element: WebElement, index: int) -> bool:
        """
        Select dropdown option by index.

        Args:
            element: Select WebElement
            index: Index of option to select (0-based)

        Returns:
            True if successful, False otherwise

        Example:
            interactor.select_by_index(country_dropdown, 0)  # First option
        """
        try:
            select = Select(element)
            select.select_by_index(index)
            self.logger.debug(f"✓ Selected by index: {index}")
            return True
        except Exception as e:
            self.logger.warning(f"✗ Select by index failed: {e}")
            return False

    def get_select_options(self, element: WebElement) -> List[str]:
        """
        Get all option texts from a dropdown.

        DISCOVERY METHOD: Discovers available options automatically.

        Args:
            element: Select WebElement

        Returns:
            List of option texts

        Example:
            options = interactor.get_select_options(country_dropdown)
            print(f"Available countries: {options}")
        """
        try:
            select = Select(element)
            options = [opt.text for opt in select.options]
            self.logger.debug(f"✓ Found {len(options)} options")
            return options
        except Exception as e:
            self.logger.warning(f"✗ Get options failed: {e}")
            return []

    def hover(self, element: WebElement) -> bool:
        """
        Hover over an element.

        Args:
            element: WebElement to hover over

        Returns:
            True if successful, False otherwise

        Example:
            interactor.hover(menu_item)
        """
        try:
            actions = ActionChains(self.driver)
            actions.move_to_element(element).perform()
            self.logger.debug("✓ Hovered over element")
            return True
        except Exception as e:
            self.logger.warning(f"✗ Hover failed: {e}")
            return False

    def double_click(self, element: WebElement) -> bool:
        """
        Double-click an element.

        Args:
            element: WebElement to double-click

        Returns:
            True if successful, False otherwise

        Example:
            interactor.double_click(cell)
        """
        try:
            actions = ActionChains(self.driver)
            actions.double_click(element).perform()
            self.logger.debug("✓ Double-clicked element")
            return True
        except Exception as e:
            self.logger.warning(f"✗ Double-click failed: {e}")
            return False

    def right_click(self, element: WebElement) -> bool:
        """
        Right-click an element (context menu).

        Args:
            element: WebElement to right-click

        Returns:
            True if successful, False otherwise

        Example:
            interactor.right_click(file_item)
        """
        try:
            actions = ActionChains(self.driver)
            actions.context_click(element).perform()
            self.logger.debug("✓ Right-clicked element")
            return True
        except Exception as e:
            self.logger.warning(f"✗ Right-click failed: {e}")
            return False

    def drag_and_drop(self, source: WebElement, target: WebElement) -> bool:
        """
        Drag and drop source element to target element.

        Args:
            source: Element to drag
            target: Element to drop on

        Returns:
            True if successful, False otherwise

        Example:
            interactor.drag_and_drop(item, cart)
        """
        try:
            actions = ActionChains(self.driver)
            actions.drag_and_drop(source, target).perform()
            self.logger.debug("✓ Drag and drop completed")
            return True
        except Exception as e:
            self.logger.warning(f"✗ Drag and drop failed: {e}")
            return False

    def scroll_to_element(self, element: WebElement) -> bool:
        """
        Scroll element into view.

        Args:
            element: WebElement to scroll to

        Returns:
            True if successful, False otherwise

        Example:
            interactor.scroll_to_element(footer_link)
        """
        try:
            self.driver.execute_script(
                "arguments[0].scrollIntoView({behavior: 'smooth', block: 'center'});",
                element,
            )
            self.logger.debug("✓ Scrolled to element")
            return True
        except Exception as e:
            self.logger.warning(f"✗ Scroll failed: {e}")
            return False

    def send_keys(self, element: WebElement, *keys) -> bool:
        """
        Send special keys to element (e.g., ENTER, TAB, ESCAPE).

        Args:
            element: WebElement to send keys to
            *keys: Keys to send (can be multiple)

        Returns:
            True if successful, False otherwise

        Example:
            interactor.send_keys(search_field, Keys.ENTER)
            interactor.send_keys(input_field, Keys.CONTROL, "a")
        """
        try:
            element.send_keys(*keys)
            self.logger.debug(f"✓ Sent keys: {keys}")
            return True
        except Exception as e:
            self.logger.warning(f"✗ Send keys failed: {e}")
            return False

    def get_text(self, element: WebElement) -> str:
        """
        Get visible text from element.

        Args:
            element: WebElement

        Returns:
            Visible text content

        Example:
            text = interactor.get_text(error_message)
        """
        try:
            text = element.text
            self.logger.debug(f"✓ Got text: '{text[:50]}...'")
            return text
        except Exception as e:
            self.logger.warning(f"✗ Get text failed: {e}")
            return ""

    def get_attribute(
        self, element: WebElement, attribute: str
    ) -> Optional[str]:
        """
        Get attribute value from element.

        Args:
            element: WebElement
            attribute: Attribute name

        Returns:
            Attribute value or None if not found

        Example:
            href = interactor.get_attribute(link, "href")
            placeholder = interactor.get_attribute(input_field, "placeholder")
        """
        try:
            value = element.get_attribute(attribute)
            self.logger.debug(f"✓ Got attribute '{attribute}': '{value}'")
            return value
        except Exception as e:
            self.logger.warning(f"✗ Get attribute failed: {e}")
            return None

    def is_displayed(self, element: WebElement) -> bool:
        """
        Check if element is visible.

        Args:
            element: WebElement

        Returns:
            True if visible, False otherwise

        Example:
            if interactor.is_displayed(error_msg):
                print("Error is visible")
        """
        try:
            return element.is_displayed()
        except Exception:
            return False

    def is_enabled(self, element: WebElement) -> bool:
        """
        Check if element is enabled (not disabled).

        Args:
            element: WebElement

        Returns:
            True if enabled, False otherwise

        Example:
            if interactor.is_enabled(submit_button):
                print("Button is enabled")
        """
        try:
            return element.is_enabled()
        except Exception:
            return False

    def is_selected(self, element: WebElement) -> bool:
        """
        Check if element is selected (checkbox/radio).

        Args:
            element: WebElement

        Returns:
            True if selected, False otherwise

        Example:
            if interactor.is_selected(checkbox):
                print("Checkbox is checked")
        """
        try:
            return element.is_selected()
        except Exception:
            return False

    def __str__(self) -> str:
        """String representation."""
        return "ElementInteractor"

    def __repr__(self) -> str:
        """Detailed representation."""
        return f"ElementInteractor(driver={self.driver})"
