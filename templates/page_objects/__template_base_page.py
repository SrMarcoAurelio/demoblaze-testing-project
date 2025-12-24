"""
Universal Base Page Template

INSTRUCTIONS:
1. Copy this file to your pages/ directory
2. Rename it to: base_page.py
3. Replace ALL_CAPS placeholders with your application values
4. Remove pytest.skip() when ready to use
5. Adapt methods to YOUR application's needs

This template provides common functionality for all page objects.
"""

from typing import List, Optional, Tuple

import pytest
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.support import expected_conditions as EC

from framework.core.element_finder import ElementFinder
from framework.core.element_interactor import ElementInteractor
from framework.core.wait_handler import WaitHandler

# SKIP BY DEFAULT - Remove this when you adapt the template
pytest.skip(
    "Template not adapted - replace placeholders with your application values",
    allow_module_level=True,
)


class BasePage:
    """
    Base page object providing common functionality for all pages.

    Attributes:
        driver: Selenium WebDriver instance
        finder: ElementFinder for discovering elements
        interactor: ElementInteractor for element interactions
        waiter: WaitHandler for intelligent waiting

    Example:
        class LoginPage(BasePage):
            def __init__(self, driver):
                super().__init__(driver)

            def login(self, username, password):
                # Use inherited finder, interactor, waiter
                pass
    """

    def __init__(self, driver: WebDriver):
        """
        Initialize base page with framework components.

        Args:
            driver: Selenium WebDriver instance
        """
        self.driver = driver
        self.finder = ElementFinder(driver)
        self.interactor = ElementInteractor(driver)
        self.waiter = WaitHandler(driver)

    def navigate_to(self, url: str) -> None:
        """
        Navigate to a specific URL.

        Args:
            url: URL to navigate to

        Example:
            self.navigate_to("https://YOUR_APP_URL/login")
        """
        self.driver.get(url)

    def get_current_url(self) -> str:
        """
        Get current page URL.

        Returns:
            Current URL as string
        """
        return self.driver.current_url

    def get_page_title(self) -> str:
        """
        Get current page title.

        Returns:
            Page title as string
        """
        return self.driver.title

    def wait_for_element(
        self, locator: Tuple[By, str], timeout: int = 10
    ) -> None:
        """
        Wait for element to be present.

        Args:
            locator: Tuple of (By strategy, locator string)
            timeout: Maximum wait time in seconds

        Example:
            self.wait_for_element((By.ID, "username"), timeout=15)
        """
        self.waiter.wait_for_element(locator, timeout=timeout)

    def wait_for_element_visible(
        self, locator: Tuple[By, str], timeout: int = 10
    ) -> None:
        """
        Wait for element to be visible.

        Args:
            locator: Tuple of (By strategy, locator string)
            timeout: Maximum wait time in seconds
        """
        self.waiter.wait_for_element_visible(locator, timeout=timeout)

    def wait_for_element_clickable(
        self, locator: Tuple[By, str], timeout: int = 10
    ) -> None:
        """
        Wait for element to be clickable.

        Args:
            locator: Tuple of (By strategy, locator string)
            timeout: Maximum wait time in seconds
        """
        self.waiter.wait_for_element_clickable(locator, timeout=timeout)

    def is_element_visible(self, locator: Tuple[By, str]) -> bool:
        """
        Check if element is visible on the page.

        Args:
            locator: Tuple of (By strategy, locator string)

        Returns:
            True if element is visible, False otherwise
        """
        try:
            element = self.finder.find_element(locator)
            return element.is_displayed()
        except:
            return False

    def get_element_text(self, locator: Tuple[By, str]) -> str:
        """
        Get text content of an element.

        Args:
            locator: Tuple of (By strategy, locator string)

        Returns:
            Element text content
        """
        element = self.finder.find_element(locator)
        return element.text

    def click_element(self, locator: Tuple[By, str]) -> None:
        """
        Click an element.

        Args:
            locator: Tuple of (By strategy, locator string)
        """
        self.interactor.click(locator)

    def type_text(
        self, locator: Tuple[By, str], text: str, clear_first: bool = True
    ) -> None:
        """
        Type text into an element.

        Args:
            locator: Tuple of (By strategy, locator string)
            text: Text to type
            clear_first: Whether to clear field before typing
        """
        if clear_first:
            element = self.finder.find_element(locator)
            element.clear()
        self.interactor.send_keys(locator, text)

    def execute_script(self, script: str, *args) -> any:
        """
        Execute JavaScript on the page.

        Args:
            script: JavaScript code to execute
            *args: Arguments to pass to the script

        Returns:
            Script execution result
        """
        return self.driver.execute_script(script, *args)

    def scroll_to_element(self, locator: Tuple[By, str]) -> None:
        """
        Scroll to make element visible.

        Args:
            locator: Tuple of (By strategy, locator string)
        """
        element = self.finder.find_element(locator)
        self.execute_script("arguments[0].scrollIntoView(true);", element)

    def get_attribute(self, locator: Tuple[By, str], attribute: str) -> str:
        """
        Get attribute value from an element.

        Args:
            locator: Tuple of (By strategy, locator string)
            attribute: Attribute name

        Returns:
            Attribute value
        """
        element = self.finder.find_element(locator)
        return element.get_attribute(attribute)


# ADAPTATION CHECKLIST:
# [ ] Copied to pages/base_page.py
# [ ] Removed pytest.skip() line
# [ ] Reviewed all methods for your application's needs
# [ ] Added application-specific methods if needed
# [ ] Tested with your application
