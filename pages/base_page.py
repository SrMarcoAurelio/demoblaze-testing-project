"""
Base Page Object Model
Author: Marc Arévalo
Version: 2.0

This base class contains common methods used across all page objects.
All page objects should inherit from this class.
Universal and reusable across any web application.
"""

import logging
import time
from typing import Any, List, Optional, Tuple, Union

from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.alert import Alert
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from config import config


class BasePage:
    """
    Base class for all Page Objects.

    Provides common methods for interacting with web elements:
    - Finding elements with waits
    - Clicking elements
    - Typing text
    - Handling alerts
    - Taking screenshots

    Universal and reusable across any web application.
    """

    SLEEP_SHORT = 0.5
    SLEEP_MEDIUM = 1.0
    SLEEP_LONG = 2.0
    SLEEP_MODAL = 1.5

    def __init__(
        self,
        driver: WebDriver,
        base_url: Optional[str] = None,
        timeout: int = 10,
    ) -> None:
        """
        Initialize the BasePage.

        Args:
            driver: Selenium WebDriver instance
            base_url: Base URL of the application (optional, defaults to config.BASE_URL)
            timeout: Default timeout for waits (default: 10 seconds)
        """
        self.driver: WebDriver = driver
        self.base_url: str = base_url or config.BASE_URL
        self.timeout: int = timeout
        self.logger: logging.Logger = logging.getLogger(
            self.__class__.__name__
        )

    def find_element(
        self, locator: Tuple[str, str], timeout: Optional[int] = None
    ) -> WebElement:
        """
        Find an element with explicit wait.

        Args:
            locator: Tuple (By.TYPE, "value")
            timeout: Optional custom timeout

        Returns:
            WebElement if found

        Raises:
            TimeoutException if element not found
        """
        wait_time: int = timeout if timeout else self.timeout
        try:
            element: WebElement = WebDriverWait(self.driver, wait_time).until(
                EC.presence_of_element_located(locator)
            )
            self.logger.debug(f"Element found: {locator}")
            return element
        except TimeoutException:
            self.logger.error(f"Element not found: {locator}")
            raise

    def find_elements(
        self, locator: Tuple[str, str], timeout: Optional[int] = None
    ) -> List[WebElement]:
        """
        Find multiple elements with explicit wait.

        Args:
            locator: Tuple (By.TYPE, "value")
            timeout: Optional custom timeout

        Returns:
            List of WebElements
        """
        wait_time: int = timeout if timeout else self.timeout
        try:
            elements: List[WebElement] = WebDriverWait(
                self.driver, wait_time
            ).until(EC.presence_of_all_elements_located(locator))
            self.logger.debug(f"Found {len(elements)} elements: {locator}")
            return elements
        except TimeoutException:
            self.logger.warning(f"No elements found: {locator}")
            return []

    def wait_for_element_visible(
        self, locator: Tuple[str, str], timeout: Optional[int] = None
    ) -> WebElement:
        """
        Wait for element to be visible.

        Args:
            locator: Tuple (By.TYPE, "value")
            timeout: Optional custom timeout

        Returns:
            WebElement if visible
        """
        wait_time: int = timeout if timeout else self.timeout
        try:
            element: WebElement = WebDriverWait(self.driver, wait_time).until(
                EC.visibility_of_element_located(locator)
            )
            self.logger.debug(f"Element visible: {locator}")
            return element
        except TimeoutException:
            self.logger.error(f"Element not visible: {locator}")
            raise

    def wait_for_element_clickable(
        self, locator: Tuple[str, str], timeout: Optional[int] = None
    ) -> WebElement:
        """
        Wait for element to be clickable.

        Args:
            locator: Tuple (By.TYPE, "value")
            timeout: Optional custom timeout

        Returns:
            WebElement if clickable
        """
        wait_time: int = timeout if timeout else self.timeout
        try:
            element: WebElement = WebDriverWait(self.driver, wait_time).until(
                EC.element_to_be_clickable(locator)
            )
            self.logger.debug(f"Element clickable: {locator}")
            return element
        except TimeoutException:
            self.logger.error(f"Element not clickable: {locator}")
            raise

    def wait_for_element_invisible(
        self, locator: Tuple[str, str], timeout: Optional[int] = None
    ) -> bool:
        """
        Wait for element to become invisible.

        Args:
            locator: Tuple (By.TYPE, "value")
            timeout: Optional custom timeout

        Returns:
            True if element becomes invisible
        """
        wait_time = timeout if timeout else self.timeout
        try:
            result = WebDriverWait(self.driver, wait_time).until(
                EC.invisibility_of_element_located(locator)
            )
            self.logger.debug(f"Element invisible: {locator}")
            return bool(result)
        except TimeoutException:
            self.logger.error(f"Element still visible: {locator}")
            raise

    def click(
        self, locator: Tuple[str, str], timeout: Optional[int] = None
    ) -> None:
        """
        Click an element.

        Args:
            locator: Tuple (By.TYPE, "value")
            timeout: Optional custom timeout
        """
        element: WebElement = self.wait_for_element_clickable(locator, timeout)
        element.click()
        self.logger.info(f"Clicked: {locator}")

    def type(
        self,
        locator: Tuple[str, str],
        text: str,
        clear_first: bool = True,
        timeout: Optional[int] = None,
    ) -> None:
        """
        Type text into an element.

        Args:
            locator: Tuple (By.TYPE, "value")
            text: Text to type
            clear_first: Clear field before typing (default: True)
            timeout: Optional custom timeout
        """
        element: WebElement = self.wait_for_element_visible(locator, timeout)
        if clear_first:
            element.clear()
        element.send_keys(text)
        self.logger.info(f"Typed '{text}' into: {locator}")

    def get_text(
        self, locator: Tuple[str, str], timeout: Optional[int] = None
    ) -> str:
        """
        Get text from an element.

        Args:
            locator: Tuple (By.TYPE, "value")
            timeout: Optional custom timeout

        Returns:
            Text content of element
        """
        element: WebElement = self.wait_for_element_visible(locator, timeout)
        text: str = element.text
        self.logger.debug(f"Got text '{text}' from: {locator}")
        return text

    def get_attribute(
        self,
        locator: Tuple[str, str],
        attribute: str,
        timeout: Optional[int] = None,
    ) -> Optional[str]:
        """
        Get attribute value from an element.

        Args:
            locator: Tuple (By.TYPE, "value")
            attribute: Attribute name
            timeout: Optional custom timeout

        Returns:
            Attribute value
        """
        element = self.find_element(locator, timeout)
        value = element.get_attribute(attribute)
        self.logger.debug(
            f"Got attribute '{attribute}' = '{value}' from: {locator}"
        )
        return value

    def is_element_present(
        self, locator: Tuple[str, str], timeout: int = 2
    ) -> bool:
        """
        Check if element is present (short timeout).

        Args:
            locator: Tuple (By.TYPE, "value")
            timeout: Timeout in seconds (default: 2)

        Returns:
            True if element present, False otherwise
        """
        try:
            self.find_element(locator, timeout)
            return True
        except TimeoutException:
            return False

    def is_element_visible(
        self, locator: Tuple[str, str], timeout: int = 2
    ) -> bool:
        """
        Check if element is visible (short timeout).

        Args:
            locator: Tuple (By.TYPE, "value")
            timeout: Timeout in seconds (default: 2)

        Returns:
            True if element visible, False otherwise
        """
        try:
            self.wait_for_element_visible(locator, timeout)
            return True
        except TimeoutException:
            return False

    def wait_for_alert(self, timeout: int = 5) -> Optional[Alert]:
        """
        Wait for alert to be present.

        Args:
            timeout: Timeout in seconds (default: 5)

        Returns:
            Alert object if present, None otherwise
        """
        try:
            WebDriverWait(self.driver, timeout).until(EC.alert_is_present())
            alert: Alert = self.driver.switch_to.alert
            self.logger.info(f"Alert present: '{alert.text}'")
            return alert
        except TimeoutException:
            self.logger.debug("No alert present")
            return None

    def get_alert_text(self, timeout: int = 5) -> Optional[str]:
        """
        Get alert text and accept it.

        Args:
            timeout: Timeout in seconds (default: 5)

        Returns:
            Alert text if present, None otherwise
        """
        alert: Optional[Alert] = self.wait_for_alert(timeout)
        if alert:
            alert_text: str = alert.text
            alert.accept()
            self.logger.info(f"Alert accepted: '{alert_text}'")
            return alert_text
        return None

    def accept_alert(self, timeout: int = 5) -> None:
        """
        Accept alert if present.

        Args:
            timeout: Timeout in seconds (default: 5)
        """
        alert = self.wait_for_alert(timeout)
        if alert:
            alert.accept()
            self.logger.info("Alert accepted")

    def dismiss_alert(self, timeout: int = 5) -> None:
        """
        Dismiss alert if present.

        Args:
            timeout: Timeout in seconds (default: 5)
        """
        alert = self.wait_for_alert(timeout)
        if alert:
            alert.dismiss()
            self.logger.info("Alert dismissed")

    def navigate_to(self, url: str) -> None:
        """
        Navigate to a URL.

        Args:
            url: URL to navigate to
        """
        self.driver.get(url)
        self.logger.info(f"Navigated to: {url}")

    def refresh_page(self) -> None:
        """Refresh the current page."""
        self.driver.refresh()
        self.logger.info("Page refreshed")

    def go_back(self) -> None:
        """Navigate back in browser history."""
        self.driver.back()
        self.logger.info("Navigated back")

    def get_current_url(self) -> str:
        """
        Get current URL.

        Returns:
            Current URL
        """
        url: str = self.driver.current_url
        self.logger.debug(f"Current URL: {url}")
        return url

    def get_page_title(self) -> str:
        """
        Get page title.

        Returns:
            Page title
        """
        title: str = self.driver.title
        self.logger.debug(f"Page title: {title}")
        return title

    def execute_script(self, script: str, *args: Any) -> Any:
        """
        Execute JavaScript.

        Args:
            script: JavaScript code
            *args: Arguments to pass to script

        Returns:
            Script return value
        """
        result = self.driver.execute_script(script, *args)
        self.logger.debug(f"Executed script: {script[:50]}...")
        return result

    def scroll_to_element(self, locator: Tuple[str, str]) -> None:
        """
        Scroll to element.

        Args:
            locator: Tuple (By.TYPE, "value")
        """
        element = self.find_element(locator)
        self.driver.execute_script(
            "arguments[0].scrollIntoView(true);", element
        )
        self.logger.info(f"Scrolled to: {locator}")

    def scroll_to_bottom(self) -> None:
        """Scroll to bottom of page."""
        self.driver.execute_script(
            "window.scrollTo(0, document.body.scrollHeight);"
        )
        self.logger.info("Scrolled to bottom")

    def send_keys(
        self,
        locator: Tuple[str, str],
        keys: str,
        timeout: Optional[int] = None,
    ) -> None:
        """
        Send keyboard keys to element.

        Args:
            locator: Tuple (By.TYPE, "value")
            keys: Keys to send (e.g., Keys.ENTER)
            timeout: Optional custom timeout
        """
        element = self.find_element(locator, timeout)
        element.send_keys(keys)
        self.logger.info(f"Sent keys to: {locator}")

    def press_key(self, key: str) -> None:
        """
        Press a keyboard key.

        Args:
            key: Key to press (e.g., Keys.ESCAPE)
        """
        ActionChains(self.driver).send_keys(key).perform()
        self.logger.info(f"Pressed key: {key}")

    def hover(
        self, locator: Tuple[str, str], timeout: Optional[int] = None
    ) -> None:
        """
        Hover over element.

        Args:
            locator: Tuple (By.TYPE, "value")
            timeout: Optional custom timeout
        """
        element = self.find_element(locator, timeout)
        ActionChains(self.driver).move_to_element(element).perform()
        self.logger.info(f"Hovered over: {locator}")

    def wait(self, seconds: Union[int, float]) -> None:
        """
        Explicit wait (use sparingly, prefer explicit waits).

        Args:
            seconds: Seconds to wait
        """
        time.sleep(seconds)
        self.logger.debug(f"Waited {seconds} seconds")

    def wait_for_page_load(self, timeout: int = 30) -> bool:
        """
        Wait for page to finish loading.

        Uses JavaScript document.readyState to verify page is fully loaded.

        Args:
            timeout: Maximum time to wait in seconds (default: 30)

        Returns:
            True if page loaded successfully

        Raises:
            TimeoutException: If page doesn't load within timeout
        """
        try:
            WebDriverWait(self.driver, timeout).until(
                lambda d: d.execute_script("return document.readyState")
                == "complete"
            )
            self.logger.debug("Page loaded successfully")
            return True
        except TimeoutException:
            self.logger.error(f"Page did not load within {timeout} seconds")
            raise

    def take_screenshot(self, filename: str) -> None:
        """
        Take screenshot.

        Args:
            filename: Path to save screenshot
        """
        self.driver.save_screenshot(filename)
        self.logger.info(f"Screenshot saved: {filename}")

    def get_page_source(self) -> str:
        """
        Get page source HTML.

        Returns:
            Page source HTML
        """
        return self.driver.page_source
