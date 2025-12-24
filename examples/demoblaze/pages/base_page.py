"""
Base Page Object Model - Universal Test Automation Framework
Author: Marc Arevalo
Version: 6.0

Base class for Page Objects using composition with universal framework components.
All page objects should inherit from this class.

This class is a CONVENIENCE WRAPPER around the universal framework components.
For new code, consider using ElementFinder, ElementInteractor, and WaitHandler directly.
"""

import logging
import time
from typing import Any, List, Optional, Tuple, Union

from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.alert import Alert
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from config import config
from framework.core import ElementFinder, ElementInteractor, WaitHandler


class BasePage:
    """
    Base class for all Page Objects.

    Uses composition with universal framework components:
    - ElementFinder: For finding elements with intelligent strategies
    - ElementInteractor: For reliable element interactions
    - WaitHandler: For intelligent waiting without sleep()

    This class provides backward compatibility while using modern
    discovery-based testing patterns internally.

    For new code, consider using the framework components directly:
        from framework.core import ElementFinder, ElementInteractor, WaitHandler

    Attributes:
        driver: Selenium WebDriver instance
        base_url: Base URL of the application
        timeout: Default timeout for waits
        finder: ElementFinder instance for element discovery
        interactor: ElementInteractor instance for interactions
        waiter: WaitHandler instance for intelligent waiting
    """

    def __init__(
        self,
        driver: WebDriver,
        base_url: Optional[str] = None,
        timeout: int = 10,
    ) -> None:
        """
        Initialize the BasePage with universal framework components.

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

        # Universal framework components (composition over inheritance)
        self.finder: ElementFinder = ElementFinder(driver)
        self.interactor: ElementInteractor = ElementInteractor(driver)
        self.waiter: WaitHandler = WaitHandler(driver, default_timeout=timeout)

    # ========================================================================
    # ELEMENT FINDING METHODS - Delegate to ElementFinder
    # ========================================================================

    def find_element(
        self, locator: Tuple[str, str], timeout: Optional[int] = None
    ) -> WebElement:
        """
        Find an element with explicit wait.

        Delegates to WaitHandler for intelligent waiting.

        Args:
            locator: Tuple (By.TYPE, "value")
            timeout: Optional custom timeout

        Returns:
            WebElement if found

        Raises:
            TimeoutException if element not found
        """
        wait_time: int = timeout if timeout else self.timeout
        element = self.waiter.wait_for_element_present(
            locator[0], locator[1], timeout=wait_time
        )
        if element:
            self.logger.debug(f"Element found: {locator}")
            return element
        else:
            self.logger.error(f"Element not found: {locator}")
            raise TimeoutException(f"Element not found: {locator}")

    def find_elements(
        self, locator: Tuple[str, str], timeout: Optional[int] = None
    ) -> List[WebElement]:
        """
        Find multiple elements with explicit wait.

        Delegates to ElementFinder.

        Args:
            locator: Tuple (By.TYPE, "value")
            timeout: Optional custom timeout

        Returns:
            List of WebElements
        """
        wait_time: int = timeout if timeout else self.timeout
        try:
            WebDriverWait(self.driver, wait_time).until(
                EC.presence_of_element_located(locator)
            )
            elements: List[WebElement] = self.finder.find_elements(
                locator[0], locator[1]
            )
            self.logger.debug(f"Found {len(elements)} elements: {locator}")
            return elements
        except TimeoutException:
            self.logger.warning(f"No elements found: {locator}")
            return []

    # ========================================================================
    # WAITING METHODS - Delegate to WaitHandler
    # ========================================================================

    def wait_for_element_visible(
        self, locator: Tuple[str, str], timeout: Optional[int] = None
    ) -> Optional[WebElement]:
        """
        Wait for element to be visible.

        Delegates to WaitHandler.

        Args:
            locator: Tuple (By.TYPE, "value")
            timeout: Optional custom timeout

        Returns:
            WebElement if visible, None if timeout
        """
        wait_time: int = timeout if timeout else self.timeout
        element = self.waiter.wait_for_element_visible(
            locator[0], locator[1], timeout=wait_time
        )
        if element:
            self.logger.debug(f"Element visible: {locator}")
        else:
            self.logger.warning(f"Element not visible: {locator}")
        return element

    def wait_for_element_clickable(
        self, locator: Tuple[str, str], timeout: Optional[int] = None
    ) -> Optional[WebElement]:
        """
        Wait for element to be clickable.

        Delegates to WaitHandler.

        Args:
            locator: Tuple (By.TYPE, "value")
            timeout: Optional custom timeout

        Returns:
            WebElement if clickable, None if timeout
        """
        wait_time: int = timeout if timeout else self.timeout
        element = self.waiter.wait_for_element_clickable(
            locator[0], locator[1], timeout=wait_time
        )
        if element:
            self.logger.debug(f"Element clickable: {locator}")
        else:
            self.logger.warning(f"Element not clickable: {locator}")
        return element

    def wait_for_element_invisible(
        self, locator: Tuple[str, str], timeout: Optional[int] = None
    ) -> bool:
        """
        Wait for element to become invisible.

        Delegates to WaitHandler.

        Args:
            locator: Tuple (By.TYPE, "value")
            timeout: Optional custom timeout

        Returns:
            True if element became invisible, False if timeout
        """
        wait_time: int = timeout if timeout else self.timeout
        result = self.waiter.wait_for_element_invisible(
            locator[0], locator[1], timeout=wait_time
        )
        if result:
            self.logger.debug(f"Element invisible: {locator}")
        else:
            self.logger.warning(f"Element still visible: {locator}")
        return result

    # ========================================================================
    # INTERACTION METHODS - Delegate to ElementInteractor
    # ========================================================================

    def click(self, locator: Tuple[str, str], force: bool = False) -> None:
        """
        Click an element.

        Delegates to ElementInteractor with retry logic.

        Args:
            locator: Tuple (By.TYPE, "value")
            force: If True, use JavaScript click as fallback
        """
        element = self.find_element(locator)
        success = self.interactor.click(element, force=force)
        if success:
            self.logger.debug(f"Clicked element: {locator}")
        else:
            self.logger.error(f"Failed to click: {locator}")
            raise Exception(f"Failed to click element: {locator}")

    def type(
        self, locator: Tuple[str, str], text: str, clear_first: bool = True
    ) -> None:
        """
        Type text into an element.

        Delegates to ElementInteractor.

        Args:
            locator: Tuple (By.TYPE, "value")
            text: Text to type
            clear_first: Clear field before typing (default: True)
        """
        element = self.find_element(locator)
        success = self.interactor.type(element, text, clear_first=clear_first)
        if success:
            self.logger.debug(f"Typed '{text}' into: {locator}")
        else:
            self.logger.error(f"Failed to type into: {locator}")
            raise Exception(f"Failed to type into element: {locator}")

    def get_text(self, locator: Tuple[str, str]) -> str:
        """
        Get text content of an element.

        Args:
            locator: Tuple (By.TYPE, "value")

        Returns:
            Text content of the element
        """
        element = self.find_element(locator)
        text = element.text
        self.logger.debug(f"Got text '{text}' from: {locator}")
        return text

    def get_attribute(
        self, locator: Tuple[str, str], attribute: str
    ) -> Optional[str]:
        """
        Get attribute value of an element.

        Args:
            locator: Tuple (By.TYPE, "value")
            attribute: Attribute name

        Returns:
            Attribute value or None
        """
        element = self.find_element(locator)
        value = element.get_attribute(attribute)
        self.logger.debug(
            f"Got attribute '{attribute}'='{value}' from: {locator}"
        )
        return value

    # ========================================================================
    # ELEMENT STATE CHECKING METHODS
    # ========================================================================

    def is_element_present(
        self, locator: Tuple[str, str], timeout: int = 3
    ) -> bool:
        """
        Check if element is present in DOM.

        Args:
            locator: Tuple (By.TYPE, "value")
            timeout: Timeout for check (default: 3 seconds)

        Returns:
            True if present, False otherwise
        """
        element = self.waiter.wait_for_element_present(
            locator[0], locator[1], timeout=timeout
        )
        return element is not None

    def is_element_visible(
        self, locator: Tuple[str, str], timeout: int = 3
    ) -> bool:
        """
        Check if element is visible.

        Args:
            locator: Tuple (By.TYPE, "value")
            timeout: Timeout for check (default: 3 seconds)

        Returns:
            True if visible, False otherwise
        """
        element = self.waiter.wait_for_element_visible(
            locator[0], locator[1], timeout=timeout
        )
        return element is not None

    # ========================================================================
    # ALERT HANDLING METHODS
    # ========================================================================

    def wait_for_alert(self, timeout: int = 5) -> Optional[Alert]:
        """
        Wait for alert to be present.

        Delegates to WaitHandler.

        Args:
            timeout: Timeout in seconds

        Returns:
            Alert object if present, None if timeout
        """
        alert = self.waiter.wait_for_alert(timeout=timeout)
        if alert:
            self.logger.debug("Alert present")
        return alert

    def get_alert_text(self, timeout: int = 5) -> Optional[str]:
        """
        Get alert text.

        Args:
            timeout: Timeout in seconds

        Returns:
            Alert text or None if no alert
        """
        alert = self.wait_for_alert(timeout=timeout)
        if alert:
            text = alert.text
            self.logger.debug(f"Alert text: '{text}'")
            return text
        return None

    def accept_alert(self, timeout: int = 5) -> None:
        """
        Accept (click OK on) alert.

        Args:
            timeout: Timeout in seconds
        """
        alert = self.wait_for_alert(timeout=timeout)
        if alert:
            alert.accept()
            self.logger.debug("Alert accepted")

    def dismiss_alert(self, timeout: int = 5) -> None:
        """
        Dismiss (click Cancel on) alert.

        Args:
            timeout: Timeout in seconds
        """
        alert = self.wait_for_alert(timeout=timeout)
        if alert:
            alert.dismiss()
            self.logger.debug("Alert dismissed")

    # ========================================================================
    # NAVIGATION METHODS
    # ========================================================================

    def navigate_to(self, url: str) -> None:
        """Navigate to a URL."""
        self.driver.get(url)
        self.logger.info(f"Navigated to: {url}")

    def refresh_page(self) -> None:
        """Refresh the current page."""
        self.driver.refresh()
        self.logger.debug("Page refreshed")

    def go_back(self) -> None:
        """Go back to previous page."""
        self.driver.back()
        self.logger.debug("Navigated back")

    def get_current_url(self) -> str:
        """
        Get current URL.

        Returns:
            Current page URL
        """
        url = self.driver.current_url
        self.logger.debug(f"Current URL: {url}")
        return url

    def get_page_title(self) -> str:
        """
        Get page title.

        Returns:
            Page title
        """
        title = self.driver.title
        self.logger.debug(f"Page title: {title}")
        return title

    # ========================================================================
    # JAVASCRIPT EXECUTION METHODS
    # ========================================================================

    def execute_script(self, script: str, *args: Any) -> Any:
        """
        Execute JavaScript.

        Args:
            script: JavaScript code to execute
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

        Delegates to ElementInteractor.

        Args:
            locator: Tuple (By.TYPE, "value")
        """
        element = self.find_element(locator)
        self.interactor.scroll_to_element(element)
        self.logger.debug(f"Scrolled to: {locator}")

    def scroll_to_bottom(self) -> None:
        """Scroll to bottom of page."""
        self.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        self.logger.debug("Scrolled to bottom")

    # ========================================================================
    # KEYBOARD AND MOUSE METHODS
    # ========================================================================

    def send_keys(self, locator: Tuple[str, str], *keys_to_send: str) -> None:
        """
        Send keys to an element.

        Args:
            locator: Tuple (By.TYPE, "value")
            *keys_to_send: Keys to send
        """
        element = self.find_element(locator)
        element.send_keys(*keys_to_send)
        self.logger.debug(f"Sent keys to: {locator}")

    def press_key(self, key: str) -> None:
        """
        Press a keyboard key (e.g., Keys.ENTER, Keys.ESCAPE).

        Args:
            key: Key to press (from selenium.webdriver.common.keys.Keys)
        """
        actions = ActionChains(self.driver)
        actions.send_keys(key).perform()
        self.logger.debug(f"Pressed key: {key}")

    def hover(self, locator: Tuple[str, str], duration: float = 0.5) -> None:
        """
        Hover over an element.

        Delegates to ElementInteractor.

        Args:
            locator: Tuple (By.TYPE, "value")
            duration: Hover duration in seconds
        """
        element = self.find_element(locator)
        self.interactor.hover(element)
        if duration > 0:
            time.sleep(duration)
        self.logger.debug(f"Hovered over: {locator}")

    # ========================================================================
    # UTILITY METHODS
    # ========================================================================

    def wait(self, seconds: Union[int, float]) -> None:
        """
        Explicit wait (sleep).

        WARNING: Use WaitHandler condition-based waits instead when possible.
        This method should only be used when absolutely necessary.

        Args:
            seconds: Seconds to wait
        """
        self.logger.warning(
            f"Using explicit sleep({seconds}s) - consider using WaitHandler instead"
        )
        time.sleep(seconds)

    def wait_for_page_load(self, timeout: int = 30) -> bool:
        """
        Wait for page to load completely.

        Args:
            timeout: Timeout in seconds

        Returns:
            True if page loaded, False if timeout
        """
        try:
            WebDriverWait(self.driver, timeout).until(
                lambda driver: driver.execute_script(
                    "return document.readyState"
                )
                == "complete"
            )
            self.logger.debug("Page loaded completely")
            return True
        except TimeoutException:
            self.logger.warning("Page load timeout")
            return False

    def take_screenshot(self, filename: str) -> None:
        """
        Take screenshot and save to file.

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
        source = self.driver.page_source
        self.logger.debug(f"Got page source ({len(source)} chars)")
        return source

    # ========================================================================
    # MODAL HANDLING METHODS
    # ========================================================================

    def close_modal_with_button(
        self,
        button_locator: Tuple[str, str],
        timeout: int = 5,
        wait_after: float = 0.5,
    ) -> bool:
        """
        Close modal by clicking a button.

        Args:
            button_locator: Locator for close button
            timeout: Timeout to wait for button
            wait_after: Time to wait after clicking (default: 0.5s)

        Returns:
            True if closed successfully, False otherwise
        """
        try:
            button = self.wait_for_element_clickable(
                button_locator, timeout=timeout
            )
            if button:
                self.click(button_locator)
                if wait_after > 0:
                    time.sleep(wait_after)
                self.logger.debug("Modal closed with button")
                return True
            return False
        except Exception as e:
            self.logger.warning(f"Failed to close modal: {e}")
            return False

    def close_modal_with_esc(self, wait_after: float = 0.5) -> None:
        """
        Close modal by pressing ESC key.

        Args:
            wait_after: Time to wait after pressing ESC (default: 0.5s)
        """
        self.press_key(Keys.ESCAPE)
        if wait_after > 0:
            time.sleep(wait_after)
        self.logger.debug("Modal closed with ESC key")

    def is_modal_visible(
        self, modal_locator: Tuple[str, str], timeout: int = 3
    ) -> bool:
        """
        Check if modal is visible.

        Args:
            modal_locator: Locator for modal element
            timeout: Timeout for check

        Returns:
            True if modal visible, False otherwise
        """
        return self.is_element_visible(modal_locator, timeout=timeout)
