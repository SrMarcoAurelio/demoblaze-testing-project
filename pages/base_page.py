"""
Base Page Object Model
Author: Marc Arévalo
Version: 1.0

This base class contains common methods used across all page objects.
All page objects should inherit from this class.
"""

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.action_chains import ActionChains
import logging
import time

logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')


class BasePage:
    """
    Base class for all Page Objects.

    Provides common methods for interacting with web elements:
    - Finding elements with waits
    - Clicking elements
    - Typing text
    - Handling alerts
    - Taking screenshots
    """

    def __init__(self, driver, timeout=10):
        """
        Initialize the BasePage.

        Args:
            driver: Selenium WebDriver instance
            timeout: Default timeout for waits (default: 10 seconds)
        """
        self.driver = driver
        self.timeout = timeout
        self.wait = WebDriverWait(driver, timeout)
        self.logger = logging.getLogger(self.__class__.__name__)


    def find_element(self, locator, timeout=None):
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
        wait_time = timeout if timeout else self.timeout
        try:
            element = WebDriverWait(self.driver, wait_time).until(
                EC.presence_of_element_located(locator)
            )
            self.logger.debug(f"Element found: {locator}")
            return element
        except TimeoutException:
            self.logger.error(f"Element not found: {locator}")
            raise

    def find_elements(self, locator, timeout=None):
        """
        Find multiple elements with explicit wait.

        Args:
            locator: Tuple (By.TYPE, "value")
            timeout: Optional custom timeout

        Returns:
            List of WebElements
        """
        wait_time = timeout if timeout else self.timeout
        try:
            elements = WebDriverWait(self.driver, wait_time).until(
                EC.presence_of_all_elements_located(locator)
            )
            self.logger.debug(f"Found {len(elements)} elements: {locator}")
            return elements
        except TimeoutException:
            self.logger.warning(f"No elements found: {locator}")
            return []

    def wait_for_element_visible(self, locator, timeout=None):
        """
        Wait for element to be visible.

        Args:
            locator: Tuple (By.TYPE, "value")
            timeout: Optional custom timeout

        Returns:
            WebElement if visible
        """
        wait_time = timeout if timeout else self.timeout
        try:
            element = WebDriverWait(self.driver, wait_time).until(
                EC.visibility_of_element_located(locator)
            )
            self.logger.debug(f"Element visible: {locator}")
            return element
        except TimeoutException:
            self.logger.error(f"Element not visible: {locator}")
            raise

    def wait_for_element_clickable(self, locator, timeout=None):
        """
        Wait for element to be clickable.

        Args:
            locator: Tuple (By.TYPE, "value")
            timeout: Optional custom timeout

        Returns:
            WebElement if clickable
        """
        wait_time = timeout if timeout else self.timeout
        try:
            element = WebDriverWait(self.driver, wait_time).until(
                EC.element_to_be_clickable(locator)
            )
            self.logger.debug(f"Element clickable: {locator}")
            return element
        except TimeoutException:
            self.logger.error(f"Element not clickable: {locator}")
            raise

    def wait_for_element_invisible(self, locator, timeout=None):
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
            return result
        except TimeoutException:
            self.logger.error(f"Element still visible: {locator}")
            raise

    def click(self, locator, timeout=None):
        """
        Click an element.

        Args:
            locator: Tuple (By.TYPE, "value")
            timeout: Optional custom timeout
        """
        element = self.wait_for_element_clickable(locator, timeout)
        element.click()
        self.logger.info(f"Clicked: {locator}")

    def type(self, locator, text, clear_first=True, timeout=None):
        """
        Type text into an element.

        Args:
            locator: Tuple (By.TYPE, "value")
            text: Text to type
            clear_first: Clear field before typing (default: True)
            timeout: Optional custom timeout
        """
        element = self.wait_for_element_visible(locator, timeout)
        if clear_first:
            element.clear()
        element.send_keys(text)
        self.logger.info(f"Typed '{text}' into: {locator}")

    def get_text(self, locator, timeout=None):
        """
        Get text from an element.

        Args:
            locator: Tuple (By.TYPE, "value")
            timeout: Optional custom timeout

        Returns:
            Text content of element
        """
        element = self.wait_for_element_visible(locator, timeout)
        text = element.text
        self.logger.debug(f"Got text '{text}' from: {locator}")
        return text

    def get_attribute(self, locator, attribute, timeout=None):
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
        self.logger.debug(f"Got attribute '{attribute}' = '{value}' from: {locator}")
        return value

    def is_element_present(self, locator, timeout=2):
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

    def is_element_visible(self, locator, timeout=2):
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


    def wait_for_alert(self, timeout=5):
        """
        Wait for alert to be present.

        Args:
            timeout: Timeout in seconds (default: 5)

        Returns:
            Alert object if present, None otherwise
        """
        try:
            WebDriverWait(self.driver, timeout).until(EC.alert_is_present())
            alert = self.driver.switch_to.alert
            self.logger.info(f"Alert present: '{alert.text}'")
            return alert
        except TimeoutException:
            self.logger.debug("No alert present")
            return None

    def get_alert_text(self, timeout=5):
        """
        Get alert text and accept it.

        Args:
            timeout: Timeout in seconds (default: 5)

        Returns:
            Alert text if present, None otherwise
        """
        alert = self.wait_for_alert(timeout)
        if alert:
            alert_text = alert.text
            alert.accept()
            self.logger.info(f"Alert accepted: '{alert_text}'")
            return alert_text
        return None

    def accept_alert(self, timeout=5):
        """
        Accept alert if present.

        Args:
            timeout: Timeout in seconds (default: 5)
        """
        alert = self.wait_for_alert(timeout)
        if alert:
            alert.accept()
            self.logger.info("Alert accepted")

    def dismiss_alert(self, timeout=5):
        """
        Dismiss alert if present.

        Args:
            timeout: Timeout in seconds (default: 5)
        """
        alert = self.wait_for_alert(timeout)
        if alert:
            alert.dismiss()
            self.logger.info("Alert dismissed")


    def navigate_to(self, url):
        """
        Navigate to a URL.

        Args:
            url: URL to navigate to
        """
        self.driver.get(url)
        self.logger.info(f"Navigated to: {url}")

    def refresh_page(self):
        """Refresh the current page."""
        self.driver.refresh()
        self.logger.info("Page refreshed")

    def go_back(self):
        """Navigate back in browser history."""
        self.driver.back()
        self.logger.info("Navigated back")

    def get_current_url(self):
        """
        Get current URL.

        Returns:
            Current URL
        """
        url = self.driver.current_url
        self.logger.debug(f"Current URL: {url}")
        return url

    def get_page_title(self):
        """
        Get page title.

        Returns:
            Page title
        """
        title = self.driver.title
        self.logger.debug(f"Page title: {title}")
        return title


    def execute_script(self, script, *args):
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

    def scroll_to_element(self, locator):
        """
        Scroll to element.

        Args:
            locator: Tuple (By.TYPE, "value")
        """
        element = self.find_element(locator)
        self.driver.execute_script("arguments[0].scrollIntoView(true);", element)
        self.logger.info(f"Scrolled to: {locator}")

    def scroll_to_bottom(self):
        """Scroll to bottom of page."""
        self.driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        self.logger.info("Scrolled to bottom")


    def send_keys(self, locator, keys, timeout=None):
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

    def press_key(self, key):
        """
        Press a keyboard key.

        Args:
            key: Key to press (e.g., Keys.ESCAPE)
        """
        ActionChains(self.driver).send_keys(key).perform()
        self.logger.info(f"Pressed key: {key}")

    def hover(self, locator, timeout=None):
        """
        Hover over element.

        Args:
            locator: Tuple (By.TYPE, "value")
            timeout: Optional custom timeout
        """
        element = self.find_element(locator, timeout)
        ActionChains(self.driver).move_to_element(element).perform()
        self.logger.info(f"Hovered over: {locator}")


    def wait(self, seconds):
        """
        Explicit wait (use sparingly, prefer explicit waits).

        Args:
            seconds: Seconds to wait
        """
        time.sleep(seconds)
        self.logger.debug(f"Waited {seconds} seconds")

    def take_screenshot(self, filename):
        """
        Take screenshot.

        Args:
            filename: Path to save screenshot
        """
        self.driver.save_screenshot(filename)
        self.logger.info(f"Screenshot saved: {filename}")

    def get_page_source(self):
        """
        Get page source HTML.

        Returns:
            Page source HTML
        """
        return self.driver.page_source
