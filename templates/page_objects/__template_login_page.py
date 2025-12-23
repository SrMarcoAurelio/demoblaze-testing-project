"""
Universal Login Page Template

INSTRUCTIONS:
1. Copy this file to your pages/ directory
2. Rename it to: login_page.py (or YOUR_login_page.py)
3. Replace ALL_CAPS placeholders with YOUR application's actual values
4. Find YOUR application's locators using browser DevTools (F12)
5. Remove pytest.skip() when ready to use
6. Adapt methods to YOUR login workflow

Example locators (REPLACE THESE):
- USERNAME_FIELD: The input field for username/email
- PASSWORD_FIELD: The input field for password
- LOGIN_BUTTON: The button to submit login
- ERROR_MESSAGE: Where login errors are displayed
- SUCCESS_INDICATOR: Element that appears after successful login
"""

from typing import Tuple

import pytest
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webdriver import WebDriver

from pages.base_page import BasePage

# SKIP BY DEFAULT - Remove this when you adapt the template
pytest.skip(
    "Template not adapted - find YOUR application's locators first",
    allow_module_level=True,
)


class LoginPage(BasePage):
    """
    Login Page Object for YOUR application.

    IMPORTANT: Replace ALL locators with YOUR application's actual locators!

    Locators:
        USERNAME_FIELD: Replace with YOUR username input locator
        PASSWORD_FIELD: Replace with YOUR password input locator
        LOGIN_BUTTON: Replace with YOUR login button locator
        ERROR_MESSAGE: Replace with YOUR error message locator
        SUCCESS_INDICATOR: Replace with YOUR success indicator locator

    How to find locators:
        1. Open YOUR application in Chrome
        2. Press F12 to open DevTools
        3. Click the element selector (top-left corner)
        4. Click on the element you want to locate
        5. Right-click the highlighted HTML → Copy → Copy selector
        6. Use the copied selector to create your locator
    """

    # ============================================================================
    # LOCATORS - REPLACE ALL OF THESE WITH YOUR APPLICATION'S LOCATORS
    # ============================================================================

    # Example: (By.ID, "username") - REPLACE THIS
    USERNAME_FIELD: Tuple[By, str] = (By.ID, "YOUR_USERNAME_FIELD_ID")

    # Example: (By.ID, "password") - REPLACE THIS
    PASSWORD_FIELD: Tuple[By, str] = (By.ID, "YOUR_PASSWORD_FIELD_ID")

    # Example: (By.CSS_SELECTOR, "button[type='submit']") - REPLACE THIS
    LOGIN_BUTTON: Tuple[By, str] = (
        By.CSS_SELECTOR,
        "YOUR_LOGIN_BUTTON_SELECTOR",
    )

    # Example: (By.CLASS_NAME, "error-message") - REPLACE THIS
    ERROR_MESSAGE: Tuple[By, str] = (By.CLASS_NAME, "YOUR_ERROR_MESSAGE_CLASS")

    # Example: (By.ID, "dashboard") - Element that appears after login
    SUCCESS_INDICATOR: Tuple[By, str] = (By.ID, "YOUR_SUCCESS_ELEMENT_ID")

    # ============================================================================
    # METHODS - ADAPT THESE TO YOUR APPLICATION'S WORKFLOW
    # ============================================================================

    def __init__(self, driver: WebDriver, base_url: str):
        """
        Initialize login page.

        Args:
            driver: Selenium WebDriver instance
            base_url: Base URL of YOUR application
        """
        super().__init__(driver)
        self.base_url = base_url
        self.login_url = f"{base_url}/login"  # Adapt to YOUR login URL path

    def navigate(self) -> None:
        """
        Navigate to login page.

        Adapt the URL to YOUR application's login page.
        """
        self.navigate_to(self.login_url)
        self.wait_for_element_visible(self.USERNAME_FIELD)

    def enter_username(self, username: str) -> None:
        """
        Enter username into username field.

        Args:
            username: Username to enter
        """
        self.wait_for_element_clickable(self.USERNAME_FIELD)
        self.type_text(self.USERNAME_FIELD, username)

    def enter_password(self, password: str) -> None:
        """
        Enter password into password field.

        Args:
            password: Password to enter
        """
        self.wait_for_element_clickable(self.PASSWORD_FIELD)
        self.type_text(self.PASSWORD_FIELD, password)

    def click_login_button(self) -> None:
        """
        Click the login button.

        Adapt if YOUR application uses different submission method
        (e.g., pressing Enter, clicking link, etc.)
        """
        self.click_element(self.LOGIN_BUTTON)

    def login(self, username: str, password: str) -> bool:
        """
        Perform complete login action.

        Args:
            username: Username to login with
            password: Password to login with

        Returns:
            True if login successful, False otherwise

        Adapt this to YOUR application's login flow:
        - Does it redirect after login?
        - Does it show a success message?
        - Does a specific element appear?
        - Does it require additional steps (2FA, etc.)?
        """
        self.enter_username(username)
        self.enter_password(password)
        self.click_login_button()

        # Wait for either success or error
        # Adapt this logic to YOUR application
        try:
            self.wait_for_element_visible(self.SUCCESS_INDICATOR, timeout=10)
            return True
        except:
            return False

    def get_error_message(self) -> str:
        """
        Get login error message.

        Returns:
            Error message text

        Adapt this to how YOUR application displays errors:
        - Is it a div with class "error"?
        - Is it an alert/modal?
        - Is it inline under the input field?
        """
        try:
            self.wait_for_element_visible(self.ERROR_MESSAGE, timeout=5)
            return self.get_element_text(self.ERROR_MESSAGE)
        except:
            return ""

    def is_logged_in(self) -> bool:
        """
        Check if user is currently logged in.

        Returns:
            True if logged in, False otherwise

        Adapt this to YOUR application:
        - What indicates a user is logged in?
        - Is there a profile menu?
        - Is there a logout button?
        - Is there a user avatar?
        """
        return self.is_element_visible(self.SUCCESS_INDICATOR)

    def is_on_login_page(self) -> bool:
        """
        Check if currently on login page.

        Returns:
            True if on login page, False otherwise

        Adapt this to YOUR application's login page indicators.
        """
        return "login" in self.get_current_url().lower()


# ADAPTATION CHECKLIST:
# [ ] Copied to pages/login_page.py
# [ ] Removed pytest.skip() line
# [ ] Opened YOUR application in browser
# [ ] Used DevTools (F12) to find YOUR locators
# [ ] Replaced ALL locator placeholders with YOUR actual locators
# [ ] Updated login_url to YOUR application's login URL
# [ ] Tested login() method with YOUR application
# [ ] Adapted get_error_message() to YOUR error display
# [ ] Adapted is_logged_in() to YOUR success indicators
# [ ] Added any application-specific methods you need
# [ ] Removed this checklist when done
