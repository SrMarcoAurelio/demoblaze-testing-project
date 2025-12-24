"""
Login Page Object Model - TEMPLATE
Author: Marc Arevalo
Version: 6.0

IMPORTANT: This is a TEMPLATE/EXAMPLE for login page object.
The locators shown here are from a sample application and MUST be adapted
to YOUR application's actual element IDs, classes, and structure.

This template demonstrates:
- Modal-based login pattern
- Login/logout/signup workflows
- Session management patterns

ADAPTATION REQUIRED:
1. Update ALL locators to match your application's elements
2. Modify methods if your login flow differs
3. Consider loading locators from config/locators.json
4. Test thoroughly with YOUR application

For applications with different login patterns (page-based, OAuth, SSO, etc.),
use this as inspiration but create appropriate custom implementations.
"""

from typing import Any, Dict, List, Optional

from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

from .base_page import BasePage


class LoginPage(BasePage):
    """
    TEMPLATE Page Object for Login & Authentication functionality.

    This template demonstrates a MODAL-BASED login pattern.
    Adapt all locators and logic to match YOUR application.

    Handles:
    - Login modal interaction (if your app uses modals)
    - User authentication
    - Logout
    - Session management
    - Signup modal (basic support)

    IMPORTANT: All locators below are EXAMPLES and must be replaced
    with your application's actual element locators.
    """

    # ========================================================================
    # NAVIGATION LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    # These are EXAMPLE locators - replace with YOUR app's navigation elements
    LOGIN_BUTTON_NAV = (By.ID, "login-trigger")  # EXAMPLE - adapt to your app
    SIGNUP_BUTTON_NAV = (
        By.ID,
        "signup-trigger",
    )  # EXAMPLE - adapt to your app
    LOGOUT_BUTTON_NAV = (
        By.ID,
        "logout-trigger",
    )  # EXAMPLE - adapt to your app
    HOME_NAV_LINK = (By.LINK_TEXT, "Home")  # EXAMPLE - adapt to your app

    # ========================================================================
    # LOGIN MODAL LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    # If your app uses a modal-based login:
    LOGIN_MODAL = (By.ID, "login-modal")  # EXAMPLE - adapt to your app
    LOGIN_MODAL_TITLE = (
        By.CSS_SELECTOR,
        "#login-modal .modal-title",
    )  # EXAMPLE
    LOGIN_USERNAME_FIELD = (By.ID, "username")  # EXAMPLE - adapt to your app
    LOGIN_PASSWORD_FIELD = (By.ID, "password")  # EXAMPLE - adapt to your app
    LOGIN_SUBMIT_BUTTON = (By.CSS_SELECTOR, "button[type='submit']")  # EXAMPLE
    LOGIN_CLOSE_BUTTON = (By.CSS_SELECTOR, "#login-modal .close")  # EXAMPLE

    # ========================================================================
    # SIGNUP MODAL LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    # If your app has a signup modal:
    SIGNUP_MODAL = (By.ID, "signup-modal")  # EXAMPLE - adapt to your app
    SIGNUP_MODAL_TITLE = (
        By.CSS_SELECTOR,
        "#signup-modal .modal-title",
    )  # EXAMPLE
    SIGNUP_USERNAME_FIELD = (By.ID, "signup-username")  # EXAMPLE
    SIGNUP_PASSWORD_FIELD = (By.ID, "signup-password")  # EXAMPLE
    SIGNUP_SUBMIT_BUTTON = (
        By.CSS_SELECTOR,
        "button[type='submit']",
    )  # EXAMPLE

    # ========================================================================
    # SESSION STATE LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    # Element that indicates user is logged in (e.g., welcome message, user menu):
    WELCOME_USER_TEXT = (By.ID, "user-welcome")  # EXAMPLE - adapt to your app

    # ========================================================================
    # LOGIN METHODS - Adapt logic to your application's workflow
    # ========================================================================

    def open_login_modal(self) -> bool:
        """
        Open the login modal.

        TEMPLATE METHOD - Adapt to your application's login trigger.
        If your app uses a separate login page instead of a modal,
        replace this with navigation to that page.

        Returns:
            True if modal/page opened successfully
        """
        self.click(self.LOGIN_BUTTON_NAV)
        modal_visible = self.wait_for_element_visible(self.LOGIN_MODAL)
        if modal_visible:
            self.wait_for_element_visible(self.LOGIN_USERNAME_FIELD)
            self.logger.info("Login modal opened")
            return True
        return False

    def close_login_modal(self) -> None:
        """
        Close the login modal.

        TEMPLATE METHOD - Adapt to your application.
        """
        if self.is_modal_visible(self.LOGIN_MODAL):
            self.click(self.LOGIN_CLOSE_BUTTON)
            self.logger.info("Login modal closed")

    def login(self, username: str, password: str) -> bool:
        """
        Perform login.

        TEMPLATE METHOD - Adapt to your application's login flow.

        Args:
            username: Username or email
            password: Password

        Returns:
            True if login appears successful (modal closed and user element visible)

        Example:
            >>> login_page.login("testuser", "testpass")
            >>> assert login_page.is_user_logged_in()
        """
        self.open_login_modal()
        self.type(self.LOGIN_USERNAME_FIELD, username)
        self.type(self.LOGIN_PASSWORD_FIELD, password)
        self.click(self.LOGIN_SUBMIT_BUTTON)

        # Wait for modal to close (indicates submission)
        self.wait_for_element_invisible(self.LOGIN_MODAL, timeout=5)

        self.logger.info(f"Login attempted for user: {username}")

        # Check if login was successful by looking for logged-in indicator
        return self.is_user_logged_in()

    def logout(self) -> None:
        """
        Perform logout.

        TEMPLATE METHOD - Adapt to your application's logout mechanism.
        """
        if self.is_user_logged_in():
            self.click(self.LOGOUT_BUTTON_NAV)
            # Wait for logout to complete
            self.wait_for_element_invisible(self.WELCOME_USER_TEXT, timeout=5)
            self.logger.info("User logged out")

    def is_user_logged_in(self) -> bool:
        """
        Check if user is currently logged in.

        TEMPLATE METHOD - Adapt to your application's session indicators.

        Returns:
            True if user appears to be logged in, False otherwise

        Note:
            This checks for the presence of an element that only appears
            when logged in (e.g., welcome message, user menu, logout button).
            Adapt the locator to match your application.
        """
        # Check if logout button is visible (indicates logged in)
        logout_visible = self.is_element_visible(
            self.LOGOUT_BUTTON_NAV, timeout=3
        )

        # Or check for welcome message
        welcome_visible = self.is_element_visible(
            self.WELCOME_USER_TEXT, timeout=3
        )

        return logout_visible or welcome_visible

    def get_logged_in_username(self) -> Optional[str]:
        """
        Get the username of the currently logged-in user.

        TEMPLATE METHOD - Adapt to your application.

        Returns:
            Username if logged in, None otherwise
        """
        if self.is_user_logged_in():
            welcome_text = self.get_text(self.WELCOME_USER_TEXT)
            # Parse username from welcome text (e.g., "Welcome user123")
            # Adapt this parsing to match your app's format
            if welcome_text:
                return welcome_text.replace("Welcome", "").strip()
        return None

    # ========================================================================
    # SIGNUP METHODS - Adapt to your application
    # ========================================================================

    def open_signup_modal(self) -> bool:
        """
        Open the signup modal.

        TEMPLATE METHOD - Adapt to your application's signup trigger.

        Returns:
            True if modal/page opened successfully
        """
        self.click(self.SIGNUP_BUTTON_NAV)
        modal_visible = self.wait_for_element_visible(self.SIGNUP_MODAL)
        if modal_visible:
            self.wait_for_element_visible(self.SIGNUP_USERNAME_FIELD)
            self.logger.info("Signup modal opened")
            return True
        return False

    def signup(self, username: str, password: str) -> None:
        """
        Perform signup/registration.

        TEMPLATE METHOD - Adapt to your application's signup flow.
        Your app may require additional fields (email, name, etc.).

        Args:
            username: Desired username
            password: Desired password
        """
        self.open_signup_modal()
        self.type(self.SIGNUP_USERNAME_FIELD, username)
        self.type(self.SIGNUP_PASSWORD_FIELD, password)
        self.click(self.SIGNUP_SUBMIT_BUTTON)
        self.logger.info(f"Signup attempted for user: {username}")

    # ========================================================================
    # HELPER METHODS
    # ========================================================================

    def get_login_error_message(self) -> Optional[str]:
        """
        Get login error message if present.

        TEMPLATE METHOD - Adapt to your application's error display.

        Returns:
            Error message text if present, None otherwise
        """
        # Check for alert (common pattern)
        alert_text = self.get_alert_text(timeout=2)
        if alert_text:
            return alert_text

        # Or check for error element on page
        # ERROR_MESSAGE_LOCATOR = (By.CSS_SELECTOR, ".error-message")
        # if self.is_element_visible(ERROR_MESSAGE_LOCATOR, timeout=2):
        #     return self.get_text(ERROR_MESSAGE_LOCATOR)

        return None

    def wait_for_login_completion(self, timeout: int = 10) -> bool:
        """
        Wait for login process to complete.

        TEMPLATE METHOD - Adapt to your application's post-login behavior.

        Args:
            timeout: Maximum time to wait in seconds

        Returns:
            True if login completed successfully
        """
        # Wait for modal to close
        self.wait_for_element_invisible(self.LOGIN_MODAL, timeout=timeout)

        # Wait for logged-in indicator
        return (
            self.wait_for_element_visible(
                self.WELCOME_USER_TEXT, timeout=timeout
            )
            is not None
        )


# ============================================================================
# USAGE EXAMPLE - How to adapt this template to your application
# ============================================================================
"""
EXAMPLE ADAPTATION:

1. Update locators to match your application:
   LOGIN_BUTTON_NAV = (By.ID, "your-login-button-id")
   LOGIN_USERNAME_FIELD = (By.NAME, "your-username-field-name")
   # ... etc

2. If your app uses page-based login instead of modal:
   def open_login_modal(self):
       # Instead of opening modal, navigate to login page
       self.navigate_to(f"{self.base_url}/login")
       self.wait_for_page_load()

3. If your app requires additional fields (email, captcha, etc.):
   def login(self, username: str, password: str, email: str = None):
       self.open_login_modal()
       if email:
           self.type(self.EMAIL_FIELD, email)
       self.type(self.LOGIN_USERNAME_FIELD, username)
       self.type(self.LOGIN_PASSWORD_FIELD, password)
       # Handle captcha if needed
       self.click(self.LOGIN_SUBMIT_BUTTON)

4. Load locators from config/locators.json (recommended):
   from utils.locator_loader import load_locators

   class LoginPage(BasePage):
       def __init__(self, driver):
           super().__init__(driver)
           # Load locators from JSON
           self.locators = load_locators("login_page")
           self.LOGIN_BUTTON_NAV = self.locators.get("login_button_nav")

5. Use discovery-based element finding for more resilient tests:
   from framework.core import ElementFinder

   def open_login_modal(self):
       # Find login button by text (more resilient than ID)
       login_btn = self.finder.find_by_text("Login", tag="button")
       if login_btn:
           self.interactor.click(login_btn)
"""
