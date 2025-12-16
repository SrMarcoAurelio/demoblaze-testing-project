"""
Signup Page Object Model - TEMPLATE
Author: Marc Arevalo
Version: 6.0

IMPORTANT: This is a TEMPLATE/EXAMPLE for signup/registration page object.
The locators shown here are EXAMPLES and MUST be adapted to YOUR application's
actual element IDs, classes, and structure.

This template demonstrates:
- Modal-based signup/registration pattern
- User registration workflow
- Input validation patterns
- Error handling

ADAPTATION REQUIRED:
1. Update ALL locators to match your application's elements
2. Modify methods if your signup flow differs (may need email, phone, etc.)
3. Consider loading locators from config/locators.json
4. Test thoroughly with YOUR application

For applications with different registration patterns (multi-step, email verification,
OAuth, social login, etc.), use this as inspiration but create appropriate implementations.
"""

from typing import Optional

from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

from pages.base_page import BasePage


class SignupPage(BasePage):
    """
    TEMPLATE Page Object for Signup & Registration functionality.

    This template demonstrates a MODAL-BASED registration pattern.
    Adapt all locators and logic to match YOUR application.

    Handles:
    - Signup modal interaction (if your app uses modals)
    - User registration
    - Input validation
    - Error handling

    IMPORTANT: All locators below are EXAMPLES and must be replaced
    with your application's actual element locators.
    """

    # ========================================================================
    # NAVIGATION LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    SIGNUP_BUTTON_NAV = (
        By.ID,
        "signup-trigger",
    )  # EXAMPLE - adapt to your app
    LOGIN_BUTTON_NAV = (By.ID, "login-trigger")  # EXAMPLE - adapt to your app
    HOME_NAV_LINK = (By.LINK_TEXT, "Home")  # EXAMPLE - adapt to your app

    # ========================================================================
    # SIGNUP MODAL LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    # If your app uses a modal-based registration:
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
    SIGNUP_CLOSE_BUTTON = (By.CSS_SELECTOR, "#signup-modal .close")  # EXAMPLE

    # ========================================================================
    # ADDITIONAL FIELDS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    # Your app may require additional fields:
    # SIGNUP_EMAIL_FIELD = (By.ID, "signup-email")
    # SIGNUP_PHONE_FIELD = (By.ID, "signup-phone")
    # SIGNUP_CONFIRM_PASSWORD_FIELD = (By.ID, "signup-confirm-password")
    # SIGNUP_TERMS_CHECKBOX = (By.ID, "terms-checkbox")
    # SIGNUP_CAPTCHA = (By.ID, "captcha")

    # ========================================================================
    # SIGNUP METHODS - Adapt to your application's workflow
    # ========================================================================

    def open_signup_modal(self) -> bool:
        """
        Open the signup/registration modal.

        TEMPLATE METHOD - Adapt to your application's signup trigger.
        If your app uses a separate signup page instead of a modal,
        replace this with navigation to that page.

        Returns:
            True if modal/page opened successfully

        Example:
            >>> signup_page.open_signup_modal()
            >>> signup_page.signup("newuser", "password123")
        """
        self.click(self.SIGNUP_BUTTON_NAV)
        modal_visible = self.wait_for_element_visible(self.SIGNUP_MODAL)
        if modal_visible:
            self.wait_for_element_visible(self.SIGNUP_USERNAME_FIELD)
            self.logger.info("Signup modal opened")
            return True
        return False

    def close_signup_modal(self) -> None:
        """
        Close the signup modal.

        TEMPLATE METHOD - Adapt to your application.
        """
        if self.is_modal_visible(self.SIGNUP_MODAL):
            self.click(self.SIGNUP_CLOSE_BUTTON)
            self.logger.info("Signup modal closed")

    def signup(self, username: str, password: str) -> bool:
        """
        Perform user registration/signup.

        TEMPLATE METHOD - Adapt to your application's registration flow.
        Your app may require additional fields (email, phone, confirm password, etc.).

        Args:
            username: Desired username
            password: Desired password

        Returns:
            True if signup appears successful (modal closed)

        Example:
            >>> signup_page.signup("newuser123", "SecurePass123!")
            >>> alert = signup_page.get_signup_result_message()
            >>> assert "successful" in alert.lower()
        """
        self.open_signup_modal()
        self.type(self.SIGNUP_USERNAME_FIELD, username)
        self.type(self.SIGNUP_PASSWORD_FIELD, password)
        self.click(self.SIGNUP_SUBMIT_BUTTON)

        # Wait for modal to close (indicates submission)
        self.wait_for_element_invisible(self.SIGNUP_MODAL, timeout=5)

        self.logger.info(f"Signup attempted for user: {username}")

        return True

    def signup_with_validation(
        self, username: str, password: str, expect_success: bool = True
    ) -> Optional[str]:
        """
        Perform signup and return validation message.

        TEMPLATE METHOD - Adapt to your application.

        Args:
            username: Desired username
            password: Desired password
            expect_success: Whether signup is expected to succeed

        Returns:
            Success/error message if present, None otherwise
        """
        self.signup(username, password)

        # Check for alert message (common pattern)
        message = self.get_alert_text(timeout=3)
        if message:
            if expect_success:
                self.accept_alert()
            return message

        return None

    # ========================================================================
    # VALIDATION METHODS
    # ========================================================================

    def get_signup_result_message(self, timeout: int = 5) -> Optional[str]:
        """
        Get signup result message (success or error).

        TEMPLATE METHOD - Adapt to your application's feedback mechanism.

        Args:
            timeout: Timeout to wait for message

        Returns:
            Result message if present, None otherwise
        """
        # Check for alert (common pattern)
        alert_text = self.get_alert_text(timeout=timeout)
        if alert_text:
            return alert_text

        # Or check for message element on page
        # MESSAGE_LOCATOR = (By.CSS_SELECTOR, ".signup-message")
        # if self.is_element_visible(MESSAGE_LOCATOR, timeout=timeout):
        #     return self.get_text(MESSAGE_LOCATOR)

        return None

    def is_signup_successful(self) -> bool:
        """
        Check if signup was successful.

        TEMPLATE METHOD - Adapt to your application's success indicators.

        Returns:
            True if signup appears successful, False otherwise

        Note:
            Success indicators vary by application:
            - Success message/alert
            - Redirect to confirmation page
            - Email verification message
            - Automatic login after signup
            Adapt this method to match YOUR application's behavior.
        """
        # Check for success alert
        alert = self.get_alert_text(timeout=3)
        if alert and (
            "success" in alert.lower() or "registered" in alert.lower()
        ):
            return True

        # Check if modal closed (might indicate success)
        modal_closed = not self.is_element_visible(
            self.SIGNUP_MODAL, timeout=2
        )

        return modal_closed

    def get_validation_error(self) -> Optional[str]:
        """
        Get validation error message if present.

        TEMPLATE METHOD - Adapt to your application's error display.

        Returns:
            Error message if present, None otherwise
        """
        # Check for alert
        alert = self.get_alert_text(timeout=2)
        if alert and ("error" in alert.lower() or "invalid" in alert.lower()):
            return alert

        # Or check for error element
        # ERROR_LOCATOR = (By.CSS_SELECTOR, ".error-message")
        # if self.is_element_visible(ERROR_LOCATOR, timeout=2):
        #     return self.get_text(ERROR_LOCATOR)

        return None

    # ========================================================================
    # HELPER METHODS
    # ========================================================================

    def is_username_field_visible(self) -> bool:
        """Check if username field is visible."""
        return self.is_element_visible(self.SIGNUP_USERNAME_FIELD, timeout=3)

    def is_password_field_visible(self) -> bool:
        """Check if password field is visible."""
        return self.is_element_visible(self.SIGNUP_PASSWORD_FIELD, timeout=3)

    def clear_signup_form(self) -> None:
        """
        Clear all signup form fields.

        TEMPLATE METHOD - Adapt to your application's form fields.
        """
        if self.is_username_field_visible():
            self.type(self.SIGNUP_USERNAME_FIELD, "", clear_first=True)
        if self.is_password_field_visible():
            self.type(self.SIGNUP_PASSWORD_FIELD, "", clear_first=True)

    def navigate_to_login(self) -> None:
        """
        Navigate from signup to login.

        TEMPLATE METHOD - Adapt to your application.
        """
        self.close_signup_modal()
        # Assuming login is accessible from navigation
        self.click(self.LOGIN_BUTTON_NAV)


# ============================================================================
# USAGE EXAMPLE - How to adapt this template to your application
# ============================================================================
"""
EXAMPLE ADAPTATION:

1. Update locators to match your application:
   SIGNUP_BUTTON_NAV = (By.ID, "your-signup-button-id")
   SIGNUP_USERNAME_FIELD = (By.NAME, "your-username-field")
   # ... etc

2. If your app uses page-based signup instead of modal:
   def open_signup_modal(self):
       # Navigate to signup page
       self.navigate_to(f"{self.base_url}/register")
       self.wait_for_page_load()

3. If your app requires additional fields:
   def signup(self, username: str, password: str, email: str, phone: str = None):
       self.open_signup_modal()
       self.type(self.SIGNUP_USERNAME_FIELD, username)
       self.type(self.SIGNUP_EMAIL_FIELD, email)
       self.type(self.SIGNUP_PASSWORD_FIELD, password)
       if phone:
           self.type(self.SIGNUP_PHONE_FIELD, phone)
       # Handle terms checkbox if required
       if self.is_element_visible(self.SIGNUP_TERMS_CHECKBOX):
           self.click(self.SIGNUP_TERMS_CHECKBOX)
       self.click(self.SIGNUP_SUBMIT_BUTTON)

4. If your app has multi-step registration:
   def signup_step1(self, email: str):
       # First step: email
       self.type(self.EMAIL_FIELD, email)
       self.click(self.NEXT_BUTTON)

   def signup_step2(self, username: str, password: str):
       # Second step: credentials
       self.wait_for_element_visible(self.USERNAME_FIELD)
       self.type(self.USERNAME_FIELD, username)
       self.type(self.PASSWORD_FIELD, password)
       self.click(self.COMPLETE_BUTTON)

5. If your app sends email verification:
   def verify_email_sent(self) -> bool:
       message = self.get_signup_result_message()
       return message and "verify" in message.lower()

6. Use discovery-based element finding:
   from framework.core import ElementFinder

   def open_signup_modal(self):
       # Find signup button by text
       signup_btn = self.finder.find_by_text("Sign Up", tag="button")
       if signup_btn:
           self.interactor.click(signup_btn)
"""
