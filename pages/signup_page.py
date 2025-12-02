"""
Signup Page Object Model
Author: Marc Arévalo
Version: 2.0

This page object models Signup/Registration functionality.
Contains all locators and actions related to user registration.
Universal and reusable across any web application with modal-based registration.
"""

from typing import Optional

from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

from pages.base_page import BasePage


class SignupPage(BasePage):
    """
    Page Object for Signup & Registration functionality.

    Handles:
    - Signup modal interaction
    - User registration
    - Input validation
    - Error handling
    """

    SIGNUP_BUTTON_NAV = (By.ID, "signin2")
    LOGIN_BUTTON_NAV = (By.ID, "login2")
    LOGOUT_BUTTON_NAV = (By.ID, "logout2")
    HOME_NAV_LINK = (By.XPATH, "//a[contains(text(), 'Home')]")

    SIGNUP_MODAL = (By.ID, "signInModal")
    SIGNUP_MODAL_TITLE = (
        By.XPATH,
        "//div[@id='signInModal']//h5[@class='modal-title']",
    )
    SIGNUP_USERNAME_FIELD = (By.ID, "sign-username")
    SIGNUP_PASSWORD_FIELD = (By.ID, "sign-password")
    SIGNUP_SUBMIT_BUTTON = (By.XPATH, "//button[text()='Sign up']")
    SIGNUP_CLOSE_BUTTON = (
        By.XPATH,
        "//div[@id='signInModal']//button[@class='close']",
    )
    SIGNUP_CLOSE_FOOTER_BUTTON = (
        By.XPATH,
        "//div[@id='signInModal']//button[text()='Close']",
    )

    LOGIN_MODAL = (By.ID, "logInModal")
    LOGIN_USERNAME_FIELD = (By.ID, "loginusername")
    LOGIN_PASSWORD_FIELD = (By.ID, "loginpassword")
    LOGIN_SUBMIT_BUTTON = (By.XPATH, "//button[text()='Log in']")

    WELCOME_USER_TEXT = (By.ID, "nameofuser")

    def open_signup_modal(self) -> bool:
        """
        Open the signup modal.

        Returns:
            True if modal opened successfully
        """
        self.click(self.SIGNUP_BUTTON_NAV)
        self.wait_for_element_visible(self.SIGNUP_MODAL)
        self.wait_for_element_visible(self.SIGNUP_USERNAME_FIELD)
        self.logger.info("Signup modal opened")
        return True

    def close_signup_modal(self) -> None:
        """Close the signup modal using close button."""
        self.click(self.SIGNUP_CLOSE_BUTTON)
        self.wait_for_element_invisible(self.SIGNUP_MODAL)
        self.logger.info("Signup modal closed")

    def close_signup_modal_footer(self) -> None:
        """Close the signup modal using footer close button."""
        self.click(self.SIGNUP_CLOSE_FOOTER_BUTTON)
        self.wait_for_element_invisible(self.SIGNUP_MODAL)
        self.logger.info("Signup modal closed via footer button")

    def close_signup_modal_esc(self) -> None:
        """Close the signup modal using ESC key."""
        self.press_key(Keys.ESCAPE)
        self.wait_for_element_invisible(self.SIGNUP_MODAL, timeout=3)
        self.logger.info("Signup modal closed via ESC key")

    def is_signup_modal_visible(self) -> bool:
        """
        Check if signup modal is visible.

        Returns:
            True if modal is visible, False otherwise
        """
        return self.is_element_visible(self.SIGNUP_MODAL, timeout=2)

    def fill_signup_username(
        self, username: str, clear_first: bool = True
    ) -> None:
        """
        Fill the username field in signup modal.

        Args:
            username: Username to enter
            clear_first: Clear field before typing (default: True)
        """
        self.type(
            self.SIGNUP_USERNAME_FIELD, username, clear_first=clear_first
        )
        self.logger.info(f"Entered signup username: {username}")

    def fill_signup_password(
        self, password: str, clear_first: bool = True
    ) -> None:
        """
        Fill the password field in signup modal.

        Args:
            password: Password to enter
            clear_first: Clear field before typing (default: True)
        """
        self.type(
            self.SIGNUP_PASSWORD_FIELD, password, clear_first=clear_first
        )
        self.logger.info("Entered signup password")

    def click_signup_submit(self) -> None:
        """Click the signup submit button."""
        self.click(self.SIGNUP_SUBMIT_BUTTON)
        self.logger.info("Clicked signup submit button")

    def submit_signup_with_enter(self) -> None:
        """Submit signup form using ENTER key."""
        self.send_keys(self.SIGNUP_PASSWORD_FIELD, Keys.ENTER)
        self.logger.info("Submitted signup via ENTER key")

    def signup(
        self, username: str, password: str, use_enter_key: bool = False
    ) -> bool:
        """
        Complete signup flow: open modal, fill fields, submit.

        Args:
            username: Username to signup with
            password: Password to signup with
            use_enter_key: Submit using ENTER instead of click (default: False)

        Returns:
            True if signup action completed (does not verify success)
        """
        self.open_signup_modal()
        self.fill_signup_username(username)
        self.fill_signup_password(password)

        if use_enter_key:
            self.submit_signup_with_enter()
        else:
            self.click_signup_submit()

        self.logger.info(f"Signup attempted for user: {username}")
        return True

    def login_after_signup(self, username: str, password: str) -> bool:
        """
        Login with newly created account (for verification).

        Args:
            username: Username to login with
            password: Password to login with

        Returns:
            True if login action completed
        """
        self.click(self.LOGIN_BUTTON_NAV)
        self.wait_for_element_visible(self.LOGIN_MODAL)
        self.type(self.LOGIN_USERNAME_FIELD, username)
        self.type(self.LOGIN_PASSWORD_FIELD, password)
        self.click(self.LOGIN_SUBMIT_BUTTON)
        self.logger.info(
            f"Login attempted for newly signed up user: {username}"
        )
        return True

    def logout(self) -> bool:
        """
        Logout the current user.

        Returns:
            True if logout action completed
        """
        self.click(self.LOGOUT_BUTTON_NAV)
        self.wait(1)  # Wait for logout to process
        self.logger.info("Logout completed")
        return True

    def is_user_logged_in(self, timeout: int = 3) -> bool:
        """
        Check if user is currently logged in.

        Args:
            timeout: Timeout in seconds (default: 3)

        Returns:
            True if user is logged in, False otherwise
        """
        is_logged_in = self.is_element_visible(
            self.WELCOME_USER_TEXT, timeout=timeout
        )
        if is_logged_in:
            self.logger.info("User is logged in")
        else:
            self.logger.info("User is not logged in")
        return is_logged_in

    def get_welcome_message(self) -> Optional[str]:
        """
        Get the welcome message text (e.g., "Welcome username").

        Returns:
            Welcome message text, or None if not logged in
        """
        if self.is_user_logged_in():
            text = self.get_text(self.WELCOME_USER_TEXT)
            self.logger.info(f"Welcome message: {text}")
            return text
        return None

    def get_signup_username_value(self) -> Optional[str]:
        """Get current value of signup username field."""
        return self.get_attribute(self.SIGNUP_USERNAME_FIELD, "value")

    def get_signup_password_value(self) -> Optional[str]:
        """Get current value of signup password field."""
        return self.get_attribute(self.SIGNUP_PASSWORD_FIELD, "value")

    def get_signup_username_placeholder(self) -> Optional[str]:
        """Get placeholder text of signup username field."""
        return self.get_attribute(self.SIGNUP_USERNAME_FIELD, "placeholder")

    def get_signup_password_placeholder(self) -> Optional[str]:
        """Get placeholder text of signup password field."""
        return self.get_attribute(self.SIGNUP_PASSWORD_FIELD, "placeholder")

    def is_signup_username_field_enabled(self) -> bool:
        """Check if signup username field is enabled."""
        enabled = self.get_attribute(self.SIGNUP_USERNAME_FIELD, "disabled")
        return enabled is None

    def is_signup_password_field_enabled(self) -> bool:
        """Check if signup password field is enabled."""
        enabled = self.get_attribute(self.SIGNUP_PASSWORD_FIELD, "disabled")
        return enabled is None

    def get_signup_username_aria_label(self) -> Optional[str]:
        """Get aria-label of signup username field (for accessibility testing)."""
        return self.get_attribute(self.SIGNUP_USERNAME_FIELD, "aria-label")

    def get_signup_password_aria_label(self) -> Optional[str]:
        """Get aria-label of signup password field (for accessibility testing)."""
        return self.get_attribute(self.SIGNUP_PASSWORD_FIELD, "aria-label")

    def tab_through_signup_form(self) -> bool:
        """
        Tab through signup form fields (for keyboard navigation testing).

        Returns:
            True if completed
        """
        self.open_signup_modal()

        self.send_keys(self.SIGNUP_USERNAME_FIELD, Keys.TAB)

        self.send_keys(self.SIGNUP_PASSWORD_FIELD, Keys.TAB)

        self.logger.info("Tabbed through signup form")
        return True

    def inject_sql_payload_username(self, payload: str) -> bool:
        """
        Inject SQL payload into signup username field (for security testing).

        Args:
            payload: SQL injection payload

        Returns:
            True if injection attempt completed
        """
        self.open_signup_modal()
        self.fill_signup_username(payload)
        self.fill_signup_password("anypassword")
        self.click_signup_submit()
        self.logger.warning(
            f"SQL injection payload tested in signup: {payload}"
        )
        return True

    def inject_xss_payload_username(self, payload: str) -> bool:
        """
        Inject XSS payload into signup username field (for security testing).

        Args:
            payload: XSS payload

        Returns:
            True if injection attempt completed
        """
        self.open_signup_modal()
        self.fill_signup_username(payload)
        self.fill_signup_password("anypassword")
        self.click_signup_submit()
        self.logger.warning(f"XSS payload tested in signup: {payload}")
        return True

    def check_for_csrf_token(self) -> bool:
        """
        Check if signup form has CSRF token (for security testing).

        Returns:
            True if CSRF token found, False otherwise
        """
        self.open_signup_modal()
        page_source = self.get_page_source()

        has_csrf = (
            "csrf" in page_source.lower() or "token" in page_source.lower()
        )

        if has_csrf:
            self.logger.info("CSRF token detected in signup form")
        else:
            self.logger.warning("No CSRF token found in signup form")

        return has_csrf
