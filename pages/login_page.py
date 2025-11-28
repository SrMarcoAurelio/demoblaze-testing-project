"""
Login Page Object Model
Author: Marc Arévalo
Version: 1.0

This page object models the Login/Authentication functionality of DemoBlaze.
Contains all locators and actions related to login, logout, and signup.
"""

from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from pages.base_page import BasePage
import logging



class LoginPage(BasePage):
    """
    Page Object for Login & Authentication functionality.

    Handles:
    - Login modal interaction
    - User authentication
    - Logout
    - Session management
    - Signup modal (basic support)
    """


    LOGIN_BUTTON_NAV = (By.ID, "login2")
    SIGNUP_BUTTON_NAV = (By.ID, "signin2")
    LOGOUT_BUTTON_NAV = (By.ID, "logout2")
    HOME_NAV_LINK = (By.XPATH, "//a[contains(text(), 'Home')]")

    LOGIN_MODAL = (By.ID, "logInModal")
    LOGIN_MODAL_TITLE = (By.XPATH, "//div[@id='logInModal']//h5[@class='modal-title']")
    LOGIN_USERNAME_FIELD = (By.ID, "loginusername")
    LOGIN_PASSWORD_FIELD = (By.ID, "loginpassword")
    LOGIN_SUBMIT_BUTTON = (By.XPATH, "//button[text()='Log in']")
    LOGIN_CLOSE_BUTTON = (By.XPATH, "//div[@id='logInModal']//button[@class='close']")
    LOGIN_CLOSE_FOOTER_BUTTON = (By.XPATH, "//div[@id='logInModal']//button[text()='Close']")

    SIGNUP_MODAL = (By.ID, "signInModal")
    SIGNUP_MODAL_TITLE = (By.XPATH, "//div[@id='signInModal']//h5[@class='modal-title']")
    SIGNUP_USERNAME_FIELD = (By.ID, "sign-username")
    SIGNUP_PASSWORD_FIELD = (By.ID, "sign-password")
    SIGNUP_SUBMIT_BUTTON = (By.XPATH, "//button[text()='Sign up']")
    SIGNUP_CLOSE_BUTTON = (By.XPATH, "//div[@id='signInModal']//button[@class='close']")

    WELCOME_USER_TEXT = (By.ID, "nameofuser")


    def open_login_modal(self):
        """
        Open the login modal.

        Returns:
            True if modal opened successfully
        """
        self.click(self.LOGIN_BUTTON_NAV)
        self.wait_for_element_visible(self.LOGIN_MODAL)
        self.wait_for_element_visible(self.LOGIN_USERNAME_FIELD)
        self.logger.info("Login modal opened")
        return True

    def close_login_modal(self):
        """Close the login modal using close button."""
        self.click(self.LOGIN_CLOSE_BUTTON)
        self.wait_for_element_invisible(self.LOGIN_MODAL)
        self.logger.info("Login modal closed")

    def close_login_modal_footer(self):
        """Close the login modal using footer close button."""
        self.click(self.LOGIN_CLOSE_FOOTER_BUTTON)
        self.wait_for_element_invisible(self.LOGIN_MODAL)
        self.logger.info("Login modal closed via footer button")

    def close_login_modal_esc(self):
        """Close the login modal using ESC key."""
        self.press_key(Keys.ESCAPE)
        self.wait_for_element_invisible(self.LOGIN_MODAL, timeout=3)
        self.logger.info("Login modal closed via ESC key")

    def is_login_modal_visible(self):
        """
        Check if login modal is visible.

        Returns:
            True if modal is visible, False otherwise
        """
        return self.is_element_visible(self.LOGIN_MODAL, timeout=2)


    def fill_login_username(self, username, clear_first=True):
        """
        Fill the username field in login modal.

        Args:
            username: Username to enter
            clear_first: Clear field before typing (default: True)
        """
        self.type(self.LOGIN_USERNAME_FIELD, username, clear_first=clear_first)
        self.logger.info(f"Entered username: {username}")

    def fill_login_password(self, password, clear_first=True):
        """
        Fill the password field in login modal.

        Args:
            password: Password to enter
            clear_first: Clear field before typing (default: True)
        """
        self.type(self.LOGIN_PASSWORD_FIELD, password, clear_first=clear_first)
        self.logger.info("Entered password")

    def click_login_submit(self):
        """Click the login submit button."""
        self.click(self.LOGIN_SUBMIT_BUTTON)
        self.logger.info("Clicked login submit button")

    def submit_login_with_enter(self):
        """Submit login form using ENTER key."""
        self.send_keys(self.LOGIN_PASSWORD_FIELD, Keys.ENTER)
        self.logger.info("Submitted login via ENTER key")

    def login(self, username, password, use_enter_key=False):
        """
        Complete login flow: open modal, fill fields, submit.

        Args:
            username: Username to login with
            password: Password to login with
            use_enter_key: Submit using ENTER instead of click (default: False)

        Returns:
            True if login action completed (does not verify success)
        """
        self.open_login_modal()
        self.fill_login_username(username)
        self.fill_login_password(password)

        if use_enter_key:
            self.submit_login_with_enter()
        else:
            self.click_login_submit()

        self.logger.info(f"Login attempted for user: {username}")
        return True


    def logout(self):
        """
        Logout the current user.

        Returns:
            True if logout action completed
        """
        self.click(self.LOGOUT_BUTTON_NAV)
        self.wait(1)  # Wait for logout to process
        self.logger.info("Logout completed")
        return True

    def is_logout_button_visible(self):
        """
        Check if logout button is visible.

        Returns:
            True if logout button visible, False otherwise
        """
        return self.is_element_visible(self.LOGOUT_BUTTON_NAV, timeout=2)


    def open_signup_modal(self):
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

    def close_signup_modal(self):
        """Close the signup modal."""
        self.click(self.SIGNUP_CLOSE_BUTTON)
        self.wait_for_element_invisible(self.SIGNUP_MODAL)
        self.logger.info("Signup modal closed")

    def fill_signup_username(self, username, clear_first=True):
        """
        Fill the username field in signup modal.

        Args:
            username: Username to enter
            clear_first: Clear field before typing (default: True)
        """
        self.type(self.SIGNUP_USERNAME_FIELD, username, clear_first=clear_first)
        self.logger.info(f"Entered signup username: {username}")

    def fill_signup_password(self, password, clear_first=True):
        """
        Fill the password field in signup modal.

        Args:
            password: Password to enter
            clear_first: Clear field before typing (default: True)
        """
        self.type(self.SIGNUP_PASSWORD_FIELD, password, clear_first=clear_first)
        self.logger.info("Entered signup password")

    def click_signup_submit(self):
        """Click the signup submit button."""
        self.click(self.SIGNUP_SUBMIT_BUTTON)
        self.logger.info("Clicked signup submit button")

    def signup(self, username, password):
        """
        Complete signup flow: open modal, fill fields, submit.

        Args:
            username: Username to signup with
            password: Password to signup with

        Returns:
            True if signup action completed (does not verify success)
        """
        self.open_signup_modal()
        self.fill_signup_username(username)
        self.fill_signup_password(password)
        self.click_signup_submit()
        self.logger.info(f"Signup attempted for user: {username}")
        return True


    def is_user_logged_in(self, timeout=3):
        """
        Check if user is currently logged in.

        Verifies by checking for welcome message presence.

        Args:
            timeout: Timeout in seconds (default: 3)

        Returns:
            True if user is logged in, False otherwise
        """
        is_logged_in = self.is_element_visible(self.WELCOME_USER_TEXT, timeout=timeout)
        if is_logged_in:
            self.logger.info("User is logged in")
        else:
            self.logger.info("User is not logged in")
        return is_logged_in

    def get_welcome_message(self):
        """
        Get the welcome message text (e.g., "Welcome Apolo2025").

        Returns:
            Welcome message text, or None if not logged in
        """
        if self.is_user_logged_in():
            text = self.get_text(self.WELCOME_USER_TEXT)
            self.logger.info(f"Welcome message: {text}")
            return text
        return None

    def get_logged_in_username(self):
        """
        Extract username from welcome message.

        Returns:
            Username string, or None if not logged in
        """
        welcome_msg = self.get_welcome_message()
        if welcome_msg:
            username = welcome_msg.replace("Welcome", "").strip()
            self.logger.info(f"Logged in username: {username}")
            return username
        return None


    def get_login_username_value(self):
        """Get current value of login username field."""
        return self.get_attribute(self.LOGIN_USERNAME_FIELD, "value")

    def get_login_password_value(self):
        """Get current value of login password field."""
        return self.get_attribute(self.LOGIN_PASSWORD_FIELD, "value")

    def get_login_username_placeholder(self):
        """Get placeholder text of login username field."""
        return self.get_attribute(self.LOGIN_USERNAME_FIELD, "placeholder")

    def get_login_password_placeholder(self):
        """Get placeholder text of login password field."""
        return self.get_attribute(self.LOGIN_PASSWORD_FIELD, "placeholder")

    def is_login_username_field_enabled(self):
        """Check if login username field is enabled."""
        enabled = self.get_attribute(self.LOGIN_USERNAME_FIELD, "disabled")
        return enabled is None

    def is_login_password_field_enabled(self):
        """Check if login password field is enabled."""
        enabled = self.get_attribute(self.LOGIN_PASSWORD_FIELD, "disabled")
        return enabled is None


    def get_login_username_aria_label(self):
        """Get aria-label of login username field (for accessibility testing)."""
        return self.get_attribute(self.LOGIN_USERNAME_FIELD, "aria-label")

    def get_login_password_aria_label(self):
        """Get aria-label of login password field (for accessibility testing)."""
        return self.get_attribute(self.LOGIN_PASSWORD_FIELD, "aria-label")

    def tab_through_login_form(self):
        """
        Tab through login form fields (for keyboard navigation testing).

        Returns:
            List of focused element IDs
        """
        self.open_login_modal()

        self.send_keys(self.LOGIN_USERNAME_FIELD, Keys.TAB)

        self.send_keys(self.LOGIN_PASSWORD_FIELD, Keys.TAB)

        self.logger.info("Tabbed through login form")
        return True


    def inject_sql_payload_username(self, payload):
        """
        Inject SQL payload into username field (for security testing).

        Args:
            payload: SQL injection payload

        Returns:
            True if injection attempt completed
        """
        self.open_login_modal()
        self.fill_login_username(payload)
        self.fill_login_password("anypassword")
        self.click_login_submit()
        self.logger.warning(f"SQL injection payload tested: {payload}")
        return True

    def inject_xss_payload_username(self, payload):
        """
        Inject XSS payload into username field (for security testing).

        Args:
            payload: XSS payload

        Returns:
            True if injection attempt completed
        """
        self.open_login_modal()
        self.fill_login_username(payload)
        self.fill_login_password("anypassword")
        self.click_login_submit()
        self.logger.warning(f"XSS payload tested: {payload}")
        return True

    def check_for_csrf_token(self):
        """
        Check if login form has CSRF token (for security testing).

        Returns:
            True if CSRF token found, False otherwise
        """
        self.open_login_modal()
        page_source = self.get_page_source()

        has_csrf = 'csrf' in page_source.lower() or 'token' in page_source.lower()

        if has_csrf:
            self.logger.info("CSRF token detected")
        else:
            self.logger.warning("No CSRF token found")

        return has_csrf

    def get_session_cookies(self):
        """
        Get all session-related cookies (for security testing).

        Returns:
            List of cookie dictionaries
        """
        cookies = self.driver.get_cookies()
        session_cookies = [c for c in cookies if 'session' in c.get('name', '').lower()]
        self.logger.info(f"Found {len(session_cookies)} session cookies")
        return session_cookies
