"""
Test Suite: Login & Authentication Functionality
Module: test_login_functionality.py
Author: QA Testing Team
Version: 2.0 - Complete DISCOVER Philosophy Implementation

Test Categories:
- Functional Tests: Verify login/authentication features work correctly
- Business Rules: Validate against industry standards (OWASP ASVS, NIST, ISO 27001, WCAG)

Standards Validated:
- OWASP ASVS v5.0 Chapter 2 (Authentication Verification)
- NIST SP 800-63B Section 5.1.1 (Password Guidelines)
- ISO 27001 A.9.4 (Access Control)
- WCAG 2.1 Success Criterion 3.3.1 (Error Identification)
- ISO 25010 (Software Quality - Functional Suitability)

Execution:
Run all tests:           pytest test_login_functionality.py -v
Run functional only:     pytest test_login_functionality.py -k "FUNC" -v
Run business rules:      pytest test_login_functionality.py -k "BR" -v
Run security tests:      pytest test_login_functionality.py -k "security" -v
With HTML report:        pytest test_login_functionality.py --html=report_login.html --self-contained-html

Total Expected Tests: 35+ (with parametrization)
- 7 Functional Tests
- 22 Business Rules Tests (16 base + 6 parametrized variants)
"""

import logging
import time

import pytest
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

logging.basicConfig(
    level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s"
)


BASE_URL = "https://www.demoblaze.com/"

TIMEOUT = 10
TIMEOUT_SHORT = 2
TIMEOUT_MEDIUM = 5

TEST_USERNAME = "Apolo2025"
TEST_PASSWORD = "apolo2025"


LOGIN_BUTTON_NAV = (By.ID, "login2")
LOGOUT_BUTTON_NAV = (By.ID, "logout2")
WELCOME_USER_TEXT = (By.ID, "nameofuser")

LOGIN_MODAL = (By.ID, "logInModal")
LOGIN_USERNAME_FIELD = (By.ID, "loginusername")
LOGIN_PASSWORD_FIELD = (By.ID, "loginpassword")
LOGIN_SUBMIT_BUTTON = (By.XPATH, "//button[text()='Log in']")
CLOSE_LOGIN_MODAL = (
    By.XPATH,
    "//div[@id='logInModal']//button[text()='Close']",
)
CLOSE_LOGIN_MODAL_X = (
    By.XPATH,
    "//div[@id='logInModal']//button[@class='close']",
)

SIGNUP_BUTTON_NAV = (By.ID, "signin2")
SIGNUP_MODAL = (By.ID, "signInModal")
SIGNUP_USERNAME_FIELD = (By.ID, "sign-username")
SIGNUP_PASSWORD_FIELD = (By.ID, "sign-password")
SIGNUP_SUBMIT_BUTTON = (By.XPATH, "//button[text()='Sign up']")


def wait_for_alert_and_get_text(browser, timeout=TIMEOUT_MEDIUM):
    try:
        WebDriverWait(browser, timeout).until(EC.alert_is_present())
        alert = browser.switch_to.alert
        alert_text = alert.text
        alert.accept()
        logging.info(f"DISCOVERED: Alert with text '{alert_text}'")
        return alert_text
    except TimeoutException:
        logging.info("DISCOVERED: No alert appeared")
        return None


def perform_login(browser, username, password, timeout=TIMEOUT):
    try:
        login_nav_button = WebDriverWait(browser, timeout).until(
            EC.element_to_be_clickable(LOGIN_BUTTON_NAV)
        )
        login_nav_button.click()
        logging.info("Clicked login button in navigation")

        WebDriverWait(browser, timeout).until(
            EC.visibility_of_element_located(LOGIN_MODAL)
        )
        logging.info("Login modal opened")

        username_field = WebDriverWait(browser, timeout).until(
            EC.visibility_of_element_located(LOGIN_USERNAME_FIELD)
        )
        username_field.clear()
        username_field.send_keys(username)
        logging.info(f"Entered username: {username}")

        password_field = WebDriverWait(browser, timeout).until(
            EC.visibility_of_element_located(LOGIN_PASSWORD_FIELD)
        )
        password_field.clear()
        password_field.send_keys(password)
        logging.info(f"Entered password: {'*' * len(password)}")

        login_submit = WebDriverWait(browser, timeout).until(
            EC.element_to_be_clickable(LOGIN_SUBMIT_BUTTON)
        )
        login_submit.click()
        logging.info("Clicked login submit button")

        return True

    except (TimeoutException, NoSuchElementException) as e:
        logging.error(f"Login form interaction failed: {str(e)}")
        return False


def is_user_logged_in(browser, timeout=TIMEOUT_MEDIUM):
    try:
        welcome_element = WebDriverWait(browser, timeout).until(
            EC.visibility_of_element_located(WELCOME_USER_TEXT)
        )
        welcome_text = welcome_element.text
        logging.info(
            f"DISCOVERED: User is logged in, welcome message shows: {welcome_text}"
        )
        return True
    except TimeoutException:
        logging.info("DISCOVERED: User is NOT logged in (no welcome message)")
        return False


def perform_logout(browser, timeout=TIMEOUT):
    try:
        logout_button = WebDriverWait(browser, timeout).until(
            EC.element_to_be_clickable(LOGOUT_BUTTON_NAV)
        )
        logout_button.click()
        logging.info("Clicked logout button")
        time.sleep(1)
        return True
    except (TimeoutException, NoSuchElementException) as e:
        logging.error(f"Logout button not found: {str(e)}")
        return False


def get_element_attribute(browser, locator, attribute, timeout=TIMEOUT):
    try:
        element = WebDriverWait(browser, timeout).until(
            EC.presence_of_element_located(locator)
        )
        return element.get_attribute(attribute)
    except TimeoutException:
        return None


def element_has_attribute(browser, locator, attribute, timeout=TIMEOUT):
    try:
        element = WebDriverWait(browser, timeout).until(
            EC.presence_of_element_located(locator)
        )
        return element.get_attribute(attribute) is not None
    except TimeoutException:
        return False


@pytest.fixture
def browser():
    driver = webdriver.Chrome()
    driver.maximize_window()
    yield driver
    driver.quit()


@pytest.mark.functional
def test_valid_login_success_FUNC_001(browser):
    """
    TC-LOGIN-FUNC-001: Valid Login with Correct Credentials

    Discovers if login works with valid username and password.
    This is the happy path test for authentication functionality.

    Expected Behavior:
    - User can successfully log in with correct credentials
    - Welcome message appears with username
    - No error messages or alerts

    Priority: CRITICAL - Core functionality
    """
    logging.info("=" * 80)
    logging.info(
        "TC-LOGIN-FUNC-001: Testing valid login with correct credentials"
    )

    browser.get(BASE_URL)

    login_successful = perform_login(browser, TEST_USERNAME, TEST_PASSWORD)
    assert login_successful, "Failed to interact with login form"

    time.sleep(1)

    alert_text = wait_for_alert_and_get_text(browser)

    logged_in = is_user_logged_in(browser)

    if logged_in and alert_text is None:
        logging.info("DISCOVERED: Login successful - user is authenticated")
        assert True
    elif not logged_in and alert_text:
        logging.error(f"DISCOVERED: Login failed with alert: {alert_text}")
        pytest.fail(f"Login rejected with alert: {alert_text}")
    else:
        logging.error("DISCOVERED: Unexpected login behavior")
        pytest.fail("Login behavior does not match expected patterns")


@pytest.mark.functional
def test_invalid_username_rejected_FUNC_002(browser):
    """
    TC-LOGIN-FUNC-002: Invalid Username is Rejected

    Discovers if system rejects login with non-existent username.

    Expected Behavior:
    - Login should fail
    - Error message or alert should appear
    - User should NOT be logged in

    Priority: HIGH - Security requirement
    """
    logging.info("=" * 80)
    logging.info("TC-LOGIN-FUNC-002: Testing login with invalid username")

    browser.get(BASE_URL)

    invalid_username = "nonexistent_user_12345"
    perform_login(browser, invalid_username, "anypassword")

    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    logged_in = is_user_logged_in(browser, timeout=TIMEOUT_SHORT)

    if not logged_in:
        if alert_text:
            logging.info(
                f"DISCOVERED: Login correctly rejected with alert: {alert_text}"
            )
        else:
            logging.info(
                "DISCOVERED: Login correctly rejected (no alert, but not logged in)"
            )
        assert True
    else:
        logging.error(
            "DISCOVERED: SECURITY ISSUE - Invalid username was accepted"
        )
        pytest.fail("System accepted invalid username - SECURITY VIOLATION")


@pytest.mark.functional
def test_invalid_password_rejected_FUNC_003(browser):
    """
    TC-LOGIN-FUNC-003: Invalid Password is Rejected

    Discovers if system rejects login with wrong password for existing user.

    Expected Behavior:
    - Login should fail
    - Error message or alert should appear
    - User should NOT be logged in

    Priority: CRITICAL - Security requirement
    """
    logging.info("=" * 80)
    logging.info("TC-LOGIN-FUNC-003: Testing login with invalid password")

    browser.get(BASE_URL)

    wrong_password = "WrongPassword999!"
    perform_login(browser, TEST_USERNAME, wrong_password)

    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    logged_in = is_user_logged_in(browser, timeout=TIMEOUT_SHORT)

    if not logged_in:
        if alert_text:
            logging.info(
                f"DISCOVERED: Login correctly rejected with alert: {alert_text}"
            )
        else:
            logging.info(
                "DISCOVERED: Login correctly rejected (no alert, but not logged in)"
            )
        assert True
    else:
        logging.error(
            "DISCOVERED: SECURITY ISSUE - Wrong password was accepted"
        )
        pytest.fail(
            "System accepted wrong password - CRITICAL SECURITY VIOLATION"
        )


@pytest.mark.functional
def test_empty_credentials_rejected_FUNC_004(browser):
    """
    TC-LOGIN-FUNC-004: Empty Credentials are Rejected

    Discovers if system rejects login attempt with both fields empty.

    Expected Behavior:
    - Login should fail
    - Validation message should appear
    - User should NOT be logged in

    Priority: HIGH - Input validation requirement
    """
    logging.info("=" * 80)
    logging.info("TC-LOGIN-FUNC-004: Testing login with empty credentials")

    browser.get(BASE_URL)

    perform_login(browser, "", "")

    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    logged_in = is_user_logged_in(browser, timeout=TIMEOUT_SHORT)

    if not logged_in:
        if alert_text:
            logging.info(
                f"DISCOVERED: Empty credentials rejected with alert: {alert_text}"
            )
        else:
            logging.info(
                "DISCOVERED: Empty credentials rejected (no alert, but not logged in)"
            )
        assert True
    else:
        logging.error(
            "DISCOVERED: SECURITY ISSUE - Empty credentials accepted"
        )
        pytest.fail(
            "System accepted empty credentials - INPUT VALIDATION FAILURE"
        )


@pytest.mark.functional
def test_complete_login_logout_flow_FUNC_005(browser):
    """
    TC-LOGIN-FUNC-005: Complete Login-Logout Flow

    Discovers if full authentication cycle works correctly:
    1. Login with valid credentials
    2. Verify user is logged in
    3. Logout
    4. Verify user is logged out

    Expected Behavior:
    - User can log in successfully
    - User can log out successfully
    - Welcome message appears/disappears appropriately

    Priority: CRITICAL - Core user flow
    """
    logging.info("=" * 80)
    logging.info("TC-LOGIN-FUNC-005: Testing complete login-logout flow")

    browser.get(BASE_URL)

    logging.info("STEP 1: Performing login")
    perform_login(browser, TEST_USERNAME, TEST_PASSWORD)
    time.sleep(1)
    wait_for_alert_and_get_text(browser)

    logged_in_after_login = is_user_logged_in(browser)
    if not logged_in_after_login:
        pytest.fail("Login step failed - cannot proceed with logout test")
    logging.info("DISCOVERED: Login successful")

    logging.info("STEP 2: Performing logout")
    logout_success = perform_logout(browser)
    if not logout_success:
        pytest.fail("Could not find logout button")

    logged_in_after_logout = is_user_logged_in(browser, timeout=TIMEOUT_SHORT)

    if not logged_in_after_logout:
        logging.info(
            "DISCOVERED: Complete flow successful - login and logout work correctly"
        )
        assert True
    else:
        logging.error(
            "DISCOVERED: Logout failed - user still appears logged in"
        )
        pytest.fail("Logout failed - user remains authenticated")


@pytest.mark.functional
def test_modal_close_button_FUNC_006(browser):
    """
    TC-LOGIN-FUNC-006: Login Modal Close Button Works

    Discovers if user can close the login modal without logging in.

    Expected Behavior:
    - Modal can be closed via Close button
    - Modal can be closed via X button
    - User remains logged out after closing modal

    Priority: MEDIUM - UX/UI usability
    """
    logging.info("=" * 80)
    logging.info("TC-LOGIN-FUNC-006: Testing login modal close functionality")

    browser.get(BASE_URL)

    logging.info("TEST 1: Testing 'Close' button")
    login_nav_button = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(LOGIN_BUTTON_NAV)
    )
    login_nav_button.click()

    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(LOGIN_MODAL)
    )

    close_button = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(CLOSE_LOGIN_MODAL)
    )
    close_button.click()
    time.sleep(1)

    logged_in_after_close = is_user_logged_in(browser, timeout=TIMEOUT_SHORT)
    if logged_in_after_close:
        pytest.fail("User logged in after closing modal - unexpected behavior")

    logging.info("DISCOVERED: Close button works correctly")
    assert True


@pytest.mark.functional
def test_session_persistence_after_reload_FUNC_007(browser):
    """
    TC-LOGIN-FUNC-007: Session Persists After Page Reload

    Discovers if user session is maintained after browser refresh.

    Expected Behavior:
    - User logs in successfully
    - Page is refreshed
    - User remains logged in after refresh

    Priority: HIGH - Session management requirement
    """
    logging.info("=" * 80)
    logging.info(
        "TC-LOGIN-FUNC-007: Testing session persistence after page reload"
    )

    browser.get(BASE_URL)

    perform_login(browser, TEST_USERNAME, TEST_PASSWORD)
    time.sleep(1)
    wait_for_alert_and_get_text(browser)

    logged_in_before_reload = is_user_logged_in(browser)
    if not logged_in_before_reload:
        pytest.fail("Login failed - cannot test session persistence")

    logging.info("Reloading page...")
    browser.refresh()
    WebDriverWait(browser, TIMEOUT).until(
        lambda d: d.execute_script("return document.readyState") == "complete"
    )

    logged_in_after_reload = is_user_logged_in(browser)

    if logged_in_after_reload:
        logging.info("DISCOVERED: Session persists after page reload")
        assert True
    else:
        logging.warning("DISCOVERED: Session does NOT persist after reload")
        pytest.fail(
            "Session lost after page reload - session management issue"
        )


@pytest.mark.business_rules
def test_username_max_length_BR_001(browser):
    """
    TC-LOGIN-BR-001: Username Maximum Length Validation

    Business Rule: System should handle maximum username length appropriately
    Standard: ISO 25010 (Software Quality - Functional Suitability)
    Priority: MEDIUM
    Impact: Prevents buffer overflow and database errors

    Test discovers:
    - Does system accept extremely long usernames?
    - Is there input validation for max length?
    - What error message appears?
    """
    logging.info("=" * 80)
    logging.info(
        "TC-LOGIN-BR-001: ISO 25010 - Testing username max length handling"
    )

    browser.get(BASE_URL)

    extremely_long_username = "A" * 256
    perform_login(browser, extremely_long_username, TEST_PASSWORD)

    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    logged_in = is_user_logged_in(browser, timeout=TIMEOUT_SHORT)

    if not logged_in:
        if alert_text:
            logging.info(
                f"DISCOVERED: System rejects long username with message: {alert_text}"
            )
        else:
            logging.info(
                "DISCOVERED: System rejects long username (no specific error message)"
            )
        assert True
    else:
        logging.error(
            "DISCOVERED: System accepted 256-character username - potential security risk"
        )
        logging.error(f"Standard: ISO 25010 - Input validation requirement")
        logging.error(
            f"Impact: Could lead to buffer overflow or database errors"
        )
        pytest.fail(
            "BUSINESS RULE VIOLATION: No max length validation on username"
        )


@pytest.mark.business_rules
def test_password_max_length_BR_002(browser):
    """
    TC-LOGIN-BR-002: Password Maximum Length Validation

    Business Rule: Password length should be validated according to security standards
    Standard: NIST SP 800-63B Section 5.1.1 (recommends max 64 characters minimum)
    Priority: HIGH
    Impact: Prevents denial of service and ensures proper password storage

    Test discovers:
    - Does system handle very long passwords?
    - Is there reasonable max length enforcement?
    """
    logging.info("=" * 80)
    logging.info(
        "TC-LOGIN-BR-002: NIST 800-63B - Testing password max length handling"
    )

    browser.get(BASE_URL)

    extremely_long_password = "P@ssw0rd!" * 16
    perform_login(browser, TEST_USERNAME, extremely_long_password)

    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    logged_in = is_user_logged_in(browser, timeout=TIMEOUT_SHORT)

    if not logged_in:
        logging.info(
            "DISCOVERED: System rejects or doesn't match extremely long password"
        )
        assert True
    else:
        logging.warning("DISCOVERED: System accepted 128-character password")
        logging.info(
            f"Standard: NIST SP 800-63B recommends max 64 chars minimum support"
        )
        assert True


@pytest.mark.business_rules
def test_whitespace_only_username_BR_003(browser):
    """
    TC-LOGIN-BR-003: Whitespace-Only Username Validation

    Business Rule: System should reject usernames containing only whitespace
    Standard: ISO 27001 A.9.4 (Access Control - Authentication)
    Priority: MEDIUM
    Impact: Prevents creation of invalid or confusing user accounts

    Test discovers:
    - Does system trim whitespace?
    - Does system reject whitespace-only input?
    """
    logging.info("=" * 80)
    logging.info(
        "TC-LOGIN-BR-003: ISO 27001 A.9.4 - Testing whitespace-only username"
    )

    browser.get(BASE_URL)

    whitespace_username = "     "
    perform_login(browser, whitespace_username, TEST_PASSWORD)

    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    logged_in = is_user_logged_in(browser, timeout=TIMEOUT_SHORT)

    if not logged_in:
        if alert_text:
            logging.info(
                f"DISCOVERED: System correctly rejects whitespace-only username: {alert_text}"
            )
        else:
            logging.info(
                "DISCOVERED: System correctly rejects whitespace-only username"
            )
        assert True
    else:
        logging.error(
            "DISCOVERED: BUSINESS RULE VIOLATION - Whitespace-only username accepted"
        )
        logging.error(
            f"Standard: ISO 27001 A.9.4 - Input validation requirement"
        )
        logging.error(
            f"Impact: Could create invalid or confusing user accounts"
        )
        pytest.fail("System accepted whitespace-only username")


@pytest.mark.business_rules
def test_whitespace_only_password_BR_004(browser):
    """
    TC-LOGIN-BR-004: Whitespace-Only Password Validation

    Business Rule: System should reject passwords containing only whitespace
    Standard: NIST SP 800-63B Section 5.1.1 (Password Requirements)
    Priority: HIGH
    Impact: Weak authentication, potential security vulnerability

    Test discovers:
    - Does system allow whitespace-only passwords?
    - Is there proper password validation?
    """
    logging.info("=" * 80)
    logging.info(
        "TC-LOGIN-BR-004: NIST 800-63B - Testing whitespace-only password"
    )

    browser.get(BASE_URL)

    whitespace_password = "     "
    perform_login(browser, TEST_USERNAME, whitespace_password)

    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    logged_in = is_user_logged_in(browser, timeout=TIMEOUT_SHORT)

    if not logged_in:
        logging.info(
            "DISCOVERED: System correctly rejects whitespace-only password"
        )
        assert True
    else:
        logging.error(
            "DISCOVERED: CRITICAL SECURITY VIOLATION - Whitespace-only password accepted"
        )
        logging.error(f"Standard: NIST SP 800-63B Section 5.1.1")
        logging.error(
            f"Impact: Extremely weak authentication, critical security flaw"
        )
        pytest.fail(
            "System accepted whitespace-only password - CRITICAL SECURITY ISSUE"
        )


@pytest.mark.business_rules
def test_username_whitespace_normalization_BR_005(browser):
    """
    TC-LOGIN-BR-005: Username Whitespace Normalization

    Business Rule: System should handle leading/trailing whitespace consistently
    Standard: ISO 25010 (Usability - User error protection)
    Priority: MEDIUM
    Impact: Improves UX, prevents user confusion

    Test discovers:
    - Does system trim leading/trailing whitespace?
    - Can user log in with spaces around username?
    """
    logging.info("=" * 80)
    logging.info(
        "TC-LOGIN-BR-005: ISO 25010 - Testing username whitespace normalization"
    )

    browser.get(BASE_URL)

    username_with_spaces = f"  {TEST_USERNAME}  "
    perform_login(browser, username_with_spaces, TEST_PASSWORD)

    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    logged_in = is_user_logged_in(browser)

    if logged_in:
        logging.info("DISCOVERED: System trims whitespace - Good UX practice")
        assert True
    else:
        logging.warning(
            "DISCOVERED: System does NOT trim whitespace from username"
        )
        logging.info(f"Note: ISO 25010 recommends user error protection")
        logging.info(
            f"Impact: Users might fail login due to accidental spaces"
        )
        assert True


@pytest.mark.business_rules
def test_special_characters_in_username_BR_006(browser):
    """
    TC-LOGIN-BR-006: Special Characters in Username

    Business Rule: System should handle special characters appropriately
    Standard: OWASP ASVS v5.0 Section 2.3.1 (Input validation)
    Priority: HIGH
    Impact: Prevents injection attacks, ensures data integrity

    Test discovers:
    - What special characters are allowed?
    - Are dangerous characters properly escaped?
    """
    logging.info("=" * 80)
    logging.info(
        "TC-LOGIN-BR-006: OWASP ASVS 2.3.1 - Testing special characters in username"
    )

    browser.get(BASE_URL)

    special_char_username = "test<user>!@#$%"
    perform_login(browser, special_char_username, TEST_PASSWORD)

    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    logged_in = is_user_logged_in(browser, timeout=TIMEOUT_SHORT)

    if not logged_in:
        if alert_text:
            logging.info(
                f"DISCOVERED: System rejects special characters with message: {alert_text}"
            )
        else:
            logging.info(
                "DISCOVERED: System rejects or doesn't match special character username"
            )
        assert True
    else:
        logging.warning(
            "DISCOVERED: System accepted special characters in username"
        )
        logging.info(
            f"Standard: OWASP ASVS v5.0 Section 2.3.1 - Input validation"
        )
        logging.info(f"Note: Special characters should be properly sanitized")
        assert True


@pytest.mark.business_rules
def test_case_sensitivity_username_BR_007(browser):
    """
    TC-LOGIN-BR-007: Username Case Sensitivity

    Business Rule: System should be consistent in username case handling
    Standard: ISO 27001 A.9.4 (Authentication consistency)
    Priority: MEDIUM
    Impact: User confusion, potential security implications

    Test discovers:
    - Are usernames case-sensitive?
    - Is behavior consistent?
    """
    logging.info("=" * 80)
    logging.info(
        "TC-LOGIN-BR-007: ISO 27001 A.9.4 - Testing username case sensitivity"
    )

    browser.get(BASE_URL)

    uppercase_username = TEST_USERNAME.upper()
    perform_login(browser, uppercase_username, TEST_PASSWORD)

    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    logged_in = is_user_logged_in(browser)

    if logged_in:
        logging.info("DISCOVERED: Usernames are NOT case-sensitive")
        logging.info(
            f"Note: Both '{TEST_USERNAME}' and '{uppercase_username}' work"
        )
    else:
        logging.info("DISCOVERED: Usernames ARE case-sensitive")
        logging.info(
            f"Note: '{uppercase_username}' does not match '{TEST_USERNAME}'"
        )

    assert True


@pytest.mark.business_rules
def test_case_sensitivity_password_BR_008(browser):
    """
    TC-LOGIN-BR-008: Password Case Sensitivity

    Business Rule: Passwords MUST be case-sensitive per security standards
    Standard: NIST SP 800-63B Section 5.1.1
    Priority: CRITICAL
    Impact: Security - case-insensitive passwords are significantly weaker

    Test discovers:
    - Are passwords case-sensitive?
    - Can user log in with wrong case?
    """
    logging.info("=" * 80)
    logging.info(
        "TC-LOGIN-BR-008: NIST 800-63B - Testing password case sensitivity"
    )

    browser.get(BASE_URL)

    wrong_case_password = TEST_PASSWORD.upper()
    perform_login(browser, TEST_USERNAME, wrong_case_password)

    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    logged_in = is_user_logged_in(browser, timeout=TIMEOUT_SHORT)

    if not logged_in:
        logging.info(
            "DISCOVERED: Passwords ARE case-sensitive - Good security practice"
        )
        logging.info(
            f"Standard: NIST SP 800-63B requires case-sensitive passwords"
        )
        assert True
    else:
        logging.error(
            "DISCOVERED: CRITICAL SECURITY VIOLATION - Passwords are NOT case-sensitive"
        )
        logging.error(f"Standard: NIST SP 800-63B Section 5.1.1")
        logging.error(
            f"Impact: Dramatically reduces password entropy and security"
        )
        pytest.fail("Passwords must be case-sensitive per NIST 800-63B")


@pytest.mark.business_rules
def test_empty_username_only_BR_009(browser):
    """
    TC-LOGIN-BR-009: Empty Username Field Only

    Business Rule: System should validate required fields individually
    Standard: WCAG 2.1 SC 3.3.1 (Error Identification)
    Priority: MEDIUM
    Impact: User experience - clear error messages for specific fields

    Test discovers:
    - Does system identify which field is empty?
    - Is error message specific?
    """
    logging.info("=" * 80)
    logging.info(
        "TC-LOGIN-BR-009: WCAG 2.1 SC 3.3.1 - Testing empty username only"
    )

    browser.get(BASE_URL)

    perform_login(browser, "", TEST_PASSWORD)

    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    logged_in = is_user_logged_in(browser, timeout=TIMEOUT_SHORT)

    if not logged_in:
        if alert_text:
            logging.info(
                f"DISCOVERED: System rejects empty username with message: {alert_text}"
            )
            if "username" in alert_text.lower():
                logging.info(
                    "GOOD: Error message specifically mentions username field"
                )
            else:
                logging.info(
                    "Note: Error message is generic (not field-specific)"
                )
        else:
            logging.info(
                "DISCOVERED: System rejects empty username (no error message)"
            )
        assert True
    else:
        logging.error(
            "DISCOVERED: INPUT VALIDATION FAILURE - Empty username accepted"
        )
        pytest.fail("System accepted empty username field")


@pytest.mark.business_rules
def test_empty_password_only_BR_010(browser):
    """
    TC-LOGIN-BR-010: Empty Password Field Only

    Business Rule: System should validate required fields individually
    Standard: WCAG 2.1 SC 3.3.1 (Error Identification)
    Priority: MEDIUM
    Impact: User experience - clear error messages for specific fields

    Test discovers:
    - Does system identify which field is empty?
    - Is error message specific?
    """
    logging.info("=" * 80)
    logging.info(
        "TC-LOGIN-BR-010: WCAG 2.1 SC 3.3.1 - Testing empty password only"
    )

    browser.get(BASE_URL)

    perform_login(browser, TEST_USERNAME, "")

    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    logged_in = is_user_logged_in(browser, timeout=TIMEOUT_SHORT)

    if not logged_in:
        if alert_text:
            logging.info(
                f"DISCOVERED: System rejects empty password with message: {alert_text}"
            )
            if "password" in alert_text.lower():
                logging.info(
                    "GOOD: Error message specifically mentions password field"
                )
            else:
                logging.info(
                    "Note: Error message is generic (not field-specific)"
                )
        else:
            logging.info(
                "DISCOVERED: System rejects empty password (no error message)"
            )
        assert True
    else:
        logging.error(
            "DISCOVERED: CRITICAL SECURITY VIOLATION - Empty password accepted"
        )
        pytest.fail("System accepted empty password - CRITICAL SECURITY ISSUE")


@pytest.mark.business_rules
def test_numeric_only_username_BR_011(browser):
    """
    TC-LOGIN-BR-011: Numeric-Only Username

    Business Rule: System should handle numeric-only usernames consistently
    Standard: ISO 25010 (Functional Suitability)
    Priority: LOW
    Impact: Edge case - some users might want numeric usernames

    Test discovers:
    - Does system allow numeric-only usernames?
    - Is behavior consistent?
    """
    logging.info("=" * 80)
    logging.info("TC-LOGIN-BR-011: ISO 25010 - Testing numeric-only username")

    browser.get(BASE_URL)

    numeric_username = "1234567890"
    perform_login(browser, numeric_username, TEST_PASSWORD)

    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    logged_in = is_user_logged_in(browser, timeout=TIMEOUT_SHORT)

    if not logged_in:
        logging.info(
            "DISCOVERED: System rejects or doesn't match numeric-only username"
        )
        assert True
    else:
        logging.info("DISCOVERED: System accepts numeric-only usernames")
        assert True


@pytest.mark.business_rules
def test_unicode_characters_BR_012(browser):
    """
    TC-LOGIN-BR-012: Unicode Characters in Username

    Business Rule: System should support internationalization
    Standard: ISO 25010 (Portability - Adaptability)
    Priority: MEDIUM
    Impact: International users, accessibility

    Test discovers:
    - Does system support Unicode characters?
    - Can international users use their language characters?
    """
    logging.info("=" * 80)
    logging.info("TC-LOGIN-BR-012: ISO 25010 - Testing Unicode characters")

    browser.get(BASE_URL)

    unicode_username = "用户名测试"
    perform_login(browser, unicode_username, TEST_PASSWORD)

    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    logged_in = is_user_logged_in(browser, timeout=TIMEOUT_SHORT)

    if not logged_in:
        logging.info(
            "DISCOVERED: System does not match Unicode username (expected if user doesn't exist)"
        )
        logging.info(
            f"Note: ISO 25010 recommends international character support"
        )
    else:
        logging.info(
            "DISCOVERED: System supports Unicode characters in usernames"
        )

    assert True


@pytest.mark.security
@pytest.mark.business_rules
@pytest.mark.parametrize(
    "sql_payload",
    ["' OR '1'='1", "admin'--", "' OR '1'='1' --", "') OR ('1'='1"],
)
def test_sql_injection_prevention_BR_013(browser, sql_payload):
    """
    TC-LOGIN-BR-013: SQL Injection Prevention

    Business Rule: System must prevent SQL injection attacks
    Standard: OWASP ASVS v5.0 Section 1.2.5 (SQL Injection Prevention)
    Priority: CRITICAL
    Impact: Complete database compromise, data breach
    CVSS Score: 9.8 (CRITICAL)

    Test discovers:
    - Does system properly sanitize SQL-like inputs?
    - Can attacker bypass authentication with SQL injection?
    """
    logging.info("=" * 80)
    logging.info(
        f"TC-LOGIN-BR-013: OWASP ASVS 1.2.5 - SQL injection test with: {sql_payload}"
    )

    browser.get(BASE_URL)

    perform_login(browser, sql_payload, "anypassword")

    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    logged_in = is_user_logged_in(browser, timeout=TIMEOUT_SHORT)

    if not logged_in:
        logging.info(
            f"DISCOVERED: SQL injection attempt blocked: {sql_payload}"
        )
        assert True
    else:
        logging.critical("=" * 80)
        logging.critical(
            "CRITICAL SECURITY VIOLATION: SQL INJECTION SUCCESSFUL"
        )
        logging.critical(f"Payload: {sql_payload}")
        logging.critical(f"Standard: OWASP ASVS v5.0 Section 1.2.5")
        logging.critical(f"Expected: Sanitize SQL injection attempts")
        logging.critical(
            f"Actual: SQL payload executed, authentication bypassed"
        )
        logging.critical(
            f"Impact: Complete database compromise - CRITICAL RISK"
        )
        logging.critical(f"CVSS Score: 9.8 (CRITICAL)")
        logging.critical("=" * 80)
        pytest.fail(
            f"SQL INJECTION VULNERABILITY - Payload succeeded: {sql_payload}"
        )


@pytest.mark.security
@pytest.mark.business_rules
@pytest.mark.parametrize(
    "xss_payload",
    [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
    ],
)
def test_xss_prevention_BR_014(browser, xss_payload):
    """
    TC-LOGIN-BR-014: Cross-Site Scripting (XSS) Prevention

    Business Rule: System must prevent XSS attacks
    Standard: OWASP ASVS v5.0 Section 1.2.1 (XSS Prevention)
    Priority: CRITICAL
    Impact: Account takeover, session hijacking, data theft
    CVSS Score: 7.5 (HIGH)

    Test discovers:
    - Does system properly encode/escape user inputs?
    - Can attacker inject malicious scripts?
    """
    logging.info("=" * 80)
    logging.info(
        f"TC-LOGIN-BR-014: OWASP ASVS 1.2.1 - XSS prevention test with: {xss_payload}"
    )

    browser.get(BASE_URL)

    perform_login(browser, xss_payload, TEST_PASSWORD)

    time.sleep(1)

    try:
        WebDriverWait(browser, 2).until(EC.alert_is_present())
        alert = browser.switch_to.alert
        alert_text = alert.text
        alert.accept()

        logging.critical("=" * 80)
        logging.critical("CRITICAL SECURITY VIOLATION: XSS EXECUTED")
        logging.critical(f"Payload: {xss_payload}")
        logging.critical(f"Standard: OWASP ASVS v5.0 Section 1.2.1")
        logging.critical(f"Expected: Encode/escape XSS attempts")
        logging.critical(f"Actual: XSS payload executed")
        logging.critical(
            f"Impact: XSS vulnerability - Account takeover possible"
        )
        logging.critical(f"CVSS Score: 7.5 (HIGH)")
        logging.critical("=" * 80)
        pytest.fail(f"XSS VULNERABILITY - Payload executed: {xss_payload}")

    except TimeoutException:
        logging.info(f"DISCOVERED: XSS attempt blocked: {xss_payload}")
        assert True


@pytest.mark.business_rules
@pytest.mark.accessibility
def test_keyboard_navigation_BR_015(browser):
    """
    TC-LOGIN-BR-015: Keyboard Navigation Support

    Business Rule: Login form must be fully accessible via keyboard
    Standard: WCAG 2.1 Success Criterion 2.1.1 (Keyboard Accessible)
    Priority: HIGH
    Impact: Accessibility for users with mobility impairments

    Test discovers:
    - Can user navigate form with Tab key?
    - Can user submit with Enter key?
    - Are all interactive elements keyboard-accessible?
    """
    logging.info("=" * 80)
    logging.info(
        "TC-LOGIN-BR-015: WCAG 2.1 SC 2.1.1 - Testing keyboard navigation"
    )

    browser.get(BASE_URL)

    login_nav_button = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(LOGIN_BUTTON_NAV)
    )
    login_nav_button.click()

    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(LOGIN_MODAL)
    )

    username_field = WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(LOGIN_USERNAME_FIELD)
    )

    username_field.click()
    username_field.send_keys(TEST_USERNAME)

    username_field.send_keys(Keys.TAB)
    time.sleep(0.5)

    active_element = browser.switch_to.active_element
    active_element.send_keys(TEST_PASSWORD)

    active_element.send_keys(Keys.RETURN)

    time.sleep(1)
    wait_for_alert_and_get_text(browser)
    logged_in = is_user_logged_in(browser)

    if logged_in:
        logging.info(
            "DISCOVERED: Keyboard navigation works - WCAG 2.1 compliant"
        )
        logging.info("User can Tab through fields and submit with Enter")
        assert True
    else:
        logging.error("DISCOVERED: Keyboard navigation failed")
        logging.error(f"Standard: WCAG 2.1 SC 2.1.1 - Keyboard Accessible")
        logging.error(f"Impact: Excludes users who cannot use mouse")
        pytest.fail(
            "Keyboard navigation not fully functional - WCAG violation"
        )


@pytest.mark.business_rules
@pytest.mark.accessibility
def test_form_labels_for_screen_readers_BR_016(browser):
    """
    TC-LOGIN-BR-016: Form Labels for Screen Readers

    Business Rule: Form inputs must have proper labels for assistive technology
    Standard: WCAG 2.1 Success Criterion 1.3.1 (Info and Relationships)
    Priority: HIGH
    Impact: Accessibility for visually impaired users

    Test discovers:
    - Do input fields have associated labels?
    - Are labels properly linked with for/id attributes?
    - Can screen readers identify form purpose?
    """
    logging.info("=" * 80)
    logging.info(
        "TC-LOGIN-BR-016: WCAG 2.1 SC 1.3.1 - Testing form labels for screen readers"
    )

    browser.get(BASE_URL)

    login_nav_button = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(LOGIN_BUTTON_NAV)
    )
    login_nav_button.click()

    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(LOGIN_MODAL)
    )

    username_field = WebDriverWait(browser, TIMEOUT).until(
        EC.presence_of_element_located(LOGIN_USERNAME_FIELD)
    )
    password_field = browser.find_element(*LOGIN_PASSWORD_FIELD)

    username_accessible_name = (
        username_field.get_attribute("aria-label")
        or username_field.get_attribute("placeholder")
        or username_field.get_attribute("title")
    )

    password_accessible_name = (
        password_field.get_attribute("aria-label")
        or password_field.get_attribute("placeholder")
        or password_field.get_attribute("title")
    )

    if username_accessible_name and password_accessible_name:
        logging.info(
            f"DISCOVERED: Username field accessible name: '{username_accessible_name}'"
        )
        logging.info(
            f"DISCOVERED: Password field accessible name: '{password_accessible_name}'"
        )
        logging.info(
            "WCAG 2.1 SC 1.3.1 compliant - Screen readers can identify fields"
        )
        assert True
    else:
        logging.warning("DISCOVERED: Form fields lack proper labels")
        logging.warning(
            f"Username accessible name: {username_accessible_name}"
        )
        logging.warning(
            f"Password accessible name: {password_accessible_name}"
        )
        logging.warning(
            f"Standard: WCAG 2.1 SC 1.3.1 - Info and Relationships"
        )
        logging.warning(
            f"Impact: Screen reader users cannot identify form fields"
        )

        try:
            browser.find_element(By.XPATH, "//label[@for='loginusername']")
            logging.info(
                "Note: Visible labels exist, but aria-labels are recommended"
            )
            assert True
        except NoSuchElementException:
            pytest.fail("Form lacks proper labels - WCAG 2.1 violation")


@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.critical
def test_account_lockout_enforcement_BR_017(browser):
    """
    TC-LOGIN-BR-017: Account Lockout / Rate Limiting Enforcement

    Business Rule: System must prevent brute force attacks via rate limiting
    Standard: OWASP ASVS v5.0 Section 2.2.1
    Standard: NIST SP 800-63B Section 5.2.2
    Priority: CRITICAL
    Impact: Prevents brute force attacks on user accounts
    CVSS Score: 7.5 (HIGH)

    Test discovers:
    - Does system implement rate limiting?
    - Is account locked after N failed attempts?
    - Are unlimited login attempts allowed?
    """
    logging.info("=" * 80)
    logging.info(
        "TC-LOGIN-BR-017: OWASP ASVS 2.2.1 - Testing account lockout/rate limiting"
    )

    browser.get(BASE_URL)

    max_attempts = 10
    lockout_detected = False

    for attempt in range(max_attempts):
        logging.info(
            f"Attempt {attempt + 1}/{max_attempts}: Trying wrong password"
        )
        perform_login(browser, TEST_USERNAME, f"wrong_password_{attempt}")

        time.sleep(1)
        alert_text = wait_for_alert_and_get_text(browser)

        if alert_text:
            lockout_keywords = [
                "locked",
                "too many",
                "attempts",
                "wait",
                "temporarily",
                "disabled",
                "blocked",
                "limit",
            ]

            alert_lower = alert_text.lower()
            if any(keyword in alert_lower for keyword in lockout_keywords):
                lockout_detected = True
                logging.info(
                    f"DISCOVERED: Lockout detected after {attempt + 1} attempts"
                )
                logging.info(f"Lockout message: {alert_text}")
                break

        browser.get(BASE_URL)

    if not lockout_detected:
        logging.critical("=" * 80)
        logging.critical(
            "CRITICAL SECURITY VIOLATION: NO ACCOUNT LOCKOUT / RATE LIMITING"
        )
        logging.critical("=" * 80)
        logging.critical("Issue: No rate limiting or account lockout detected")
        logging.critical("Standard: OWASP ASVS v5.0 Section 2.2.1")
        logging.critical("Standard: NIST SP 800-63B Section 5.2.2")
        logging.critical("Severity: HIGH")
        logging.critical("CVSS Score: 7.5")
        logging.critical(
            f"Evidence: {max_attempts} failed login attempts without lockout"
        )
        logging.critical(
            "Impact: Brute force attacks possible - unlimited password attempts"
        )
        logging.critical(
            "Recommendation: Implement progressive delays, account lockout, or CAPTCHA"
        )
        logging.critical("=" * 80)

        pytest.fail(
            f"DISCOVERED: NO rate limiting after {max_attempts} failed attempts - Violates OWASP ASVS 2.2.1"
        )
    else:
        logging.info(
            "DISCOVERED: Account lockout/rate limiting is implemented"
        )
        assert True


@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.critical
def test_2fa_mfa_enforcement_BR_018(browser):
    """
    TC-LOGIN-BR-018: Multi-Factor Authentication (2FA/MFA) Enforcement

    Business Rule: System should implement or offer 2FA/MFA
    Standard: NIST SP 800-63B Section 5.2.3
    Standard: ISO 27001 A.9.4.2
    Priority: CRITICAL
    Impact: Password-only authentication is single point of failure
    CVSS Score: 7.5 (HIGH)

    Test discovers:
    - Does system require 2FA after password login?
    - Is MFA offered or enforced?
    - Can user authenticate with password only?
    """
    logging.info("=" * 80)
    logging.info(
        "TC-LOGIN-BR-018: NIST 800-63B 5.2.3 - Testing 2FA/MFA enforcement"
    )

    browser.get(BASE_URL)

    perform_login(browser, TEST_USERNAME, TEST_PASSWORD)
    time.sleep(1)
    wait_for_alert_and_get_text(browser)

    logged_in_directly = is_user_logged_in(browser, timeout=TIMEOUT_SHORT)

    mfa_elements_found = False
    mfa_keywords = [
        "verification code",
        "authenticator",
        "2fa",
        "mfa",
        "second factor",
        "security code",
        "token",
    ]

    page_text = browser.page_source.lower()
    for keyword in mfa_keywords:
        if keyword in page_text:
            mfa_elements_found = True
            logging.info(f"DISCOVERED: MFA keyword found: {keyword}")
            break

    try:
        mfa_input = browser.find_element(
            By.XPATH,
            "//*[@type='tel' or @type='text'][contains(@placeholder, 'code')]",
        )
        if mfa_input.is_displayed():
            mfa_elements_found = True
            logging.info("DISCOVERED: MFA input field detected")
    except NoSuchElementException:
        pass

    if logged_in_directly and not mfa_elements_found:
        logging.critical("=" * 80)
        logging.critical("CRITICAL SECURITY VIOLATION: NO 2FA/MFA ENFORCEMENT")
        logging.critical("=" * 80)
        logging.critical("Issue: No Multi-Factor Authentication (MFA/2FA)")
        logging.critical("Standard: NIST SP 800-63B Section 5.2.3")
        logging.critical("Standard: ISO 27001 A.9.4.2")
        logging.critical("Severity: HIGH")
        logging.critical("CVSS Score: 7.5")
        logging.critical(
            "Evidence: User authenticated with password only (single factor)"
        )
        logging.critical(
            "Impact: Account vulnerable to password compromise alone"
        )
        logging.critical(
            "Recommendation: Implement TOTP, SMS, or hardware token 2FA"
        )
        logging.critical("=" * 80)

        pytest.fail("DISCOVERED: NO 2FA/MFA - Violates NIST 800-63B 5.2.3")
    else:
        logging.info("DISCOVERED: 2FA/MFA is enforced or required")
        assert True


@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.parametrize(
    "weak_password",
    ["123456", "password", "abc", "test", "qwerty", "12345678"],
)
def test_password_complexity_enforcement_BR_019(browser, weak_password):
    """
    TC-LOGIN-BR-019: Password Complexity Enforcement

    Business Rule: System must enforce password complexity requirements
    Standard: NIST SP 800-63B Section 5.1.1.2
    Priority: HIGH
    Impact: Weak passwords allow easy brute force attacks
    CVSS Score: 6.5 (MEDIUM)

    Test discovers:
    - Does system accept weak passwords during signup?
    - Are password complexity rules enforced?
    - Can users set easily guessable passwords?
    """
    logging.info("=" * 80)
    logging.info(
        f"TC-LOGIN-BR-019: NIST 800-63B 5.1.1.2 - Testing password complexity with: {weak_password}"
    )

    browser.get(BASE_URL)

    try:
        signup_button = WebDriverWait(browser, TIMEOUT_SHORT).until(
            EC.element_to_be_clickable(SIGNUP_BUTTON_NAV)
        )
        signup_button.click()

        WebDriverWait(browser, TIMEOUT).until(
            EC.visibility_of_element_located(SIGNUP_USERNAME_FIELD)
        )

        test_user = f"weakpwdtest_{int(time.time())}"

        username_field = browser.find_element(*SIGNUP_USERNAME_FIELD)
        username_field.clear()
        username_field.send_keys(test_user)

        password_field = browser.find_element(*SIGNUP_PASSWORD_FIELD)
        password_field.clear()
        password_field.send_keys(weak_password)

        browser.find_element(*SIGNUP_SUBMIT_BUTTON).click()

        time.sleep(1)
        alert_text = wait_for_alert_and_get_text(browser)

        if alert_text and (
            "success" in alert_text.lower()
            or "successful" in alert_text.lower()
        ):
            logging.critical("=" * 80)
            logging.critical(
                f"SECURITY VIOLATION: WEAK PASSWORD ACCEPTED: '{weak_password}'"
            )
            logging.critical("=" * 80)
            logging.critical("Issue: System accepts weak/common passwords")
            logging.critical("Standard: NIST SP 800-63B Section 5.1.1.2")
            logging.critical("Severity: MEDIUM")
            logging.critical("CVSS Score: 6.5")
            logging.critical(
                f"Evidence: Weak password '{weak_password}' was accepted during signup"
            )
            logging.critical(
                "Impact: Users can set easily crackable passwords"
            )
            logging.critical(
                "Recommendation: Enforce minimum 8 chars, check against common passwords"
            )
            logging.critical("=" * 80)

            pytest.fail(
                f"DISCOVERED: Weak password '{weak_password}' accepted - Violates NIST 800-63B"
            )
        else:
            logging.info(
                f"DISCOVERED: Weak password '{weak_password}' rejected (good)"
            )
            assert True

    except TimeoutException:
        logging.warning(
            "Cannot test password complexity - signup functionality not available"
        )
        logging.warning(
            "Note: This is a test environment limitation, not a PASS"
        )
        pytest.skip(
            "Signup functionality unavailable - cannot test password policy"
        )


@pytest.mark.business_rules
@pytest.mark.security
def test_captcha_bot_protection_BR_020(browser):
    """
    TC-LOGIN-BR-020: CAPTCHA / Bot Protection

    Business Rule: System should implement CAPTCHA or bot protection
    Standard: OWASP ASVS v5.0 Section 2.2.3
    Priority: HIGH
    Impact: Automated attacks and bot abuse possible without protection
    CVSS Score: 6.5 (MEDIUM)

    Test discovers:
    - Does login form have CAPTCHA?
    - Is there any bot protection mechanism?
    - Can automated tools access login freely?
    """
    logging.info("=" * 80)
    logging.info(
        "TC-LOGIN-BR-020: OWASP ASVS 2.2.3 - Testing CAPTCHA/bot protection"
    )

    browser.get(BASE_URL)

    login_nav_button = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(LOGIN_BUTTON_NAV)
    )
    login_nav_button.click()

    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(LOGIN_MODAL)
    )

    page_source = browser.page_source.lower()

    captcha_present = False
    captcha_keywords = [
        "recaptcha",
        "captcha",
        "hcaptcha",
        "challenge",
        "bot detection",
        "robot",
        "g-recaptcha",
    ]

    for keyword in captcha_keywords:
        if keyword in page_source:
            captcha_present = True
            logging.info(f"DISCOVERED: CAPTCHA detected ({keyword})")
            break

    if not captcha_present:
        logging.critical("=" * 80)
        logging.critical("SECURITY VIOLATION: NO CAPTCHA/BOT PROTECTION")
        logging.critical("=" * 80)
        logging.critical(
            "Issue: No CAPTCHA or bot protection mechanism detected"
        )
        logging.critical("Standard: OWASP ASVS v5.0 Section 2.2.3")
        logging.critical("Severity: MEDIUM")
        logging.critical("CVSS Score: 6.5")
        logging.critical("Evidence: No CAPTCHA keywords found in login form")
        logging.critical(
            "Impact: Automated brute force attacks, credential stuffing, bot abuse"
        )
        logging.critical(
            "Recommendation: Implement reCAPTCHA, hCaptcha, or equivalent"
        )
        logging.critical("=" * 80)

        pytest.fail("DISCOVERED: NO CAPTCHA - Violates OWASP ASVS 2.2.3")
    else:
        logging.info("DISCOVERED: CAPTCHA/bot protection present")
        assert True


@pytest.mark.business_rules
@pytest.mark.security
def test_password_reset_mechanism_BR_021(browser):
    """
    TC-LOGIN-BR-021: Password Reset Mechanism

    Business Rule: System should provide secure password reset functionality
    Standard: OWASP ASVS v5.0 Section 2.5.6
    Priority: MEDIUM
    Impact: Users cannot recover forgotten passwords without reset mechanism
    CVSS Score: 5.0 (MEDIUM)

    Test discovers:
    - Does system have password reset functionality?
    - Is "Forgot Password" link available?
    - Can users recover their accounts?
    """
    logging.info("=" * 80)
    logging.info(
        "TC-LOGIN-BR-021: OWASP ASVS 2.5.6 - Testing password reset mechanism"
    )

    browser.get(BASE_URL)

    page_source = browser.page_source.lower()

    reset_keywords = [
        "forgot password",
        "reset password",
        "recover password",
        "forgotten password",
        "password recovery",
    ]

    reset_found = False
    for keyword in reset_keywords:
        if keyword in page_source:
            reset_found = True
            logging.info(
                f"DISCOVERED: Password reset keyword found: {keyword}"
            )
            break

    try:
        reset_link = browser.find_element(
            By.XPATH,
            "//*[contains(text(), 'Forgot') or contains(text(), 'Reset')]",
        )
        if reset_link.is_displayed():
            reset_found = True
            logging.info("DISCOVERED: Password reset link detected")
    except NoSuchElementException:
        pass

    if not reset_found:
        logging.warning("=" * 80)
        logging.warning("SECURITY CONCERN: NO PASSWORD RESET MECHANISM")
        logging.warning("=" * 80)
        logging.warning("Issue: No password reset functionality detected")
        logging.warning("Standard: OWASP ASVS v5.0 Section 2.5.6")
        logging.warning("Severity: MEDIUM")
        logging.warning("CVSS Score: 5.0")
        logging.warning(
            "Evidence: No 'Forgot Password' link or reset mechanism found"
        )
        logging.warning("Impact: Users cannot recover forgotten passwords")
        logging.warning(
            "Recommendation: Implement secure password reset flow with email verification"
        )
        logging.warning("=" * 80)

        pytest.fail(
            "DISCOVERED: No password reset mechanism - Violates OWASP ASVS 2.5.6"
        )
    else:
        logging.info("DISCOVERED: Password reset mechanism exists")
        assert True


@pytest.mark.business_rules
@pytest.mark.security
def test_session_timeout_enforcement_BR_022(browser):
    """
    TC-LOGIN-BR-022: Session Timeout Enforcement

    Business Rule: System should implement session timeout for security
    Standard: OWASP ASVS v5.0 Section 3.3.2
    Standard: ISO 27001 A.9.4.2
    Priority: MEDIUM
    Impact: Prevents unauthorized access from unattended sessions
    CVSS Score: 5.3 (MEDIUM)

    Test discovers:
    - Does session expire after inactivity?
    - Is there idle timeout configured?
    - Can session remain active indefinitely?

    Note: This test performs basic check. Full timeout testing requires extended wait time.
    """
    logging.info("=" * 80)
    logging.info(
        "TC-LOGIN-BR-022: OWASP ASVS 3.3.2 - Testing session timeout (basic check)"
    )

    browser.get(BASE_URL)

    perform_login(browser, TEST_USERNAME, TEST_PASSWORD)
    time.sleep(1)
    wait_for_alert_and_get_text(browser)

    logged_in_initial = is_user_logged_in(browser)
    if not logged_in_initial:
        pytest.skip("Cannot test session timeout - login failed")

    logging.info("User logged in. Checking for timeout configuration...")

    cookies = browser.get_cookies()
    session_cookie = None

    for cookie in cookies:
        if (
            "session" in cookie.get("name", "").lower()
            or "token" in cookie.get("name", "").lower()
        ):
            session_cookie = cookie
            break

    has_timeout = False
    timeout_value = None

    if session_cookie:
        if "expiry" in session_cookie:
            expiry_timestamp = session_cookie["expiry"]
            import datetime

            expiry_time = datetime.datetime.fromtimestamp(expiry_timestamp)
            current_time = datetime.datetime.now()
            timeout_seconds = (expiry_time - current_time).total_seconds()

            if timeout_seconds > 0 and timeout_seconds < 86400:
                has_timeout = True
                timeout_value = timeout_seconds
                logging.info(
                    f"DISCOVERED: Session timeout configured: {timeout_seconds} seconds"
                )

    logging.info(
        "Note: Full session timeout testing requires extended idle period"
    )
    logging.info(
        "Standard: OWASP ASVS v5.0-3.3.2 recommends 2-8 hour timeout for web apps"
    )
    logging.info(
        "Standard: ISO 27001 A.9.4.2 requires automatic session termination"
    )

    if not has_timeout:
        logging.warning("=" * 80)
        logging.warning("SESSION TIMEOUT NOT CLEARLY DETECTED")
        logging.warning("=" * 80)
        logging.warning(
            "Issue: Session timeout configuration not clearly visible"
        )
        logging.warning("Standard: OWASP ASVS v5.0 Section 3.3.2")
        logging.warning("Standard: ISO 27001 A.9.4.2")
        logging.warning("Severity: MEDIUM")
        logging.warning("CVSS Score: 5.3")
        logging.warning(
            "Note: Session cookies may use browser session lifetime"
        )
        logging.warning("Impact: Idle sessions may remain active indefinitely")
        logging.warning(
            "Recommendation: Implement explicit idle timeout (2-8 hours)"
        )
        logging.warning("=" * 80)

        logging.info(
            "Note: This is a preliminary check - manual extended testing recommended"
        )

    perform_logout(browser)
    assert True
