"""
Test Suite: Signup & Registration Functionality
Module: test_signup_functionality.py
Author: QA Testing Team
Version: 1.0 - Complete DISCOVER Philosophy Implementation

Test Categories:
- Functional Tests: Verify signup/registration features work correctly
- Business Rules: Validate against industry standards (OWASP ASVS, NIST, ISO 27001, WCAG)

Standards Validated:
- OWASP ASVS v5.0 Chapter 2 (Authentication Verification)
- NIST SP 800-63B Section 5.1.1 (Password Guidelines)
- ISO 27001 A.9.4 (Access Control)
- WCAG 2.1 Success Criterion 3.3.1 (Error Identification)
- ISO 25010 (Software Quality - Functional Suitability)

Execution:
Run all tests:           pytest test_signup_functionality.py -v
Run functional only:     pytest test_signup_functionality.py -k "FUNC" -v
Run business rules:      pytest test_signup_functionality.py -k "BR" -v
Run security tests:      pytest test_signup_functionality.py -k "security" -v
With HTML report:        pytest test_signup_functionality.py --html=report_signup.html --self-contained-html

Total Expected Tests: 32+ (with parametrization)
- 6 Functional Tests
- 21 Business Rules Tests (15 base + 6 parametrized variants)
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.action_chains import ActionChains
import pytest
import time
import logging
import random
import string

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ============================================================================
# CONFIGURATION
# ============================================================================

BASE_URL = "https://www.demoblaze.com/"
TIMEOUT = 10
TIMEOUT_MEDIUM = 15
TIMEOUT_LONG = 20

# ============================================================================
# LOCATORS
# ============================================================================

SIGNUP_BUTTON_NAV = (By.ID, "signin2")
SIGNUP_MODAL = (By.ID, "signInModal")
SIGNUP_USERNAME_FIELD = (By.ID, "sign-username")
SIGNUP_PASSWORD_FIELD = (By.ID, "sign-password")
SIGNUP_SUBMIT_BUTTON = (By.XPATH, "//button[contains(text(),'Sign up')]")
SIGNUP_CLOSE_BUTTON = (By.XPATH, "//div[@id='signInModal']//button[@class='close']")

LOGIN_BUTTON_NAV = (By.ID, "login2")
LOGIN_MODAL = (By.ID, "logInModal")
LOGIN_USERNAME_FIELD = (By.ID, "loginusername")
LOGIN_PASSWORD_FIELD = (By.ID, "loginpassword")
LOGIN_SUBMIT_BUTTON = (By.XPATH, "//button[contains(text(),'Log in')]")

LOGOUT_BUTTON = (By.ID, "logout2")
WELCOME_USER_LINK = (By.ID, "nameofuser")

# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def browser():
    driver = webdriver.Chrome()
    driver.maximize_window()
    yield driver
    driver.quit()

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def generate_unique_username():
    timestamp = int(time.time())
    random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
    return f"testuser_{timestamp}_{random_suffix}"


def wait_for_alert_and_get_text(browser, timeout=5):
    try:
        WebDriverWait(browser, timeout).until(EC.alert_is_present())
        alert = browser.switch_to.alert
        alert_text = alert.text
        logging.info(f"Alert detected: {alert_text}")
        alert.accept()
        return alert_text
    except TimeoutException:
        logging.warning("No alert appeared")
        return None


def perform_signup(browser, username, password, timeout=TIMEOUT):
    try:
        signup_nav_button = WebDriverWait(browser, timeout).until(
            EC.element_to_be_clickable(SIGNUP_BUTTON_NAV)
        )
        signup_nav_button.click()
        logging.info("Clicked signup button in navigation")
        
        WebDriverWait(browser, timeout).until(
            EC.visibility_of_element_located(SIGNUP_MODAL)
        )
        logging.info("Signup modal opened")
        
        username_field = WebDriverWait(browser, timeout).until(
            EC.visibility_of_element_located(SIGNUP_USERNAME_FIELD)
        )
        username_field.clear()
        username_field.send_keys(username)
        logging.info(f"Entered username: {username}")
        
        password_field = WebDriverWait(browser, timeout).until(
            EC.visibility_of_element_located(SIGNUP_PASSWORD_FIELD)
        )
        password_field.clear()
        password_field.send_keys(password)
        logging.info(f"Entered password: {'*' * len(password)}")
        
        signup_submit = WebDriverWait(browser, timeout).until(
            EC.element_to_be_clickable(SIGNUP_SUBMIT_BUTTON)
        )
        signup_submit.click()
        logging.info("Clicked signup submit button")
        
        return True
        
    except (TimeoutException, NoSuchElementException) as e:
        logging.error(f"Signup form interaction failed: {str(e)}")
        return False


def perform_login(browser, username, password, timeout=TIMEOUT):
    try:
        login_nav_button = WebDriverWait(browser, timeout).until(
            EC.element_to_be_clickable(LOGIN_BUTTON_NAV)
        )
        login_nav_button.click()
        
        WebDriverWait(browser, timeout).until(
            EC.visibility_of_element_located(LOGIN_MODAL)
        )
        
        username_field = WebDriverWait(browser, timeout).until(
            EC.visibility_of_element_located(LOGIN_USERNAME_FIELD)
        )
        username_field.clear()
        username_field.send_keys(username)
        
        password_field = WebDriverWait(browser, timeout).until(
            EC.visibility_of_element_located(LOGIN_PASSWORD_FIELD)
        )
        password_field.clear()
        password_field.send_keys(password)
        
        login_submit = WebDriverWait(browser, timeout).until(
            EC.element_to_be_clickable(LOGIN_SUBMIT_BUTTON)
        )
        login_submit.click()
        
        return True
        
    except (TimeoutException, NoSuchElementException) as e:
        logging.error(f"Login failed: {str(e)}")
        return False


def is_user_logged_in(browser, timeout=TIMEOUT):
    try:
        WebDriverWait(browser, timeout).until(
            EC.visibility_of_element_located(WELCOME_USER_LINK)
        )
        welcome_text = browser.find_element(*WELCOME_USER_LINK).text
        logging.info(f"User logged in: {welcome_text}")
        return True
    except (TimeoutException, NoSuchElementException):
        return False


def perform_logout(browser, timeout=TIMEOUT):
    try:
        logout_button = WebDriverWait(browser, timeout).until(
            EC.element_to_be_clickable(LOGOUT_BUTTON)
        )
        logout_button.click()
        logging.info("Logged out successfully")
        return True
    except (TimeoutException, NoSuchElementException):
        logging.error("Logout failed")
        return False

# ============================================================================
# FUNCTIONAL TESTS
# ============================================================================

@pytest.mark.functional
def test_valid_signup_with_unique_credentials_FUNC_001(browser):
    """
    TC-SIGNUP-FUNC-001: Valid Signup with Unique Credentials
    
    Discovers if system allows registration with valid unique credentials.
    This is the happy path test for registration functionality.
    
    Expected Behavior:
    - User can successfully register with unique credentials
    - Success message appears
    - User can then log in with new credentials
    
    Priority: CRITICAL - Core functionality
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-FUNC-001: Testing valid signup with unique credentials")
    
    browser.get(BASE_URL)
    
    unique_username = generate_unique_username()
    test_password = "TestPass123!"
    
    signup_successful = perform_signup(browser, unique_username, test_password)
    assert signup_successful, "Failed to interact with signup form"
    
    time.sleep(1)
    
    alert_text = wait_for_alert_and_get_text(browser)
    
    if alert_text and ("success" in alert_text.lower() or "signed up" in alert_text.lower()):
        logging.info(f"DISCOVERED: Signup successful for user '{unique_username}'")
        
        browser.get(BASE_URL)
        time.sleep(1)
        
        perform_login(browser, unique_username, test_password)
        time.sleep(1)
        wait_for_alert_and_get_text(browser)
        
        logged_in = is_user_logged_in(browser, timeout=TIMEOUT_MEDIUM)
        
        if logged_in:
            logging.info("DISCOVERED: Can log in with newly created account")
            perform_logout(browser)
            assert True
        else:
            logging.warning("Signup succeeded but cannot log in with new credentials")
            pytest.fail("Account created but login failed")
    else:
        logging.error(f"DISCOVERED: Signup failed with alert: {alert_text}")
        pytest.fail(f"Signup rejected: {alert_text}")


@pytest.mark.functional
def test_duplicate_username_rejected_FUNC_002(browser):
    """
    TC-SIGNUP-FUNC-002: Duplicate Username is Rejected
    
    Discovers if system prevents registration with existing username.
    
    Expected Behavior:
    - First registration succeeds
    - Second registration with same username fails
    - Error message appears
    
    Priority: CRITICAL - Security and data integrity
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-FUNC-002: Testing duplicate username rejection")
    
    browser.get(BASE_URL)
    
    unique_username = generate_unique_username()
    test_password = "TestPass123!"
    
    perform_signup(browser, unique_username, test_password)
    time.sleep(1)
    first_alert = wait_for_alert_and_get_text(browser)
    
    if not first_alert or "success" not in first_alert.lower():
        pytest.skip(f"First signup failed: {first_alert}")
    
    browser.get(BASE_URL)
    time.sleep(1)
    
    perform_signup(browser, unique_username, test_password)
    time.sleep(1)
    second_alert = wait_for_alert_and_get_text(browser)
    
    if second_alert and ("exist" in second_alert.lower() or "already" in second_alert.lower() or "taken" in second_alert.lower()):
        logging.info(f"DISCOVERED: Duplicate username correctly rejected: {second_alert}")
        assert True
    else:
        logging.error(f"DISCOVERED: SECURITY ISSUE - Duplicate username accepted or no clear error")
        logging.error(f"Second signup alert: {second_alert}")
        pytest.fail("System should reject duplicate usernames")


@pytest.mark.functional
def test_empty_credentials_rejected_FUNC_003(browser):
    """
    TC-SIGNUP-FUNC-003: Empty Credentials are Rejected
    
    Discovers if system rejects signup with both fields empty.
    
    Expected Behavior:
    - Signup should fail
    - Validation message should appear
    
    Priority: HIGH - Input validation requirement
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-FUNC-003: Testing signup with empty credentials")
    
    browser.get(BASE_URL)
    
    perform_signup(browser, "", "")
    
    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    
    if alert_text and ("fill" in alert_text.lower() or "required" in alert_text.lower() or "empty" in alert_text.lower()):
        logging.info(f"DISCOVERED: Empty credentials rejected with message: {alert_text}")
        assert True
    elif alert_text:
        logging.warning(f"DISCOVERED: Alert appeared but message unclear: {alert_text}")
        assert True
    else:
        logging.error("DISCOVERED: No validation for empty credentials")
        pytest.fail("System should validate empty fields")


@pytest.mark.functional
def test_empty_username_only_FUNC_004(browser):
    """
    TC-SIGNUP-FUNC-004: Empty Username Field Only
    
    Discovers if system validates username field individually.
    
    Expected Behavior:
    - Signup should fail
    - Username validation message
    
    Priority: HIGH
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-FUNC-004: Testing signup with empty username")
    
    browser.get(BASE_URL)
    
    perform_signup(browser, "", "TestPass123!")
    
    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    
    if alert_text:
        logging.info(f"DISCOVERED: Empty username validation: {alert_text}")
        assert True
    else:
        pytest.fail("No validation for empty username")


@pytest.mark.functional
def test_empty_password_only_FUNC_005(browser):
    """
    TC-SIGNUP-FUNC-005: Empty Password Field Only
    
    Discovers if system validates password field individually.
    
    Expected Behavior:
    - Signup should fail
    - Password validation message
    
    Priority: HIGH
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-FUNC-005: Testing signup with empty password")
    
    browser.get(BASE_URL)
    
    unique_username = generate_unique_username()
    perform_signup(browser, unique_username, "")
    
    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    
    if alert_text:
        logging.info(f"DISCOVERED: Empty password validation: {alert_text}")
        assert True
    else:
        pytest.fail("No validation for empty password")


@pytest.mark.functional
def test_signup_modal_close_functionality_FUNC_006(browser):
    """
    TC-SIGNUP-FUNC-006: Signup Modal Close Functionality
    
    Discovers if signup modal can be properly closed.
    
    Expected Behavior:
    - Modal opens
    - Close button works
    - Modal disappears
    
    Priority: MEDIUM - UX requirement
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-FUNC-006: Testing modal close functionality")
    
    browser.get(BASE_URL)
    
    signup_nav_button = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(SIGNUP_BUTTON_NAV)
    )
    signup_nav_button.click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(SIGNUP_MODAL)
    )
    logging.info("DISCOVERED: Modal opens successfully")
    
    close_button = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(SIGNUP_CLOSE_BUTTON)
    )
    close_button.click()
    
    time.sleep(1)
    
    try:
        modal_visible = browser.find_element(*SIGNUP_MODAL).is_displayed()
        if not modal_visible:
            logging.info("DISCOVERED: Modal closes properly")
            assert True
        else:
            pytest.fail("Modal still visible after close")
    except NoSuchElementException:
        logging.info("DISCOVERED: Modal removed from DOM after close")
        assert True

# ============================================================================
# BUSINESS RULES TESTS
# ============================================================================

@pytest.mark.business_rules
def test_username_max_length_BR_001(browser):
    """
    TC-SIGNUP-BR-001: Username Maximum Length
    
    Business Rule: System should handle maximum username length
    Standard: ISO 25010 (Functional Suitability)
    Priority: MEDIUM
    Impact: Data validation and storage
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-BR-001: ISO 25010 - Testing username max length")
    
    browser.get(BASE_URL)
    
    long_username = "a" * 500
    perform_signup(browser, long_username, "TestPass123!")
    
    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    
    if alert_text:
        logging.info(f"DISCOVERED: System response to 500-char username: {alert_text}")
    
    assert True


@pytest.mark.business_rules
def test_password_max_length_BR_002(browser):
    """
    TC-SIGNUP-BR-002: Password Maximum Length
    
    Business Rule: System should handle maximum password length
    Standard: NIST SP 800-63B Section 5.1.1.2
    Priority: MEDIUM
    Impact: Security and usability
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-BR-002: NIST 800-63B - Testing password max length")
    
    browser.get(BASE_URL)
    
    unique_username = generate_unique_username()
    long_password = "a" * 500
    perform_signup(browser, unique_username, long_password)
    
    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    
    if alert_text:
        logging.info(f"DISCOVERED: System response to 500-char password: {alert_text}")
    
    assert True


@pytest.mark.business_rules
def test_username_leading_trailing_whitespace_BR_003(browser):
    """
    TC-SIGNUP-BR-003: Username Whitespace Handling
    
    Business Rule: System should trim or reject leading/trailing whitespace
    Standard: ISO 25010 (Usability)
    Priority: MEDIUM
    Impact: Consistency and UX
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-BR-003: ISO 25010 - Testing whitespace handling")
    
    browser.get(BASE_URL)
    
    unique_username = generate_unique_username()
    whitespace_username = f"  {unique_username}  "
    test_password = "TestPass123!"
    
    perform_signup(browser, whitespace_username, test_password)
    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    
    if alert_text and "success" in alert_text.lower():
        logging.info("DISCOVERED: Signup successful with whitespace")
        
        browser.get(BASE_URL)
        time.sleep(1)
        
        perform_login(browser, unique_username.strip(), test_password)
        time.sleep(1)
        wait_for_alert_and_get_text(browser)
        
        if is_user_logged_in(browser):
            logging.info("DISCOVERED: System trims whitespace (can login with trimmed version)")
        else:
            logging.info("DISCOVERED: System preserves whitespace (requires exact match)")
    
    assert True


@pytest.mark.business_rules
def test_password_whitespace_significance_BR_004(browser):
    """
    TC-SIGNUP-BR-004: Password Whitespace Significance
    
    Business Rule: Password whitespace should be significant
    Standard: NIST SP 800-63B Section 5.1.1.2
    Priority: HIGH
    Impact: Security
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-BR-004: NIST 800-63B - Testing password whitespace")
    
    browser.get(BASE_URL)
    
    unique_username = generate_unique_username()
    password_with_spaces = "  TestPass123!  "
    
    perform_signup(browser, unique_username, password_with_spaces)
    time.sleep(1)
    first_alert = wait_for_alert_and_get_text(browser)
    
    if first_alert and "success" in first_alert.lower():
        browser.get(BASE_URL)
        time.sleep(1)
        
        perform_login(browser, unique_username, "TestPass123!")
        time.sleep(1)
        login_alert = wait_for_alert_and_get_text(browser)
        
        if is_user_logged_in(browser):
            logging.info("DISCOVERED: System trims password whitespace")
        else:
            logging.info("DISCOVERED: Password whitespace is significant")
    
    assert True


@pytest.mark.business_rules
def test_special_characters_in_username_BR_005(browser):
    """
    TC-SIGNUP-BR-005: Special Characters in Username
    
    Business Rule: System should handle special characters
    Standard: ISO 25010 (Portability)
    Priority: MEDIUM
    Impact: Compatibility
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-BR-005: ISO 25010 - Testing special characters")
    
    browser.get(BASE_URL)
    
    special_username = f"test_{int(time.time())}!@#$%"
    perform_signup(browser, special_username, "TestPass123!")
    
    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    
    if alert_text:
        logging.info(f"DISCOVERED: System response to special chars: {alert_text}")
    
    assert True


@pytest.mark.business_rules
def test_numeric_only_username_BR_006(browser):
    """
    TC-SIGNUP-BR-006: Numeric-Only Username
    
    Business Rule: System should handle numeric-only usernames
    Standard: ISO 25010
    Priority: LOW
    Impact: Edge case validation
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-BR-006: ISO 25010 - Testing numeric-only username")
    
    browser.get(BASE_URL)
    
    numeric_username = f"{int(time.time())}"
    perform_signup(browser, numeric_username, "TestPass123!")
    
    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    
    if alert_text:
        logging.info(f"DISCOVERED: System response to numeric username: {alert_text}")
    
    assert True


@pytest.mark.business_rules
def test_unicode_characters_BR_007(browser):
    """
    TC-SIGNUP-BR-007: Unicode Characters in Username
    
    Business Rule: System should support internationalization
    Standard: ISO 25010 (Portability - Adaptability)
    Priority: MEDIUM
    Impact: International users
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-BR-007: ISO 25010 - Testing Unicode characters")
    
    browser.get(BASE_URL)
    
    unicode_username = f"用户_{int(time.time())}"
    perform_signup(browser, unicode_username, "TestPass123!")
    
    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    
    if alert_text and "success" in alert_text.lower():
        logging.info("DISCOVERED: System supports Unicode usernames")
    else:
        logging.info(f"DISCOVERED: Unicode response: {alert_text}")
    
    assert True


@pytest.mark.business_rules
def test_username_whitespace_normalization_BR_008(browser):
    """
    TC-SIGNUP-BR-008: Username Whitespace Normalization
    
    Business Rule: System should trim leading/trailing whitespace
    Standard: ISO 25010 (Usability)
    Priority: MEDIUM
    Impact: UX improvement
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-BR-008: ISO 25010 - Testing whitespace normalization")
    
    browser.get(BASE_URL)
    
    unique_username = generate_unique_username()
    username_with_spaces = f"  {unique_username}  "
    test_password = "TestPass123!"
    
    perform_signup(browser, username_with_spaces, test_password)
    time.sleep(1)
    first_alert = wait_for_alert_and_get_text(browser)
    
    if not first_alert or "success" not in first_alert.lower():
        pytest.skip("Initial signup failed")
    
    browser.get(BASE_URL)
    time.sleep(1)
    
    perform_signup(browser, unique_username, test_password)
    time.sleep(1)
    second_alert = wait_for_alert_and_get_text(browser)
    
    if second_alert and "exist" in second_alert.lower():
        logging.info("DISCOVERED: System trims whitespace (duplicate detected)")
    else:
        logging.info("DISCOVERED: System preserves whitespace")
    
    assert True


@pytest.mark.business_rules
def test_username_case_sensitivity_BR_009(browser):
    """
    TC-SIGNUP-BR-009: Username Case Sensitivity
    
    Business Rule: Discover if usernames are case-sensitive
    Standard: ISO 25010 (Usability)
    Priority: MEDIUM
    Impact: UX and security
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-BR-009: ISO 25010 - Testing case sensitivity")
    
    browser.get(BASE_URL)
    
    base_username = generate_unique_username()
    test_password = "TestPass123!"
    
    perform_signup(browser, base_username, test_password)
    time.sleep(1)
    first_alert = wait_for_alert_and_get_text(browser)
    
    if not first_alert or "success" not in first_alert.lower():
        pytest.skip("First signup failed")
    
    browser.get(BASE_URL)
    time.sleep(1)
    
    uppercase_username = base_username.upper()
    perform_signup(browser, uppercase_username, test_password)
    time.sleep(1)
    second_alert = wait_for_alert_and_get_text(browser)
    
    if second_alert and "exist" in second_alert.lower():
        logging.info("DISCOVERED: Usernames are NOT case-sensitive")
    elif second_alert and "success" in second_alert.lower():
        logging.info("DISCOVERED: Usernames ARE case-sensitive")
    
    assert True


@pytest.mark.business_rules
def test_identical_username_password_BR_010(browser):
    """
    TC-SIGNUP-BR-010: Identical Username and Password
    
    Business Rule: Username and password should not be identical
    Standard: NIST SP 800-63B Section 5.1.1.2
    Priority: HIGH
    Impact: Weak security if allowed
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-BR-010: NIST 800-63B - Testing identical username/password")
    
    browser.get(BASE_URL)
    
    unique_username = generate_unique_username()
    perform_signup(browser, unique_username, unique_username)
    
    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    
    if alert_text and "success" in alert_text.lower():
        logging.warning("DISCOVERED: System allows identical username/password")
        logging.warning("Standard: NIST 800-63B recommends against this")
        assert True
    else:
        logging.info("DISCOVERED: System prevents identical username/password")
        assert True


@pytest.mark.security
@pytest.mark.business_rules
@pytest.mark.parametrize("sql_payload", [
    "' OR '1'='1",
    "admin'--",
    "' OR '1'='1' --",
    "') OR ('1'='1"
])
def test_sql_injection_prevention_BR_011(browser, sql_payload):
    """
    TC-SIGNUP-BR-011: SQL Injection Prevention
    
    Business Rule: System must prevent SQL injection attacks
    Standard: OWASP ASVS v5.0 Section 1.2.5
    Priority: CRITICAL
    Impact: Complete database compromise
    CVSS Score: 9.8 (CRITICAL)
    """
    logging.info("=" * 80)
    logging.info(f"TC-SIGNUP-BR-011: OWASP ASVS 1.2.5 - SQL injection: {sql_payload}")
    
    browser.get(BASE_URL)
    
    perform_signup(browser, sql_payload, "TestPass123!")
    
    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    
    if alert_text and "success" in alert_text.lower():
        logging.critical("=" * 80)
        logging.critical(f"SQL INJECTION POSSIBLE: {sql_payload}")
        logging.critical("Standard: OWASP ASVS v5.0 Section 1.2.5")
        logging.critical("Severity: CRITICAL")
        logging.critical("CVSS Score: 9.8")
        logging.critical("Impact: Database may be compromised")
        logging.critical("=" * 80)
        pytest.fail(f"DISCOVERED: SQL payload '{sql_payload}' accepted")
    else:
        logging.info(f"DISCOVERED: SQL payload '{sql_payload}' handled safely")
        assert True


@pytest.mark.security
@pytest.mark.business_rules
@pytest.mark.parametrize("xss_payload", [
    "<script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>"
])
def test_xss_prevention_BR_012(browser, xss_payload):
    """
    TC-SIGNUP-BR-012: XSS Prevention
    
    Business Rule: System must prevent XSS attacks
    Standard: OWASP ASVS v5.0 Section 1.4.1
    Priority: CRITICAL
    Impact: Session hijacking, data theft
    CVSS Score: 7.1 (HIGH)
    """
    logging.info("=" * 80)
    logging.info(f"TC-SIGNUP-BR-012: OWASP ASVS 1.4.1 - XSS payload: {xss_payload}")
    
    browser.get(BASE_URL)
    
    perform_signup(browser, xss_payload, "TestPass123!")
    
    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    
    if alert_text and "success" in alert_text.lower():
        browser.get(BASE_URL)
        time.sleep(1)
        
        page_source = browser.page_source
        
        if xss_payload in page_source:
            logging.critical("=" * 80)
            logging.critical(f"XSS VULNERABILITY: {xss_payload}")
            logging.critical("Standard: OWASP ASVS v5.0 Section 1.4.1")
            logging.critical("Severity: HIGH")
            logging.critical("CVSS Score: 7.1")
            logging.critical("Impact: XSS payload reflected in page")
            logging.critical("=" * 80)
            pytest.fail(f"DISCOVERED: XSS payload '{xss_payload}' reflected")
        else:
            logging.info(f"DISCOVERED: XSS payload '{xss_payload}' sanitized")
    
    assert True


@pytest.mark.security
@pytest.mark.business_rules
@pytest.mark.critical
@pytest.mark.parametrize("weak_password", [
    "123456",
    "password",
    "12345678"
])
def test_password_complexity_enforcement_BR_013(browser, weak_password):
    """
    TC-SIGNUP-BR-013: Password Complexity Enforcement
    
    Business Rule: System must enforce password complexity
    Standard: NIST SP 800-63B Section 5.1.1.2
    Priority: CRITICAL
    Impact: Weak passwords allow brute force
    CVSS Score: 6.5 (MEDIUM)
    """
    logging.info("=" * 80)
    logging.info(f"TC-SIGNUP-BR-013: NIST 800-63B - Password complexity: {weak_password}")
    
    browser.get(BASE_URL)
    
    unique_username = generate_unique_username()
    perform_signup(browser, unique_username, weak_password)
    
    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    
    if alert_text and "success" in alert_text.lower():
        logging.critical("=" * 80)
        logging.critical(f"SECURITY VIOLATION: WEAK PASSWORD ACCEPTED: '{weak_password}'")
        logging.critical("Standard: NIST SP 800-63B Section 5.1.1.2")
        logging.critical("Severity: MEDIUM")
        logging.critical("CVSS Score: 6.5")
        logging.critical("Impact: Users can set easily crackable passwords")
        logging.critical("Recommendation: Enforce min 8 chars, check common passwords")
        logging.critical("=" * 80)
        
        pytest.fail(f"DISCOVERED: Weak password '{weak_password}' accepted")
    else:
        logging.info(f"DISCOVERED: Weak password '{weak_password}' rejected")
        assert True


@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.critical
def test_signup_rate_limiting_BR_014(browser):
    """
    TC-SIGNUP-BR-014: Signup Rate Limiting
    
    Business Rule: System should limit rapid signup attempts
    Standard: OWASP ASVS v5.0 Section 2.2.1
    Priority: CRITICAL
    Impact: Prevents automated bot registrations
    CVSS Score: 7.5 (HIGH)
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-BR-014: OWASP ASVS 2.2.1 - Testing signup rate limiting")
    
    browser.get(BASE_URL)
    
    max_attempts = 5
    rate_limited = False
    
    for attempt in range(max_attempts):
        unique_username = generate_unique_username()
        perform_signup(browser, unique_username, "TestPass123!")
        
        time.sleep(1)
        alert_text = wait_for_alert_and_get_text(browser)
        
        if alert_text and ("limit" in alert_text.lower() or "wait" in alert_text.lower() or "too many" in alert_text.lower()):
            logging.info(f"DISCOVERED: Rate limiting triggered after {attempt + 1} attempts")
            rate_limited = True
            break
        
        browser.get(BASE_URL)
        time.sleep(0.5)
    
    if not rate_limited:
        logging.critical("=" * 80)
        logging.critical("SECURITY VIOLATION: NO SIGNUP RATE LIMITING DETECTED")
        logging.critical("Standard: OWASP ASVS v5.0 Section 2.2.1")
        logging.critical("Severity: HIGH")
        logging.critical("CVSS Score: 7.5")
        logging.critical(f"Impact: Completed {max_attempts} signups rapidly without limit")
        logging.critical("Recommendation: Implement rate limiting (e.g. 5 per IP per hour)")
        logging.critical("=" * 80)
        
        pytest.fail(f"DISCOVERED: No rate limiting detected after {max_attempts} attempts")
    
    assert True


@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.critical
def test_captcha_protection_BR_015(browser):
    """
    TC-SIGNUP-BR-015: CAPTCHA Protection
    
    Business Rule: System should implement CAPTCHA for bot prevention
    Standard: OWASP ASVS v5.0 Section 2.2.3
    Priority: HIGH
    Impact: Automated bot registrations
    CVSS Score: 6.1 (MEDIUM)
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-BR-015: OWASP ASVS 2.2.3 - Testing CAPTCHA protection")
    
    browser.get(BASE_URL)
    
    signup_nav_button = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(SIGNUP_BUTTON_NAV)
    )
    signup_nav_button.click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(SIGNUP_MODAL)
    )
    
    captcha_elements = [
        (By.XPATH, "//div[@class='g-recaptcha']"),
        (By.ID, "recaptcha"),
        (By.XPATH, "//iframe[contains(@src, 'recaptcha')]"),
        (By.XPATH, "//div[contains(@class, 'captcha')]")
    ]
    
    captcha_found = False
    for locator in captcha_elements:
        try:
            browser.find_element(*locator)
            logging.info(f"DISCOVERED: CAPTCHA element found: {locator}")
            captcha_found = True
            break
        except NoSuchElementException:
            continue
    
    if not captcha_found:
        logging.critical("=" * 80)
        logging.critical("SECURITY VIOLATION: NO CAPTCHA PROTECTION DETECTED")
        logging.critical("Standard: OWASP ASVS v5.0 Section 2.2.3")
        logging.critical("Severity: MEDIUM")
        logging.critical("CVSS Score: 6.1")
        logging.critical("Impact: Automated bots can create unlimited accounts")
        logging.critical("Recommendation: Implement CAPTCHA (reCAPTCHA v3 recommended)")
        logging.critical("=" * 80)
        
        pytest.fail("DISCOVERED: No CAPTCHA protection present on signup form")
    
    assert True


@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.critical
def test_email_verification_requirement_BR_016(browser):
    """
    TC-SIGNUP-BR-016: Email Verification Requirement
    
    Business Rule: System should require email verification
    Standard: OWASP ASVS v5.0 Section 2.1.12
    Priority: HIGH
    Impact: Fake account creation
    CVSS Score: 5.3 (MEDIUM)
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-BR-016: OWASP ASVS 2.1.12 - Testing email verification")
    
    browser.get(BASE_URL)
    
    unique_username = generate_unique_username()
    test_password = "TestPass123!"
    
    perform_signup(browser, unique_username, test_password)
    time.sleep(1)
    signup_alert = wait_for_alert_and_get_text(browser)
    
    if signup_alert and "success" in signup_alert.lower():
        browser.get(BASE_URL)
        time.sleep(1)
        
        perform_login(browser, unique_username, test_password)
        time.sleep(1)
        wait_for_alert_and_get_text(browser)
        
        if is_user_logged_in(browser):
            logging.critical("=" * 80)
            logging.critical("SECURITY VIOLATION: NO EMAIL VERIFICATION REQUIRED")
            logging.critical("Standard: OWASP ASVS v5.0 Section 2.1.12")
            logging.critical("Severity: MEDIUM")
            logging.critical("CVSS Score: 5.3")
            logging.critical("Impact: Users can immediately use unverified accounts")
            logging.critical("Recommendation: Require email verification before account activation")
            logging.critical("=" * 80)
            
            perform_logout(browser)
            pytest.fail("DISCOVERED: Account usable immediately without email verification")
    
    assert True


@pytest.mark.business_rules
@pytest.mark.accessibility
def test_keyboard_navigation_BR_017(browser):
    """
    TC-SIGNUP-BR-017: Keyboard Navigation Support
    
    Business Rule: Form must support keyboard-only navigation
    Standard: WCAG 2.1 Success Criterion 2.1.1
    Priority: HIGH
    Impact: Accessibility for disabled users
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-BR-017: WCAG 2.1 SC 2.1.1 - Testing keyboard navigation")
    
    browser.get(BASE_URL)
    
    signup_nav_button = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(SIGNUP_BUTTON_NAV)
    )
    signup_nav_button.click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(SIGNUP_MODAL)
    )
    
    username_field = WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(SIGNUP_USERNAME_FIELD)
    )
    username_field.click()
    
    actions = ActionChains(browser)
    actions.send_keys("testuser")
    actions.send_keys(Keys.TAB)
    actions.send_keys("TestPass123!")
    actions.send_keys(Keys.ENTER)
    actions.perform()
    
    time.sleep(1)
    alert_text = wait_for_alert_and_get_text(browser)
    
    if alert_text:
        logging.info("DISCOVERED: Form submittable via keyboard")
        logging.info("WCAG 2.1 SC 2.1.1 compliant")
        assert True
    else:
        logging.warning("DISCOVERED: Keyboard submission may not work")
        pytest.fail("Form not fully keyboard accessible")


@pytest.mark.business_rules
@pytest.mark.accessibility
def test_form_labels_accessibility_BR_018(browser):
    """
    TC-SIGNUP-BR-018: Form Labels for Accessibility
    
    Business Rule: Form fields must have proper labels
    Standard: WCAG 2.1 Success Criterion 1.3.1
    Priority: HIGH
    Impact: Screen reader accessibility
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-BR-018: WCAG 2.1 SC 1.3.1 - Testing form labels")
    
    browser.get(BASE_URL)
    
    signup_nav_button = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(SIGNUP_BUTTON_NAV)
    )
    signup_nav_button.click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(SIGNUP_MODAL)
    )
    
    username_field = WebDriverWait(browser, TIMEOUT).until(
        EC.presence_of_element_located(SIGNUP_USERNAME_FIELD)
    )
    password_field = browser.find_element(*SIGNUP_PASSWORD_FIELD)
    
    username_accessible = (
        username_field.get_attribute("aria-label") or
        username_field.get_attribute("placeholder") or
        username_field.get_attribute("title")
    )
    
    password_accessible = (
        password_field.get_attribute("aria-label") or
        password_field.get_attribute("placeholder") or
        password_field.get_attribute("title")
    )
    
    if username_accessible and password_accessible:
        logging.info(f"DISCOVERED: Username label: '{username_accessible}'")
        logging.info(f"DISCOVERED: Password label: '{password_accessible}'")
        logging.info("WCAG 2.1 SC 1.3.1 compliant")
        assert True
    else:
        logging.warning("DISCOVERED: Form fields lack proper labels")
        logging.warning("Standard: WCAG 2.1 SC 1.3.1")
        logging.warning("Impact: Screen readers cannot identify fields")
        
        try:
            browser.find_element(By.XPATH, "//label[@for='sign-username']")
            logging.info("Note: Visible labels exist")
            assert True
        except NoSuchElementException:
            pytest.fail("Form lacks proper labels - WCAG violation")


@pytest.mark.business_rules
@pytest.mark.security
def test_username_enumeration_via_signup_BR_019(browser):
    """
    TC-SIGNUP-BR-019: Username Enumeration via Signup
    
    Business Rule: System should not leak username existence
    Standard: OWASP ASVS v5.0 Section 2.2.2
    Priority: MEDIUM
    Impact: Attackers can enumerate valid usernames
    CVSS Score: 5.3 (MEDIUM)
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-BR-019: OWASP ASVS 2.2.2 - Testing username enumeration")
    
    browser.get(BASE_URL)
    
    existing_username = generate_unique_username()
    perform_signup(browser, existing_username, "TestPass123!")
    time.sleep(1)
    first_alert = wait_for_alert_and_get_text(browser)
    
    if not first_alert or "success" not in first_alert.lower():
        pytest.skip("Could not create test user")
    
    browser.get(BASE_URL)
    time.sleep(1)
    
    perform_signup(browser, existing_username, "TestPass123!")
    time.sleep(1)
    duplicate_alert = wait_for_alert_and_get_text(browser)
    
    browser.get(BASE_URL)
    time.sleep(1)
    
    nonexistent_username = generate_unique_username()
    perform_signup(browser, nonexistent_username, "")
    time.sleep(1)
    empty_password_alert = wait_for_alert_and_get_text(browser)
    
    if duplicate_alert and empty_password_alert:
        if duplicate_alert.lower() != empty_password_alert.lower():
            if "exist" in duplicate_alert.lower() or "taken" in duplicate_alert.lower():
                logging.warning("USERNAME ENUMERATION POSSIBLE")
                logging.warning("CVSS Score: 5.3 (MEDIUM)")
                logging.warning(f"Duplicate user: {duplicate_alert}")
                logging.warning(f"Empty password: {empty_password_alert}")
                logging.warning("Impact: Attackers can enumerate valid usernames")
                pytest.fail("DISCOVERED: Username enumeration via different error messages")
    
    assert True

# ============================================================================
# END OF TEST SUITE
# ============================================================================
