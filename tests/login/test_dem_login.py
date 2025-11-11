"""
Test Suite: Login & Authentication
Module: test_login.py
Author: Arévalo, Marc
Description: Comprehensive automated tests for web application login functionality.
             Verifies compliance with OWASP ASVS 5.0, NIST 800-63B, ISO 25010, and WCAG 2.1.
             Tests discover security issues objectively without prior assumptions.
Version: 1.0
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager
from webdriver_manager.microsoft import EdgeChromiumDriverManager
import pytest
import time
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s - %(message)s'
)


BASE_URL = "https://www.demoblaze.com/"
TIMEOUT = 10
TEST_USERNAME = "testuser_qa_2024"
TEST_PASSWORD = "SecurePass123!"


LOGIN_BUTTON_NAV = (By.ID, "login2")
LOGIN_USERNAME_FIELD = (By.ID, "loginusername")
LOGIN_PASSWORD_FIELD = (By.ID, "loginpassword")
LOGIN_SUBMIT_BUTTON = (By.XPATH, "//button[text()='Log in']")
LOGOUT_BUTTON = (By.ID, "logout2")
WELCOME_USER_TEXT = (By.ID, "nameofuser")
SIGNUP_BUTTON = (By.ID, "signin2")
SIGNUP_USERNAME_FIELD = (By.ID, "sign-username")
SIGNUP_PASSWORD_FIELD = (By.ID, "sign-password")
SIGNUP_SUBMIT_BUTTON = (By.XPATH, "//button[text()='Sign up']")
LOGIN_MODAL_CLOSE_BUTTON = (By.XPATH, "//div[@id='logInModal']//button[@class='close']")
LOGIN_MODAL = (By.ID, "logInModal")


@pytest.fixture(scope="function")
def browser(request):
    browser_name = request.config.getoption("--browser").lower()
    driver = None
    
    if browser_name == "chrome":
        service = Service(ChromeDriverManager().install())
        options = webdriver.ChromeOptions()
        driver = webdriver.Chrome(service=service, options=options)
    elif browser_name == "firefox":
        service = Service(GeckoDriverManager().install())
        options = webdriver.FirefoxOptions()
        driver = webdriver.Firefox(service=service, options=options)
    elif browser_name == "edge":
        service = Service(EdgeChromiumDriverManager().install())
        options = webdriver.EdgeOptions()
        driver = webdriver.Edge(service=service, options=options)
    else:
        pytest.fail(f"Unsupported browser: {browser_name}")
    
    driver.maximize_window()
    driver.implicitly_wait(TIMEOUT)
    
    yield driver
    
    driver.quit()


@pytest.fixture
def login_page(browser):
    browser.get(BASE_URL)
    WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(LOGIN_BUTTON_NAV)
    ).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(LOGIN_USERNAME_FIELD)
    )
    return browser


def perform_login(browser, username, password):
    try:
        username_field = WebDriverWait(browser, TIMEOUT).until(
            EC.visibility_of_element_located(LOGIN_USERNAME_FIELD)
        )
        username_field.clear()
        username_field.send_keys(username)
        
        password_field = browser.find_element(*LOGIN_PASSWORD_FIELD)
        password_field.clear()
        password_field.send_keys(password)
        
        browser.find_element(*LOGIN_SUBMIT_BUTTON).click()
    except Exception as e:
        logging.error(f"Login action failed: {e}")


def wait_for_alert(browser, timeout=5):
    try:
        WebDriverWait(browser, timeout).until(EC.alert_is_present())
        alert = browser.switch_to.alert
        alert_text = alert.text
        alert.accept()
        return alert_text
    except TimeoutException:
        return None


def check_user_logged_in(browser, timeout=5):
    try:
        WebDriverWait(browser, timeout).until(
            EC.invisibility_of_element_located(LOGIN_MODAL)
        )
        WebDriverWait(browser, timeout).until(
            EC.visibility_of_element_located(LOGOUT_BUTTON)
        )
        return True
    except TimeoutException:
        return False


def check_user_logged_out(browser, timeout=5):
    try:
        WebDriverWait(browser, timeout).until_not(
            EC.visibility_of_element_located(LOGOUT_BUTTON)
        )
        return True
    except TimeoutException:
        return False


def log_business_rule_violation(test_id, standard, expected_behavior, actual_behavior, impact, severity):
    logging.error("=" * 80)
    logging.error(f"BUSINESS RULE VIOLATION: {test_id}")
    logging.error(f"Standard: {standard}")
    logging.error(f"Expected: {expected_behavior}")
    logging.error(f"Actual: {actual_behavior}")
    logging.error(f"Business Impact: {impact}")
    logging.error(f"Severity: {severity}")
    logging.error("=" * 80)


@pytest.mark.functional
def test_valid_login(login_page):
    """TC-LOGIN-001: Valid Login"""
    logging.info("TC-LOGIN-001: Testing valid login credentials")
    perform_login(login_page, TEST_USERNAME, TEST_PASSWORD)
    
    assert check_user_logged_in(login_page), "User should be logged in with valid credentials"
    
    welcome_element = WebDriverWait(login_page, TIMEOUT).until(
        EC.presence_of_element_located(WELCOME_USER_TEXT)
    )
    assert TEST_USERNAME in welcome_element.text, "Welcome message should contain username"


@pytest.mark.functional
def test_invalid_password(login_page):
    """TC-LOGIN-002: Invalid Password"""
    logging.info("TC-LOGIN-002: Testing invalid password rejection")
    perform_login(login_page, TEST_USERNAME, "wrongpassword123")
    alert_text = wait_for_alert(login_page)
    
    assert alert_text is not None, "System should display error for invalid password"
    assert "wrong password" in alert_text.lower() or "incorrect" in alert_text.lower(), \
        f"Error message unclear: '{alert_text}'"
    assert check_user_logged_out(login_page, 2), "User should not be logged in"


@pytest.mark.functional
def test_nonexistent_user(login_page):
    """TC-LOGIN-003: Non-existent User"""
    logging.info("TC-LOGIN-003: Testing non-existent user rejection")
    perform_login(login_page, "nonexistent_user_xyz_999", "anypassword")
    alert_text = wait_for_alert(login_page)
    
    assert alert_text is not None, "System should display error for non-existent user"
    assert check_user_logged_out(login_page, 2), "User should not be logged in"


@pytest.mark.functional
def test_empty_fields(login_page):
    """TC-LOGIN-004: Empty Fields Validation"""
    logging.info("TC-LOGIN-004: Testing empty fields validation")
    perform_login(login_page, "", "")
    alert_text = wait_for_alert(login_page)
    
    assert alert_text is not None, "System should validate empty fields"
    assert "fill" in alert_text.lower() or "required" in alert_text.lower(), \
        f"Validation message unclear: '{alert_text}'"


@pytest.mark.functional
def test_successful_logout(browser):
    """TC-LOGIN-005: Logout Functionality"""
    logging.info("TC-LOGIN-005: Testing logout functionality")
    browser.get(BASE_URL)
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(LOGIN_BUTTON_NAV)
    ).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(LOGIN_USERNAME_FIELD)
    )
    
    perform_login(browser, TEST_USERNAME, TEST_PASSWORD)
    assert check_user_logged_in(browser), "Login should succeed before testing logout"
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(LOGOUT_BUTTON)
    ).click()
    
    assert check_user_logged_out(browser), "User should be logged out after clicking logout"


@pytest.mark.functional
def test_login_modal_close(login_page):
    """TC-LOGIN-006: Login Modal Close Button"""
    logging.info("TC-LOGIN-006: Testing modal close button functionality")
    
    username_field = login_page.find_element(*LOGIN_USERNAME_FIELD)
    assert username_field.is_displayed(), "Login modal should be visible"
    
    close_button = login_page.find_element(*LOGIN_MODAL_CLOSE_BUTTON)
    close_button.click()
    
    WebDriverWait(login_page, TIMEOUT).until(
        EC.invisibility_of_element_located(LOGIN_MODAL)
    )


@pytest.mark.business_rules
def test_weak_password_acceptance(browser):
    """TC-LOGIN-BR-001: Weak Password Validation
    
    Standard: NIST SP 800-63B Section 5.1.1.2
    Requirement: User-chosen passwords SHALL be at least 8 characters
    """
    logging.info("TC-LOGIN-BR-001: Testing password minimum length requirement")
    timestamp = str(int(time.time()))
    test_user = f"weakpass_{timestamp}"
    weak_password = "123"
    
    browser.get(BASE_URL)
    WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(SIGNUP_BUTTON)
    ).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(SIGNUP_USERNAME_FIELD)
    )
    
    browser.find_element(*SIGNUP_USERNAME_FIELD).send_keys(test_user)
    browser.find_element(*SIGNUP_PASSWORD_FIELD).send_keys(weak_password)
    browser.find_element(*SIGNUP_SUBMIT_BUTTON).click()
    
    alert_text = wait_for_alert(browser)
    
    if alert_text and ("password" in alert_text.lower() and 
                       ("weak" in alert_text.lower() or 
                        "short" in alert_text.lower() or 
                        "minimum" in alert_text.lower() or 
                        "8" in alert_text)):
        logging.info("System correctly rejects weak password")
        assert True
    else:
        log_business_rule_violation(
            test_id="TC-LOGIN-BR-001",
            standard="NIST SP 800-63B Section 5.1.1.2",
            expected_behavior="Reject password < 8 characters with clear error message",
            actual_behavior=f"Accepted password '{weak_password}' (length: {len(weak_password)}). Response: '{alert_text}'",
            impact="Accounts vulnerable to brute force attacks, dictionary attacks, credential stuffing",
            severity="CRITICAL"
        )
        assert False, f"System accepted weak password with only {len(weak_password)} characters"


@pytest.mark.business_rules
def test_excessive_username_length(login_page):
    """TC-LOGIN-BR-002: Input Length Validation
    
    Standard: ISO 25010 - Functional Suitability, Input Validation
    Requirement: Username should be limited to reasonable length (50 characters)
    """
    logging.info("TC-LOGIN-BR-002: Testing excessive username length handling")
    long_username = "a" * 1000
    
    perform_login(login_page, long_username, "anypassword")
    alert_text = wait_for_alert(login_page, timeout=3)
    
    if alert_text and ("length" in alert_text.lower() or 
                       "long" in alert_text.lower() or 
                       "maximum" in alert_text.lower() or
                       "limit" in alert_text.lower()):
        logging.info("System correctly validates username length")
        assert True
    else:
        log_business_rule_violation(
            test_id="TC-LOGIN-BR-002",
            standard="ISO 25010 - Functional Suitability, Input Validation",
            expected_behavior="Reject username exceeding 50 characters with validation error",
            actual_behavior=f"Processed username of {len(long_username)} characters without length validation",
            impact="Database bloat, potential buffer overflow vulnerabilities, DoS attack vector",
            severity="MEDIUM"
        )
        assert False, f"System processed username with {len(long_username)} characters without validation"


@pytest.mark.business_rules
def test_username_enumeration_vulnerability(browser):
    """TC-LOGIN-BR-003: Username Enumeration Prevention
    
    Standard: OWASP ASVS v5.0-2.2.3
    Requirement: Authentication responses SHALL NOT indicate which part of authentication failed
    """
    logging.info("TC-LOGIN-BR-003: Testing username enumeration resistance")
    
    browser.get(BASE_URL)
    WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(LOGIN_BUTTON_NAV)
    ).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(LOGIN_USERNAME_FIELD)
    )
    
    perform_login(browser, TEST_USERNAME, "wrong_password_xyz")
    error_existing_user = wait_for_alert(browser)
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(LOGIN_MODAL_CLOSE_BUTTON)
    ).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.invisibility_of_element_located(LOGIN_MODAL)
    )
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(LOGIN_BUTTON_NAV)
    ).click()
    
    perform_login(browser, "nonexistent_user_xyz_999", "any_password")
    error_nonexistent_user = wait_for_alert(browser)
    
    if error_existing_user == error_nonexistent_user:
        logging.info("System correctly uses generic error messages")
        assert True
    else:
        log_business_rule_violation(
            test_id="TC-LOGIN-BR-003",
            standard="OWASP ASVS v5.0-2.2.3",
            expected_behavior="Generic error message for all authentication failures",
            actual_behavior=f"Different errors reveal username existence: '{error_existing_user}' vs '{error_nonexistent_user}'",
            impact="Attackers can enumerate valid usernames, enables targeted phishing and brute force attacks",
            severity="HIGH"
        )
        assert False, "System reveals username existence through different error messages"


@pytest.mark.business_rules
def test_brute_force_protection(browser):
    """TC-LOGIN-BR-004: Brute Force Attack Prevention
    
    Standard: OWASP ASVS v5.0-2.2.1, PCI-DSS Requirement 8.1.6
    Requirement: Account lockout after 6 failed authentication attempts within defined timeframe
    """
    logging.info("TC-LOGIN-BR-004: Testing brute force protection mechanisms")
    browser.get(BASE_URL)
    attempts = 7
    final_alert_text = ""
    lockout_detected = False
    
    for i in range(attempts):
        try:
            WebDriverWait(browser, TIMEOUT).until(
                EC.element_to_be_clickable(LOGIN_BUTTON_NAV)
            ).click()
            
            WebDriverWait(browser, TIMEOUT).until(
                EC.visibility_of_element_located(LOGIN_USERNAME_FIELD)
            )
            
            perform_login(browser, TEST_USERNAME, f"wrong_attempt_{i}")
            final_alert_text = wait_for_alert(browser, timeout=5)
            
            if final_alert_text and ("locked" in final_alert_text.lower() or 
                                     "too many" in final_alert_text.lower() or
                                     "blocked" in final_alert_text.lower() or
                                     "temporarily" in final_alert_text.lower()):
                lockout_detected = True
                logging.info(f"Account lockout detected after {i+1} attempts")
                break
            
            time.sleep(0.3)
        except Exception as e:
            logging.error(f"Attempt {i+1} error: {e}")
            browser.refresh()
    
    if lockout_detected:
        assert True
    else:
        log_business_rule_violation(
            test_id="TC-LOGIN-BR-004",
            standard="OWASP ASVS v5.0-2.2.1, PCI-DSS Requirement 8.1.6",
            expected_behavior="Account lockout after 6 failed login attempts",
            actual_behavior=f"No lockout mechanism detected after {attempts} failed attempts. Last response: '{final_alert_text}'",
            impact="Vulnerable to automated brute force attacks, credential stuffing, password spraying",
            severity="CRITICAL"
        )
        assert False, f"No brute force protection detected after {attempts} failed attempts"


@pytest.mark.business_rules
def test_error_message_presentation_method(login_page):
    """TC-LOGIN-BR-005: Error Message Accessibility
    
    Standard: WCAG 2.1 Level AA - Success Criterion 3.3.1 (Error Identification)
    Requirement: Error messages should be inline, accessible to screen readers
    """
    logging.info("TC-LOGIN-BR-005: Testing error message presentation accessibility")
    perform_login(login_page, "", "")
    alert_text = wait_for_alert(login_page, timeout=3)
    
    if alert_text:
        log_business_rule_violation(
            test_id="TC-LOGIN-BR-005",
            standard="WCAG 2.1 Success Criterion 3.3.1",
            expected_behavior="Inline error messages with aria-live regions for screen reader support",
            actual_behavior="JavaScript alert() used for error presentation",
            impact="Poor accessibility for screen reader users, outdated UX pattern, modal interruption",
            severity="MEDIUM"
        )
        assert False, "System uses JavaScript alerts instead of accessible inline validation"
    else:
        logging.info("No JavaScript alert detected")
        assert True


@pytest.mark.business_rules
@pytest.mark.parametrize("payload", [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "1' OR '1' = '1",
])
def test_sql_injection_prevention(login_page, payload):
    """TC-LOGIN-BR-006: SQL Injection Prevention
    
    Standard: OWASP ASVS v5.0-1.2.5 (Injection Prevention)
    Requirement: Use parameterized queries, input sanitization for all database interactions
    """
    logging.info(f"TC-LOGIN-BR-006: Testing SQL injection prevention - Payload: {payload}")
    perform_login(login_page, payload, "anypassword")
    wait_for_alert(login_page, timeout=3)
    
    if check_user_logged_in(login_page, timeout=2):
        log_business_rule_violation(
            test_id="TC-LOGIN-BR-006",
            standard="OWASP ASVS v5.0-1.2.5 (Injection Prevention)",
            expected_behavior="SQL injection attempt blocked, authentication denied",
            actual_behavior=f"Authentication bypass successful with SQL injection payload: {payload}",
            impact="Complete database compromise, unauthorized access, data breach, data manipulation",
            severity="CRITICAL"
        )
        assert False, f"SQL injection vulnerability detected - Login succeeded with payload: {payload}"
    
    assert check_user_logged_out(login_page, 2), "User should not be authenticated after injection attempt"


@pytest.mark.business_rules
@pytest.mark.parametrize("payload", [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
])
def test_xss_prevention(login_page, payload):
    """TC-LOGIN-BR-007: Cross-Site Scripting (XSS) Prevention
    
    Standard: OWASP ASVS v5.0-1.2.1 (Output Encoding)
    Requirement: All output should be encoded, Content Security Policy headers enforced
    """
    logging.info(f"TC-LOGIN-BR-007: Testing XSS prevention - Payload: {payload}")
    perform_login(login_page, payload, "anypassword")
    
    alert_text = wait_for_alert(login_page, timeout=3)
    
    if alert_text and 'XSS' in alert_text:
        log_business_rule_violation(
            test_id="TC-LOGIN-BR-007",
            standard="OWASP ASVS v5.0-1.2.1 (Output Encoding)",
            expected_behavior="XSS payload sanitized, HTML entities encoded, no script execution",
            actual_behavior=f"XSS payload executed in browser: {payload}",
            impact="Session hijacking, cookie theft, phishing attacks, malware distribution",
            severity="CRITICAL"
        )
        assert False, f"XSS vulnerability detected - Script executed with payload: {payload}"
    
    assert check_user_logged_out(login_page, 2)


@pytest.mark.business_rules
def test_password_maximum_length(login_page):
    """TC-LOGIN-BR-008: Password Maximum Length Enforcement
    
    Standard: NIST 800-63B Section 5.1.1.2, ISO 25010 - Resource Utilization
    Requirement: Maximum password length of 64 characters to prevent DoS
    """
    logging.info("TC-LOGIN-BR-008: Testing password maximum length enforcement")
    extremely_long_password = "p" * 10000
    
    perform_login(login_page, TEST_USERNAME, extremely_long_password)
    alert_text = wait_for_alert(login_page, timeout=3)
    
    if alert_text and ("length" in alert_text.lower() or 
                       "maximum" in alert_text.lower() or 
                       "long" in alert_text.lower()):
        logging.info("System correctly enforces maximum password length")
        assert True
    else:
        log_business_rule_violation(
            test_id="TC-LOGIN-BR-008",
            standard="NIST 800-63B Section 5.1.1.2, ISO 25010",
            expected_behavior="Reject passwords exceeding 64 characters",
            actual_behavior=f"Processed password with {len(extremely_long_password)} characters without validation",
            impact="Denial of Service (DoS) attack vector, excessive memory consumption, server resource exhaustion",
            severity="MEDIUM"
        )
        assert False, f"System processed password with {len(extremely_long_password)} characters"


@pytest.mark.business_rules
@pytest.mark.parametrize("test_input", [
    "   user   ",
    " testuser",
    "testuser ",
])
def test_whitespace_handling(login_page, test_input):
    """TC-LOGIN-BR-009: Whitespace Normalization
    
    Standard: ISO 25010 - Data Quality, Usability
    Requirement: Trim leading/trailing whitespace from username inputs
    """
    logging.info(f"TC-LOGIN-BR-009: Testing whitespace handling - Input: '{test_input}'")
    perform_login(login_page, test_input, TEST_PASSWORD)
    alert_text = wait_for_alert(login_page, timeout=3)
    
    trimmed_input = test_input.strip()
    if trimmed_input == TEST_USERNAME and check_user_logged_in(login_page, timeout=2):
        logging.info("System correctly trims whitespace from username")
        assert True
    elif alert_text and "does not exist" in alert_text.lower():
        log_business_rule_violation(
            test_id="TC-LOGIN-BR-009",
            standard="ISO 25010 - Data Quality, Usability",
            expected_behavior="Trim leading/trailing whitespace before authentication",
            actual_behavior=f"Whitespace-padded input '{test_input}' treated as different username",
            impact="User confusion, authentication failures for valid users, poor user experience",
            severity="LOW"
        )
        assert False, f"System does not trim whitespace from username: '{test_input}'"


@pytest.mark.business_rules
def test_session_timeout_enforcement(browser):
    """TC-LOGIN-BR-010: Session Timeout
    
    Standard: OWASP ASVS v5.0-3.3.4, ISO 27001 A.9.4.2
    Requirement: Automatic logout after 15 minutes of inactivity
    """
    logging.info("TC-LOGIN-BR-010: Testing session timeout enforcement")
    browser.get(BASE_URL)
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(LOGIN_BUTTON_NAV)
    ).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(LOGIN_USERNAME_FIELD)
    )
    
    perform_login(browser, TEST_USERNAME, TEST_PASSWORD)
    assert check_user_logged_in(browser), "Login should succeed before timeout test"
    
    logging.info("Waiting 30 seconds to check session persistence")
    time.sleep(30)
    
    session_still_active = check_user_logged_in(browser, timeout=2)
    
    if session_still_active:
        log_business_rule_violation(
            test_id="TC-LOGIN-BR-010",
            standard="OWASP ASVS v5.0-3.3.4, ISO 27001 A.9.4.2",
            expected_behavior="Automatic logout after 15 minutes of inactivity",
            actual_behavior="Session remains active after 30 seconds with no activity (timeout likely not implemented)",
            impact="Unattended sessions vulnerable to hijacking, unauthorized access from shared devices",
            severity="HIGH"
        )


@pytest.mark.business_rules
def test_password_case_sensitivity(login_page):
    """TC-LOGIN-BR-011: Password Case Sensitivity
    
    Standard: OWASP ASVS v5.0-2.1.1
    Requirement: Passwords SHALL be case-sensitive
    """
    logging.info("TC-LOGIN-BR-011: Testing password case sensitivity enforcement")
    wrong_case_password = TEST_PASSWORD.swapcase()
    
    if wrong_case_password == TEST_PASSWORD:
        pytest.skip("Test password has no case variance")
    
    perform_login(login_page, TEST_USERNAME, wrong_case_password)
    alert_text = wait_for_alert(login_page, timeout=3)
    
    if check_user_logged_in(login_page, timeout=2):
        log_business_rule_violation(
            test_id="TC-LOGIN-BR-011",
            standard="OWASP ASVS v5.0-2.1.1",
            expected_behavior="Case-swapped password rejected",
            actual_behavior=f"Login successful with case-swapped password (Original: {TEST_PASSWORD}, Used: {wrong_case_password})",
            impact="Reduced password entropy by 50%, significantly easier brute force attacks",
            severity="HIGH"
        )
        assert False, "Password case sensitivity not enforced"
    
    assert alert_text and ("wrong" in alert_text.lower() or "invalid" in alert_text.lower() or "incorrect" in alert_text.lower()), \
        "System should reject case-swapped password"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])
