"""
Test Suite: Signup & Registration Security Testing
Module: test_signup_security.py
Author: QA Testing Team
Version: 1.0

Test Categories:
- Injection Attacks: SQL Injection, Command Injection, LDAP Injection
- Cross-Site Attacks: XSS (Reflected, Stored, DOM-based)
- Authentication Security: Brute Force, Account Enumeration, Credential Stuffing
- Session Security: Session Fixation, Cookie Security
- Security Controls: CSRF, Security Headers, Timing Attacks

Standards Validated:
- OWASP ASVS v5.0 (Authentication, Session Management, Input Validation)
- OWASP Top 10 2021
- CWE (Common Weakness Enumeration)
- NIST SP 800-63B (Digital Identity Guidelines)
- PCI-DSS v4.0 (Payment Card Industry Data Security Standard)

CVSS Scoring:
All discovered vulnerabilities are scored using CVSS v3.1

Execution:
Run all tests:           pytest test_signup_security.py -v
Run by category:         pytest test_signup_security.py -k "sql_injection" -v
Run critical only:       pytest test_signup_security.py -m "critical" -v
Generate HTML report:    pytest test_signup_security.py --html=report_signup_security.html --self-contained-html

Total Expected Tests: 25+ (with parametrization)
"""

import logging
import time

import pytest
import requests
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# ============================================================================
# CONFIGURATION
# ============================================================================

BASE_URL = "https://www.demoblaze.com/"
TIMEOUT = 10
TIMEOUT_SHORT = 5
TIMEOUT_MEDIUM = 15

# ============================================================================
# LOCATORS
# ============================================================================

SIGNUP_BUTTON_NAV = (By.ID, "signin2")
SIGNUP_MODAL = (By.ID, "signInModal")
SIGNUP_USERNAME_FIELD = (By.ID, "sign-username")
SIGNUP_PASSWORD_FIELD = (By.ID, "sign-password")
SIGNUP_SUBMIT_BUTTON = (By.XPATH, "//button[contains(text(),'Sign up')]")

LOGIN_BUTTON_NAV = (By.ID, "login2")
LOGIN_MODAL = (By.ID, "logInModal")
LOGIN_USERNAME_FIELD = (By.ID, "loginusername")
LOGIN_PASSWORD_FIELD = (By.ID, "loginpassword")
LOGIN_SUBMIT_BUTTON = (By.XPATH, "//button[contains(text(),'Log in')]")

WELCOME_USER_LINK = (By.ID, "nameofuser")
LOGOUT_BUTTON = (By.ID, "logout2")

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


def wait_for_alert_and_get_text(browser, timeout=TIMEOUT_SHORT):
    try:
        WebDriverWait(browser, timeout).until(EC.alert_is_present())
        alert = browser.switch_to.alert
        alert_text = alert.text
        logging.info(f"Alert: {alert_text}")
        alert.accept()
        return alert_text
    except TimeoutException:
        return None


def perform_signup(browser, username, password, timeout=TIMEOUT):
    try:
        signup_button = WebDriverWait(browser, timeout).until(
            EC.element_to_be_clickable(SIGNUP_BUTTON_NAV)
        )
        signup_button.click()

        WebDriverWait(browser, timeout).until(
            EC.visibility_of_element_located(SIGNUP_MODAL)
        )

        username_field = WebDriverWait(browser, timeout).until(
            EC.visibility_of_element_located(SIGNUP_USERNAME_FIELD)
        )
        username_field.clear()
        username_field.send_keys(username)

        password_field = browser.find_element(*SIGNUP_PASSWORD_FIELD)
        password_field.clear()
        password_field.send_keys(password)

        submit_button = browser.find_element(*SIGNUP_SUBMIT_BUTTON)
        submit_button.click()

        return True
    except (TimeoutException, NoSuchElementException):
        return False


def perform_login(browser, username, password, timeout=TIMEOUT):
    try:
        login_button = WebDriverWait(browser, timeout).until(
            EC.element_to_be_clickable(LOGIN_BUTTON_NAV)
        )
        login_button.click()

        WebDriverWait(browser, timeout).until(
            EC.visibility_of_element_located(LOGIN_MODAL)
        )

        username_field = WebDriverWait(browser, timeout).until(
            EC.visibility_of_element_located(LOGIN_USERNAME_FIELD)
        )
        username_field.clear()
        username_field.send_keys(username)

        password_field = browser.find_element(*LOGIN_PASSWORD_FIELD)
        password_field.clear()
        password_field.send_keys(password)

        submit_button = browser.find_element(*LOGIN_SUBMIT_BUTTON)
        submit_button.click()

        return True
    except (TimeoutException, NoSuchElementException):
        return False


def is_user_logged_in(browser, timeout=TIMEOUT_SHORT):
    try:
        WebDriverWait(browser, timeout).until(
            EC.visibility_of_element_located(WELCOME_USER_LINK)
        )
        return True
    except TimeoutException:
        return False


def check_for_error_in_page(browser, payload):
    page_source = browser.page_source.lower()
    error_indicators = [
        "sql syntax",
        "mysql",
        "postgresql",
        "oracle",
        "sqlite",
        "syntax error",
        "unexpected",
        "warning:",
        "error in your sql",
        "odbc",
        "jdbc",
    ]

    for indicator in error_indicators:
        if indicator in page_source:
            return True, indicator

    return False, None


# ============================================================================
# SQL INJECTION TESTS
# ============================================================================


@pytest.mark.security
@pytest.mark.critical
@pytest.mark.parametrize(
    "sql_payload",
    [
        "' OR '1'='1",
        "admin'--",
        "' OR '1'='1' --",
        "') OR ('1'='1",
        "' OR 1=1--",
        "admin' OR '1'='1' /*",
    ],
)
def test_sql_injection_username_field_SEC_001(browser, sql_payload):
    """
    TC-SIGNUP-SEC-001: SQL Injection in Username Field

    Standard: OWASP ASVS v5.0 Section 5.3.4 (SQL Injection Prevention)
    CWE: CWE-89 (SQL Injection)
    CVSS Score: 9.8 (CRITICAL)
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Discovers if signup username field is vulnerable to SQL injection.
    """
    logging.info("=" * 80)
    logging.info(
        f"TC-SIGNUP-SEC-001: Testing SQL injection with payload: {sql_payload}"
    )

    browser.get(BASE_URL)

    perform_signup(browser, sql_payload, "TestPass123!")
    time.sleep(1)

    alert_text = wait_for_alert_and_get_text(browser)

    if alert_text and "success" in alert_text.lower():
        logging.error("=" * 80)
        logging.error("CRITICAL VULNERABILITY DISCOVERED: SQL INJECTION")
        logging.error(f"Payload: {sql_payload}")
        logging.error("Field: Username")
        logging.error("Standard: OWASP ASVS v5.0 Section 5.3.4")
        logging.error("CWE-89: SQL Injection")
        logging.error("CVSS Score: 9.8 (CRITICAL)")
        logging.error("Impact: Complete database compromise possible")
        logging.error("Evidence: Account creation succeeded with SQL payload")
        logging.error("=" * 80)

        pytest.fail(
            f"DISCOVERED: SQL Injection vulnerability with payload '{sql_payload}'"
        )

    has_error, indicator = check_for_error_in_page(browser, sql_payload)
    if has_error:
        logging.error("=" * 80)
        logging.error("SQL ERROR DISCLOSURE DETECTED")
        logging.error(f"Payload: {sql_payload}")
        logging.error(f"Error indicator found: {indicator}")
        logging.error("CVSS Score: 7.5 (HIGH)")
        logging.error("Impact: Database structure disclosure")
        logging.error("=" * 80)

        pytest.fail(
            f"DISCOVERED: SQL error disclosure with indicator '{indicator}'"
        )

    logging.info(f"SQL payload '{sql_payload}' handled safely")
    assert True


@pytest.mark.security
@pytest.mark.critical
@pytest.mark.parametrize(
    "sql_payload", ["' OR '1'='1", "' OR 1=1--", "') OR ('1'='1"]
)
def test_sql_injection_password_field_SEC_002(browser, sql_payload):
    """
    TC-SIGNUP-SEC-002: SQL Injection in Password Field

    Standard: OWASP ASVS v5.0 Section 5.3.4
    CWE: CWE-89 (SQL Injection)
    CVSS Score: 9.8 (CRITICAL)

    Discovers if signup password field is vulnerable to SQL injection.
    """
    logging.info("=" * 80)
    logging.info(
        f"TC-SIGNUP-SEC-002: Testing SQL injection in password: {sql_payload}"
    )

    browser.get(BASE_URL)

    test_username = f"testuser_{int(time.time())}"
    perform_signup(browser, test_username, sql_payload)
    time.sleep(1)

    alert_text = wait_for_alert_and_get_text(browser)

    if alert_text and "success" in alert_text.lower():
        browser.get(BASE_URL)
        time.sleep(1)

        perform_login(browser, test_username, sql_payload)
        time.sleep(1)
        wait_for_alert_and_get_text(browser)

        if is_user_logged_in(browser):
            logging.error("=" * 80)
            logging.error("SQL INJECTION IN PASSWORD FIELD")
            logging.error(f"Payload stored: {sql_payload}")
            logging.error("CVSS Score: 9.8 (CRITICAL)")
            logging.error(
                "Impact: SQL injection possible through password field"
            )
            logging.error("=" * 80)
            pytest.fail(f"DISCOVERED: SQL payload accepted in password field")

    logging.info(f"Password SQL payload '{sql_payload}' handled safely")
    assert True


# ============================================================================
# XSS TESTS
# ============================================================================


@pytest.mark.security
@pytest.mark.critical
@pytest.mark.parametrize(
    "xss_payload",
    [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "'-alert('XSS')-'",
    ],
)
def test_xss_username_field_SEC_003(browser, xss_payload):
    """
    TC-SIGNUP-SEC-003: Cross-Site Scripting (XSS) in Username

    Standard: OWASP ASVS v5.0 Section 5.3.3 (Output Encoding)
    CWE: CWE-79 (Cross-site Scripting)
    CVSS Score: 7.1 (HIGH)
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L

    Discovers if username field is vulnerable to XSS attacks.
    """
    logging.info("=" * 80)
    logging.info(f"TC-SIGNUP-SEC-003: Testing XSS with payload: {xss_payload}")

    browser.get(BASE_URL)

    perform_signup(browser, xss_payload, "TestPass123!")
    time.sleep(1)

    alert_text = wait_for_alert_and_get_text(browser)

    if alert_text and "success" in alert_text.lower():
        browser.get(BASE_URL)
        time.sleep(2)

        page_source = browser.page_source

        if xss_payload in page_source:
            logging.error("=" * 80)
            logging.error("XSS VULNERABILITY DISCOVERED")
            logging.error(f"Payload: {xss_payload}")
            logging.error("Location: Username field")
            logging.error("Standard: OWASP ASVS v5.0 Section 5.3.3")
            logging.error("CWE-79: Cross-site Scripting")
            logging.error("CVSS Score: 7.1 (HIGH)")
            logging.error(
                "Impact: Session hijacking, cookie theft, defacement"
            )
            logging.error("Evidence: XSS payload reflected unescaped in page")
            logging.error("=" * 80)

            pytest.fail(
                f"DISCOVERED: XSS vulnerability with payload '{xss_payload}'"
            )

    logging.info(f"XSS payload '{xss_payload}' handled safely")
    assert True


@pytest.mark.security
@pytest.mark.critical
def test_stored_xss_via_username_SEC_004(browser):
    """
    TC-SIGNUP-SEC-004: Stored XSS via Username

    Standard: OWASP ASVS v5.0 Section 5.3.3
    CWE: CWE-79 (Stored Cross-site Scripting)
    CVSS Score: 8.7 (HIGH)

    Discovers if XSS payload persists and executes on subsequent page loads.
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-SEC-004: Testing stored XSS")

    xss_payload = f"<img src=x onerror=alert('XSS')>_{int(time.time())}"

    browser.get(BASE_URL)
    perform_signup(browser, xss_payload, "TestPass123!")
    time.sleep(1)

    signup_alert = wait_for_alert_and_get_text(browser)

    if signup_alert and "success" in signup_alert.lower():
        browser.get(BASE_URL)
        time.sleep(1)

        perform_login(browser, xss_payload, "TestPass123!")
        time.sleep(2)

        try:
            WebDriverWait(browser, 3).until(EC.alert_is_present())
            alert = browser.switch_to.alert
            alert_content = alert.text
            alert.accept()

            if "XSS" in alert_content:
                logging.error("=" * 80)
                logging.error("STORED XSS VULNERABILITY DISCOVERED")
                logging.error("Payload executed on subsequent page load")
                logging.error("CVSS Score: 8.7 (HIGH)")
                logging.error(
                    "Impact: Persistent XSS affects all users viewing profile"
                )
                logging.error("=" * 80)
                pytest.fail("DISCOVERED: Stored XSS vulnerability")
        except TimeoutException:
            pass

    logging.info("Stored XSS test: No vulnerability detected")
    assert True


# ============================================================================
# AUTHENTICATION SECURITY TESTS
# ============================================================================


@pytest.mark.security
@pytest.mark.high
def test_brute_force_protection_SEC_005(browser):
    """
    TC-SIGNUP-SEC-005: Brute Force Protection on Signup

    Standard: OWASP ASVS v5.0 Section 2.2.1 (Anti-automation)
    CWE: CWE-307 (Improper Restriction of Excessive Authentication Attempts)
    CVSS Score: 7.5 (HIGH)

    Discovers if system limits rapid signup attempts.
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-SEC-005: Testing brute force protection")

    attempts = 10
    rate_limited = False

    for i in range(attempts):
        browser.get(BASE_URL)

        username = f"bruteforce_{int(time.time())}_{i}"
        perform_signup(browser, username, "TestPass123!")
        time.sleep(0.5)

        alert_text = wait_for_alert_and_get_text(browser, timeout=3)

        if alert_text and (
            "limit" in alert_text.lower()
            or "wait" in alert_text.lower()
            or "too many" in alert_text.lower()
        ):
            logging.info(f"Rate limiting detected after {i + 1} attempts")
            rate_limited = True
            break

    if not rate_limited:
        logging.error("=" * 80)
        logging.error("NO BRUTE FORCE PROTECTION DETECTED")
        logging.error("Standard: OWASP ASVS v5.0 Section 2.2.1")
        logging.error(
            "CWE-307: Improper Restriction of Excessive Authentication Attempts"
        )
        logging.error("CVSS Score: 7.5 (HIGH)")
        logging.error(
            f"Completed {attempts} rapid signup attempts without restriction"
        )
        logging.error("Impact: Automated account creation possible")
        logging.error(
            "Recommendation: Implement rate limiting (e.g., 5 attempts per IP per hour)"
        )
        logging.error("=" * 80)

        pytest.fail(
            f"DISCOVERED: No rate limiting after {attempts} signup attempts"
        )

    assert True


@pytest.mark.security
@pytest.mark.medium
def test_account_enumeration_timing_SEC_006(browser):
    """
    TC-SIGNUP-SEC-006: Account Enumeration via Timing Attack

    Standard: OWASP ASVS v5.0 Section 2.2.2 (Account Enumeration)
    CWE: CWE-208 (Observable Timing Discrepancy)
    CVSS Score: 5.3 (MEDIUM)

    Discovers if response times reveal account existence.
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-SEC-006: Testing timing-based enumeration")

    browser.get(BASE_URL)

    existing_user = f"existing_{int(time.time())}"
    perform_signup(browser, existing_user, "TestPass123!")
    time.sleep(1)
    first_alert = wait_for_alert_and_get_text(browser)

    if not first_alert or "success" not in first_alert.lower():
        pytest.skip("Could not create test account")

    browser.get(BASE_URL)

    start_time = time.time()
    perform_signup(browser, existing_user, "AnotherPass456!")
    time.sleep(1)
    wait_for_alert_and_get_text(browser)
    existing_duration = time.time() - start_time

    browser.get(BASE_URL)

    nonexistent_user = f"nonexistent_{int(time.time())}"
    start_time = time.time()
    perform_signup(browser, nonexistent_user, "")
    time.sleep(1)
    wait_for_alert_and_get_text(browser)
    nonexistent_duration = time.time() - start_time

    time_diff = abs(existing_duration - nonexistent_duration)

    if time_diff > 0.5:
        logging.warning("=" * 80)
        logging.warning("TIMING DISCREPANCY DETECTED")
        logging.warning(
            f"Existing account response time: {existing_duration:.2f}s"
        )
        logging.warning(
            f"Nonexistent account response time: {nonexistent_duration:.2f}s"
        )
        logging.warning(f"Difference: {time_diff:.2f}s")
        logging.warning("CVSS Score: 5.3 (MEDIUM)")
        logging.warning("Impact: Account enumeration via timing attack")
        logging.warning("=" * 80)

        pytest.fail(
            f"DISCOVERED: Timing discrepancy of {time_diff:.2f}s enables enumeration"
        )

    logging.info("No significant timing discrepancy detected")
    assert True


@pytest.mark.security
@pytest.mark.medium
def test_username_enumeration_SEC_007(browser):
    """
    TC-SIGNUP-SEC-007: Username Enumeration via Error Messages

    Standard: OWASP ASVS v5.0 Section 2.2.2
    CWE: CWE-204 (Observable Response Discrepancy)
    CVSS Score: 5.3 (MEDIUM)

    Discovers if different error messages reveal username existence.
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-SEC-007: Testing username enumeration")

    browser.get(BASE_URL)

    existing_user = f"enumtest_{int(time.time())}"
    perform_signup(browser, existing_user, "TestPass123!")
    time.sleep(1)
    signup_alert = wait_for_alert_and_get_text(browser)

    if not signup_alert or "success" not in signup_alert.lower():
        pytest.skip("Could not create test account")

    browser.get(BASE_URL)
    perform_signup(browser, existing_user, "DifferentPass!")
    time.sleep(1)
    duplicate_alert = wait_for_alert_and_get_text(browser)

    browser.get(BASE_URL)
    nonexistent_user = f"nonexistent_{int(time.time())}"
    perform_signup(browser, nonexistent_user, "")
    time.sleep(1)
    empty_alert = wait_for_alert_and_get_text(browser)

    if duplicate_alert and empty_alert:
        if duplicate_alert.lower() != empty_alert.lower():
            if (
                "exist" in duplicate_alert.lower()
                or "taken" in duplicate_alert.lower()
            ):
                logging.error("=" * 80)
                logging.error("USERNAME ENUMERATION VULNERABILITY")
                logging.error(f"Duplicate user message: {duplicate_alert}")
                logging.error(f"Empty field message: {empty_alert}")
                logging.error("CVSS Score: 5.3 (MEDIUM)")
                logging.error(
                    "Impact: Attackers can enumerate valid usernames"
                )
                logging.error("Recommendation: Use generic error messages")
                logging.error("=" * 80)

                pytest.fail(
                    "DISCOVERED: Username enumeration via different error messages"
                )

    logging.info("Generic error messages used - no enumeration possible")
    assert True


# ============================================================================
# SESSION SECURITY TESTS
# ============================================================================


@pytest.mark.security
@pytest.mark.high
def test_session_fixation_SEC_008(browser):
    """
    TC-SIGNUP-SEC-008: Session Fixation

    Standard: OWASP ASVS v5.0 Section 3.2.1 (Session Generation)
    CWE: CWE-384 (Session Fixation)
    CVSS Score: 7.5 (HIGH)

    Discovers if session ID changes after signup.
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-SEC-008: Testing session fixation")

    browser.get(BASE_URL)
    time.sleep(1)

    pre_signup_cookies = {
        cookie["name"]: cookie["value"] for cookie in browser.get_cookies()
    }
    logging.info(f"Pre-signup cookies: {pre_signup_cookies}")

    test_user = f"sessiontest_{int(time.time())}"
    perform_signup(browser, test_user, "TestPass123!")
    time.sleep(1)
    signup_alert = wait_for_alert_and_get_text(browser)

    if signup_alert and "success" in signup_alert.lower():
        browser.get(BASE_URL)
        time.sleep(1)

        perform_login(browser, test_user, "TestPass123!")
        time.sleep(2)
        wait_for_alert_and_get_text(browser)

        if is_user_logged_in(browser):
            post_login_cookies = {
                cookie["name"]: cookie["value"]
                for cookie in browser.get_cookies()
            }
            logging.info(f"Post-login cookies: {post_login_cookies}")

            session_changed = False
            for cookie_name in pre_signup_cookies:
                if cookie_name in post_login_cookies:
                    if (
                        pre_signup_cookies[cookie_name]
                        != post_login_cookies[cookie_name]
                    ):
                        session_changed = True
                        logging.info(
                            f"Session cookie '{cookie_name}' changed after authentication"
                        )

            if not session_changed:
                logging.error("=" * 80)
                logging.error("SESSION FIXATION VULNERABILITY")
                logging.error("Session ID did not change after authentication")
                logging.error("Standard: OWASP ASVS v5.0 Section 3.2.1")
                logging.error("CWE-384: Session Fixation")
                logging.error("CVSS Score: 7.5 (HIGH)")
                logging.error("Impact: Attacker can hijack user session")
                logging.error("=" * 80)

                pytest.fail("DISCOVERED: Session fixation vulnerability")

    logging.info("Session management appears secure")
    assert True


@pytest.mark.security
@pytest.mark.medium
def test_cookie_security_flags_SEC_009(browser):
    """
    TC-SIGNUP-SEC-009: Cookie Security Flags

    Standard: OWASP ASVS v5.0 Section 3.4.2 (Cookie-based Session Management)
    CWE: CWE-614 (Sensitive Cookie Without 'Secure' Flag)
    CVSS Score: 6.5 (MEDIUM)

    Discovers if cookies have HttpOnly and Secure flags.
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-SEC-009: Testing cookie security flags")

    browser.get(BASE_URL)
    time.sleep(1)

    test_user = f"cookietest_{int(time.time())}"
    perform_signup(browser, test_user, "TestPass123!")
    time.sleep(1)
    signup_alert = wait_for_alert_and_get_text(browser)

    if signup_alert and "success" in signup_alert.lower():
        browser.get(BASE_URL)
        time.sleep(1)

        perform_login(browser, test_user, "TestPass123!")
        time.sleep(2)
        wait_for_alert_and_get_text(browser)

        if is_user_logged_in(browser):
            cookies = browser.get_cookies()

            insecure_cookies = []
            for cookie in cookies:
                cookie_name = cookie.get("name", "unknown")
                is_secure = cookie.get("secure", False)
                is_httponly = cookie.get("httpOnly", False)

                if not is_secure or not is_httponly:
                    insecure_cookies.append(
                        {
                            "name": cookie_name,
                            "secure": is_secure,
                            "httponly": is_httponly,
                        }
                    )

            if insecure_cookies:
                logging.error("=" * 80)
                logging.error("INSECURE COOKIE CONFIGURATION")
                for cookie in insecure_cookies:
                    logging.error(f"Cookie: {cookie['name']}")
                    logging.error(f"  Secure flag: {cookie['secure']}")
                    logging.error(f"  HttpOnly flag: {cookie['httponly']}")
                logging.error("CVSS Score: 6.5 (MEDIUM)")
                logging.error(
                    "Impact: Session hijacking via XSS or MITM attacks"
                )
                logging.error("=" * 80)

                pytest.fail(
                    f"DISCOVERED: {len(insecure_cookies)} cookies lack security flags"
                )

    logging.info("Cookie security flags properly configured")
    assert True


# ============================================================================
# CSRF TESTS
# ============================================================================


@pytest.mark.security
@pytest.mark.high
def test_csrf_token_validation_SEC_010(browser):
    """
    TC-SIGNUP-SEC-010: CSRF Token Validation

    Standard: OWASP ASVS v5.0 Section 4.2.2 (CSRF Prevention)
    CWE: CWE-352 (Cross-Site Request Forgery)
    CVSS Score: 6.5 (MEDIUM)

    Discovers if signup form is protected against CSRF attacks.
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-SEC-010: Testing CSRF protection")

    browser.get(BASE_URL)
    time.sleep(1)

    signup_button = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(SIGNUP_BUTTON_NAV)
    )
    signup_button.click()

    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(SIGNUP_MODAL)
    )

    page_source = browser.page_source.lower()

    csrf_indicators = [
        "csrf",
        "xsrf",
        "_token",
        "authenticity_token",
        "anti-forgery",
    ]

    csrf_found = False
    for indicator in csrf_indicators:
        if indicator in page_source:
            csrf_found = True
            logging.info(f"CSRF protection detected: {indicator}")
            break

    if not csrf_found:
        logging.error("=" * 80)
        logging.error("NO CSRF PROTECTION DETECTED")
        logging.error("Standard: OWASP ASVS v5.0 Section 4.2.2")
        logging.error("CWE-352: Cross-Site Request Forgery")
        logging.error("CVSS Score: 6.5 (MEDIUM)")
        logging.error("Impact: Attacker can forge signup requests")
        logging.error("Recommendation: Implement CSRF tokens")
        logging.error("=" * 80)

        pytest.fail("DISCOVERED: No CSRF protection on signup form")

    assert True


# ============================================================================
# SECURITY HEADERS TESTS
# ============================================================================


@pytest.mark.security
@pytest.mark.medium
def test_security_headers_SEC_011(browser):
    """
    TC-SIGNUP-SEC-011: Security Headers

    Standard: OWASP ASVS v5.0 Section 14.4 (HTTP Security Headers)
    CWE: CWE-693 (Protection Mechanism Failure)
    CVSS Score: 7.5 (HIGH)

    Discovers if critical security headers are present.
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-SEC-011: Testing security headers")

    try:
        response = requests.get(BASE_URL, timeout=10)
        headers = response.headers

        required_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": ["DENY", "SAMEORIGIN"],
            "Strict-Transport-Security": "max-age",
            "Content-Security-Policy": None,
            "X-XSS-Protection": "1",
        }

        missing_headers = []
        misconfigured_headers = []

        for header, expected_value in required_headers.items():
            if header not in headers:
                missing_headers.append(header)
            elif expected_value:
                actual_value = headers[header]
                if isinstance(expected_value, list):
                    if not any(val in actual_value for val in expected_value):
                        misconfigured_headers.append(
                            f"{header}: {actual_value}"
                        )
                elif expected_value not in actual_value:
                    misconfigured_headers.append(f"{header}: {actual_value}")

        if missing_headers or misconfigured_headers:
            logging.error("=" * 80)
            logging.error("SECURITY HEADERS MISSING OR MISCONFIGURED")
            if missing_headers:
                logging.error(f"Missing headers: {', '.join(missing_headers)}")
            if misconfigured_headers:
                logging.error(
                    f"Misconfigured: {', '.join(misconfigured_headers)}"
                )
            logging.error("CVSS Score: 7.5 (HIGH)")
            logging.error("Impact: Increased attack surface")
            logging.error("=" * 80)

            pytest.fail(
                f"DISCOVERED: {len(missing_headers)} headers missing, {len(misconfigured_headers)} misconfigured"
            )

        logging.info("All critical security headers present")
        assert True

    except requests.RequestException as e:
        logging.warning(f"Could not fetch headers: {e}")
        pytest.skip("Network request failed")


# ============================================================================
# ADDITIONAL SECURITY TESTS
# ============================================================================


@pytest.mark.security
@pytest.mark.medium
def test_password_transmitted_plaintext_SEC_012(browser):
    """
    TC-SIGNUP-SEC-012: Password Transmission Security

    Standard: OWASP ASVS v5.0 Section 2.7.1 (Cryptography)
    CWE: CWE-319 (Cleartext Transmission of Sensitive Information)
    CVSS Score: 7.4 (HIGH)

    Discovers if connection uses HTTPS for password transmission.
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-SEC-012: Testing password transmission security")

    current_url = browser.current_url

    if not current_url.startswith("https://"):
        logging.error("=" * 80)
        logging.error("INSECURE PASSWORD TRANSMISSION")
        logging.error(f"Current URL: {current_url}")
        logging.error("Protocol: HTTP (unencrypted)")
        logging.error(
            "CWE-319: Cleartext Transmission of Sensitive Information"
        )
        logging.error("CVSS Score: 7.4 (HIGH)")
        logging.error("Impact: Passwords transmitted in plaintext")
        logging.error("Recommendation: Enforce HTTPS for all pages")
        logging.error("=" * 80)

        pytest.fail("DISCOVERED: Application not using HTTPS")

    logging.info("HTTPS properly enforced")
    assert True


@pytest.mark.security
@pytest.mark.low
def test_verbose_error_messages_SEC_013(browser):
    """
    TC-SIGNUP-SEC-013: Verbose Error Messages

    Standard: OWASP ASVS v5.0 Section 7.4.1 (Error Handling)
    CWE: CWE-209 (Information Exposure Through Error Message)
    CVSS Score: 3.7 (LOW)

    Discovers if error messages reveal sensitive information.
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-SEC-013: Testing error message verbosity")

    browser.get(BASE_URL)

    extreme_payload = "A" * 10000
    perform_signup(browser, extreme_payload, "test")
    time.sleep(1)

    alert_text = wait_for_alert_and_get_text(browser)

    if alert_text:
        sensitive_terms = [
            "stack trace",
            "exception",
            "database",
            "query",
            "file path",
            "server",
            "version",
        ]

        for term in sensitive_terms:
            if term in alert_text.lower():
                logging.warning("=" * 80)
                logging.warning("VERBOSE ERROR MESSAGE DETECTED")
                logging.warning(f"Alert text: {alert_text}")
                logging.warning(f"Sensitive term: {term}")
                logging.warning("CVSS Score: 3.7 (LOW)")
                logging.warning("Impact: Information disclosure")
                logging.warning("=" * 80)

                pytest.fail(f"DISCOVERED: Verbose error containing '{term}'")

    logging.info("Error messages appear appropriately generic")
    assert True


# ============================================================================
# END OF TEST SUITE
# ============================================================================
