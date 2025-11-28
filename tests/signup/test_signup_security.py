"""
Test Suite: SIGNUP Security Testing (POM Architecture)
Module: test_signup_security.py
Author: Marc Arévalo
Version: 1.0

PHILOSOPHY: DISCOVER (EXECUTE → OBSERVE → DECIDE)
These tests actively discover security vulnerabilities through real attacks,
not assumptions. Each test executes an attack, observes the system response,
and decides based on objective security standards.

Test Categories:
- Injection Attacks: SQL Injection (username/password fields)
- Cross-Site Attacks: XSS (Reflected, Stored)
- Authentication Security: Brute Force, Account Enumeration
- Session Security: Session Fixation, Cookie Security
- Security Controls: CSRF, Security Headers, Error Handling

Standards Validated:
- OWASP ASVS v5.0 (Authentication, Session Management, Input Validation)
- OWASP Top 10 2021
- CWE (Common Weakness Enumeration)
- NIST SP 800-63B (Digital Identity Guidelines)
- PCI-DSS v4.0.1

CVSS Scoring:
All discovered vulnerabilities are scored using CVSS v3.1

Execution:
pytest tests_new/signup/test_signup_security.py -v
pytest tests_new/signup/test_signup_security.py -m "critical" -v
pytest tests_new/signup/test_signup_security.py -k "sql_injection" -v

Total Tests: 13 functions (~25+ executions with parametrization)
"""

import pytest
import time
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from pages.signup_page import SignupPage

    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


@pytest.mark.security
@pytest.mark.critical
@pytest.mark.injection
@pytest.mark.parametrize("sql_payload", [
    "' OR '1'='1",
    "admin'--",
    "' OR '1'='1' --",
    "') OR ('1'='1",
    "' OR 1=1--",
    "admin' OR '1'='1' /*"
])
def test_sql_injection_username_field_SEC_001(browser, base_url, sql_payload):
    """
    TC-SIGNUP-SEC-001: SQL Injection in Username Field

    Standard: OWASP ASVS v5.0 Section 5.3.4 (SQL Injection Prevention)
    CWE: CWE-89 (SQL Injection)
    CVSS Score: 9.8 (CRITICAL)
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    DISCOVER: Tests if signup username field is vulnerable to SQL injection.
    """
    logging.info("=" * 80)
    logging.info(f"TC-SIGNUP-SEC-001: Testing SQL injection with payload: {sql_payload}")

    browser.get(base_url)
    signup_page = SignupPage(browser)
    signup_page.signup(sql_payload, "TestPass123!")

    time.sleep(1)
    alert_text = signup_page.get_alert_text(timeout=5)

    if alert_text and "success" in alert_text.lower():
        logging.critical("=" * 80)
        logging.critical("CRITICAL VULNERABILITY DISCOVERED: SQL INJECTION")
        logging.critical(f"Payload: {sql_payload}")
        logging.critical("Field: Username")
        logging.critical("Standard: OWASP ASVS v5.0 Section 5.3.4")
        logging.critical("CWE-89: SQL Injection")
        logging.critical("CVSS Score: 9.8 (CRITICAL)")
        logging.critical("Impact: Complete database compromise possible")
        logging.critical("Evidence: Account creation succeeded with SQL payload")
        logging.critical("=" * 80)

        pytest.fail(f"DISCOVERED: SQL Injection vulnerability with payload '{sql_payload}'")

    page_source = browser.page_source.lower()
    error_indicators = ["sql syntax", "mysql", "postgresql", "oracle", "sqlite",
                       "syntax error", "odbc", "jdbc", "error in your sql"]

    for indicator in error_indicators:
        if indicator in page_source:
            logging.error("=" * 80)
            logging.error("SQL ERROR DISCLOSURE DETECTED")
            logging.error(f"Payload: {sql_payload}")
            logging.error(f"Error indicator found: {indicator}")
            logging.error("CVSS Score: 7.5 (HIGH)")
            logging.error("Impact: Database structure disclosure")
            logging.error("=" * 80)

            pytest.fail(f"DISCOVERED: SQL error disclosure with indicator '{indicator}'")

    logging.info(f"✓ SQL payload '{sql_payload}' handled safely")
    assert True


@pytest.mark.security
@pytest.mark.critical
@pytest.mark.injection
@pytest.mark.parametrize("sql_payload", [
    "' OR '1'='1",
    "' OR 1=1--",
    "') OR ('1'='1"
])
def test_sql_injection_password_field_SEC_002(browser, base_url, sql_payload):
    """
    TC-SIGNUP-SEC-002: SQL Injection in Password Field

    Standard: OWASP ASVS v5.0 Section 5.3.4
    CWE: CWE-89 (SQL Injection)
    CVSS Score: 9.8 (CRITICAL)

    DISCOVER: Tests if signup password field is vulnerable to SQL injection.
    """
    logging.info("=" * 80)
    logging.info(f"TC-SIGNUP-SEC-002: Testing SQL injection in password: {sql_payload}")

    browser.get(base_url)
    signup_page = SignupPage(browser)

    test_username = signup_page.generate_unique_username()
    signup_page.signup(test_username, sql_payload)

    time.sleep(1)
    alert_text = signup_page.get_alert_text(timeout=5)

    if alert_text and "success" in alert_text.lower():
        browser.get(base_url)
        time.sleep(1)

        signup_page.login_after_signup(test_username, sql_payload)
        time.sleep(1)
        signup_page.get_alert_text(timeout=3)

        if signup_page.is_user_logged_in(timeout=3):
            logging.critical("=" * 80)
            logging.critical("SQL INJECTION IN PASSWORD FIELD")
            logging.critical(f"Payload stored: {sql_payload}")
            logging.critical("CVSS Score: 9.8 (CRITICAL)")
            logging.critical("Impact: SQL injection possible through password field")
            logging.critical("=" * 80)

            signup_page.logout()
            pytest.fail(f"DISCOVERED: SQL payload accepted in password field")

    logging.info(f"✓ Password SQL payload '{sql_payload}' handled safely")
    assert True



@pytest.mark.security
@pytest.mark.critical
@pytest.mark.xss
@pytest.mark.parametrize("xss_payload", [
    "<script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "'-alert('XSS')-'"
])
def test_xss_username_field_SEC_003(browser, base_url, xss_payload):
    """
    TC-SIGNUP-SEC-003: Cross-Site Scripting (XSS) in Username

    Standard: OWASP ASVS v5.0 Section 5.3.3 (Output Encoding)
    CWE: CWE-79 (Cross-site Scripting)
    CVSS Score: 7.1 (HIGH)
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L

    DISCOVER: Tests if username field is vulnerable to XSS attacks.
    """
    logging.info("=" * 80)
    logging.info(f"TC-SIGNUP-SEC-003: Testing XSS with payload: {xss_payload}")

    browser.get(base_url)
    signup_page = SignupPage(browser)
    signup_page.signup(xss_payload, "TestPass123!")

    time.sleep(1)
    alert_text = signup_page.get_alert_text(timeout=5)

    if alert_text and "success" in alert_text.lower():
        browser.get(base_url)
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
            logging.error("Impact: Session hijacking, cookie theft, defacement")
            logging.error("Evidence: XSS payload reflected unescaped in page")
            logging.error("=" * 80)

            pytest.fail(f"DISCOVERED: XSS vulnerability with payload '{xss_payload}'")

    logging.info(f"✓ XSS payload '{xss_payload}' handled safely")
    assert True


@pytest.mark.security
@pytest.mark.critical
@pytest.mark.xss
def test_stored_xss_via_username_SEC_004(browser, base_url):
    """
    TC-SIGNUP-SEC-004: Stored XSS via Username

    Standard: OWASP ASVS v5.0 Section 5.3.3
    CWE: CWE-79 (Stored Cross-site Scripting)
    CVSS Score: 8.7 (HIGH)

    DISCOVER: Tests if XSS payload persists and executes on subsequent page loads.
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-SEC-004: Testing stored XSS")

    xss_payload = f"<img src=x onerror=alert('XSS')>_{int(time.time())}"

    browser.get(base_url)
    signup_page = SignupPage(browser)
    signup_page.signup(xss_payload, "TestPass123!")

    time.sleep(1)
    signup_alert = signup_page.get_alert_text(timeout=5)

    if signup_alert and "success" in signup_alert.lower():
        browser.get(base_url)
        time.sleep(1)

        signup_page.login_after_signup(xss_payload, "TestPass123!")
        time.sleep(2)

        try:
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
            from selenium.common.exceptions import TimeoutException

            WebDriverWait(browser, 3).until(EC.alert_is_present())
            alert = browser.switch_to.alert
            alert_content = alert.text
            alert.accept()

            if "XSS" in alert_content:
                logging.critical("=" * 80)
                logging.critical("STORED XSS VULNERABILITY DISCOVERED")
                logging.critical("Payload executed on subsequent page load")
                logging.critical("CVSS Score: 8.7 (HIGH)")
                logging.critical("Impact: Persistent XSS affects all users viewing profile")
                logging.critical("=" * 80)

                pytest.fail("DISCOVERED: Stored XSS vulnerability")
        except TimeoutException:
            pass

    logging.info("✓ Stored XSS test: No vulnerability detected")
    assert True



@pytest.mark.security
@pytest.mark.high
@pytest.mark.brute_force
def test_brute_force_protection_SEC_005(browser, base_url):
    """
    TC-SIGNUP-SEC-005: Brute Force Protection on Signup

    Standard: OWASP ASVS v5.0 Section 2.2.1 (Anti-automation)
    CWE: CWE-307 (Improper Restriction of Excessive Authentication Attempts)
    CVSS Score: 7.5 (HIGH)

    DISCOVER: Tests if system limits rapid signup attempts.
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-SEC-005: Testing brute force protection")

    signup_page = SignupPage(browser)
    attempts = 10
    rate_limited = False

    for i in range(attempts):
        browser.get(base_url)

        username = signup_page.generate_unique_username()
        signup_page.signup(username, "TestPass123!")
        time.sleep(0.5)

        alert_text = signup_page.get_alert_text(timeout=3)

        if alert_text and any(keyword in alert_text.lower() for keyword in ["limit", "wait", "too many"]):
            logging.info(f"✓ Rate limiting detected after {i + 1} attempts")
            rate_limited = True
            break

    if not rate_limited:
        logging.error("=" * 80)
        logging.error("NO BRUTE FORCE PROTECTION DETECTED")
        logging.error("Standard: OWASP ASVS v5.0 Section 2.2.1")
        logging.error("CWE-307: Improper Restriction of Excessive Authentication Attempts")
        logging.error("CVSS Score: 7.5 (HIGH)")
        logging.error(f"Completed {attempts} rapid signup attempts without restriction")
        logging.error("Impact: Automated account creation possible")
        logging.error("Recommendation: Implement rate limiting (e.g., 5 attempts per IP per hour)")
        logging.error("=" * 80)

        pytest.fail(f"DISCOVERED: No rate limiting after {attempts} signup attempts")

    assert True


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.enumeration
def test_account_enumeration_timing_SEC_006(browser, base_url):
    """
    TC-SIGNUP-SEC-006: Account Enumeration via Timing Attack

    Standard: OWASP ASVS v5.0 Section 2.2.2 (Account Enumeration)
    CWE: CWE-208 (Observable Timing Discrepancy)
    CVSS Score: 5.3 (MEDIUM)

    DISCOVER: Tests if response times reveal account existence.
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-SEC-006: Testing timing-based enumeration")

    signup_page = SignupPage(browser)

    browser.get(base_url)
    existing_user = signup_page.generate_unique_username()
    signup_page.signup(existing_user, "TestPass123!")
    time.sleep(1)
    first_alert = signup_page.get_alert_text(timeout=5)

    if not first_alert or "success" not in first_alert.lower():
        pytest.skip("Could not create test account")

    browser.get(base_url)
    start_time = time.time()
    signup_page.signup(existing_user, "AnotherPass456!")
    time.sleep(1)
    signup_page.get_alert_text(timeout=5)
    existing_duration = time.time() - start_time

    browser.get(base_url)
    nonexistent_user = signup_page.generate_unique_username()
    start_time = time.time()
    signup_page.signup(nonexistent_user, "")
    time.sleep(1)
    signup_page.get_alert_text(timeout=5)
    nonexistent_duration = time.time() - start_time

    time_diff = abs(existing_duration - nonexistent_duration)

    if time_diff > 0.5:
        logging.error("=" * 80)
        logging.error("TIMING DISCREPANCY DETECTED")
        logging.error(f"Existing account response time: {existing_duration:.2f}s")
        logging.error(f"Nonexistent account response time: {nonexistent_duration:.2f}s")
        logging.error(f"Difference: {time_diff:.2f}s")
        logging.error("CVSS Score: 5.3 (MEDIUM)")
        logging.error("Impact: Account enumeration via timing attack")
        logging.error("=" * 80)

        pytest.fail(f"DISCOVERED: Timing discrepancy of {time_diff:.2f}s enables enumeration")

    logging.info(f"✓ No significant timing discrepancy detected (diff: {time_diff:.2f}s)")
    assert True


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.enumeration
def test_username_enumeration_SEC_007(browser, base_url):
    """
    TC-SIGNUP-SEC-007: Username Enumeration via Error Messages

    Standard: OWASP ASVS v5.0 Section 2.2.2
    CWE: CWE-204 (Observable Response Discrepancy)
    CVSS Score: 5.3 (MEDIUM)

    DISCOVER: Tests if different error messages reveal username existence.
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-SEC-007: Testing username enumeration")

    signup_page = SignupPage(browser)

    browser.get(base_url)
    existing_user = signup_page.generate_unique_username()
    signup_page.signup(existing_user, "TestPass123!")
    time.sleep(1)
    signup_alert = signup_page.get_alert_text(timeout=5)

    if not signup_alert or "success" not in signup_alert.lower():
        pytest.skip("Could not create test account")

    browser.get(base_url)
    signup_page.signup(existing_user, "DifferentPass!")
    time.sleep(1)
    duplicate_alert = signup_page.get_alert_text(timeout=5)

    browser.get(base_url)
    nonexistent_user = signup_page.generate_unique_username()
    signup_page.signup(nonexistent_user, "")
    time.sleep(1)
    empty_alert = signup_page.get_alert_text(timeout=5)

    if duplicate_alert and empty_alert:
        if duplicate_alert.lower() != empty_alert.lower():
            if any(keyword in duplicate_alert.lower() for keyword in ["exist", "taken", "already"]):
                logging.error("=" * 80)
                logging.error("USERNAME ENUMERATION VULNERABILITY")
                logging.error(f"Duplicate user message: {duplicate_alert}")
                logging.error(f"Empty field message: {empty_alert}")
                logging.error("CVSS Score: 5.3 (MEDIUM)")
                logging.error("Impact: Attackers can enumerate valid usernames")
                logging.error("Recommendation: Use generic error messages")
                logging.error("=" * 80)

                pytest.fail("DISCOVERED: Username enumeration via different error messages")

    logging.info("✓ Generic error messages used - no enumeration possible")
    assert True



@pytest.mark.security
@pytest.mark.high
@pytest.mark.session
def test_session_fixation_SEC_008(browser, base_url):
    """
    TC-SIGNUP-SEC-008: Session Fixation

    Standard: OWASP ASVS v5.0 Section 3.2.1 (Session Generation)
    CWE: CWE-384 (Session Fixation)
    CVSS Score: 7.5 (HIGH)

    DISCOVER: Tests if session ID changes after signup.
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-SEC-008: Testing session fixation")

    signup_page = SignupPage(browser)

    browser.get(base_url)
    time.sleep(1)

    pre_signup_cookies = {cookie['name']: cookie['value'] for cookie in browser.get_cookies()}
    logging.info(f"Pre-signup cookies: {list(pre_signup_cookies.keys())}")

    test_user = signup_page.generate_unique_username()
    signup_page.signup(test_user, "TestPass123!")
    time.sleep(1)
    signup_alert = signup_page.get_alert_text(timeout=5)

    if signup_alert and "success" in signup_alert.lower():
        browser.get(base_url)
        time.sleep(1)

        signup_page.login_after_signup(test_user, "TestPass123!")
        time.sleep(2)
        signup_page.get_alert_text(timeout=3)

        if signup_page.is_user_logged_in(timeout=3):
            post_login_cookies = {cookie['name']: cookie['value'] for cookie in browser.get_cookies()}
            logging.info(f"Post-login cookies: {list(post_login_cookies.keys())}")

            session_changed = False
            for cookie_name in pre_signup_cookies:
                if cookie_name in post_login_cookies:
                    if pre_signup_cookies[cookie_name] != post_login_cookies[cookie_name]:
                        session_changed = True
                        logging.info(f"✓ Session cookie '{cookie_name}' changed after authentication")

            if not session_changed and pre_signup_cookies:
                logging.error("=" * 80)
                logging.error("SESSION FIXATION VULNERABILITY")
                logging.error("Session ID did not change after authentication")
                logging.error("Standard: OWASP ASVS v5.0 Section 3.2.1")
                logging.error("CWE-384: Session Fixation")
                logging.error("CVSS Score: 7.5 (HIGH)")
                logging.error("Impact: Attacker can hijack user session")
                logging.error("=" * 80)

                signup_page.logout()
                pytest.fail("DISCOVERED: Session fixation vulnerability")

            signup_page.logout()

    logging.info("✓ Session management appears secure")
    assert True


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.session
def test_cookie_security_flags_SEC_009(browser, base_url):
    """
    TC-SIGNUP-SEC-009: Cookie Security Flags

    Standard: OWASP ASVS v5.0 Section 3.4.2 (Cookie-based Session Management)
    CWE: CWE-614 (Sensitive Cookie Without 'Secure' Flag)
    CVSS Score: 6.5 (MEDIUM)

    DISCOVER: Tests if cookies have HttpOnly and Secure flags.
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-SEC-009: Testing cookie security flags")

    signup_page = SignupPage(browser)

    browser.get(base_url)
    time.sleep(1)

    test_user = signup_page.generate_unique_username()
    signup_page.signup(test_user, "TestPass123!")
    time.sleep(1)
    signup_alert = signup_page.get_alert_text(timeout=5)

    if signup_alert and "success" in signup_alert.lower():
        browser.get(base_url)
        time.sleep(1)

        signup_page.login_after_signup(test_user, "TestPass123!")
        time.sleep(2)
        signup_page.get_alert_text(timeout=3)

        if signup_page.is_user_logged_in(timeout=3):
            cookies = browser.get_cookies()

            insecure_cookies = []
            for cookie in cookies:
                cookie_name = cookie.get('name', 'unknown')
                is_secure = cookie.get('secure', False)
                is_httponly = cookie.get('httpOnly', False)

                if not is_secure or not is_httponly:
                    insecure_cookies.append({
                        'name': cookie_name,
                        'secure': is_secure,
                        'httponly': is_httponly
                    })

            if insecure_cookies:
                logging.error("=" * 80)
                logging.error("INSECURE COOKIE CONFIGURATION")
                for cookie in insecure_cookies:
                    logging.error(f"Cookie: {cookie['name']}")
                    logging.error(f"  Secure flag: {cookie['secure']}")
                    logging.error(f"  HttpOnly flag: {cookie['httponly']}")
                logging.error("CVSS Score: 6.5 (MEDIUM)")
                logging.error("Impact: Session hijacking via XSS or MITM attacks")
                logging.error("=" * 80)

                signup_page.logout()
                pytest.fail(f"DISCOVERED: {len(insecure_cookies)} cookies lack security flags")

            signup_page.logout()

    logging.info("✓ Cookie security flags properly configured")
    assert True



@pytest.mark.security
@pytest.mark.high
@pytest.mark.csrf
def test_csrf_token_validation_SEC_010(browser, base_url):
    """
    TC-SIGNUP-SEC-010: CSRF Token Validation

    Standard: OWASP ASVS v5.0 Section 4.2.2 (CSRF Prevention)
    CWE: CWE-352 (Cross-Site Request Forgery)
    CVSS Score: 6.5 (MEDIUM)

    DISCOVER: Tests if signup form is protected against CSRF attacks.
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-SEC-010: Testing CSRF protection")

    signup_page = SignupPage(browser)

    browser.get(base_url)
    time.sleep(1)

    signup_page.open_signup_modal()
    time.sleep(1)

    page_source = browser.page_source.lower()

    csrf_indicators = [
        'csrf',
        'xsrf',
        '_token',
        'authenticity_token',
        'anti-forgery'
    ]

    csrf_found = False
    for indicator in csrf_indicators:
        if indicator in page_source:
            csrf_found = True
            logging.info(f"✓ CSRF protection detected: {indicator}")
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



@pytest.mark.security
@pytest.mark.medium
@pytest.mark.headers
def test_security_headers_SEC_011(browser, base_url):
    """
    TC-SIGNUP-SEC-011: Security Headers

    Standard: OWASP ASVS v5.0 Section 14.4 (HTTP Security Headers)
    CWE: CWE-693 (Protection Mechanism Failure)
    CVSS Score: 7.5 (HIGH)

    DISCOVER: Tests if critical security headers are present.
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-SEC-011: Testing security headers")

    try:
        response = requests.get(base_url, timeout=10)
        headers = response.headers

        required_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'Strict-Transport-Security': 'max-age',
            'Content-Security-Policy': None,
            'X-XSS-Protection': '1'
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
                        misconfigured_headers.append(f"{header}: {actual_value}")
                elif expected_value not in actual_value:
                    misconfigured_headers.append(f"{header}: {actual_value}")

        if missing_headers or misconfigured_headers:
            logging.error("=" * 80)
            logging.error("SECURITY HEADERS MISSING OR MISCONFIGURED")
            if missing_headers:
                logging.error(f"Missing headers: {', '.join(missing_headers)}")
            if misconfigured_headers:
                logging.error(f"Misconfigured: {', '.join(misconfigured_headers)}")
            logging.error("CVSS Score: 7.5 (HIGH)")
            logging.error("Impact: Increased attack surface")
            logging.error("=" * 80)

            pytest.fail(f"DISCOVERED: {len(missing_headers)} headers missing, {len(misconfigured_headers)} misconfigured")

        logging.info("✓ All critical security headers present")
        assert True

    except requests.RequestException as e:
        logging.warning(f"Could not fetch headers: {e}")
        pytest.skip("Network request failed")



@pytest.mark.security
@pytest.mark.medium
@pytest.mark.crypto
def test_password_transmitted_plaintext_SEC_012(browser, base_url):
    """
    TC-SIGNUP-SEC-012: Password Transmission Security

    Standard: OWASP ASVS v5.0 Section 2.7.1 (Cryptography)
    CWE: CWE-319 (Cleartext Transmission of Sensitive Information)
    CVSS Score: 7.4 (HIGH)

    DISCOVER: Tests if connection uses HTTPS for password transmission.
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-SEC-012: Testing password transmission security")

    browser.get(base_url)

    current_url = browser.current_url

    if not current_url.startswith("https://"):
        logging.error("=" * 80)
        logging.error("INSECURE PASSWORD TRANSMISSION")
        logging.error(f"Current URL: {current_url}")
        logging.error("Protocol: HTTP (unencrypted)")
        logging.error("CWE-319: Cleartext Transmission of Sensitive Information")
        logging.error("CVSS Score: 7.4 (HIGH)")
        logging.error("Impact: Passwords transmitted in plaintext")
        logging.error("Recommendation: Enforce HTTPS for all pages")
        logging.error("=" * 80)

        pytest.fail("DISCOVERED: Application not using HTTPS")

    logging.info("✓ HTTPS properly enforced")
    assert True


@pytest.mark.security
@pytest.mark.low
@pytest.mark.info_disclosure
def test_verbose_error_messages_SEC_013(browser, base_url):
    """
    TC-SIGNUP-SEC-013: Verbose Error Messages

    Standard: OWASP ASVS v5.0 Section 7.4.1 (Error Handling)
    CWE: CWE-209 (Information Exposure Through Error Message)
    CVSS Score: 3.7 (LOW)

    DISCOVER: Tests if error messages reveal sensitive information.
    """
    logging.info("=" * 80)
    logging.info("TC-SIGNUP-SEC-013: Testing error message verbosity")

    signup_page = SignupPage(browser)

    browser.get(base_url)
    extreme_payload = "A" * 10000
    signup_page.signup(extreme_payload, "test")

    time.sleep(1)
    alert_text = signup_page.get_alert_text(timeout=5)

    if alert_text:
        sensitive_terms = [
            "stack trace",
            "exception",
            "database",
            "query",
            "file path",
            "server",
            "version"
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

    logging.info("✓ Error messages appear appropriately generic")
    assert True


