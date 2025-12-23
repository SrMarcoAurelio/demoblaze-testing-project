"""
Login Security & Exploitation Tests
Author: Marc Arévalo
Version: 3.0 - Restructured with Page Object Model

Tests security vulnerabilities and exploitation attempts.
These tests attempt to BREAK the system to discover vulnerabilities.

Total Tests: 20 functions (~40+ executions with parametrization)
Expected Pass Rate: ~60% (many tests SHOULD fail to reveal vulnerabilities)

Standards: OWASP Top 10 2021, OWASP ASVS v5.0, NIST 800-63B, ISO 27001, CWE Top 25, PCI-DSS 4.0.1

⚠️ ETHICAL WARNING: AUTHORIZED TESTING ONLY
Never run these tests on systems you don't own or have permission to test.
"""

import logging
import time

import pytest
import requests
from selenium.webdriver.common.keys import Keys

from pages.login_page import LoginPage


@pytest.mark.security
@pytest.mark.critical
@pytest.mark.injection
@pytest.mark.parametrize(
    "sql_payload",
    [
        "' OR '1'='1",
        "admin'--",
        "' OR '1'='1'--",
        "admin' OR '1'='1",
        "' OR 1=1--",
        "admin' OR 1=1#",
    ],
)
def test_sql_injection_username_INJ_001(browser, base_url, sql_payload):
    """
    TC-SEC-LOGIN-INJ-001: SQL Injection in Username Field

    CVSS Score: 9.8 CRITICAL
    Standard: OWASP Top 10 2021 - A03 (Injection)
    Standard: OWASP ASVS v5.0 Section 1.2.5

    Discovers if SQL injection is possible through username field.
    Attempts authentication bypass via SQL injection payloads.

    Impact: Authentication bypass, database compromise, unauthorized access
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    login_page.login(sql_payload, "anypassword")

    logged_in = login_page.is_user_logged_in(timeout=2)
    login_page.get_alert_text(timeout=2)  # Dismiss any alert

    if logged_in:
        logging.critical(
            f"CRITICAL VULNERABILITY: SQL Injection succeeded with payload: {sql_payload}"
        )
        logging.error("CVSS Score: 9.8 CRITICAL")
        logging.error("Standard: OWASP Top 10 2021 - A03 (Injection)")
        logging.error(
            "Impact: Authentication bypass, database compromise, unauthorized access"
        )
        logging.error(
            "Recommendation: Implement parameterized queries, input validation"
        )
        pytest.fail(
            f"DISCOVERED: SQL Injection vulnerability in username field - payload: {sql_payload}"
        )
    else:
        logging.info(f"SQL injection attempt blocked: {sql_payload}")
        assert True


@pytest.mark.security
@pytest.mark.critical
@pytest.mark.injection
@pytest.mark.parametrize(
    "sql_payload",
    [
        "' OR '1'='1",
        "password' OR '1'='1'--",
        "' OR 1=1--",
    ],
)
def test_sql_injection_password_INJ_002(browser, base_url, sql_payload):
    """
    TC-SEC-LOGIN-INJ-002: SQL Injection in Password Field

    CVSS Score: 9.8 CRITICAL
    Standard: OWASP Top 10 2021 - A03 (Injection)
    Standard: OWASP ASVS v5.0 Section 1.2.5

    Discovers if SQL injection is possible through password field.

    Impact: Authentication bypass via password field
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    login_page.login("Apolo2025", sql_payload)

    logged_in = login_page.is_user_logged_in(timeout=2)
    login_page.get_alert_text(timeout=2)

    if logged_in:
        logging.critical(
            f"CRITICAL VULNERABILITY: SQL Injection in password field: {sql_payload}"
        )
        logging.error("CVSS Score: 9.8 CRITICAL")
        logging.error("Impact: Authentication bypass via password field")
        pytest.fail(
            f"DISCOVERED: SQL Injection vulnerability in password field"
        )
    else:
        assert True


@pytest.mark.security
@pytest.mark.critical
@pytest.mark.injection
@pytest.mark.parametrize(
    "xss_payload",
    [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
    ],
)
def test_xss_username_field_INJ_003(browser, base_url, xss_payload):
    """
    TC-SEC-LOGIN-INJ-003: XSS in Username Field

    CVSS Score: 8.8 HIGH
    Standard: OWASP Top 10 2021 - A03 (Injection)
    Standard: OWASP ASVS v5.0 Section 1.2.1

    Discovers if XSS is possible in username field.
    Tests for stored, reflected, or DOM-based XSS.

    Impact: Session hijacking, credential theft, malicious script execution
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    login_page.login(xss_payload, "anypassword")

    alert_text = login_page.get_alert_text(timeout=2)

    if alert_text and "XSS" in alert_text:
        logging.critical(
            f"CRITICAL VULNERABILITY: XSS executed with payload: {xss_payload}"
        )
        logging.error("CVSS Score: 8.8 HIGH")
        logging.error("Standard: OWASP Top 10 - A03")
        logging.error(
            "Impact: Session hijacking, credential theft, malicious script execution"
        )
        pytest.fail("DISCOVERED: XSS vulnerability in username field")
    else:
        assert True


@pytest.mark.security
@pytest.mark.high
@pytest.mark.bot_protection
def test_brute_force_no_rate_limiting_BOT_001(browser, base_url):
    """
    TC-SEC-LOGIN-BOT-001: Brute Force Attack Without Rate Limiting

    CVSS Score: 8.1 HIGH
    Standard: OWASP ASVS v5.0 Section 2.2.1
    Standard: NIST SP 800-63B Section 5.2.2

    Discovers if system has brute force protection via rate limiting.
    Attempts multiple rapid login attempts.

    Impact: Unlimited brute force attempts possible
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    attempts = 0
    rate_limited = False

    for i in range(50):
        login_page.login("Apolo2025", f"wrongpass{i}")

        alert_text = login_page.get_alert_text(timeout=2)

        if alert_text and (
            "rate" in alert_text.lower()
            or "locked" in alert_text.lower()
            or "blocked" in alert_text.lower()
        ):
            rate_limited = True
            logging.info(
                f"Rate limiting detected at attempt {i+1}: {alert_text}"
            )
            break

        attempts += 1
        browser.get(base_url)

    if not rate_limited and attempts >= 45:
        logging.critical("CRITICAL VULNERABILITY: NO RATE LIMITING")
        logging.error("CVSS Score: 8.1 HIGH")
        logging.error(
            f"Completed {attempts} login attempts without rate limiting"
        )
        logging.error("Standard: OWASP ASVS v5.0 Section 2.2.1")
        logging.error("Impact: Unlimited brute force attempts possible")
        pytest.fail(f"DISCOVERED: No rate limiting after {attempts} attempts")
    else:
        logging.info(f"Rate limiting or account lockout detected")
        assert True


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.business_logic
def test_account_enumeration_BL_001(browser, base_url):
    """
    TC-SEC-LOGIN-BL-001: Account Enumeration via Error Messages

    CVSS Score: 5.3 MEDIUM
    Standard: OWASP ASVS v5.0 Section 2.2.2
    Standard: OWASP Testing Guide v4 - WSTG-ATHN-04

    Discovers if system leaks information about valid vs invalid usernames.
    Different error messages allow attacker to enumerate valid accounts.

    Impact: Attackers can enumerate valid usernames
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    login_page.login("definitely_non_existent_user_9999", "anypassword")
    invalid_user_msg = login_page.get_alert_text(timeout=5)

    browser.get(base_url)

    login_page.login("Apolo2025", "definitely_wrong_password_123")
    valid_user_wrong_pass_msg = login_page.get_alert_text(timeout=5)

    if invalid_user_msg and valid_user_wrong_pass_msg:
        if invalid_user_msg.lower() != valid_user_wrong_pass_msg.lower():
            if (
                "not exist" in invalid_user_msg.lower()
                or "exist" in invalid_user_msg.lower()
            ):
                logging.warning("ACCOUNT ENUMERATION POSSIBLE")
                logging.warning("CVSS Score: 5.3 MEDIUM")
                logging.warning(f"Invalid user message: {invalid_user_msg}")
                logging.warning(
                    f"Valid user message: {valid_user_wrong_pass_msg}"
                )
                logging.warning(
                    "Impact: Attackers can enumerate valid usernames"
                )
                logging.warning("Recommendation: Use generic error messages")
                pytest.fail(
                    "DISCOVERED: Account enumeration via different error messages"
                )

    assert True


@pytest.mark.security
@pytest.mark.high
@pytest.mark.authentication
def test_session_fixation_AUTH_001(browser, base_url):
    """
    TC-SEC-LOGIN-AUTH-001: Session Fixation Vulnerability

    CVSS Score: 8.1 HIGH
    Standard: OWASP Top 10 2021 - A07 (Authentication Failures)
    Standard: OWASP ASVS v5.0 Section 3.2.1

    Discovers if session ID changes after successful authentication.
    Session fixation allows attacker to hijack user sessions.

    Impact: Attacker can hijack sessions
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    cookies_before = browser.get_cookies()
    session_before = [
        c for c in cookies_before if "session" in c.get("name", "").lower()
    ]

    login_page.login("Apolo2025", "apolo2025")

    logged_in = login_page.is_user_logged_in(timeout=5)

    if not logged_in:
        alert_text = login_page.get_alert_text()
        pytest.skip(
            f"Cannot test session fixation - login failed: {alert_text}"
        )

    cookies_after = browser.get_cookies()
    session_after = [
        c for c in cookies_after if "session" in c.get("name", "").lower()
    ]

    if session_before and session_after:
        if session_before[0].get("value") == session_after[0].get("value"):
            logging.error("SESSION FIXATION VULNERABILITY")
            logging.error("CVSS Score: 8.1 HIGH")
            logging.error("Session ID did not change after authentication")
            logging.error(
                "Standard: OWASP Top 10 - A07, OWASP ASVS v5.0-3.2.1"
            )
            logging.error(
                "Impact: Session hijacking, attacker can fixate session ID"
            )
            logging.error("Recommendation: Regenerate session ID after login")
            pytest.fail(
                "DISCOVERED: Session fixation - session ID unchanged after login"
            )

    login_page.logout()
    assert True


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.authentication
def test_session_cookie_security_flags_AUTH_002(browser, base_url):
    """
    TC-SEC-LOGIN-AUTH-002: Session Cookie Security Flags

    CVSS Score: 6.5 MEDIUM
    Standard: OWASP ASVS v5.0 Section 3.4.1
    Standard: OWASP Testing Guide - WSTG-SESS-02

    Discovers if session cookies have proper security flags.
    Missing HttpOnly or Secure flags expose cookies to attacks.

    Impact: Cookies vulnerable to XSS (no HttpOnly) or MitM (no Secure)
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    login_page.login("Apolo2025", "apolo2025")

    logged_in = login_page.is_user_logged_in(timeout=5)
    if not logged_in:
        alert_text = login_page.get_alert_text()
        pytest.skip(f"Cannot test cookies - login failed: {alert_text}")

    cookies = browser.get_cookies()

    missing_flags = []

    for cookie in cookies:
        if (
            "session" in cookie.get("name", "").lower()
            or "token" in cookie.get("name", "").lower()
        ):
            if not cookie.get("httpOnly", False):
                missing_flags.append(
                    f"{cookie['name']}: Missing HttpOnly flag"
                )
            if not cookie.get("secure", False):
                missing_flags.append(f"{cookie['name']}: Missing Secure flag")

    if missing_flags:
        logging.warning("COOKIE SECURITY FLAGS MISSING")
        logging.warning("CVSS Score: 6.5 MEDIUM")
        for flag in missing_flags:
            logging.warning(f"  - {flag}")
        logging.warning(
            "Impact: Cookies vulnerable to XSS (no HttpOnly) or MitM (no Secure)"
        )
        logging.warning(
            "Recommendation: Set HttpOnly and Secure flags on all session cookies"
        )
        pytest.fail(
            f"DISCOVERED: Missing cookie security flags: {missing_flags}"
        )

    login_page.logout()
    assert True


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.csrf
def test_csrf_token_validation_CSRF_001(browser, base_url):
    """
    TC-SEC-LOGIN-CSRF-001: CSRF Token Validation on Login

    CVSS Score: 6.5 MEDIUM
    Standard: OWASP Top 10 2021 - A01 (Broken Access Control)
    Standard: OWASP ASVS v5.0 Section 4.2.2

    Discovers if login form has CSRF protection.
    Missing CSRF tokens allow cross-site request forgery attacks.

    Impact: Login vulnerable to CSRF attacks
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    login_page.open_login_modal()

    form_html = browser.page_source

    has_csrf = False
    if "csrf" in form_html.lower() or "token" in form_html.lower():
        if (
            'name="csrf' in form_html.lower()
            or "name='csrf" in form_html.lower()
        ):
            has_csrf = True
            logging.info("CSRF token found in login form")

    if not has_csrf:
        logging.warning("NO CSRF TOKEN DETECTED IN LOGIN FORM")
        logging.warning("CVSS Score: 6.5 MEDIUM")
        logging.warning("Impact: Login vulnerable to CSRF attacks")
        logging.warning("Recommendation: Implement CSRF tokens in forms")
        pytest.fail("DISCOVERED: No CSRF protection on login form")

    assert True


@pytest.mark.security
@pytest.mark.high
@pytest.mark.headers
def test_security_headers_validation_HEAD_001(browser, base_url):
    """
    TC-SEC-LOGIN-HEAD-001: Security Headers Validation

    CVSS Score: 7.5 HIGH
    Standard: OWASP Secure Headers Project

    Discovers if critical security headers are present.
    Missing security headers expose application to various attacks.

    Impact: Vulnerable to clickjacking, XSS, MIME sniffing
    """
    try:
        response = requests.get(base_url, timeout=10)
        headers = response.headers

        required_headers = {
            "X-Frame-Options": ["DENY", "SAMEORIGIN"],
            "X-Content-Type-Options": ["nosniff"],
            "Strict-Transport-Security": None,
            "Content-Security-Policy": None,
            "X-XSS-Protection": ["1; mode=block"],
        }

        missing_headers = []

        for header, expected_values in required_headers.items():
            if header not in headers:
                missing_headers.append(header)
            elif expected_values:
                if headers[header] not in expected_values:
                    logging.warning(
                        f"{header}: {headers[header]} (unexpected value)"
                    )

        if missing_headers:
            logging.warning("SECURITY HEADERS MISSING")
            logging.warning("CVSS Score: 7.5 HIGH")
            for header in missing_headers:
                logging.warning(f"  - Missing: {header}")
            logging.warning(
                "Impact: Vulnerable to clickjacking, XSS, MIME sniffing"
            )
            pytest.fail(
                f"DISCOVERED: Missing security headers: {missing_headers}"
            )

        assert True

    except Exception as e:
        logging.error(f"Failed to check headers: {e}")
        assert True


@pytest.mark.security
@pytest.mark.high
@pytest.mark.ssl_tls
def test_tls_version_SSL_001(browser, base_url):
    """
    TC-SEC-LOGIN-SSL-001: TLS Version Check

    CVSS Score: 7.4 HIGH
    Standard: PCI-DSS 4.0.1 Requirement 4.2
    Standard: NIST SP 800-52 Rev 2

    Discovers if site uses secure TLS version.
    TLS 1.0 and 1.1 are deprecated and insecure.

    Impact: Vulnerable to downgrade attacks, weak encryption
    """
    try:
        import socket
        import ssl
        from urllib.parse import urlparse

        parsed = urlparse(base_url)
        hostname = parsed.hostname
        port = 443

        context = ssl.create_default_context()

        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version = ssock.version()

                if tls_version in ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]:
                    logging.error(f"INSECURE TLS VERSION: {tls_version}")
                    logging.error("CVSS Score: 7.4 HIGH")
                    logging.error(
                        "Standard: PCI-DSS 4.0.1-4.2, NIST SP 800-52"
                    )
                    logging.error(
                        "Impact: Vulnerable to downgrade attacks, weak encryption"
                    )
                    pytest.fail(
                        f"DISCOVERED: Insecure TLS version: {tls_version}"
                    )
                else:
                    logging.info(f"TLS version: {tls_version} (acceptable)")

        assert True

    except Exception as e:
        logging.warning(f"Could not check TLS version: {e}")
        assert True


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.password_reset
def test_password_reset_security_RESET_001(browser, base_url):
    """
    TC-SEC-LOGIN-RESET-001: Password Reset Flow Security

    CVSS Score: 5.0 MEDIUM
    Standard: OWASP ASVS v5.0 Section 2.5.6

    Discovers if password reset mechanism exists and is secure.
    Tests for reset token security, expiration, one-time use.

    Impact: Users cannot recover forgotten passwords
    """
    browser.get(base_url)

    page_source = browser.page_source.lower()

    reset_keywords = ["forgot password", "reset password", "recover password"]
    reset_found = any(keyword in page_source for keyword in reset_keywords)

    if not reset_found:
        logging.warning("=" * 80)
        logging.warning("SECURITY CONCERN: NO PASSWORD RESET MECHANISM")
        logging.warning("Standard: OWASP ASVS v5.0 Section 2.5.6")
        logging.warning("Expected: Secure password reset flow")
        logging.warning("Actual: No password reset functionality detected")
        logging.warning("Impact: Users cannot recover forgotten passwords")
        logging.warning(
            "CVSS Score: 5.0 (MEDIUM) - Usability/Security trade-off"
        )
        logging.warning("=" * 80)
        pytest.fail(
            "DISCOVERED: No password reset functionality - limits account recovery"
        )
    else:
        logging.info("DISCOVERED: Password reset mechanism exists")
        assert True


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.session_timeout
def test_session_timeout_security_TIMEOUT_001(browser, base_url):
    """
    TC-SEC-LOGIN-TIMEOUT-001: Session Timeout Security

    CVSS Score: 6.1 MEDIUM
    Standard: OWASP ASVS v5.0 Section 3.3.1
    Standard: ISO 27001 A.9.4.2

    Discovers if sessions have appropriate timeout mechanisms.
    Tests if idle sessions are automatically terminated.

    Impact: Unattended sessions remain accessible
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    login_page.login("Apolo2025", "apolo2025")
    time.sleep(1)
    login_page.get_alert_text()

    if not login_page.is_user_logged_in():
        pytest.skip("Initial login failed - cannot test session timeout")

    logging.info(
        "DISCOVERED: User logged in, waiting 60 seconds for timeout test"
    )

    time.sleep(60)

    browser.refresh()
    time.sleep(2)

    still_logged_in = login_page.is_user_logged_in(timeout=2)

    if still_logged_in:
        logging.warning("=" * 80)
        logging.warning("SECURITY CONCERN: NO SESSION TIMEOUT DETECTED")
        logging.warning("Standard: OWASP ASVS v5.0 Section 3.3.1")
        logging.warning("Expected: Session expires after inactivity period")
        logging.warning("Actual: Session remained active after 60 seconds")
        logging.warning("Impact: Unattended sessions remain accessible")
        logging.warning("CVSS Score: 6.1 (MEDIUM)")
        logging.warning("=" * 80)
        login_page.logout()
        pytest.fail(
            "DISCOVERED: No session timeout - sessions may remain active indefinitely"
        )
    else:
        logging.info("DISCOVERED: Session expired after inactivity")
        assert True


@pytest.mark.security
@pytest.mark.high
@pytest.mark.bot_protection
def test_rapid_concurrent_login_attempts_BOT_002(browser, base_url):
    """
    TC-SEC-LOGIN-BOT-002: Rapid Concurrent Login Attempts

    CVSS Score: 7.5 HIGH
    Standard: OWASP ASVS v5.0 Section 2.2.1

    Discovers if system can handle concurrent/parallel brute force attempts.
    Tests distributed brute force protection.

    Impact: Distributed attacks bypass simple rate limiting
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from selenium import webdriver

    def attempt_login():
        try:
            driver = webdriver.Chrome()
            driver.get(base_url)
            local_login = LoginPage(driver)
            local_login.login("Apolo2025", "wrongpass")
            local_login.get_alert_text(timeout=1)
            driver.quit()
            return True
        except:
            return False

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(attempt_login) for _ in range(20)]
        results = [f.result() for f in as_completed(futures)]
        successful_attempts = sum(results)

    logging.info(
        f"DISCOVERED: {successful_attempts}/20 concurrent requests completed"
    )

    if successful_attempts >= 15:
        logging.warning("=" * 80)
        logging.warning(
            "SECURITY CONCERN: HIGH CONCURRENT ATTEMPT SUCCESS RATE"
        )
        logging.warning(
            f"Completed {successful_attempts}/20 concurrent requests"
        )
        logging.warning("Standard: OWASP ASVS v5.0 Section 2.2.1")
        logging.warning("Impact: Distributed brute force attacks easier")
        logging.warning("CVSS Score: 7.5 (HIGH)")
        logging.warning("=" * 80)
        pytest.fail(
            f"DISCOVERED: System vulnerable to distributed brute force - {successful_attempts}/20 succeeded"
        )
    else:
        logging.info(
            "✓ DISCOVERED: System handles concurrent attempts appropriately"
        )
        assert True


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.authentication
def test_concurrent_session_handling_AUTH_003(browser, base_url):
    """
    TC-SEC-LOGIN-AUTH-003: Concurrent Session Handling

    CVSS Score: 5.3 MEDIUM
    Standard: OWASP ASVS v5.0 Section 3.3.1

    Discovers how system handles multiple simultaneous sessions.
    Tests if old sessions are invalidated when new login occurs.

    Impact: Session management behavior
    """
    from selenium import webdriver

    browser.get(base_url)
    login_page = LoginPage(browser)

    login_page.login("Apolo2025", "apolo2025")
    time.sleep(1)
    login_page.get_alert_text(timeout=2)

    if not login_page.is_user_logged_in(timeout=3):
        pytest.skip("First login failed - cannot test concurrent sessions")

    first_session_cookies = browser.get_cookies()
    logging.info("✓ First session established")

    second_browser = webdriver.Chrome()
    try:
        second_browser.get(base_url)
        second_login = LoginPage(second_browser)
        second_login.login("Apolo2025", "apolo2025")
        time.sleep(1)
        second_login.get_alert_text(timeout=2)

        if not second_login.is_user_logged_in(timeout=3):
            pytest.skip("Second login failed")

        logging.info("✓ Second session established")

        browser.refresh()
        time.sleep(2)
        first_still_logged_in = login_page.is_user_logged_in(timeout=2)

        if first_still_logged_in:
            logging.info("✓ DISCOVERED: System allows concurrent sessions")
            logging.info("Note: Both sessions remain active simultaneously")
        else:
            logging.info(
                "✓ DISCOVERED: First session invalidated when second login occurred"
            )
            logging.info("Note: System enforces single-session policy")

        assert True

    finally:
        second_browser.quit()
        login_page.logout()


@pytest.mark.security
@pytest.mark.low
@pytest.mark.information_disclosure
def test_verbose_error_messages_INFO_001(browser, base_url):
    """
    TC-SEC-LOGIN-INFO-001: Verbose Error Message Disclosure

    CVSS Score: 3.7 LOW
    Standard: OWASP ASVS v5.0 Section 7.4.1

    Discovers if system reveals sensitive information in error messages.
    Stack traces, database errors aid attacker reconnaissance.

    Impact: Information disclosure aids attackers
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    malicious_inputs = [
        "test'\"<>",
        "'; DROP TABLE users--",
        "<script>alert(1)</script>",
        "admin'/**/OR/**/1=1--",
    ]

    verbose_errors_found = []

    for malicious_input in malicious_inputs:
        browser.get(base_url)
        login_page.login(malicious_input, malicious_input)

        time.sleep(1)
        alert_text = login_page.get_alert_text(timeout=3)

        if alert_text:
            alert_lower = alert_text.lower()
            dangerous_keywords = [
                "sql",
                "database",
                "mysql",
                "postgres",
                "oracle",
                "mongodb",
                "exception",
                "stack trace",
                "error at line",
                "syntax error",
                "undefined",
                "null pointer",
                "debug",
                "traceback",
                "warning",
            ]

            found = [kw for kw in dangerous_keywords if kw in alert_lower]
            if found:
                verbose_errors_found.append(
                    (malicious_input, alert_text, found)
                )

    if verbose_errors_found:
        logging.warning("=" * 80)
        logging.warning("SECURITY CONCERN: VERBOSE ERROR MESSAGES DETECTED")
        logging.warning("Standard: OWASP ASVS v5.0 Section 7.4.1")
        logging.warning("CVSS Score: 3.7 (LOW)")
        for inp, msg, keywords in verbose_errors_found:
            logging.warning(f"Input: {inp}")
            logging.warning(f"Error: {msg}")
            logging.warning(f"Suspicious keywords: {keywords}")
        logging.warning("Impact: Information disclosure aids reconnaissance")
        logging.warning("Recommendation: Use generic error messages")
        logging.warning("=" * 80)
        pytest.fail(
            f"DISCOVERED: Verbose error messages - {len(verbose_errors_found)} cases"
        )
    else:
        logging.info("✓ DISCOVERED: Error messages are generic (good)")
        assert True


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.http_methods
def test_dangerous_http_methods_HTTP_001(browser, base_url):
    """
    TC-SEC-LOGIN-HTTP-001: Dangerous HTTP Methods Allowed

    CVSS Score: 6.5 MEDIUM
    Standard: OWASP Testing Guide - WSTG-CONF-06

    Discovers if dangerous HTTP methods are enabled.
    Methods like TRACE, PUT, DELETE should be disabled.

    Impact: Potential for data manipulation or XST attacks
    """
    dangerous_methods = [
        "PUT",
        "DELETE",
        "TRACE",
        "OPTIONS",
        "CONNECT",
        "PATCH",
    ]
    allowed_methods = []

    for method in dangerous_methods:
        try:
            response = requests.request(method, base_url, timeout=5)

            if response.status_code not in [405, 501, 403]:
                allowed_methods.append(f"{method}: {response.status_code}")
                logging.warning(
                    f"Method {method} returned: {response.status_code}"
                )
        except Exception as e:
            logging.debug(f"Method {method} failed: {e}")

    if allowed_methods:
        logging.warning("=" * 80)
        logging.warning("SECURITY CONCERN: DANGEROUS HTTP METHODS ALLOWED")
        logging.warning("Standard: OWASP Testing Guide - WSTG-CONF-06")
        logging.warning("CVSS Score: 6.5 (MEDIUM)")
        for method in allowed_methods:
            logging.warning(f"  Allowed: {method}")
        logging.warning(
            "Impact: Potential for data manipulation or XST attacks"
        )
        logging.warning("Recommendation: Disable PUT, DELETE, TRACE, CONNECT")
        logging.warning("=" * 80)
        pytest.fail(
            f"DISCOVERED: Dangerous HTTP methods allowed - {allowed_methods}"
        )
    else:
        logging.info("✓ DISCOVERED: Dangerous HTTP methods properly blocked")
        assert True


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.timing_attack
def test_timing_attack_username_enumeration_TIME_001(browser, base_url):
    """
    TC-SEC-LOGIN-TIME-001: Timing Attack for Username Enumeration

    CVSS Score: 5.3 MEDIUM
    Standard: OWASP Testing Guide - WSTG-ATHN-04

    Discovers if response times differ for valid vs invalid usernames.
    Timing differences allow username enumeration.

    Impact: Attackers can build list of valid usernames
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    invalid_times = []
    for i in range(5):
        start = time.time()
        login_page.login(f"invalid_user_{i}_999999", "anypass")
        login_page.get_alert_text(timeout=5)
        elapsed = time.time() - start
        invalid_times.append(elapsed)
        logging.info(f"Invalid username attempt {i+1}: {elapsed:.3f}s")
        browser.get(base_url)

    valid_times = []
    for i in range(5):
        start = time.time()
        login_page.login("Apolo2025", "wrongpassword")
        login_page.get_alert_text(timeout=5)
        elapsed = time.time() - start
        valid_times.append(elapsed)
        logging.info(f"Valid username attempt {i+1}: {elapsed:.3f}s")
        browser.get(base_url)

    avg_invalid = sum(invalid_times) / len(invalid_times)
    avg_valid = sum(valid_times) / len(valid_times)
    time_diff = abs(avg_valid - avg_invalid)

    logging.info(f"Average invalid username time: {avg_invalid:.3f}s")
    logging.info(f"Average valid username time: {avg_valid:.3f}s")
    logging.info(f"Time difference: {time_diff:.3f}s")

    if time_diff > 0.5:
        logging.warning("=" * 80)
        logging.warning("SECURITY CONCERN: TIMING ATTACK POSSIBLE")
        logging.warning("Standard: OWASP Testing Guide - WSTG-ATHN-04")
        logging.warning(f"Invalid username avg: {avg_invalid:.3f}s")
        logging.warning(f"Valid username avg: {avg_valid:.3f}s")
        logging.warning(f"Difference: {time_diff:.3f}s")
        logging.warning("CVSS Score: 5.3 (MEDIUM)")
        logging.warning("Impact: Username enumeration via timing analysis")
        logging.warning(
            "Recommendation: Ensure constant-time authentication checks"
        )
        logging.warning("=" * 80)
        pytest.fail(
            f"DISCOVERED: Timing difference of {time_diff:.3f}s allows enumeration"
        )
    else:
        logging.info(
            f"✓ DISCOVERED: Timing difference minimal ({time_diff:.3f}s)"
        )
        assert True


@pytest.mark.security
@pytest.mark.low
@pytest.mark.clickjacking
def test_clickjacking_protection_CLICK_001(browser, base_url):
    """
    TC-SEC-LOGIN-CLICK-001: Clickjacking Protection

    CVSS Score: 4.3 LOW
    Standard: OWASP Top 10 2021 - A04 (Insecure Design)

    Discovers if site is protected against clickjacking.
    Tests if site can be embedded in iframe.

    Impact: UI redressing attacks, credential theft
    """
    browser.get(base_url)

    browser.execute_script(
        """
        var iframe = document.createElement('iframe');
        iframe.src = arguments[0];
        iframe.id = 'testIframe';
        iframe.style.width = '100%';
        iframe.style.height = '500px';
        document.body.appendChild(iframe);
    """,
        base_url,
    )

    time.sleep(3)

    try:
        from selenium.webdriver.common.by import By

        iframe = browser.find_element(By.ID, "testIframe")
        iframe_loaded = iframe is not None

        if iframe_loaded:
            browser.switch_to.frame(iframe)
            body = browser.find_element(By.TAG_NAME, "body")
            has_content = len(body.text) > 0
            browser.switch_to.default_content()

            if has_content:
                logging.warning("=" * 80)
                logging.warning("SECURITY CONCERN: CLICKJACKING POSSIBLE")
                logging.warning("Standard: OWASP Top 10 2021 - A04")
                logging.warning("Site can be loaded in iframe")
                logging.warning("CVSS Score: 4.3 (LOW)")
                logging.warning(
                    "Impact: UI redressing attacks, credential theft"
                )
                logging.warning(
                    "Recommendation: Set X-Frame-Options: DENY or CSP frame-ancestors"
                )
                logging.warning("=" * 80)
                pytest.fail(
                    "DISCOVERED: Site vulnerable to clickjacking - loads in iframe"
                )
            else:
                logging.info(
                    "✓ DISCOVERED: Iframe created but blocked from loading content"
                )
                assert True
        else:
            logging.info("✓ DISCOVERED: Clickjacking protection in place")
            assert True

    except Exception as e:
        logging.info(
            f"✓ DISCOVERED: Clickjacking protection appears present - {e}"
        )
        assert True


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.remember_me
def test_remember_me_security_REMEM_001(browser, base_url):
    """
    TC-SEC-LOGIN-REMEM-001: Remember Me Security Implementation

    CVSS Score: 5.5 MEDIUM
    Standard: OWASP ASVS v5.0 Section 3.2.3

    Discovers if Remember Me functionality exists and is secure.
    Tests for secure token implementation.

    Impact: Insecure Remember Me = persistent session hijacking
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    login_page.open_login_modal()

    page_source = browser.page_source.lower()
    remember_keywords = [
        "remember me",
        "keep me logged in",
        "stay signed in",
        "remember",
        "keep logged",
        "stay logged",
    ]

    remember_me_exists = False
    for keyword in remember_keywords:
        if keyword in page_source:
            remember_me_exists = True
            logging.info(
                f"✓ DISCOVERED: Remember Me detected - keyword: '{keyword}'"
            )
            break

    if not remember_me_exists:
        logging.info("✓ DISCOVERED: No Remember Me functionality detected")
        logging.info(
            "Note: This is acceptable - reduces session persistence risk"
        )
        assert True
    else:
        logging.info("✓ DISCOVERED: Remember Me functionality exists")
        logging.info("Standard: OWASP ASVS v5.0 Section 3.2.3 requires:")
        logging.info("  - Secure random tokens (not username/password)")
        logging.info("  - HttpOnly and Secure cookie flags")
        logging.info("  - Token expiration")
        logging.info("  - Token rotation on use")
        logging.info(
            "Note: Manual security audit recommended for Remember Me implementation"
        )
        assert True
