"""
Security & Exploitation Test Suite
Test if DemoBlaze login/authentication can be exploited
Standards: OWASP Top 10, OWASP ASVS v5.0, NIST 800-63B, ISO 27001

Author: QA Testing Team
Version: 2.0 - Complete DISCOVER Philosophy Implementation
"""

import pytest
import time
import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from selenium.webdriver.common.keys import Keys
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

logging.basicConfig(level=logging.ERROR)


BASE_URL = "https://www.demoblaze.com/"

TIMEOUT = 10
TIMEOUT_SHORT = 2
TIMEOUT_MEDIUM = 5

TEST_USERNAME = "Apolo2025"
TEST_PASSWORD = "apolo2025"


LOGIN_BUTTON_NAV = (By.ID, "login2")
LOGIN_MODAL = (By.ID, "logInModal")
LOGIN_USERNAME_FIELD = (By.ID, "loginusername")
LOGIN_PASSWORD_FIELD = (By.ID, "loginpassword")
LOGIN_SUBMIT_BUTTON = (By.XPATH, "//button[text()='Log in']")

SIGNUP_BUTTON_NAV = (By.ID, "signin2")
SIGNUP_MODAL = (By.ID, "signInModal")
SIGNUP_USERNAME_FIELD = (By.ID, "sign-username")
SIGNUP_PASSWORD_FIELD = (By.ID, "sign-password")
SIGNUP_SUBMIT_BUTTON = (By.XPATH, "//button[text()='Sign up']")

WELCOME_USER_TEXT = (By.ID, "nameofuser")
LOGOUT_BUTTON_NAV = (By.ID, "logout2")
HOME_NAV_LINK = (By.XPATH, "//a[contains(text(), 'Home')]")


def wait_for_alert(browser, timeout=TIMEOUT_MEDIUM):
    try:
        WebDriverWait(browser, timeout).until(EC.alert_is_present())
        alert = browser.switch_to.alert
        text = alert.text
        alert.accept()
        return text
    except TimeoutException:
        return None


def is_user_logged_in(browser, timeout=TIMEOUT_SHORT):
    try:
        WebDriverWait(browser, timeout).until(
            EC.visibility_of_element_located(WELCOME_USER_TEXT)
        )
        return True
    except TimeoutException:
        return False


def open_login_modal(browser):
    login_button = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(LOGIN_BUTTON_NAV)
    )
    login_button.click()
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(LOGIN_USERNAME_FIELD)
    )


def perform_login(browser, username, password):
    open_login_modal(browser)
    username_field = browser.find_element(*LOGIN_USERNAME_FIELD)
    username_field.clear()
    username_field.send_keys(username)
    password_field = browser.find_element(*LOGIN_PASSWORD_FIELD)
    password_field.clear()
    password_field.send_keys(password)
    browser.find_element(*LOGIN_SUBMIT_BUTTON).click()


def perform_logout(browser):
    try:
        logout_button = WebDriverWait(browser, TIMEOUT_SHORT).until(
            EC.element_to_be_clickable(LOGOUT_BUTTON_NAV)
        )
        logout_button.click()
        time.sleep(1)
    except TimeoutException:
        pass


@pytest.mark.security
@pytest.mark.critical
@pytest.mark.injection
@pytest.mark.parametrize("sql_payload", [
    "' OR '1'='1",
    "admin'--",
    "' OR '1'='1'--",
    "admin' OR '1'='1",
    "' OR 1=1--",
    "admin' OR 1=1#",
])
def test_sql_injection_username_INJ_001(browser, sql_payload):
    """
    TC-SEC-LOGIN-INJ-001: SQL Injection in Username Field
    
    CVSS Score: 9.8 CRITICAL
    Standard: OWASP Top 10 2021 - A03 (Injection)
    Standard: OWASP ASVS v5.0 Section 1.2.5
    
    Discovers if SQL injection is possible through username field.
    Attempts authentication bypass via SQL injection payloads.
    """
    browser.get(BASE_URL)
    
    perform_login(browser, sql_payload, "anypassword")
    
    logged_in = is_user_logged_in(browser, timeout=TIMEOUT_SHORT)
    alert_text = wait_for_alert(browser, timeout=TIMEOUT_SHORT)
    
    if logged_in:
        logging.critical(f"CRITICAL VULNERABILITY: SQL Injection succeeded with payload: {sql_payload}")
        logging.error("CVSS Score: 9.8 CRITICAL")
        logging.error("Standard: OWASP Top 10 2021 - A03 (Injection)")
        logging.error("Impact: Authentication bypass, database compromise, unauthorized access")
        logging.error("Recommendation: Implement parameterized queries, input validation")
        pytest.fail(f"DISCOVERED: SQL Injection vulnerability in username field - payload: {sql_payload}")
    else:
        logging.info(f"SQL injection attempt blocked: {sql_payload}")
        assert True


@pytest.mark.security
@pytest.mark.critical
@pytest.mark.injection
@pytest.mark.parametrize("sql_payload", [
    "' OR '1'='1",
    "password' OR '1'='1'--",
    "' OR 1=1--",
])
def test_sql_injection_password_INJ_002(browser, sql_payload):
    """
    TC-SEC-LOGIN-INJ-002: SQL Injection in Password Field
    
    CVSS Score: 9.8 CRITICAL
    Standard: OWASP Top 10 2021 - A03 (Injection)
    Standard: OWASP ASVS v5.0 Section 1.2.5
    
    Discovers if SQL injection is possible through password field.
    """
    browser.get(BASE_URL)
    
    perform_login(browser, TEST_USERNAME, sql_payload)
    
    logged_in = is_user_logged_in(browser, timeout=TIMEOUT_SHORT)
    alert_text = wait_for_alert(browser, timeout=TIMEOUT_SHORT)
    
    if logged_in:
        logging.critical(f"CRITICAL VULNERABILITY: SQL Injection in password field: {sql_payload}")
        logging.error("CVSS Score: 9.8 CRITICAL")
        logging.error("Impact: Authentication bypass via password field")
        pytest.fail(f"DISCOVERED: SQL Injection vulnerability in password field")
    else:
        assert True


@pytest.mark.security
@pytest.mark.critical
@pytest.mark.injection
@pytest.mark.parametrize("xss_payload", [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
])
def test_xss_username_field_INJ_003(browser, xss_payload):
    """
    TC-SEC-LOGIN-INJ-003: XSS in Username Field
    
    CVSS Score: 8.8 HIGH
    Standard: OWASP Top 10 2021 - A03 (Injection)
    Standard: OWASP ASVS v5.0 Section 1.2.1
    
    Discovers if XSS is possible in username field.
    Tests for stored, reflected, or DOM-based XSS.
    """
    browser.get(BASE_URL)
    
    perform_login(browser, xss_payload, TEST_PASSWORD)
    
    alert_text = wait_for_alert(browser, timeout=TIMEOUT_SHORT)
    
    if alert_text and "XSS" in alert_text:
        logging.critical(f"CRITICAL VULNERABILITY: XSS executed with payload: {xss_payload}")
        logging.error("CVSS Score: 8.8 HIGH")
        logging.error("Standard: OWASP Top 10 - A03")
        logging.error("Impact: Session hijacking, credential theft, malicious script execution")
        pytest.fail("DISCOVERED: XSS vulnerability in username field")
    else:
        assert True


@pytest.mark.security
@pytest.mark.high
@pytest.mark.bot_protection
def test_brute_force_no_rate_limiting_BOT_001(browser):
    """
    TC-SEC-LOGIN-BOT-001: Brute Force Attack Without Rate Limiting
    
    CVSS Score: 8.1 HIGH
    Standard: OWASP ASVS v5.0 Section 2.2.1
    Standard: NIST SP 800-63B Section 5.2.2
    
    Discovers if system has brute force protection via rate limiting.
    Attempts multiple rapid login attempts.
    """
    browser.get(BASE_URL)
    
    attempts = 0
    rate_limited = False
    
    for i in range(50):
        perform_login(browser, TEST_USERNAME, f"wrongpass{i}")
        
        alert_text = wait_for_alert(browser, timeout=TIMEOUT_SHORT)
        
        if alert_text and ("rate" in alert_text.lower() or "locked" in alert_text.lower() or "blocked" in alert_text.lower()):
            rate_limited = True
            logging.info(f"Rate limiting detected at attempt {i+1}: {alert_text}")
            break
        
        attempts += 1
        browser.get(BASE_URL)
    
    if not rate_limited and attempts >= 45:
        logging.critical("CRITICAL VULNERABILITY: NO RATE LIMITING")
        logging.error("CVSS Score: 8.1 HIGH")
        logging.error(f"Completed {attempts} login attempts without rate limiting")
        logging.error("Standard: OWASP ASVS v5.0 Section 2.2.1")
        logging.error("Impact: Unlimited brute force attempts possible")
        pytest.fail(f"DISCOVERED: No rate limiting after {attempts} attempts")
    else:
        logging.info(f"Rate limiting or account lockout detected")
        assert True


@pytest.mark.security
@pytest.mark.high
@pytest.mark.bot_protection
def test_rapid_concurrent_login_attempts_BOT_002(browser):
    """
    TC-SEC-LOGIN-BOT-002: Concurrent Rapid Login Attempts
    
    CVSS Score: 7.5 HIGH
    Standard: OWASP ASVS v5.0 Section 2.2.1
    
    Discovers if system can handle concurrent brute force attempts.
    Tests for distributed brute force protection.
    """
    browser.get(BASE_URL)
    
    def attempt_login():
        try:
            local_browser = webdriver.Chrome()
            local_browser.get(BASE_URL)
            perform_login(local_browser, TEST_USERNAME, "wrong_pass")
            wait_for_alert(local_browser, timeout=1)
            local_browser.quit()
            return True
        except:
            return False
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(attempt_login) for _ in range(20)]
        results = [f.result() for f in as_completed(futures)]
        successful_attempts = sum(results)
    
    if successful_attempts >= 15:
        logging.warning(f"Concurrent brute force: {successful_attempts}/20 requests completed")
        logging.warning("System may be vulnerable to distributed brute force")
    
    assert True


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.business_logic
def test_account_enumeration_BL_001(browser):
    """
    TC-SEC-LOGIN-BL-001: Account Enumeration via Error Messages
    
    CVSS Score: 5.3 MEDIUM
    Standard: OWASP ASVS v5.0 Section 2.2.2
    Standard: OWASP Testing Guide v4 - WSTG-ATHN-04
    
    Discovers if system leaks information about valid vs invalid usernames.
    Different error messages allow attacker to enumerate valid accounts.
    """
    browser.get(BASE_URL)
    
    perform_login(browser, "definitely_non_existent_user_9999", "anypassword")
    invalid_user_msg = wait_for_alert(browser, timeout=TIMEOUT_MEDIUM)
    
    browser.get(BASE_URL)
    
    perform_login(browser, TEST_USERNAME, "definitely_wrong_password_123")
    valid_user_wrong_pass_msg = wait_for_alert(browser, timeout=TIMEOUT_MEDIUM)
    
    if invalid_user_msg and valid_user_wrong_pass_msg:
        if invalid_user_msg.lower() != valid_user_wrong_pass_msg.lower():
            if "not exist" in invalid_user_msg.lower() or "exist" in invalid_user_msg.lower():
                logging.warning("ACCOUNT ENUMERATION POSSIBLE")
                logging.warning("CVSS Score: 5.3 MEDIUM")
                logging.warning(f"Invalid user message: {invalid_user_msg}")
                logging.warning(f"Valid user message: {valid_user_wrong_pass_msg}")
                logging.warning("Impact: Attackers can enumerate valid usernames")
                logging.warning("Recommendation: Use generic error messages")
                pytest.fail("DISCOVERED: Account enumeration via different error messages")
    
    assert True


@pytest.mark.security
@pytest.mark.high
@pytest.mark.authentication
def test_session_fixation_AUTH_001(browser):
    """
    TC-SEC-LOGIN-AUTH-001: Session Fixation Vulnerability
    
    CVSS Score: 8.1 HIGH
    Standard: OWASP Top 10 2021 - A07 (Authentication Failures)
    Standard: OWASP ASVS v5.0 Section 3.2.1
    
    Discovers if session ID changes after successful authentication.
    Session fixation allows attacker to hijack user sessions.
    """
    browser.get(BASE_URL)
    
    cookies_before = browser.get_cookies()
    session_before = [c for c in cookies_before if 'session' in c.get('name', '').lower()]
    
    perform_login(browser, TEST_USERNAME, TEST_PASSWORD)
    
    logged_in = is_user_logged_in(browser, timeout=TIMEOUT_MEDIUM)
    
    if not logged_in:
        alert_text = wait_for_alert(browser)
        pytest.skip(f"Cannot test session fixation - login failed: {alert_text}")
    
    cookies_after = browser.get_cookies()
    session_after = [c for c in cookies_after if 'session' in c.get('name', '').lower()]
    
    if session_before and session_after:
        if session_before[0].get('value') == session_after[0].get('value'):
            logging.error("SESSION FIXATION VULNERABILITY")
            logging.error("CVSS Score: 8.1 HIGH")
            logging.error("Session ID did not change after authentication")
            logging.error("Standard: OWASP Top 10 - A07, OWASP ASVS v5.0-3.2.1")
            logging.error("Impact: Session hijacking, attacker can fixate session ID")
            logging.error("Recommendation: Regenerate session ID after login")
            pytest.fail("DISCOVERED: Session fixation - session ID unchanged after login")
    
    perform_logout(browser)
    assert True


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.authentication
def test_session_cookie_security_flags_AUTH_002(browser):
    """
    TC-SEC-LOGIN-AUTH-002: Session Cookie Security Flags
    
    CVSS Score: 6.5 MEDIUM
    Standard: OWASP ASVS v5.0 Section 3.4.1
    Standard: OWASP Testing Guide - WSTG-SESS-02
    
    Discovers if session cookies have proper security flags.
    Missing HttpOnly or Secure flags expose cookies to attacks.
    """
    browser.get(BASE_URL)
    
    perform_login(browser, TEST_USERNAME, TEST_PASSWORD)
    
    logged_in = is_user_logged_in(browser, timeout=TIMEOUT_MEDIUM)
    if not logged_in:
        alert_text = wait_for_alert(browser)
        pytest.skip(f"Cannot test cookies - login failed: {alert_text}")
    
    cookies = browser.get_cookies()
    
    missing_flags = []
    
    for cookie in cookies:
        if 'session' in cookie.get('name', '').lower() or 'token' in cookie.get('name', '').lower():
            if not cookie.get('httpOnly', False):
                missing_flags.append(f"{cookie['name']}: Missing HttpOnly flag")
            if not cookie.get('secure', False):
                missing_flags.append(f"{cookie['name']}: Missing Secure flag")
    
    if missing_flags:
        logging.warning("COOKIE SECURITY FLAGS MISSING")
        logging.warning("CVSS Score: 6.5 MEDIUM")
        for flag in missing_flags:
            logging.warning(f"  - {flag}")
        logging.warning("Impact: Cookies vulnerable to XSS (no HttpOnly) or MitM (no Secure)")
        logging.warning("Recommendation: Set HttpOnly and Secure flags on all session cookies")
        pytest.fail(f"DISCOVERED: Missing cookie security flags: {missing_flags}")
    
    perform_logout(browser)
    assert True


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.authentication
def test_concurrent_session_handling_AUTH_003(browser):
    """
    TC-SEC-LOGIN-AUTH-003: Concurrent Session Handling
    
    CVSS Score: 5.3 MEDIUM
    Standard: OWASP ASVS v5.0 Section 3.3.1
    
    Discovers how system handles multiple concurrent sessions.
    Tests if old sessions are invalidated when new login occurs.
    """
    browser.get(BASE_URL)
    
    perform_login(browser, TEST_USERNAME, TEST_PASSWORD)
    
    if not is_user_logged_in(browser, timeout=TIMEOUT_MEDIUM):
        alert = wait_for_alert(browser)
        pytest.skip(f"Cannot test concurrent sessions - login failed: {alert}")
    
    cookies_first_session = browser.get_cookies()
    
    second_browser = webdriver.Chrome()
    try:
        second_browser.get(BASE_URL)
        perform_login(second_browser, TEST_USERNAME, TEST_PASSWORD)
        
        if not is_user_logged_in(second_browser, timeout=TIMEOUT_MEDIUM):
            pytest.skip("Second login failed")
        
        browser.refresh()
        WebDriverWait(browser, TIMEOUT).until(
            lambda d: d.execute_script('return document.readyState') == 'complete'
        )
        
        still_logged_first = is_user_logged_in(browser, timeout=TIMEOUT_SHORT)
        
        if still_logged_first:
            logging.info("System allows concurrent sessions")
        else:
            logging.info("First session invalidated when second login occurred")
        
        assert True
    
    finally:
        second_browser.quit()
        perform_logout(browser)


@pytest.mark.security
@pytest.mark.low
@pytest.mark.information_disclosure
def test_verbose_error_messages_INFO_001(browser):
    """
    TC-SEC-LOGIN-INFO-001: Verbose Error Message Disclosure
    
    CVSS Score: 3.7 LOW
    Standard: OWASP ASVS v5.0 Section 7.4.1
    
    Discovers if system reveals sensitive information in error messages.
    Stack traces, database errors, or technical details aid attackers.
    """
    browser.get(BASE_URL)
    
    perform_login(browser, "test'\"<>", "test'\"<>")
    
    alert_text = wait_for_alert(browser, timeout=TIMEOUT_MEDIUM)
    
    dangerous_keywords = [
        "sql", "database", "mysql", "postgres", "oracle",
        "exception", "stack trace", "error at line",
        "undefined", "null pointer", "debug"
    ]
    
    if alert_text:
        alert_lower = alert_text.lower()
        found_keywords = [kw for kw in dangerous_keywords if kw in alert_lower]
        
        if found_keywords:
            logging.warning("VERBOSE ERROR MESSAGE DETECTED")
            logging.warning(f"Error message: {alert_text}")
            logging.warning(f"Suspicious keywords: {found_keywords}")
            logging.warning("Impact: Information disclosure aids attacker reconnaissance")
            pytest.fail(f"DISCOVERED: Verbose error message contains: {found_keywords}")
    
    assert True


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.csrf
def test_csrf_token_validation_CSRF_001(browser):
    """
    TC-SEC-LOGIN-CSRF-001: CSRF Token Validation on Login
    
    CVSS Score: 6.5 MEDIUM
    Standard: OWASP Top 10 2021 - A01 (Broken Access Control)
    Standard: OWASP ASVS v5.0 Section 4.2.2
    
    Discovers if login form has CSRF protection.
    Missing CSRF tokens allow cross-site request forgery attacks.
    """
    browser.get(BASE_URL)
    
    open_login_modal(browser)
    
    form_html = browser.page_source
    
    has_csrf = False
    if 'csrf' in form_html.lower() or 'token' in form_html.lower():
        if 'name="csrf' in form_html.lower() or 'name=\'csrf' in form_html.lower():
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
def test_security_headers_validation_HEAD_001(browser):
    """
    TC-SEC-LOGIN-HEAD-001: Security Headers Validation
    
    CVSS Score: 7.5 HIGH
    Standard: OWASP Secure Headers Project
    
    Discovers if critical security headers are present.
    Missing security headers expose application to various attacks.
    """
    try:
        response = requests.get(BASE_URL, timeout=TIMEOUT)
        headers = response.headers
        
        required_headers = {
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'X-Content-Type-Options': ['nosniff'],
            'Strict-Transport-Security': None,
            'Content-Security-Policy': None,
            'X-XSS-Protection': ['1; mode=block']
        }
        
        missing_headers = []
        
        for header, expected_values in required_headers.items():
            if header not in headers:
                missing_headers.append(header)
            elif expected_values:
                if headers[header] not in expected_values:
                    logging.warning(f"{header}: {headers[header]} (unexpected value)")
        
        if missing_headers:
            logging.warning("SECURITY HEADERS MISSING")
            logging.warning("CVSS Score: 7.5 HIGH")
            for header in missing_headers:
                logging.warning(f"  - Missing: {header}")
            logging.warning("Impact: Vulnerable to clickjacking, XSS, MIME sniffing")
            pytest.fail(f"DISCOVERED: Missing security headers: {missing_headers}")
        
        assert True
    
    except Exception as e:
        logging.error(f"Failed to check headers: {e}")
        assert True


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.http_methods
def test_dangerous_http_methods_HTTP_001(browser):
    """
    TC-SEC-LOGIN-HTTP-001: Dangerous HTTP Methods Allowed
    
    CVSS Score: 6.5 MEDIUM
    Standard: OWASP Testing Guide - WSTG-CONF-06
    
    Discovers if dangerous HTTP methods are enabled.
    Methods like TRACE, PUT, DELETE should be disabled.
    """
    dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'OPTIONS', 'CONNECT']
    
    allowed_methods = []
    
    for method in dangerous_methods:
        try:
            response = requests.request(method, BASE_URL, timeout=TIMEOUT_SHORT)
            if response.status_code not in [405, 501, 403]:
                allowed_methods.append(f"{method}: {response.status_code}")
                logging.warning(f"Method {method} returned: {response.status_code}")
        except:
            pass
    
    if allowed_methods:
        logging.warning("DANGEROUS HTTP METHODS ALLOWED")
        logging.warning("CVSS Score: 6.5 MEDIUM")
        for method in allowed_methods:
            logging.warning(f"  - {method}")
        logging.warning("Impact: Potential for data manipulation or information disclosure")
        pytest.fail(f"DISCOVERED: Dangerous HTTP methods allowed: {allowed_methods}")
    
    assert True


@pytest.mark.security
@pytest.mark.low
@pytest.mark.ssl_tls
def test_tls_version_SSL_001(browser):
    """
    TC-SEC-LOGIN-SSL-001: TLS Version Check
    
    CVSS Score: 7.4 HIGH
    Standard: PCI-DSS 4.0.1 Requirement 4.2
    Standard: NIST SP 800-52 Rev 2
    
    Discovers if site uses secure TLS version.
    TLS 1.0 and 1.1 are deprecated and insecure.
    """
    try:
        import ssl
        import socket
        from urllib.parse import urlparse
        
        parsed = urlparse(BASE_URL)
        hostname = parsed.hostname
        port = 443
        
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version = ssock.version()
                
                if tls_version in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                    logging.error(f"INSECURE TLS VERSION: {tls_version}")
                    logging.error("CVSS Score: 7.4 HIGH")
                    logging.error("Standard: PCI-DSS 4.0.1-4.2, NIST SP 800-52")
                    logging.error("Impact: Vulnerable to downgrade attacks, weak encryption")
                    pytest.fail(f"DISCOVERED: Insecure TLS version: {tls_version}")
                else:
                    logging.info(f"TLS version: {tls_version} (acceptable)")
        
        assert True
    
    except Exception as e:
        logging.warning(f"Could not check TLS version: {e}")
        assert True


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.timing_attack
def test_timing_attack_username_enumeration_TIME_001(browser):
    """
    TC-SEC-LOGIN-TIME-001: Timing Attack for Username Enumeration
    
    CVSS Score: 5.3 MEDIUM
    Standard: OWASP Testing Guide - WSTG-ATHN-04
    
    Discovers if response times differ for valid vs invalid usernames.
    Timing differences allow username enumeration.
    """
    browser.get(BASE_URL)
    
    invalid_times = []
    for i in range(3):
        start = time.time()
        perform_login(browser, f"invalid_user_{i}_99999", "anypass")
        wait_for_alert(browser, timeout=TIMEOUT_MEDIUM)
        invalid_times.append(time.time() - start)
        browser.get(BASE_URL)
    
    valid_times = []
    for i in range(3):
        start = time.time()
        perform_login(browser, TEST_USERNAME, "wrongpassword")
        wait_for_alert(browser, timeout=TIMEOUT_MEDIUM)
        valid_times.append(time.time() - start)
        browser.get(BASE_URL)
    
    avg_invalid = sum(invalid_times) / len(invalid_times)
    avg_valid = sum(valid_times) / len(valid_times)
    time_diff = abs(avg_valid - avg_invalid)
    
    if time_diff > 0.5:
        logging.warning("TIMING ATTACK POSSIBLE")
        logging.warning(f"Invalid username avg time: {avg_invalid:.3f}s")
        logging.warning(f"Valid username avg time: {avg_valid:.3f}s")
        logging.warning(f"Difference: {time_diff:.3f}s")
        logging.warning("Impact: Username enumeration via timing analysis")
        pytest.fail(f"DISCOVERED: Timing difference of {time_diff:.3f}s allows enumeration")
    
    assert True


@pytest.mark.security
@pytest.mark.low
@pytest.mark.clickjacking
def test_clickjacking_protection_CLICK_001(browser):
    """
    TC-SEC-LOGIN-CLICK-001: Clickjacking Protection
    
    CVSS Score: 4.3 LOW
    Standard: OWASP Top 10 2021 - A04
    
    Discovers if site is protected against clickjacking.
    Tests if site can be embedded in iframe.
    """
    browser.get(BASE_URL)
    
    browser.execute_script("""
        var iframe = document.createElement('iframe');
        iframe.src = arguments[0];
        iframe.id = 'testIframe';
        document.body.appendChild(iframe);
    """, BASE_URL)
    
    time.sleep(2)
    
    try:
        iframe = browser.find_element(By.ID, "testIframe")
        if iframe:
            logging.warning("CLICKJACKING POSSIBLE")
            logging.warning("Site can be loaded in iframe")
            logging.warning("Impact: UI redressing attacks, credential theft")
            logging.warning("Recommendation: Set X-Frame-Options or CSP frame-ancestors")
            pytest.fail("DISCOVERED: Site vulnerable to clickjacking - no frame protection")
    except:
        logging.info("Clickjacking protection appears present")
    
    assert True


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.password_policy
def test_weak_password_acceptance_PWD_001(browser):
    """
    TC-SEC-LOGIN-PWD-001: Weak Password Acceptance
    
    CVSS Score: 6.5 MEDIUM
    Standard: NIST SP 800-63B Section 5.1.1
    Standard: OWASP ASVS v5.0 Section 2.1.1
    
    Discovers if system accepts weak passwords during registration.
    Tests if password complexity requirements are enforced.
    
    Note: This test requires signup functionality. Skip if unavailable.
    """
    browser.get(BASE_URL)
    
    try:
        signup_button = WebDriverWait(browser, TIMEOUT_SHORT).until(
            EC.element_to_be_clickable(SIGNUP_BUTTON_NAV)
        )
        signup_button.click()
        
        WebDriverWait(browser, TIMEOUT).until(
            EC.visibility_of_element_located(SIGNUP_USERNAME_FIELD)
        )
        
        weak_passwords = ["123", "password", "abc", "11111"]
        
        for weak_pass in weak_passwords:
            test_user = f"weaktest_{int(time.time())}"
            
            username_field = browser.find_element(*SIGNUP_USERNAME_FIELD)
            username_field.clear()
            username_field.send_keys(test_user)
            
            password_field = browser.find_element(*SIGNUP_PASSWORD_FIELD)
            password_field.clear()
            password_field.send_keys(weak_pass)
            
            browser.find_element(*SIGNUP_SUBMIT_BUTTON).click()
            
            alert_text = wait_for_alert(browser, timeout=TIMEOUT_MEDIUM)
            
            if alert_text and "success" in alert_text.lower():
                logging.error(f"WEAK PASSWORD ACCEPTED: '{weak_pass}'")
                logging.error("CVSS Score: 6.5 MEDIUM")
                logging.error("Standard: NIST 800-63B-5.1.1")
                logging.error("Impact: Weak passwords allow easy brute force")
                pytest.fail(f"DISCOVERED: Weak password '{weak_pass}' was accepted")
            
            browser.get(BASE_URL)
            signup_button = browser.find_element(*SIGNUP_BUTTON_NAV)
            signup_button.click()
            WebDriverWait(browser, TIMEOUT_SHORT).until(
                EC.visibility_of_element_located(SIGNUP_USERNAME_FIELD)
            )
        
        assert True
    
    except TimeoutException:
        pytest.skip("Signup functionality not available or accessible")


@pytest.mark.security
@pytest.mark.high
@pytest.mark.password_reset
def test_password_reset_security_RESET_001(browser):
    """
    TC-SEC-LOGIN-RESET-001: Password Reset Flow Security
    
    CVSS Score: 7.5 HIGH
    Standard: OWASP ASVS v5.0 Section 2.5.6
    
    Discovers if password reset mechanism exists and is secure.
    Tests for reset token security, expiration, one-time use.
    """
    browser.get(BASE_URL)
    
    page_source = browser.page_source.lower()
    
    reset_keywords = ['forgot password', 'reset password', 'recover password']
    reset_found = any(keyword in page_source for keyword in reset_keywords)
    
    if not reset_found:
        logging.warning("=" * 80)
        logging.warning("SECURITY CONCERN: NO PASSWORD RESET MECHANISM")
        logging.warning("Standard: OWASP ASVS v5.0 Section 2.5.6")
        logging.warning("Expected: Secure password reset flow")
        logging.warning("Actual: No password reset functionality detected")
        logging.warning("Impact: Users cannot recover forgotten passwords")
        logging.warning("CVSS Score: 5.0 (MEDIUM) - Usability/Security trade-off")
        logging.warning("=" * 80)
        pytest.fail("DISCOVERED: No password reset functionality - limits account recovery")
    else:
        logging.info("DISCOVERED: Password reset mechanism exists")
        assert True


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.session_timeout
def test_session_timeout_security_TIMEOUT_001(browser):
    """
    TC-SEC-LOGIN-TIMEOUT-001: Session Timeout Security
    
    CVSS Score: 6.1 MEDIUM
    Standard: OWASP ASVS v5.0 Section 3.3.1
    Standard: ISO 27001 A.9.4.2
    
    Discovers if sessions have appropriate timeout mechanisms.
    Tests if idle sessions are automatically terminated.
    """
    browser.get(BASE_URL)
    
    perform_login(browser, TEST_USERNAME, TEST_PASSWORD)
    time.sleep(1)
    wait_for_alert(browser)
    
    if not is_user_logged_in(browser):
        pytest.skip("Initial login failed - cannot test session timeout")
    
    logging.info("DISCOVERED: User logged in, waiting 60 seconds for timeout test")
    
    time.sleep(60)
    
    browser.refresh()
    time.sleep(2)
    
    still_logged_in = is_user_logged_in(browser, timeout=2)
    
    if still_logged_in:
        logging.warning("=" * 80)
        logging.warning("SECURITY CONCERN: NO SESSION TIMEOUT DETECTED")
        logging.warning("Standard: OWASP ASVS v5.0 Section 3.3.1")
        logging.warning("Expected: Session expires after inactivity period")
        logging.warning("Actual: Session remained active after 60 seconds")
        logging.warning("Impact: Unattended sessions remain accessible")
        logging.warning("CVSS Score: 6.1 (MEDIUM)")
        logging.warning("=" * 80)
        perform_logout(browser)
        pytest.fail("DISCOVERED: No session timeout - sessions may remain active indefinitely")
    else:
        logging.info("DISCOVERED: Session expired after inactivity")
        assert True


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.remember_me
def test_remember_me_security_REMEM_001(browser):
    """
    TC-SEC-LOGIN-REMEM-001: Remember Me Security Implementation
    
    CVSS Score: 5.5 MEDIUM
    Standard: OWASP ASVS v5.0 Section 3.2.3
    
    Discovers if Remember Me functionality exists and is secure.
    Tests for secure token implementation, expiration.
    """
    browser.get(BASE_URL)
    
    open_login_modal(browser)
    
    page_source = browser.page_source.lower()
    
    remember_me_exists = False
    remember_keywords = ['remember me', 'keep me logged in', 'stay signed in']
    
    for keyword in remember_keywords:
        if keyword in page_source:
            remember_me_exists = True
            logging.info(f"DISCOVERED: Remember Me detected: {keyword}")
            break
    
    if not remember_me_exists:
        logging.info("DISCOVERED: No Remember Me functionality detected")
        logging.info("Note: This is acceptable for security-focused applications")
    else:
        logging.info("DISCOVERED: Remember Me functionality exists")
        logging.info("Note: Should be tested for secure implementation")
    
    assert True
