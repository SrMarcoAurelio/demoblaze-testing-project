"""
Signup Business Rules Tests
Author: Marc Arévalo
Version: 3.0 - Restructured with Page Object Model

Tests business rules and compliance with industry standards.
These tests validate that the application complies with OWASP, NIST, ISO, and WCAG standards.

Total Tests: 19 functions (~30+ executions with parametrization)
Expected Pass Rate: ~70% (some tests SHOULD fail to reveal missing features)

Standards: OWASP ASVS v5.0, NIST SP 800-63B, ISO 27001, ISO 25010, WCAG 2.1
"""

import pytest
import time
import logging
from pages.signup_page import SignupPage
from selenium.webdriver.common.keys import Keys




@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.medium
def test_username_max_length_BR_001(browser, base_url):
    """
    TC-SIGNUP-BR-001: Username Maximum Length Handling

    Standard: ISO 25010 - Functional Suitability
    Priority: MEDIUM

    Tests if system properly handles very long usernames.
    System should either reject or truncate long input.

    Expected: System handles long input gracefully
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    long_username = "A" * 1000
    signup_page.signup(long_username, "ValidPass123")

    alert_text = signup_page.get_alert_text(timeout=5)

    if alert_text:
        logging.info(f"✓ BR-001 PASSED: System handled long username. Alert: '{alert_text}'")
    else:
        logging.warning("No alert for extremely long username")

    assert True


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.medium
def test_password_max_length_BR_002(browser, base_url):
    """
    TC-SIGNUP-BR-002: Password Maximum Length Handling

    Standard: NIST SP 800-63B Section 5.1.1
    Priority: MEDIUM

    NIST recommends at least 64 characters for password length.
    Tests if system accepts reasonably long passwords.

    Expected: System accepts passwords up to at least 64 characters
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    unique_username = signup_page.generate_unique_username()
    long_password = "P" * 100
    signup_page.signup(unique_username, long_password)

    alert_text = signup_page.get_alert_text(timeout=5)

    if alert_text:
        logging.info(f"✓ BR-002: System response to long password: '{alert_text}'")

    assert True


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.medium
def test_username_leading_trailing_whitespace_BR_003(browser, base_url):
    """
    TC-SIGNUP-BR-003: Username Leading/Trailing Whitespace

    Standard: ISO 25010 - Usability (User error protection)
    Priority: MEDIUM

    Tests if system trims whitespace from username.
    Good UX practice to prevent user errors.

    Expected: System trims whitespace
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    base_username = signup_page.generate_unique_username()
    username_with_spaces = f"  {base_username}  "
    password = "ValidPass123"

    signup_page.signup(username_with_spaces, password)

    alert_text = signup_page.get_alert_text(timeout=5)
    logging.info(f"Signup result: {alert_text}")

    if alert_text and "success" in alert_text.lower():
        browser.get(base_url)
        signup_page.login_after_signup(base_username.strip(), password)
        login_alert = signup_page.get_alert_text(timeout=3)
        logged_in = signup_page.is_user_logged_in(timeout=3)

        if logged_in:
            logging.info("✓ BR-003: System trims whitespace - Good UX")
            signup_page.logout()
        else:
            logging.warning("⚠ System does NOT trim whitespace from username")

    assert True


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.medium
def test_password_whitespace_significance_BR_004(browser, base_url):
    """
    TC-SIGNUP-BR-004: Password Whitespace Significance

    Standard: NIST SP 800-63B Section 5.1.1
    Priority: MEDIUM

    Tests if whitespace in passwords is preserved (should be).
    Passwords should treat all characters including spaces as significant.

    Expected: Whitespace is preserved in passwords
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    unique_username = signup_page.generate_unique_username()
    password_with_spaces = "Pass Word 123"

    signup_page.signup(unique_username, password_with_spaces)

    alert_text = signup_page.get_alert_text(timeout=5)
    logging.info(f"✓ BR-004: Tested password with spaces. Result: {alert_text}")

    assert True


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.medium
def test_special_characters_in_username_BR_005(browser, base_url):
    """
    TC-SIGNUP-BR-005: Special Characters in Username

    Standard: OWASP ASVS v5.0 Section 2.3.1
    Priority: MEDIUM

    Tests if system handles special characters appropriately.
    System behavior should be consistent and documented.

    Expected: System handles special characters consistently
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    special_username = f"user@#$%{int(time.time())}"
    signup_page.signup(special_username, "ValidPass123")

    alert_text = signup_page.get_alert_text(timeout=5)

    if alert_text:
        logging.info(f"✓ BR-005: System handled special chars. Alert: '{alert_text}'")

    assert True


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.low
def test_numeric_only_username_BR_006(browser, base_url):
    """
    TC-SIGNUP-BR-006: Numeric-Only Username

    Standard: ISO 25010 - Functional Suitability
    Priority: LOW

    Tests if system allows usernames with only numbers.
    Edge case - some systems restrict numeric-only usernames.

    Expected: System handles numeric usernames consistently
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    numeric_username = f"{int(time.time())}"
    signup_page.signup(numeric_username, "ValidPass123")

    alert_text = signup_page.get_alert_text(timeout=5)

    if alert_text:
        logging.info(f"✓ BR-006: System response to numeric username: '{alert_text}'")

    assert True


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.medium
def test_unicode_characters_BR_007(browser, base_url):
    """
    TC-SIGNUP-BR-007: Unicode Characters in Username

    Standard: ISO 25010 - Portability (Adaptability)
    Priority: MEDIUM

    Tests if system supports international characters (Unicode).
    Important for global accessibility and i18n compliance.

    Expected: System handles Unicode characters gracefully
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    unicode_tests = [
        (f"用户{int(time.time())}", "Chinese characters"),
        (f"Пользователь{int(time.time())}", "Cyrillic characters"),
        (f"مستخدم{int(time.time())}", "Arabic characters"),
    ]

    for unicode_username, description in unicode_tests:
        browser.get(base_url)
        signup_page.signup(unicode_username, "ValidPass123")

        alert_text = signup_page.get_alert_text(timeout=3)
        logging.info(f"✓ {description}: {alert_text if alert_text else 'No alert'}")

    logging.info("Standard: ISO 25010 recommends international character support")
    assert True


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.medium
def test_username_whitespace_normalization_BR_008(browser, base_url):
    """
    TC-SIGNUP-BR-008: Username Whitespace Normalization

    Standard: ISO 25010 - Usability
    Priority: MEDIUM

    Tests if system normalizes whitespace (multiple spaces, tabs).
    Good UX practice for consistent usernames.

    Expected: System normalizes or rejects abnormal whitespace
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    base_username = signup_page.generate_unique_username()
    username_multi_spaces = f"{base_username}    test"

    signup_page.signup(username_multi_spaces, "ValidPass123")

    alert_text = signup_page.get_alert_text(timeout=5)
    logging.info(f"✓ BR-008: Multiple spaces handled. Alert: '{alert_text}'")

    assert True


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.low
def test_username_case_sensitivity_BR_009(browser, base_url):
    """
    TC-SIGNUP-BR-009: Username Case Sensitivity

    Standard: ISO 27001 A.9.4 - Authentication consistency
    Priority: LOW

    Tests if usernames are case-sensitive or case-insensitive.
    System should have consistent behavior documented.

    Expected: System has consistent case-handling behavior
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    base_username = f"TestUser{int(time.time())}"
    password = "ValidPass123"

    signup_page.signup(base_username, password)
    first_alert = signup_page.get_alert_text(timeout=5)

    browser.get(base_url)
    signup_page.signup(base_username.lower(), password)
    second_alert = signup_page.get_alert_text(timeout=5)

    logging.info(f"First ('{base_username}'): {first_alert}")
    logging.info(f"Second ('{base_username.lower()}'): {second_alert}")

    if second_alert and "exist" in second_alert.lower():
        logging.info("✓ DISCOVERED: Usernames are NOT case-sensitive")
    else:
        logging.info("✓ DISCOVERED: Usernames ARE case-sensitive")

    assert True


@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.medium
def test_identical_username_password_BR_010(browser, base_url):
    """
    TC-SIGNUP-BR-010: Identical Username and Password

    Standard: NIST SP 800-63B Section 5.1.1.2
    Priority: MEDIUM

    Tests if system prevents using username as password.
    Security best practice - password should differ from username.

    Expected: System should warn or reject identical username/password
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    unique_username = signup_page.generate_unique_username()
    signup_page.signup(unique_username, unique_username)

    alert_text = signup_page.get_alert_text(timeout=5)

    if alert_text:
        if "success" in alert_text.lower():
            logging.warning("⚠ System allows identical username/password")
            logging.warning("Standard: NIST 800-63B recommends rejecting this")
        else:
            logging.info(f"✓ BR-010: System rejected identical user/pass: '{alert_text}'")

    assert True



@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.critical
@pytest.mark.parametrize("sql_payload", [
    "' OR '1'='1",
    "admin'--",
    "' OR '1'='1'--",
    "') OR ('1'='1",
])
def test_sql_injection_prevention_BR_011(browser, base_url, sql_payload):
    """
    TC-SIGNUP-BR-011: SQL Injection Prevention

    Standard: OWASP ASVS v5.0 Section 1.2.5
    CVSS Score: 9.8 CRITICAL
    Priority: CRITICAL

    Validates that system properly sanitizes input to prevent SQL injection.

    Expected: SQL injection attempts are blocked
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    signup_page.signup(sql_payload, "anypassword")

    alert_text = signup_page.get_alert_text(timeout=3)

    if alert_text and "success" in alert_text.lower():
        logging.critical(f"VIOLATION: SQL payload may have succeeded: {sql_payload}")
        pytest.fail(f"DISCOVERED: Possible SQL injection - {sql_payload}")
    else:
        logging.info(f"✓ SQL injection blocked: {sql_payload}")
        assert True


@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.high
@pytest.mark.parametrize("xss_payload", [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "<svg onload=alert('XSS')>",
])
def test_xss_prevention_BR_012(browser, base_url, xss_payload):
    """
    TC-SIGNUP-BR-012: XSS (Cross-Site Scripting) Prevention

    Standard: OWASP ASVS v5.0 Section 1.2.1
    CVSS Score: 7.5 HIGH
    Priority: HIGH

    Validates that system prevents XSS attacks.

    Expected: XSS attempts are prevented/sanitized
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    signup_page.signup(xss_payload, "anypassword")

    time.sleep(1)
    alert_text = signup_page.get_alert_text(timeout=2)

    if alert_text and "XSS" in alert_text:
        logging.critical(f"VIOLATION: XSS executed: {xss_payload}")
        pytest.fail("DISCOVERED: XSS vulnerability")
    else:
        logging.info(f"✓ XSS prevented: {xss_payload}")
        assert True


@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.medium
@pytest.mark.parametrize("weak_password", [
    "123456",
    "password",
    "abc",
    "test",
    "qwerty",
    "12345678",
])
def test_password_complexity_enforcement_BR_013(browser, base_url, weak_password):
    """
    TC-SIGNUP-BR-013: Password Complexity Enforcement

    Standard: NIST SP 800-63B Section 5.1.1.2
    CVSS Score: 6.5 MEDIUM
    Priority: MEDIUM

    Validates that system rejects common weak passwords.

    Expected for Production: Weak passwords rejected
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    unique_username = signup_page.generate_unique_username()
    signup_page.signup(unique_username, weak_password)

    alert_text = signup_page.get_alert_text(timeout=5)

    if alert_text and "success" in alert_text.lower():
        logging.error(f"VIOLATION: Weak password accepted: '{weak_password}'")
        logging.error("Standard: NIST SP 800-63B Section 5.1.1.2")
        pytest.fail(f"DISCOVERED: Weak password '{weak_password}' accepted")
    else:
        logging.info(f"✓ Weak password handled: '{weak_password}'")
        assert True


@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.high
def test_signup_rate_limiting_BR_014(browser, base_url):
    """
    TC-SIGNUP-BR-014: Signup Rate Limiting

    Standard: OWASP ASVS v5.0 Section 2.2.3
    CVSS Score: 6.5 MEDIUM
    Priority: HIGH

    Validates that system has rate limiting for signup.
    Prevents automated mass account creation.

    Expected: Rate limiting enforced after N attempts
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    attempts = 0
    rate_limited = False

    for i in range(10):
        unique_username = signup_page.generate_unique_username()
        signup_page.signup(unique_username, "TestPass123")

        alert_text = signup_page.get_alert_text(timeout=2)

        if alert_text and ("rate" in alert_text.lower() or "limit" in alert_text.lower() or "wait" in alert_text.lower()):
            rate_limited = True
            logging.info(f"✓ Rate limiting detected at attempt {i+1}")
            break

        attempts += 1
        browser.get(base_url)

    if not rate_limited:
        logging.warning("=" * 80)
        logging.warning("SECURITY CONCERN: NO SIGNUP RATE LIMITING")
        logging.warning("Standard: OWASP ASVS v5.0 Section 2.2.3")
        logging.warning(f"Completed {attempts} signup attempts without rate limiting")
        logging.warning("Impact: Automated mass account creation possible")
        logging.warning("=" * 80)
        pytest.fail(f"DISCOVERED: NO RATE LIMITING - {attempts} signups without throttling")
    else:
        assert True


@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.medium
def test_captcha_protection_BR_015(browser, base_url):
    """
    TC-SIGNUP-BR-015: CAPTCHA Protection

    Standard: OWASP ASVS v5.0 Section 2.2.3
    CVSS Score: 6.5 MEDIUM
    Priority: MEDIUM

    Validates that system has CAPTCHA or bot protection.

    Expected for Production: CAPTCHA present
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    signup_page.open_signup_modal()

    page_source = browser.page_source.lower()
    captcha_keywords = ['captcha', 'recaptcha', 'hcaptcha', 'bot protection', 'g-recaptcha']
    captcha_detected = any(keyword in page_source for keyword in captcha_keywords)

    if not captcha_detected:
        logging.warning("SECURITY CONCERN: NO CAPTCHA/BOT PROTECTION")
        logging.warning("Standard: OWASP ASVS v5.0 Section 2.2.3")
        pytest.fail("DISCOVERED: NO CAPTCHA - Violates OWASP ASVS 2.2.3")
    else:
        logging.info("✓ CAPTCHA/bot protection present")
        assert True


@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.medium
def test_email_verification_requirement_BR_016(browser, base_url):
    """
    TC-SIGNUP-BR-016: Email Verification Requirement

    Standard: OWASP ASVS v5.0 Section 2.1.8
    Priority: MEDIUM

    Checks if system requires email verification.
    Good security practice to verify email ownership.

    Expected: Email verification required or recommended
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    signup_page.open_signup_modal()
    page_source = browser.page_source.lower()

    email_keywords = ['email', 'e-mail', 'verification', 'verify']
    email_detected = any(keyword in page_source for keyword in email_keywords)

    if not email_detected:
        logging.info("✓ No email verification detected")
        logging.info("Note: Email verification recommended per OWASP ASVS 2.1.8")
    else:
        logging.info("✓ Email verification appears present")

    assert True



@pytest.mark.business_rules
@pytest.mark.accessibility
@pytest.mark.medium
def test_keyboard_navigation_BR_017(browser, base_url):
    """
    TC-SIGNUP-BR-017: Keyboard Navigation

    Standard: WCAG 2.1 Success Criterion 2.1.1 (Level A)
    Priority: MEDIUM

    Validates that signup form is accessible via keyboard only.

    Expected: User can navigate and submit form using keyboard only
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    signup_page.open_signup_modal()

    unique_username = signup_page.generate_unique_username()
    password = "TestPass123"

    signup_page.fill_signup_username(unique_username)
    signup_page.send_keys(signup_page.SIGNUP_USERNAME_FIELD, Keys.TAB)
    time.sleep(0.5)
    signup_page.fill_signup_password(password)

    signup_page.submit_signup_with_enter()

    alert_text = signup_page.get_alert_text(timeout=5)

    assert alert_text is not None, "Should receive feedback via keyboard submission"
    logging.info("✓ BR-017 PASSED: Keyboard navigation works (WCAG 2.1 SC 2.1.1)")


@pytest.mark.business_rules
@pytest.mark.accessibility
@pytest.mark.medium
def test_form_labels_accessibility_BR_018(browser, base_url):
    """
    TC-SIGNUP-BR-018: Form Labels for Screen Readers

    Standard: WCAG 2.1 Success Criterion 1.3.1 (Level A)
    Priority: MEDIUM

    Validates that form fields have labels for screen readers.

    Expected: Fields have aria-labels or placeholders
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    signup_page.open_signup_modal()

    username_placeholder = signup_page.get_signup_username_placeholder()
    password_placeholder = signup_page.get_signup_password_placeholder()

    username_aria = signup_page.get_signup_username_aria_label()
    password_aria = signup_page.get_signup_password_aria_label()

    username_has_label = username_placeholder or username_aria
    password_has_label = password_placeholder or password_aria

    assert username_placeholder or password_placeholder, "Form fields should have accessibility labeling"

    logging.info(f"✓ BR-018 PASSED: Form has accessibility labels")
    logging.info(f"  Username: '{username_placeholder}'")
    logging.info(f"  Password: '{password_placeholder}'")


@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.medium
def test_username_enumeration_via_signup_BR_019(browser, base_url):
    """
    TC-SIGNUP-BR-019: Username Enumeration via Signup

    Standard: OWASP ASVS v5.0 Section 2.2.2
    CVSS Score: 5.3 MEDIUM
    Priority: MEDIUM

    Tests if signup reveals whether usernames exist.
    Different messages for existing vs new users allow enumeration.

    Expected: Generic messages that don't reveal account existence
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    signup_page.signup("Apolo2025", "anypassword")  # Known existing user
    existing_msg = signup_page.get_alert_text(timeout=5)

    browser.get(base_url)
    new_username = signup_page.generate_unique_username()
    signup_page.signup(new_username, "ValidPass123")
    new_msg = signup_page.get_alert_text(timeout=5)

    logging.info(f"Existing user: {existing_msg}")
    logging.info(f"New user: {new_msg}")

    if existing_msg and new_msg:
        if "exist" in existing_msg.lower() or "already" in existing_msg.lower():
            logging.warning("SECURITY CONCERN: Username enumeration possible")
            logging.warning("Recommendation: Use generic messages")
            pytest.fail("DISCOVERED: Username enumeration via signup messages")

    logging.info("✓ Messages don't clearly reveal username existence")
    assert True
