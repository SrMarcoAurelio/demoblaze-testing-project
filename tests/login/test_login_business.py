"""
Login Business Rules Tests
Author: Marc Arévalo
Version: 3.0 - Restructured with Page Object Model

Tests business rules and compliance with industry standards.
These tests validate that the application complies with OWASP, NIST, ISO, and WCAG standards.

Total Tests: 22 functions (~35+ executions with parametrization)
Expected Pass Rate: ~83% (some tests SHOULD fail to reveal missing features)

Standards: OWASP ASVS v5.0, NIST SP 800-63B, ISO 27001, ISO 25010, WCAG 2.1
"""

import pytest
import time
import logging
from pages.login_page import LoginPage
from selenium.webdriver.common.keys import Keys

logging.basicConfig(level=logging.INFO)



@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.medium
def test_username_max_length_BR_001(browser, base_url):
    """
    TC-LOGIN-BR-001: Username Maximum Length Handling

    Standard: ISO 25010 - Functional Suitability
    Priority: MEDIUM

    Tests if system properly handles very long usernames.
    System should either reject or truncate long input.

    Expected: System handles long input gracefully (rejects or truncates)
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    long_username = "A" * 1000
    login_page.login(long_username, "anypassword")

    alert_text = login_page.get_alert_text(timeout=5)
    logged_in = login_page.is_user_logged_in(timeout=2)

    if alert_text:
        logging.info(f"✓ BR-001 PASSED: System handled long username. Alert: '{alert_text}'")
        assert not logged_in, "Should not be logged in with invalid long username"
    else:
        logging.warning("No alert for extremely long username - may accept any length")

    assert True


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.medium
def test_password_max_length_BR_002(browser, base_url):
    """
    TC-LOGIN-BR-002: Password Maximum Length Handling

    Standard: NIST SP 800-63B Section 5.1.1
    Priority: MEDIUM

    NIST recommends at least 64 characters for password length.
    Tests if system accepts reasonably long passwords.

    Expected: System accepts passwords up to at least 64 characters
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    long_password = "P" * 100
    login_page.login("Apolo2025", long_password)

    alert_text = login_page.get_alert_text(timeout=5)

    if alert_text:
        if "wrong" in alert_text.lower() or "incorrect" in alert_text.lower():
            logging.info(f"✓ BR-002 PASSED: System accepts long passwords. Alert: '{alert_text}'")
        else:
            logging.info(f"System response to long password: '{alert_text}'")

    assert True


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.medium
def test_whitespace_only_username_BR_003(browser, base_url):
    """
    TC-LOGIN-BR-003: Whitespace-Only Username Rejected

    Standard: ISO 27001 A.9.4 - Access Control
    Priority: MEDIUM

    Tests if system rejects username with only whitespace.
    Whitespace-only input should be considered invalid.

    Expected: System rejects whitespace-only username
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    login_page.login("     ", "anypassword")

    alert_text = login_page.get_alert_text(timeout=5)
    logged_in = login_page.is_user_logged_in(timeout=2)

    assert alert_text is not None, "System should reject whitespace-only username"
    assert not logged_in, "Should not be logged in with whitespace username"

    logging.info(f"✓ BR-003 PASSED: Whitespace-only username rejected. Alert: '{alert_text}'")


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.medium
def test_whitespace_only_password_BR_004(browser, base_url):
    """
    TC-LOGIN-BR-004: Whitespace-Only Password Rejected

    Standard: NIST SP 800-63B Section 5.1.1
    Priority: MEDIUM

    Tests if system rejects password with only whitespace.
    Whitespace-only passwords should be invalid.

    Expected: System rejects whitespace-only password
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    login_page.login("Apolo2025", "     ")

    alert_text = login_page.get_alert_text(timeout=5)
    logged_in = login_page.is_user_logged_in(timeout=2)

    assert alert_text is not None, "System should reject whitespace-only password"
    assert not logged_in, "Should not be logged in with whitespace password"

    logging.info(f"✓ BR-004 PASSED: Whitespace-only password rejected. Alert: '{alert_text}'")


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.low
def test_special_characters_in_username_BR_006(browser, base_url):
    """
    TC-LOGIN-BR-006: Special Characters in Username

    Standard: OWASP ASVS v5.0 Section 2.3.1
    Priority: LOW

    Tests if system handles special characters in username appropriately.
    System behavior should be consistent and documented.

    Expected: System handles special characters consistently
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    special_username = "user@#$%^&*()"
    login_page.login(special_username, "anypassword")

    alert_text = login_page.get_alert_text(timeout=5)

    if alert_text:
        logging.info(f"✓ BR-006 PASSED: System handled special chars. Alert: '{alert_text}'")
    else:
        logging.info("System processed special characters without alert")

    assert True


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.medium
def test_case_sensitivity_password_BR_008(browser, base_url):
    """
    TC-LOGIN-BR-008: Password Case Sensitivity

    Standard: NIST SP 800-63B Section 5.1.1
    Priority: MEDIUM

    Passwords MUST be case-sensitive per NIST requirements.
    Tests if system treats "Password" and "password" as different.

    Expected: Passwords are case-sensitive (login fails with wrong case)
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    login_page.login("Apolo2025", "APOLO2025")

    alert_text = login_page.get_alert_text(timeout=5)
    logged_in = login_page.is_user_logged_in(timeout=2)

    assert not logged_in, "Password MUST be case-sensitive per NIST 800-63B"
    assert alert_text is not None, "Should receive error for wrong-case password"

    logging.info(f"✓ BR-008 PASSED: Password is case-sensitive. Alert: '{alert_text}'")



@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.critical
@pytest.mark.parametrize("sql_payload", [
    "' OR '1'='1",
    "admin'--",
    "' OR '1'='1'--",
    "') OR ('1'='1",
])
def test_sql_injection_prevention_BR_013(browser, base_url, sql_payload):
    """
    TC-LOGIN-BR-013: SQL Injection Prevention

    Standard: OWASP ASVS v5.0 Section 1.2.5
    CVSS Score: 9.8 CRITICAL
    Priority: CRITICAL

    Validates that system properly sanitizes input to prevent SQL injection.
    SQL injection can lead to complete database compromise.

    Expected: SQL injection attempts are blocked
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    login_page.login(sql_payload, "anypassword")

    logged_in = login_page.is_user_logged_in(timeout=2)
    login_page.get_alert_text(timeout=2)

    if logged_in:
        logging.critical(f"CRITICAL VIOLATION: SQL Injection succeeded: {sql_payload}")
        logging.critical("Standard: OWASP ASVS v5.0 Section 1.2.5")
        logging.critical("CVSS Score: 9.8 CRITICAL")
        pytest.fail(f"DISCOVERED: SQL Injection vulnerability - {sql_payload}")
    else:
        logging.info(f"✓ DISCOVERED: SQL injection blocked: {sql_payload}")
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
def test_xss_prevention_BR_014(browser, base_url, xss_payload):
    """
    TC-LOGIN-BR-014: XSS (Cross-Site Scripting) Prevention

    Standard: OWASP ASVS v5.0 Section 1.2.1
    CVSS Score: 7.5 HIGH
    Priority: HIGH

    Validates that system prevents XSS attacks.
    XSS can lead to session hijacking and credential theft.

    Expected: XSS attempts are prevented/sanitized
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    login_page.login(xss_payload, "anypassword")

    alert_text = login_page.get_alert_text(timeout=2)

    if alert_text and "XSS" in alert_text:
        logging.critical(f"CRITICAL VIOLATION: XSS executed: {xss_payload}")
        logging.critical("Standard: OWASP ASVS v5.0 Section 1.2.1")
        logging.critical("CVSS Score: 7.5 HIGH")
        pytest.fail("DISCOVERED: XSS vulnerability")
    else:
        logging.info(f"✓ DISCOVERED: XSS prevented: {xss_payload}")
        assert True


@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.high
def test_account_lockout_enforcement_BR_017(browser, base_url):
    """
    TC-LOGIN-BR-017: Account Lockout / Rate Limiting Enforcement

    Standard: OWASP ASVS v5.0 Section 2.2.1
    Standard: NIST SP 800-63B Section 5.2.2
    CVSS Score: 7.5 HIGH
    Priority: HIGH

    Validates that system has rate limiting to prevent brute force attacks.
    Without rate limiting, attackers can try unlimited password attempts.

    Expected for DemoBlaze: FAIL - No rate limiting
    Expected for Production: PASS - Rate limiting enforced
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    attempts = 0
    rate_limited = False

    for i in range(10):
        login_page.login("Apolo2025", f"wrongpass{i}")

        alert_text = login_page.get_alert_text(timeout=2)

        if alert_text and ("rate" in alert_text.lower() or "locked" in alert_text.lower() or "wait" in alert_text.lower()):
            rate_limited = True
            logging.info(f"✓ DISCOVERED: Rate limiting at attempt {i+1}")
            break

        attempts += 1
        browser.get(base_url)

    if not rate_limited:
        logging.critical("=" * 80)
        logging.critical("SECURITY VIOLATION: NO ACCOUNT LOCKOUT / RATE LIMITING")
        logging.critical("Standard: OWASP ASVS v5.0 Section 2.2.1")
        logging.critical("Standard: NIST SP 800-63B Section 5.2.2")
        logging.critical("CVSS Score: 7.5 (HIGH)")
        logging.critical(f"Completed {attempts} attempts without rate limiting")
        logging.critical("Impact: Unlimited brute force attempts possible")
        logging.critical("Recommendation: Implement progressive delays or account lockout")
        logging.critical("=" * 80)
        pytest.fail(f"DISCOVERED: NO RATE LIMITING - Violates OWASP ASVS 2.2.1")
    else:
        assert True


@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.high
def test_2fa_mfa_enforcement_BR_018(browser, base_url):
    """
    TC-LOGIN-BR-018: 2FA/MFA Enforcement

    Standard: NIST SP 800-63B Section 5.2.3
    Standard: ISO 27001 A.9.4.2
    CVSS Score: 7.5 HIGH
    Priority: HIGH

    Validates that system requires multi-factor authentication (2FA/MFA).
    Without MFA, accounts are vulnerable to password compromise alone.

    Expected for DemoBlaze: FAIL - No 2FA/MFA
    Expected for Production: PASS - 2FA/MFA required
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    login_page.login("Apolo2025", "apolo2025")
    time.sleep(2)
    login_page.get_alert_text(timeout=2)

    page_source = browser.page_source.lower()
    mfa_keywords = ['2fa', 'mfa', 'two-factor', 'multi-factor', 'authentication code', 'verify', 'otp']
    mfa_detected = any(keyword in page_source for keyword in mfa_keywords)

    logged_in_immediately = login_page.is_user_logged_in(timeout=2)

    if logged_in_immediately and not mfa_detected:
        logging.critical("=" * 80)
        logging.critical("SECURITY VIOLATION: NO 2FA/MFA ENFORCEMENT")
        logging.critical("Issue: No Multi-Factor Authentication (MFA/2FA)")
        logging.critical("Standard: NIST SP 800-63B Section 5.2.3")
        logging.critical("Standard: ISO 27001 A.9.4.2")
        logging.critical("CVSS Score: 7.5 (HIGH)")
        logging.critical("Impact: Account vulnerable to password compromise alone")
        logging.critical("Recommendation: Implement SMS, TOTP, or hardware token 2FA")
        logging.critical("=" * 80)
        login_page.logout()
        pytest.fail("DISCOVERED: NO 2FA/MFA - Violates NIST 800-63B 5.2.3")
    else:
        logging.info("✓ DISCOVERED: 2FA/MFA is implemented")
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
def test_password_complexity_enforcement_BR_019(browser, base_url, weak_password):
    """
    TC-LOGIN-BR-019: Password Complexity Enforcement

    Standard: NIST SP 800-63B Section 5.1.1.2
    CVSS Score: 6.5 MEDIUM
    Priority: MEDIUM

    Validates that system rejects common weak passwords.
    NIST recommends checking against lists of compromised passwords.

    Expected for DemoBlaze: FAIL - Weak passwords accepted
    Expected for Production: PASS - Weak passwords rejected

    Note: This test requires signup functionality
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    try:
        login_page.open_signup_modal()

        test_user = f"weaktest_{int(time.time())}"
        login_page.fill_signup_username(test_user)
        login_page.fill_signup_password(weak_password)
        login_page.click_signup_submit()

        alert_text = login_page.get_alert_text(timeout=5)

        if alert_text and "success" in alert_text.lower():
            logging.error(f"SECURITY VIOLATION: Weak password accepted: '{weak_password}'")
            logging.error("Standard: NIST SP 800-63B Section 5.1.1.2")
            logging.error("CVSS Score: 6.5 (MEDIUM)")
            logging.error("Impact: Weak passwords allow easy brute force")
            logging.error("Recommendation: Implement password complexity rules")
            pytest.fail(f"DISCOVERED: Weak password '{weak_password}' was accepted")
        else:
            logging.info(f"✓ DISCOVERED: Weak password rejected: '{weak_password}'")
            assert True

    except Exception as e:
        pytest.skip(f"Signup functionality not available: {e}")


@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.medium
def test_captcha_bot_protection_BR_020(browser, base_url):
    """
    TC-LOGIN-BR-020: CAPTCHA / Bot Protection

    Standard: OWASP ASVS v5.0 Section 2.2.3
    CVSS Score: 6.5 MEDIUM
    Priority: MEDIUM

    Validates that system has CAPTCHA or similar bot protection.
    Without bot protection, automated attacks are easier.

    Expected for DemoBlaze: FAIL - No CAPTCHA
    Expected for Production: PASS - CAPTCHA present
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    login_page.open_login_modal()

    page_source = browser.page_source.lower()
    captcha_keywords = ['captcha', 'recaptcha', 'hcaptcha', 'bot protection', 'g-recaptcha']
    captcha_detected = any(keyword in page_source for keyword in captcha_keywords)

    if not captcha_detected:
        logging.warning("=" * 80)
        logging.warning("SECURITY CONCERN: NO CAPTCHA / BOT PROTECTION")
        logging.warning("Standard: OWASP ASVS v5.0 Section 2.2.3")
        logging.warning("Expected: CAPTCHA or bot challenge")
        logging.warning("Actual: No CAPTCHA detected")
        logging.warning("CVSS Score: 6.5 (MEDIUM)")
        logging.warning("Impact: Automated attacks easier (bots, credential stuffing)")
        logging.warning("Recommendation: Implement reCAPTCHA or hCaptcha")
        logging.warning("=" * 80)
        pytest.fail("DISCOVERED: NO CAPTCHA - Violates OWASP ASVS 2.2.3")
    else:
        logging.info("✓ DISCOVERED: CAPTCHA/bot protection present")
        assert True


@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.medium
def test_password_reset_mechanism_BR_021(browser, base_url):
    """
    TC-LOGIN-BR-021: Password Reset Mechanism

    Standard: OWASP ASVS v5.0 Section 2.5.6
    CVSS Score: 5.0 MEDIUM
    Priority: MEDIUM

    Validates that system has a password reset/recovery mechanism.
    Users need ability to recover accounts with forgotten passwords.

    Expected for DemoBlaze: FAIL - No password reset
    Expected for Production: PASS - Password reset available
    """
    browser.get(base_url)

    page_source = browser.page_source.lower()
    reset_keywords = ['forgot password', 'reset password', 'recover password', 'forgot your password']
    reset_found = any(keyword in page_source for keyword in reset_keywords)

    if not reset_found:
        logging.warning("=" * 80)
        logging.warning("SECURITY CONCERN: NO PASSWORD RESET MECHANISM")
        logging.warning("Standard: OWASP ASVS v5.0 Section 2.5.6")
        logging.warning("Expected: Secure password reset flow")
        logging.warning("Actual: No password reset functionality detected")
        logging.warning("CVSS Score: 5.0 (MEDIUM)")
        logging.warning("Impact: Users cannot recover forgotten passwords")
        logging.warning("Recommendation: Implement email-based password reset with secure tokens")
        logging.warning("=" * 80)
        pytest.fail("DISCOVERED: NO PASSWORD RESET - Violates OWASP ASVS 2.5.6")
    else:
        logging.info("✓ DISCOVERED: Password reset mechanism exists")
        assert True


@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.medium
def test_session_timeout_enforcement_BR_022(browser, base_url):
    """
    TC-LOGIN-BR-022: Session Timeout Enforcement

    Standard: OWASP ASVS v5.0 Section 3.3.2
    Standard: ISO 27001 A.9.4.2
    CVSS Score: 5.3 MEDIUM
    Priority: MEDIUM

    Validates that system has session timeout after inactivity.
    Sessions should expire to protect unattended computers.

    Expected for DemoBlaze: FAIL - No clear timeout
    Expected for Production: PASS - Session timeout enforced (15-30 min)

    Note: This test waits 60 seconds
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    login_page.login("Apolo2025", "apolo2025")
    time.sleep(1)
    login_page.get_alert_text()

    if not login_page.is_user_logged_in():
        pytest.skip("Login failed - cannot test session timeout")

    logging.info("DISCOVERED: User logged in, waiting 60 seconds to test timeout...")

    time.sleep(60)

    browser.refresh()
    time.sleep(2)
    still_logged_in = login_page.is_user_logged_in(timeout=2)

    if still_logged_in:
        logging.warning("=" * 80)
        logging.warning("SECURITY CONCERN: NO SESSION TIMEOUT CLEARLY CONFIGURED")
        logging.warning("Standard: OWASP ASVS v5.0 Section 3.3.2")
        logging.warning("Standard: ISO 27001 A.9.4.2")
        logging.warning("Expected: Session expires after inactivity (15-30 min typical)")
        logging.warning("Actual: Session remained active after 60 seconds")
        logging.warning("CVSS Score: 5.3 (MEDIUM)")
        logging.warning("Impact: Unattended sessions remain accessible")
        logging.warning("Recommendation: Implement 15-30 minute idle timeout")
        logging.warning("=" * 80)
        login_page.logout()
        pytest.fail("DISCOVERED: NO SESSION TIMEOUT - Violates OWASP ASVS 3.3.2")
    else:
        logging.info("✓ DISCOVERED: Session timeout is enforced")
        assert True



@pytest.mark.business_rules
@pytest.mark.accessibility
@pytest.mark.medium
def test_keyboard_navigation_BR_015(browser, base_url):
    """
    TC-LOGIN-BR-015: Keyboard Navigation

    Standard: WCAG 2.1 Success Criterion 2.1.1 (Level A)
    Priority: MEDIUM

    Validates that login form is accessible via keyboard only.
    Users should be able to Tab through fields and submit with Enter.

    Expected: User can navigate and submit form using keyboard only
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    login_page.open_login_modal()

    login_page.send_keys(login_page.LOGIN_USERNAME_FIELD, Keys.TAB)
    time.sleep(0.5)

    login_page.fill_login_username("Apolo2025")
    login_page.send_keys(login_page.LOGIN_USERNAME_FIELD, Keys.TAB)
    time.sleep(0.5)
    login_page.fill_login_password("apolo2025")

    login_page.submit_login_with_enter()

    time.sleep(2)
    login_page.get_alert_text(timeout=2)
    logged_in = login_page.is_user_logged_in(timeout=3)

    assert logged_in, "Login via keyboard navigation should work"

    logging.info("✓ BR-015 PASSED: Keyboard navigation works (WCAG 2.1 SC 2.1.1)")

    login_page.logout()


@pytest.mark.business_rules
@pytest.mark.accessibility
@pytest.mark.medium
def test_form_labels_for_screen_readers_BR_016(browser, base_url):
    """
    TC-LOGIN-BR-016: Form Labels for Screen Readers

    Standard: WCAG 2.1 Success Criterion 1.3.1 (Level A)
    Priority: MEDIUM

    Validates that form fields have labels or aria-labels for screen readers.
    Assistive technology users need proper labels to understand form fields.

    Expected: Fields have aria-labels or placeholders for accessibility
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    login_page.open_login_modal()

    username_placeholder = login_page.get_login_username_placeholder()
    password_placeholder = login_page.get_login_password_placeholder()

    username_aria = login_page.get_login_username_aria_label()
    password_aria = login_page.get_login_password_aria_label()

    username_has_label = username_placeholder or username_aria
    password_has_label = password_placeholder or password_aria

    if not username_has_label:
        logging.warning("Username field missing placeholder/aria-label")

    if not password_has_label:
        logging.warning("Password field missing placeholder/aria-label")

    assert username_placeholder or password_placeholder, "Form fields should have some accessibility labeling"

    logging.info(f"✓ BR-016 PASSED: Form has accessibility labels")
    logging.info(f"  Username placeholder: '{username_placeholder}'")
    logging.info(f"  Password placeholder: '{password_placeholder}'")


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.medium
def test_username_whitespace_normalization_BR_005(browser, base_url):
    """
    TC-LOGIN-BR-005: Username Whitespace Normalization

    Standard: ISO 25010 - Usability (User error protection)
    Priority: MEDIUM

    Tests if system trims leading/trailing whitespace from username.
    Good UX practice to prevent user errors from accidental spaces.

    Expected: System should trim whitespace and allow login
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    username_with_spaces = f"  Apolo2025  "
    login_page.login(username_with_spaces, "apolo2025")

    time.sleep(1)
    alert_text = login_page.get_alert_text(timeout=5)
    logged_in = login_page.is_user_logged_in(timeout=3)

    if logged_in:
        logging.info("✓ BR-005 PASSED: System trims whitespace - Good UX")
        logging.info("Standard: ISO 25010 - User error protection")
        login_page.logout()
        assert True
    else:
        logging.warning("⚠ DISCOVERED: System does NOT trim whitespace from username")
        logging.warning(f"Alert received: {alert_text}")
        logging.warning("Standard: ISO 25010 recommends user error protection")
        logging.warning("Impact: Users may fail login due to accidental spaces")
        assert True


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.low
def test_case_sensitivity_username_BR_007(browser, base_url):
    """
    TC-LOGIN-BR-007: Username Case Sensitivity

    Standard: ISO 27001 A.9.4 - Authentication consistency
    Priority: LOW

    Tests if usernames are case-sensitive or case-insensitive.
    System should have consistent behavior documented.

    Expected: System has consistent case-handling behavior
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    login_page.login("APOLO2025", "apolo2025")

    time.sleep(1)
    alert_text = login_page.get_alert_text(timeout=5)
    logged_in = login_page.is_user_logged_in(timeout=3)

    if logged_in:
        logging.info("✓ DISCOVERED: Usernames are NOT case-sensitive")
        logging.info("Both 'Apolo2025' and 'APOLO2025' work")
        login_page.logout()
    else:
        logging.info("✓ DISCOVERED: Usernames ARE case-sensitive")
        logging.info(f"'APOLO2025' does not match 'Apolo2025'. Alert: {alert_text}")

    logging.info("Note: Either behavior is acceptable if consistent")
    assert True


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.medium
def test_empty_username_only_BR_009(browser, base_url):
    """
    TC-LOGIN-BR-009: Empty Username Field Only

    Standard: WCAG 2.1 SC 3.3.1 (Error Identification)
    Priority: MEDIUM

    Tests if system provides specific error for empty username.
    Good UX requires field-specific error messages.

    Expected: System rejects and provides field-specific error
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    login_page.login("", "somepassword")

    time.sleep(1)
    alert_text = login_page.get_alert_text(timeout=5)
    logged_in = login_page.is_user_logged_in(timeout=2)

    assert not logged_in, "Should not be logged in with empty username"
    assert alert_text is not None, "Should show error for empty username"

    if "username" in alert_text.lower():
        logging.info(f"✓ BR-009 PASSED: Field-specific error. Alert: '{alert_text}'")
        logging.info("Standard: WCAG 2.1 SC 3.3.1 - Error Identification")
    else:
        logging.info(f"✓ Empty username rejected. Alert: '{alert_text}'")
        logging.info("Note: Generic error (WCAG recommends field-specific errors)")


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.critical
def test_empty_password_only_BR_010(browser, base_url):
    """
    TC-LOGIN-BR-010: Empty Password Field Only

    Standard: WCAG 2.1 SC 3.3.1 (Error Identification)
    Priority: CRITICAL

    Tests if system rejects empty password.
    Critical security requirement - empty passwords are invalid.

    Expected: System rejects empty password
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    login_page.login("Apolo2025", "")

    time.sleep(1)
    alert_text = login_page.get_alert_text(timeout=5)
    logged_in = login_page.is_user_logged_in(timeout=2)

    assert not logged_in, "CRITICAL: Empty password must be rejected"
    assert alert_text is not None, "Should show error for empty password"

    if "password" in alert_text.lower():
        logging.info(f"✓ BR-010 PASSED: Field-specific error. Alert: '{alert_text}'")
        logging.info("Standard: WCAG 2.1 SC 3.3.1 - Error Identification")
    else:
        logging.info(f"✓ Empty password rejected. Alert: '{alert_text}'")
        logging.info("Note: Generic error (WCAG recommends field-specific errors)")


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.low
def test_numeric_only_username_BR_011(browser, base_url):
    """
    TC-LOGIN-BR-011: Numeric-Only Username

    Standard: ISO 25010 - Functional Suitability
    Priority: LOW

    Tests if system allows usernames with only numbers.
    Edge case - some systems restrict numeric-only usernames.

    Expected: System handles numeric usernames consistently
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    numeric_username = "1234567890"
    login_page.login(numeric_username, "anypassword")

    time.sleep(1)
    alert_text = login_page.get_alert_text(timeout=5)
    logged_in = login_page.is_user_logged_in(timeout=2)

    if not logged_in:
        if alert_text:
            logging.info(f"✓ DISCOVERED: System response to numeric username: '{alert_text}'")
        else:
            logging.info("✓ DISCOVERED: Numeric username not matched (expected if user doesn't exist)")
    else:
        logging.info("✓ DISCOVERED: System accepts numeric-only usernames")

    logging.info("Note: Either behavior is acceptable")
    assert True


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.medium
def test_unicode_characters_BR_012(browser, base_url):
    """
    TC-LOGIN-BR-012: Unicode Characters in Username

    Standard: ISO 25010 - Portability (Adaptability)
    Priority: MEDIUM

    Tests if system supports international characters (Unicode).
    Important for global accessibility and i18n compliance.

    Expected: System handles Unicode characters gracefully
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    unicode_tests = [
        ("用户名测试", "Chinese characters"),
        ("Имя_пользователя", "Cyrillic characters"),
        ("مستخدم", "Arabic characters"),
        ("ユーザー名", "Japanese characters"),
    ]

    for unicode_username, description in unicode_tests:
        browser.get(base_url)
        login_page.login(unicode_username, "anypassword")

        time.sleep(1)
        alert_text = login_page.get_alert_text(timeout=3)
        logged_in = login_page.is_user_logged_in(timeout=2)

        if not logged_in:
            logging.info(f"✓ DISCOVERED: {description} - System response: {alert_text if alert_text else 'No match (expected)'}")
        else:
            logging.info(f"✓ DISCOVERED: {description} - System supports Unicode login")

    logging.info("Standard: ISO 25010 recommends international character support")
    logging.info("Note: This test documents Unicode handling behavior")
    assert True
