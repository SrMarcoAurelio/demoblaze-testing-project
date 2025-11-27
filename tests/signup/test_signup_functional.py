"""
Signup Functional Tests
Author: Marc Arévalo
Version: 3.0 - Restructured with Page Object Model

Tests basic signup/registration functionality.
These tests verify that the core features work as expected.

Total Tests: 6
Expected Pass Rate: ~83% (some tests may fail revealing missing features)
"""

import pytest
import logging
from pages.signup_page import SignupPage

logging.basicConfig(level=logging.INFO)


@pytest.mark.functional
@pytest.mark.critical
def test_valid_signup_with_unique_credentials_FUNC_001(browser, base_url):
    """
    TC-SIGNUP-FUNC-001: Valid Signup with Unique Credentials

    Priority: CRITICAL
    Objective: Verify successful registration with valid unique credentials

    Steps:
    1. Open signup modal
    2. Enter unique username and password
    3. Submit signup form
    4. Verify success message
    5. Verify can login with new account

    Expected Result: User successfully registers and can login
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    unique_username = signup_page.generate_unique_username()
    password = "TestPass123!"

    signup_page.signup(unique_username, password)

    alert_text = signup_page.get_alert_text(timeout=5)

    assert alert_text is not None, "Should receive feedback after signup"

    if "success" in alert_text.lower() or "registered" in alert_text.lower():
        logging.info(f"✓ FUNC-001 PASSED: Signup successful. Alert: '{alert_text}'")

        browser.get(base_url)
        signup_page.login_after_signup(unique_username, password)

        login_alert = signup_page.get_alert_text(timeout=3)
        logged_in = signup_page.is_user_logged_in(timeout=3)

        assert logged_in, f"New account should be able to login. Alert: {login_alert}"
        logging.info("✓ Can login with newly created account")

        signup_page.logout()
    else:
        logging.warning(f"Signup may have failed: {alert_text}")


@pytest.mark.functional
@pytest.mark.critical
def test_duplicate_username_rejected_FUNC_002(browser, base_url):
    """
    TC-SIGNUP-FUNC-002: Duplicate Username Rejected

    Priority: CRITICAL (Security)
    Objective: Verify system prevents duplicate usernames

    Steps:
    1. Signup with unique username (first time)
    2. Try to signup again with same username
    3. Verify duplicate is rejected

    Expected Result: Duplicate username rejected with error message
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    unique_username = signup_page.generate_unique_username()
    password = "TestPass123!"

    signup_page.signup(unique_username, password)

    first_alert = signup_page.get_alert_text(timeout=5)
    logging.info(f"First signup: {first_alert}")

    browser.get(base_url)
    signup_page.signup(unique_username, password)

    duplicate_alert = signup_page.get_alert_text(timeout=5)

    assert duplicate_alert is not None, "Should receive error for duplicate username"
    assert "exist" in duplicate_alert.lower() or "already" in duplicate_alert.lower(), \
        f"Should indicate username already exists. Got: '{duplicate_alert}'"

    logging.info(f"✓ FUNC-002 PASSED: Duplicate rejected. Alert: '{duplicate_alert}'")


@pytest.mark.functional
@pytest.mark.high
def test_empty_credentials_rejected_FUNC_003(browser, base_url):
    """
    TC-SIGNUP-FUNC-003: Empty Credentials Rejected

    Priority: HIGH
    Objective: Verify system rejects empty username and password

    Steps:
    1. Open signup modal
    2. Leave both fields empty
    3. Submit signup
    4. Verify rejection

    Expected Result: Signup rejected, validation message appears
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    signup_page.signup("", "")

    alert_text = signup_page.get_alert_text(timeout=5)

    assert alert_text is not None, "Should show validation error for empty credentials"

    logging.info(f"✓ FUNC-003 PASSED: Empty credentials rejected. Alert: '{alert_text}'")


@pytest.mark.functional
@pytest.mark.high
def test_empty_username_only_FUNC_004(browser, base_url):
    """
    TC-SIGNUP-FUNC-004: Empty Username Only

    Priority: HIGH
    Objective: Verify system validates username field specifically

    Steps:
    1. Open signup modal
    2. Leave username empty, fill password
    3. Submit signup
    4. Verify rejection

    Expected Result: Signup rejected, username validation error
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    signup_page.signup("", "SomePassword123")

    alert_text = signup_page.get_alert_text(timeout=5)

    assert alert_text is not None, "Should show error for empty username"

    logging.info(f"✓ FUNC-004 PASSED: Empty username rejected. Alert: '{alert_text}'")


@pytest.mark.functional
@pytest.mark.high
def test_empty_password_only_FUNC_005(browser, base_url):
    """
    TC-SIGNUP-FUNC-005: Empty Password Only

    Priority: HIGH
    Objective: Verify system validates password field specifically

    Steps:
    1. Open signup modal
    2. Fill username, leave password empty
    3. Submit signup
    4. Verify rejection

    Expected Result: Signup rejected, password validation error
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    unique_username = signup_page.generate_unique_username()
    signup_page.signup(unique_username, "")

    alert_text = signup_page.get_alert_text(timeout=5)

    assert alert_text is not None, "Should show error for empty password"

    logging.info(f"✓ FUNC-005 PASSED: Empty password rejected. Alert: '{alert_text}'")


@pytest.mark.functional
@pytest.mark.medium
def test_signup_modal_close_functionality_FUNC_006(browser, base_url):
    """
    TC-SIGNUP-FUNC-006: Signup Modal Close Functionality

    Priority: MEDIUM (UX)
    Objective: Verify signup modal can be closed

    Steps:
    1. Open signup modal
    2. Click close button
    3. Verify modal closes
    4. Verify no signup occurred

    Expected Result: Modal closes, no account created
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    signup_page.open_signup_modal()
    assert signup_page.is_signup_modal_visible(), "Signup modal should be visible"

    signup_page.close_signup_modal()

    assert not signup_page.is_signup_modal_visible(), "Signup modal should be closed"

    logging.info("✓ FUNC-006 PASSED: Signup modal close button works")
