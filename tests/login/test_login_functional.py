"""
Login Functional Tests
Author: Marc Arévalo
Version: 3.0 - Restructured with Page Object Model

Tests basic login/logout functionality.
These tests verify that the core features work as expected.

Total Tests: 7
Expected Pass Rate: 100%
"""

import pytest
import logging
from pages.login_page import LoginPage

logging.basicConfig(level=logging.INFO)


@pytest.mark.functional
@pytest.mark.critical
def test_valid_login_success_FUNC_001(browser, base_url):
    """
    TC-LOGIN-FUNC-001: Valid Login Success

    Priority: CRITICAL
    Objective: Verify successful authentication with valid credentials

    Steps:
    1. Open login modal
    2. Enter valid username and password
    3. Submit login form
    4. Verify user is logged in
    5. Verify welcome message contains username

    Expected Result: User successfully authenticates
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    # Perform login
    login_page.login("Apolo2025", "apolo2025")

    # Wait for potential alert
    alert_text = login_page.get_alert_text(timeout=5)
    if alert_text:
        logging.warning(f"Alert received: {alert_text}")

    # Verify login success
    assert login_page.is_user_logged_in(), "User should be logged in after valid credentials"

    welcome_msg = login_page.get_welcome_message()
    assert welcome_msg is not None, "Welcome message should be present"
    assert "Apolo2025" in welcome_msg, f"Welcome message should contain username. Got: {welcome_msg}"

    logging.info("✓ FUNC-001 PASSED: Valid login successful")

    # Cleanup
    login_page.logout()


@pytest.mark.functional
@pytest.mark.high
def test_invalid_username_rejected_FUNC_002(browser, base_url):
    """
    TC-LOGIN-FUNC-002: Invalid Username Rejected

    Priority: HIGH (Security)
    Objective: Verify system rejects non-existent usernames

    Steps:
    1. Open login modal
    2. Enter non-existent username
    3. Enter any password
    4. Submit login
    5. Verify login is rejected

    Expected Result: Login rejected, error message appears
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    # Attempt login with invalid username
    login_page.login("nonexistent_user_99999", "anypassword")

    # Wait for alert (error message)
    alert_text = login_page.get_alert_text(timeout=5)

    assert alert_text is not None, "Error alert should appear for invalid username"
    assert not login_page.is_user_logged_in(), "User should NOT be logged in with invalid username"

    logging.info(f"✓ FUNC-002 PASSED: Invalid username rejected. Alert: '{alert_text}'")


@pytest.mark.functional
@pytest.mark.critical
def test_invalid_password_rejected_FUNC_003(browser, base_url):
    """
    TC-LOGIN-FUNC-003: Invalid Password Rejected

    Priority: CRITICAL (Security)
    Objective: Verify system rejects wrong passwords

    Steps:
    1. Open login modal
    2. Enter valid username
    3. Enter wrong password
    4. Submit login
    5. Verify login is rejected

    Expected Result: Login rejected, error message appears
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    # Attempt login with wrong password
    login_page.login("Apolo2025", "wrong_password_12345")

    # Wait for alert (error message)
    alert_text = login_page.get_alert_text(timeout=5)

    assert alert_text is not None, "Error alert should appear for wrong password"
    assert not login_page.is_user_logged_in(), "User should NOT be logged in with wrong password"

    logging.info(f"✓ FUNC-003 PASSED: Invalid password rejected. Alert: '{alert_text}'")


@pytest.mark.functional
@pytest.mark.high
def test_empty_credentials_rejected_FUNC_004(browser, base_url):
    """
    TC-LOGIN-FUNC-004: Empty Credentials Rejected

    Priority: HIGH
    Objective: Verify validation for empty username and password fields

    Steps:
    1. Open login modal
    2. Leave both fields empty
    3. Submit login
    4. Verify login is rejected

    Expected Result: Login rejected, validation message appears
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    # Attempt login with empty credentials
    login_page.login("", "")

    # Wait for alert (validation message)
    alert_text = login_page.get_alert_text(timeout=5)

    assert alert_text is not None, "Validation alert should appear for empty credentials"
    assert not login_page.is_user_logged_in(), "User should NOT be logged in with empty credentials"

    logging.info(f"✓ FUNC-004 PASSED: Empty credentials rejected. Alert: '{alert_text}'")


@pytest.mark.functional
@pytest.mark.critical
def test_complete_login_logout_flow_FUNC_005(browser, base_url):
    """
    TC-LOGIN-FUNC-005: Complete Login-Logout Flow

    Priority: CRITICAL
    Objective: Verify full authentication cycle (login → logout)

    Steps:
    1. Login with valid credentials
    2. Verify user is logged in
    3. Logout
    4. Verify user is logged out

    Expected Result: Both login and logout operations work correctly
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    # Step 1: Login
    login_page.login("Apolo2025", "apolo2025")
    login_page.get_alert_text(timeout=5)  # Handle potential alert

    # Step 2: Verify logged in
    assert login_page.is_user_logged_in(), "User should be logged in"
    logging.info("✓ Login successful")

    # Step 3: Logout
    login_page.logout()

    # Step 4: Verify logged out
    assert not login_page.is_user_logged_in(), "User should be logged out"
    assert login_page.is_element_visible(login_page.LOGIN_BUTTON_NAV, timeout=3), "Login button should be visible after logout"

    logging.info("✓ FUNC-005 PASSED: Complete login-logout cycle successful")


@pytest.mark.functional
@pytest.mark.medium
def test_modal_close_button_FUNC_006(browser, base_url):
    """
    TC-LOGIN-FUNC-006: Login Modal Close Button

    Priority: MEDIUM (UX)
    Objective: Verify login modal can be closed

    Steps:
    1. Open login modal
    2. Click close button
    3. Verify modal closes
    4. Verify user remains logged out

    Expected Result: Modal closes, user remains logged out
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    # Step 1: Open modal
    login_page.open_login_modal()
    assert login_page.is_login_modal_visible(), "Login modal should be visible"

    # Step 2: Close modal
    login_page.close_login_modal()

    # Step 3: Verify modal closed
    assert not login_page.is_login_modal_visible(), "Login modal should be closed"

    # Step 4: Verify still logged out
    assert not login_page.is_user_logged_in(), "User should remain logged out"

    logging.info("✓ FUNC-006 PASSED: Login modal close button works")


@pytest.mark.functional
@pytest.mark.high
def test_session_persistence_after_reload_FUNC_007(browser, base_url):
    """
    TC-LOGIN-FUNC-007: Session Persistence After Page Reload

    Priority: HIGH
    Objective: Verify session persists after browser refresh

    Steps:
    1. Login with valid credentials
    2. Verify user is logged in
    3. Refresh browser
    4. Verify user is still logged in

    Expected Result: User remains logged in after page reload
    """
    browser.get(base_url)
    login_page = LoginPage(browser)

    # Step 1: Login
    login_page.login("Apolo2025", "apolo2025")
    login_page.get_alert_text(timeout=5)  # Handle potential alert

    # Step 2: Verify logged in
    assert login_page.is_user_logged_in(), "User should be logged in before reload"
    logging.info("✓ Logged in successfully")

    # Step 3: Refresh page
    login_page.refresh_page()
    login_page.wait(2)  # Wait for page to fully reload

    # Step 4: Verify still logged in
    assert login_page.is_user_logged_in(), "User should remain logged in after page reload (session persistence)"

    logging.info("✓ FUNC-007 PASSED: Session persisted after reload")

    # Cleanup
    login_page.logout()
