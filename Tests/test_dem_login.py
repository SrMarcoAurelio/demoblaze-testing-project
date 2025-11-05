"""
Test Suite: Login & Authentication
Module: test_dem_login.py
Author: Arévalo, Marc
Description: Automated tests for DemoBlaze login functionality
Related Bugs: #10, #11, #12
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service
import pytest
import time


BASE_URL = "https://www.demoblaze.com/"
TIMEOUT = 10
TEST_USERNAME = "testuser_qa_2024"
TEST_PASSWORD = "SecurePass123!"

LOGIN_BUTTON_NAV = "login2"
LOGIN_USERNAME_FIELD = "loginusername"
LOGIN_PASSWORD_FIELD = "loginpassword"
LOGIN_SUBMIT_BUTTON = "//button[text()='Log in']"
LOGOUT_BUTTON = "logout2"
WELCOME_USER_TEXT = "nameofuser"


@pytest.fixture
def browser():
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service)
    driver.maximize_window()
    driver.implicitly_wait(TIMEOUT)
    
    yield driver
    
    driver.quit()


@pytest.fixture
def login_page(browser):
    browser.get(BASE_URL)
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.presence_of_element_located((By.ID, LOGIN_BUTTON_NAV))
    )
    
    login_btn = browser.find_element(By.ID, LOGIN_BUTTON_NAV)
    login_btn.click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located((By.ID, LOGIN_USERNAME_FIELD))
    )
    
    return browser


def perform_login(browser, username, password):
    username_field = browser.find_element(By.ID, LOGIN_USERNAME_FIELD)
    username_field.clear()
    username_field.send_keys(username)
    
    password_field = browser.find_element(By.ID, LOGIN_PASSWORD_FIELD)
    password_field.clear()
    password_field.send_keys(password)
    
    submit_btn = browser.find_element(By.XPATH, LOGIN_SUBMIT_BUTTON)
    submit_btn.click()


def wait_for_alert_and_get_text(browser, timeout=TIMEOUT):
    try:
        WebDriverWait(browser, timeout).until(EC.alert_is_present())
        alert = browser.switch_to.alert
        alert_text = alert.text
        alert.accept()
        return alert_text
    except TimeoutException:
        return None


def is_user_logged_in(browser):
    try:
        browser.find_element(By.ID, LOGOUT_BUTTON)
        return True
    except:
        return False


def test_login_valid_credentials(login_page):
    """
    TC-LOGIN-001: Valid Login
    
    Test that user can successfully login with valid credentials.
    
    Steps:
    1. Navigate to login page (done by fixture)
    2. Enter valid username
    3. Enter valid password
    4. Click submit
    5. Verify user is logged in
    
    Expected Result:
    - Login successful
    - "Log out" button visible
    - Username displayed in navbar
    """
    perform_login(login_page, TEST_USERNAME, TEST_PASSWORD)
    time.sleep(2)
    
    assert is_user_logged_in(login_page), "User should be logged in after valid credentials"
    
    welcome_element = login_page.find_element(By.ID, WELCOME_USER_TEXT)
    assert TEST_USERNAME in welcome_element.text, f"Welcome message should contain username '{TEST_USERNAME}'"


def test_login_invalid_password(login_page):
    """
    TC-LOGIN-002: Invalid Password
    
    Test that login fails with incorrect password.
    
    Steps:
    1. Enter valid username
    2. Enter INVALID password
    3. Click submit
    4. Verify error message appears
    
    Expected Result:
    - Login fails
    - Alert shows: "Wrong password."
    - User remains logged out
    """
    perform_login(login_page, TEST_USERNAME, "wrongpassword123")
    alert_text = wait_for_alert_and_get_text(login_page)
    
    assert alert_text == "Wrong password.", f"Expected 'Wrong password.' but got '{alert_text}'"
    assert not is_user_logged_in(login_page), "User should NOT be logged in with wrong password"


def test_login_nonexistent_user(login_page):
    """
    TC-LOGIN-003: Non-existent User
    
    Test that login fails for user that doesn't exist.
    
    Steps:
    1. Enter non-existent username
    2. Enter any password
    3. Click submit
    4. Verify error message
    
    Expected Result:
    - Login fails
    - Alert shows: "User does not exist."
    - User remains logged out
    """
    perform_login(login_page, "nonexistent_user_xyz_999", "anypassword")
    alert_text = wait_for_alert_and_get_text(login_page)
    
    assert alert_text == "User does not exist.", f"Expected 'User does not exist.' but got '{alert_text}'"
    assert not is_user_logged_in(login_page), "User should NOT be logged in with invalid username"


def test_login_empty_fields(login_page):
    """
    TC-LOGIN-004: Empty Fields
    
    Test validation when fields are left empty.
    
    Steps:
    1. Leave username empty
    2. Leave password empty
    3. Click submit
    4. Verify validation message
    
    Expected Result:
    - Login fails
    - Alert shows: "Please fill out Username and Password."
    """
    perform_login(login_page, "", "")
    alert_text = wait_for_alert_and_get_text(login_page)
    
    assert alert_text == "Please fill out Username and Password.", \
        f"Expected validation message but got '{alert_text}'"


@pytest.mark.xfail(reason="Bug #11: System accepts weak passwords")
def test_login_weak_password_vulnerability(browser):
    """
    TC-LOGIN-005: Weak Password Acceptance (Bug #11)
    
    Security test: Verify system incorrectly accepts weak passwords.
    
    This test is marked as xfail (expected to fail) because it tests
    a KNOWN BUG. When the bug is fixed, this test should PASS.
    
    Steps:
    1. Register user with weak password "123"
    2. Attempt login with that weak password
    
    Current Behavior (BUG):
    - System accepts "123" as valid password
    
    Expected Behavior (AFTER FIX):
    - System should reject weak passwords
    - Should require: 8+ chars, uppercase, lowercase, numbers, symbols
    
    Related: Bug #11 - Weak password acceptance
    """
    timestamp = str(int(time.time()))
    test_user = f"weakpass_test_{timestamp}"
    weak_password = "123"
    
    browser.get(BASE_URL)
    
    signup_btn = browser.find_element(By.ID, "signin2")
    signup_btn.click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located((By.ID, "sign-username"))
    )
    
    browser.find_element(By.ID, "sign-username").send_keys(test_user)
    browser.find_element(By.ID, "sign-password").send_keys(weak_password)
    browser.find_element(By.XPATH, "//button[text()='Sign up']").click()
    
    alert_text = wait_for_alert_and_get_text(browser)
    
    assert "Password too weak" in alert_text or "password requirements" in alert_text.lower(), \
        "System should reject weak passwords (Bug #11)"


@pytest.mark.xfail(reason="Bug #10: Username enumeration vulnerability")
def test_username_enumeration_vulnerability(login_page):
    """
    TC-LOGIN-006: Username Enumeration (Bug #10)
    
    Security test: Verify different error messages reveal if username exists.
    
    This is a SECURITY VULNERABILITY because attackers can:
    1. Try random usernames
    2. See different error messages
    3. Build list of valid usernames
    4. Then try password attacks only on valid users
    
    Current Behavior (BUG):
    - Existing user + wrong password → "Wrong password."
    - Non-existent user + any password → "User does not exist."
    - Attacker learns which usernames are valid
    
    Expected Behavior (AFTER FIX):
    - ALL login failures → Same generic message: "Invalid credentials."
    - Attacker cannot tell if username exists or not
    
    Related: Bug #10 - Username enumeration
    """
    perform_login(login_page, TEST_USERNAME, "wrong_password_xyz")
    error_msg_existing_user = wait_for_alert_and_get_text(login_page)
    
    login_page.find_element(By.ID, LOGIN_BUTTON_NAV).click()
    time.sleep(1)
    
    perform_login(login_page, "definitely_not_a_real_user_xyz", "any_password")
    error_msg_nonexistent_user = wait_for_alert_and_get_text(login_page)
    
    assert error_msg_existing_user == error_msg_nonexistent_user, \
        f"Error messages should be identical to prevent username enumeration. " \
        f"Got: '{error_msg_existing_user}' vs '{error_msg_nonexistent_user}' (Bug #10)"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])