import pytest
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
import time


class TestSignup:
    
    BASE_URL = "https://www.demoblaze.com/index.html"
    
    def wait_for_alert(self, browser, timeout=5):
        try:
            WebDriverWait(browser, timeout).until(EC.alert_is_present())
            alert = browser.switch_to.alert
            alert_text = alert.text
            alert.accept()
            return alert_text
        except TimeoutException:
            return None
    
    def open_signup_modal(self, browser):
        browser.get(self.BASE_URL)
        signup_link = WebDriverWait(browser, 10).until(
            EC.element_to_be_clickable((By.ID, "signin2"))
        )
        signup_link.click()
        WebDriverWait(browser, 10).until(
            EC.visibility_of_element_located((By.ID, "sign-username"))
        )
        time.sleep(0.5)
    
    def fill_signup_form(self, browser, username, password):
        username_field = browser.find_element(By.ID, "sign-username")
        password_field = browser.find_element(By.ID, "sign-password")
        username_field.clear()
        username_field.send_keys(username)
        password_field.clear()
        password_field.send_keys(password)
    
    def click_signup_button(self, browser):
        signup_button = browser.find_element(By.XPATH, "//button[text()='Sign up']")
        signup_button.click()
    
    def verify_login_works(self, browser, username, password):
        login_link = WebDriverWait(browser, 10).until(
            EC.element_to_be_clickable((By.ID, "login2"))
        )
        login_link.click()
        WebDriverWait(browser, 10).until(
            EC.visibility_of_element_located((By.ID, "loginusername"))
        )
        time.sleep(0.5)
        
        username_field = browser.find_element(By.ID, "loginusername")
        password_field = browser.find_element(By.ID, "loginpassword")
        username_field.send_keys(username)
        password_field.send_keys(password)
        
        login_button = browser.find_element(By.XPATH, "//button[text()='Log in']")
        login_button.click()
        
        time.sleep(2)
        
        welcome_message = WebDriverWait(browser, 10).until(
            EC.visibility_of_element_located((By.ID, "nameofuser"))
        )
        assert f"Welcome {username}" in welcome_message.text
    
    
    def test_signup_valid_credentials(self, browser):
        timestamp = int(time.time())
        username = f"testuser_{timestamp}"
        password = "TestPass123"
        
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, username, password)
        self.click_signup_button(browser)
        
        alert_text = self.wait_for_alert(browser)
        assert alert_text == "Sign up successful."
    
    
    def test_signup_existing_user(self, browser):
        timestamp = int(time.time())
        username = f"existinguser_{timestamp}"
        password = "Pass123"
        
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, username, password)
        self.click_signup_button(browser)
        alert_text = self.wait_for_alert(browser)
        assert alert_text == "Sign up successful."
        
        time.sleep(1)
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, username, password)
        self.click_signup_button(browser)
        
        alert_text = self.wait_for_alert(browser)
        assert alert_text == "This user already exist."
    
    
    def test_signup_empty_username(self, browser):
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, "", "Password123")
        self.click_signup_button(browser)
        
        alert_text = self.wait_for_alert(browser)
        assert alert_text == "Please fill out Username and Password."
    
    
    def test_signup_empty_password(self, browser):
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, "testuser", "")
        self.click_signup_button(browser)
        
        alert_text = self.wait_for_alert(browser)
        assert alert_text == "Please fill out Username and Password."
    
    
    def test_signup_both_fields_empty(self, browser):
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, "", "")
        self.click_signup_button(browser)
        
        alert_text = self.wait_for_alert(browser)
        assert alert_text == "Please fill out Username and Password."
    
    
    def test_signup_weak_password_single_char(self, browser):
        timestamp = int(time.time())
        username = f"weakpass_{timestamp}"
        password = "1"
        
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, username, password)
        self.click_signup_button(browser)
        
        alert_text = self.wait_for_alert(browser)
        assert alert_text == "Sign up successful."
    
    
    def test_signup_weak_password_two_chars(self, browser):
        timestamp = int(time.time())
        username = f"weakpass2_{timestamp}"
        password = "ab"
        
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, username, password)
        self.click_signup_button(browser)
        
        alert_text = self.wait_for_alert(browser)
        assert alert_text == "Sign up successful."
    
    
    def test_signup_sql_injection_username(self, browser):
        """
        Security Test: SQL Injection Vulnerability
        
        If this test PASSES = BUG FOUND (SQL syntax accepted without sanitization)
        If this test FAILS = System properly blocks SQL injection
        """
        sql_payloads = [
            "admin' OR '1'='1",
            "admin'--",
            "' OR 1=1--",
            "admin' DROP TABLE users--"
        ]
        
        for payload in sql_payloads:
            self.open_signup_modal(browser)
            self.fill_signup_form(browser, payload, "password123")
            self.click_signup_button(browser)
            
            alert_text = self.wait_for_alert(browser)
            assert alert_text in ["Sign up successful.", "This user already exist."]
            time.sleep(1)
    
    
    def test_signup_sql_injection_password(self, browser):
        """
        Security Test: SQL Injection in Password Field
        
        If this test PASSES = BUG FOUND (SQL syntax accepted)
        If this test FAILS = System properly sanitizes input
        """
        timestamp = int(time.time())
        username = f"sqltest_{timestamp}"
        sql_password = "' OR '1'='1"
        
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, username, sql_password)
        self.click_signup_button(browser)
        
        alert_text = self.wait_for_alert(browser)
        assert alert_text == "Sign up successful."
    
    
    def test_signup_xss_username(self, browser):
        """
        Security Test: XSS Vulnerability Detection
        
        If this test PASSES = BUG FOUND (system accepts malicious scripts)
        If this test FAILS = System properly rejects XSS (secure behavior)
        """
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        
        for payload in xss_payloads:
            self.open_signup_modal(browser)
            self.fill_signup_form(browser, payload, "password123")
            self.click_signup_button(browser)
            
            alert_text = self.wait_for_alert(browser, timeout=3)
            if alert_text:
                assert alert_text in ["Sign up successful.", "This user already exist."]
            time.sleep(1)
    
    
    def test_signup_xss_password(self, browser):
        """
        Security Test: XSS Vulnerability in Password Field
        
        If this test PASSES = BUG FOUND (accepts scripts in password)
        If this test FAILS = System properly rejects XSS
        """
        timestamp = int(time.time())
        username = f"xsstest_{timestamp}"
        xss_password = "<script>alert('XSS')</script>"
        
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, username, xss_password)
        self.click_signup_button(browser)
        
        alert_text = self.wait_for_alert(browser, timeout=3)
        if alert_text:
            assert alert_text == "Sign up successful."
    
    
    def test_signup_whitespace_username_leading(self, browser):
        """
        Edge Case Test: Whitespace Trimming
        
        If this test PASSES = BUG FOUND (leading spaces not trimmed)
        If this test FAILS = System properly trims whitespace
        """
        timestamp = int(time.time())
        username = f"   leadingspace_{timestamp}"
        password = "Pass123"
        
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, username, password)
        self.click_signup_button(browser)
        
        alert_text = self.wait_for_alert(browser)
        assert alert_text == "Sign up successful."
    
    
    def test_signup_whitespace_username_trailing(self, browser):
        """
        Edge Case Test: Whitespace Trimming
        
        If this test PASSES = BUG FOUND (trailing spaces not trimmed)
        If this test FAILS = System properly trims whitespace
        """
        timestamp = int(time.time())
        username = f"trailingspace_{timestamp}   "
        password = "Pass123"
        
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, username, password)
        self.click_signup_button(browser)
        
        alert_text = self.wait_for_alert(browser)
        assert alert_text == "Sign up successful."
    
    
    def test_signup_whitespace_only_username(self, browser):
        """
        Edge Case Test: Whitespace-Only Username
        
        CRITICAL: Username with only spaces should be REJECTED
        If this test PASSES = System correctly rejects whitespace-only input
        If this test FAILS = BUG FOUND (accepts whitespace-only as valid username)
        """
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, "     ", "Pass123")
        self.click_signup_button(browser)
        
        alert_text = self.wait_for_alert(browser)
        assert alert_text == "Please fill out Username and Password.", \
            f"WHITESPACE BUG: Expected validation error, got '{alert_text}' - system accepts whitespace-only usernames!"
    
    
    def test_signup_whitespace_password(self, browser):
        timestamp = int(time.time())
        username = f"whitepass_{timestamp}"
        password = "   spaces   "
        
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, username, password)
        self.click_signup_button(browser)
        
        alert_text = self.wait_for_alert(browser)
        assert alert_text == "Sign up successful."
    
    
    def test_signup_special_characters_valid(self, browser):
        timestamp = int(time.time())
        username = f"user_@#$_{timestamp}"
        password = "P@ssw0rd!#$"
        
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, username, password)
        self.click_signup_button(browser)
        
        alert_text = self.wait_for_alert(browser)
        assert alert_text == "Sign up successful."
    
    
    def test_signup_username_very_long(self, browser):
        """
        Boundary Test: Input Length Validation
        
        If this test PASSES = BUG FOUND (no maximum length validation)
        If this test FAILS = System enforces character limits (secure behavior)
        """
        timestamp = int(time.time())
        username = f"a{'x' * 200}_{timestamp}"
        password = "Pass123"
        
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, username, password)
        self.click_signup_button(browser)
        
        alert_text = self.wait_for_alert(browser)
        assert alert_text in ["Sign up successful.", "This user already exist."]
    
    
    def test_signup_password_very_long(self, browser):
        """
        Boundary Test: Password Length Validation
        
        If this test PASSES = BUG FOUND (no maximum length validation)
        If this test FAILS = System enforces reasonable limits
        """
        timestamp = int(time.time())
        username = f"longpass_{timestamp}"
        password = "P" + "x" * 200
        
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, username, password)
        self.click_signup_button(browser)
        
        alert_text = self.wait_for_alert(browser)
        assert alert_text == "Sign up successful."
    
    
    def test_signup_username_with_numbers(self, browser):
        timestamp = int(time.time())
        username = f"user123456_{timestamp}"
        password = "Pass123"
        
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, username, password)
        self.click_signup_button(browser)
        
        alert_text = self.wait_for_alert(browser)
        assert alert_text == "Sign up successful."
    
    
    def test_signup_username_numbers_only(self, browser):
        timestamp = int(time.time())
        username = f"123456{timestamp}"
        password = "Pass123"
        
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, username, password)
        self.click_signup_button(browser)
        
        alert_text = self.wait_for_alert(browser)
        assert alert_text == "Sign up successful."
    
    
    def test_signup_case_sensitivity_uppercase(self, browser):
        timestamp = int(time.time())
        username_lower = f"casetest_{timestamp}"
        username_upper = username_lower.upper()
        password = "Pass123"
        
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, username_lower, password)
        self.click_signup_button(browser)
        alert_text = self.wait_for_alert(browser)
        assert alert_text == "Sign up successful."
        
        time.sleep(1)
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, username_upper, password)
        self.click_signup_button(browser)
        
        alert_text = self.wait_for_alert(browser)
        assert alert_text in ["Sign up successful.", "This user already exist."]
    
    
    def test_signup_then_login(self, browser):
        timestamp = int(time.time())
        username = f"logintest_{timestamp}"
        password = "TestLogin123"
        
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, username, password)
        self.click_signup_button(browser)
        
        alert_text = self.wait_for_alert(browser)
        assert alert_text == "Sign up successful."
        
        time.sleep(1)
        self.verify_login_works(browser, username, password)
    
    
    def test_signup_multiple_rapid_same_username(self, browser):
        timestamp = int(time.time())
        username = f"rapidtest_{timestamp}"
        password = "Pass123"
        
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, username, password)
        self.click_signup_button(browser)
        alert_text = self.wait_for_alert(browser)
        assert alert_text == "Sign up successful."
        
        for _ in range(3):
            time.sleep(0.5)
            self.open_signup_modal(browser)
            self.fill_signup_form(browser, username, password)
            self.click_signup_button(browser)
            alert_text = self.wait_for_alert(browser)
            assert alert_text == "This user already exist."
    
    
    def test_signup_unicode_username(self, browser):
        timestamp = int(time.time())
        username = f"用户_{timestamp}"
        password = "Pass123"
        
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, username, password)
        self.click_signup_button(browser)
        
        alert_text = self.wait_for_alert(browser)
        assert alert_text in ["Sign up successful.", "This user already exist."]
    
    
    @pytest.mark.skip(reason="ChromeDriver doesn't support emoji characters - not a DemoBlaze bug")
    def test_signup_emoji_username(self, browser):
        timestamp = int(time.time())
        username = f"user😀🎉_{timestamp}"
        password = "Pass123"
        
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, username, password)
        self.click_signup_button(browser)
        
        alert_text = self.wait_for_alert(browser)
        assert alert_text in ["Sign up successful.", "This user already exist."]
    
    
    def test_signup_modal_close_without_action(self, browser):
        self.open_signup_modal(browser)
        
        close_button = browser.find_element(By.XPATH, "//div[@id='signInModal']//button[@class='close']")
        close_button.click()
        
        time.sleep(1)
        
        modal = browser.find_elements(By.ID, "signInModal")
        if modal:
            assert not modal[0].is_displayed()
    
    
    def test_signup_modal_cancel_button(self, browser):
        self.open_signup_modal(browser)
        
        cancel_button = browser.find_element(By.XPATH, "//div[@id='signInModal']//button[contains(@class, 'btn-secondary')]")
        cancel_button.click()
        
        time.sleep(1)
        
        modal = browser.find_elements(By.ID, "signInModal")
        if modal:
            assert not modal[0].is_displayed()
    
    
    def test_signup_password_with_spaces_middle(self, browser):
        timestamp = int(time.time())
        username = f"spacepass_{timestamp}"
        password = "Pass Word 123"
        
        self.open_signup_modal(browser)
        self.fill_signup_form(browser, username, password)
        self.click_signup_button(browser)
        
        alert_text = self.wait_for_alert(browser)
        assert alert_text == "Sign up successful."
