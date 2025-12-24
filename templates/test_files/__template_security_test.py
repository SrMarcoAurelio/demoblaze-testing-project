"""
Universal Security Test Template

INSTRUCTIONS:
1. Copy this file to your tests/security/ directory
2. Rename it to: test_YOUR_FEATURE_security.py
3. Replace ALL_CAPS placeholders with YOUR test logic
4. Remove pytest.skip() decorators when ready to use
5. Adapt to YOUR application's security requirements

⚠️ SECURITY TESTING GUIDELINES:
- Only test applications you have permission to test
- Never test production environments without approval
- Follow responsible disclosure for any findings
- Document all security tests and results

Common security tests:
- SQL Injection
- XSS (Cross-Site Scripting)
- CSRF (Cross-Site Request Forgery)
- Authentication bypass
- Authorization issues
- Input validation
- Session management
"""

import pytest

from pages.YOUR_PAGE import YourPage  # Replace with YOUR page object
from utils.security_payload_library import SecurityPayloadLibrary

# MARK THIS FILE WITH PYTEST MARKERS
pytestmark = [
    pytest.mark.security,  # This is a security test
]


class TestYourFeatureSecurity:
    """
    Security tests for YOUR_FEATURE.

    ⚠️ IMPORTANT: These tests attempt to find security vulnerabilities.
    Only run against applications you have permission to test.

    Test coverage:
    - Input validation
    - Injection attacks
    - XSS vulnerabilities
    - Authentication/Authorization
    - Session management

    Replace this docstring with YOUR security test scope.
    """

    @pytest.fixture(autouse=True)
    def setup(self):
        """
        Setup for security tests.

        Adapt this to YOUR application's needs:
        - Create test user accounts
        - Set up test data
        - Configure security testing tools
        """
        self.payload_library = SecurityPayloadLibrary()
        yield
        # Teardown if needed

    @pytest.mark.skip(
        reason="Template not adapted - replace with YOUR test logic"
    )
    def test_sql_injection_protection(self, browser, base_url):
        """
        Test that YOUR_FEATURE is protected against SQL injection.

        Steps:
        1. Navigate to YOUR page with input fields
        2. Submit SQL injection payloads
        3. Verify application rejects malicious input

        Expected result:
        - Input is sanitized/rejected
        - No SQL errors visible
        - No unauthorized data access

        Replace this with YOUR actual SQL injection tests.
        """
        # Arrange
        page = YourPage(browser, base_url)
        sql_payloads = self.payload_library.get_sql_injection_payloads()

        # Act & Assert
        for payload in sql_payloads[:5]:  # Test first 5 payloads
            page.navigate()
            result = page.submit_form_with_data(
                {"field": payload}  # Replace with YOUR input field
            )

            # Verify payload is rejected/sanitized
            assert (
                not page.has_sql_error()
            ), f"SQL error visible with payload: {payload}"
            assert (
                not page.is_unauthorized_data_visible()
            ), f"Unauthorized access with: {payload}"

    @pytest.mark.skip(
        reason="Template not adapted - replace with YOUR test logic"
    )
    def test_xss_protection(self, browser, base_url):
        """
        Test that YOUR_FEATURE is protected against XSS attacks.

        Steps:
        1. Navigate to YOUR page
        2. Submit XSS payloads in input fields
        3. Verify scripts are not executed

        Expected result:
        - Input is HTML-encoded
        - Scripts are not executed
        - No alert boxes appear

        Replace this with YOUR actual XSS tests.
        """
        # Arrange
        page = YourPage(browser, base_url)
        xss_payloads = self.payload_library.get_xss_payloads()

        # Act & Assert
        for payload in xss_payloads[:5]:  # Test first 5 payloads
            page.navigate()
            page.submit_form_with_data(
                {"field": payload}  # Replace with YOUR input field
            )

            # Verify XSS is prevented
            try:
                browser.switch_to.alert
                pytest.fail(f"XSS alert triggered with payload: {payload}")
            except:
                pass  # Good - no alert means XSS was blocked

            # Verify payload is encoded, not executed
            page_source = browser.page_source
            assert (
                payload not in page_source or f"&lt;script" in page_source
            ), f"XSS payload not properly encoded: {payload}"

    @pytest.mark.skip(
        reason="Template not adapted - replace with YOUR test logic"
    )
    def test_authentication_bypass_attempt(self, browser, base_url):
        """
        Test that authentication cannot be bypassed.

        Steps:
        1. Attempt to access protected pages without authentication
        2. Verify redirect to login or access denied

        Expected result:
        - Unauthenticated users redirected to login
        - Protected resources not accessible

        Replace this with YOUR authentication tests.
        """
        # Arrange
        page = YourPage(browser, base_url)
        protected_urls = [
            f"{base_url}/YOUR_PROTECTED_PAGE_1",
            f"{base_url}/YOUR_PROTECTED_PAGE_2",
            # Add YOUR protected URLs
        ]

        # Act & Assert
        for url in protected_urls:
            browser.get(url)

            # Verify access is denied
            current_url = browser.current_url
            assert (
                "login" in current_url.lower()
                or "access-denied" in current_url.lower()
            ), f"Protected URL accessible without authentication: {url}"

    @pytest.mark.skip(
        reason="Template not adapted - replace with YOUR test logic"
    )
    def test_authorization_horizontal_privilege_escalation(
        self, browser, base_url, test_user_1, test_user_2
    ):
        """
        Test that users cannot access other users' data.

        Steps:
        1. Login as user1
        2. Note user1's resource URL
        3. Logout and login as user2
        4. Attempt to access user1's resource
        5. Verify access denied

        Expected result:
        - User2 cannot access User1's resources

        Replace this with YOUR authorization tests.
        """
        # Arrange
        page = YourPage(browser, base_url)

        # Login as user1 and get their resource URL
        page.login(test_user_1["username"], test_user_1["password"])
        user1_resource_url = page.get_user_resource_url()  # Adapt to YOUR app
        page.logout()

        # Login as user2
        page.login(test_user_2["username"], test_user_2["password"])

        # Act - Attempt to access user1's resource
        browser.get(user1_resource_url)

        # Assert - Access should be denied
        assert (
            page.is_access_denied()
        ), "User2 can access User1's resources - authorization vulnerability!"

    @pytest.mark.skip(
        reason="Template not adapted - replace with YOUR test logic"
    )
    def test_input_validation_length_limits(self, browser, base_url):
        """
        Test that input length limits are enforced.

        Steps:
        1. Navigate to form
        2. Submit excessively long input
        3. Verify rejection or truncation

        Expected result:
        - Input rejected or truncated to max length
        - No buffer overflow or crashes

        Replace this with YOUR input validation tests.
        """
        # Arrange
        page = YourPage(browser, base_url)
        max_length = 1000  # Adapt to YOUR application's limits
        excessive_input = "A" * (max_length * 10)

        # Act
        page.navigate()
        result = page.submit_form_with_data(
            {"field": excessive_input}  # Replace with YOUR input field
        )

        # Assert
        error = page.get_error_message()
        assert (
            "too long" in error.lower() or "maximum" in error.lower()
        ), "Excessive input not properly validated"

    @pytest.mark.skip(
        reason="Template not adapted - replace with YOUR test logic"
    )
    def test_session_timeout(self, browser, base_url, test_user):
        """
        Test that sessions timeout after inactivity.

        Steps:
        1. Login
        2. Wait for session timeout period
        3. Attempt protected action
        4. Verify session expired

        Expected result:
        - Session expires after timeout
        - User redirected to login

        Replace this with YOUR session management tests.
        """
        # Arrange
        page = YourPage(browser, base_url)
        timeout_seconds = 300  # Adapt to YOUR app's timeout (e.g., 5 minutes)

        # Act
        page.login(test_user["username"], test_user["password"])

        # Wait for timeout (use smaller value for testing)
        import time

        time.sleep(10)  # In real test, wait for actual timeout

        # Attempt protected action
        page.perform_protected_action()  # Replace with YOUR action

        # Assert
        assert (
            "login" in browser.current_url.lower()
        ), "Session did not timeout as expected"


# ADAPTATION CHECKLIST:
# [ ] Copied to tests/security/test_YOUR_FEATURE_security.py
# [ ] Removed @pytest.mark.skip() decorators
# [ ] Replaced YourPage with YOUR actual page object
# [ ] Identified YOUR application's security requirements
# [ ] Adapted SQL injection tests to YOUR input fields
# [ ] Adapted XSS tests to YOUR input fields
# [ ] Listed YOUR protected URLs for auth tests
# [ ] Created test users with different permission levels
# [ ] Verified you have permission to run these tests
# [ ] Documented any security findings responsibly
# [ ] Removed this checklist when done

# ⚠️ SECURITY TESTING REMINDER:
# - Only test with authorization
# - Never test production without approval
# - Report findings responsibly
# - Follow your organization's security policies
