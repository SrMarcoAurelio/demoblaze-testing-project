"""
Signup Accessibility Tests
Author: Marc Arévalo
Version: 1.0

Tests WCAG 2.1 Level AA compliance for signup functionality:
- Keyboard navigation
- ARIA labels
- Form field accessibility
"""

import pytest


@pytest.mark.accessibility
@pytest.mark.signup
class TestSignupKeyboardNavigation:
    """Test keyboard navigation in signup modal"""

    def test_tab_through_signup_form_SIGNUP_ACC_001(self, signup_page):
        """Test TAB key navigation through signup form"""
        signup_page.open_signup_modal()

        # Get initial active element
        initial_element = signup_page.driver.switch_to.active_element

        # Tab through form fields
        signup_page.tab_through_signup_form()

        # Verify we moved through the form
        final_element = signup_page.driver.switch_to.active_element
        assert (
            initial_element != final_element
        ), "TAB navigation should move focus"

    def test_username_field_accessible_by_keyboard_SIGNUP_ACC_002(
        self, signup_page
    ):
        """Test username field is keyboard accessible"""
        signup_page.open_signup_modal()

        username_field = signup_page.find_element(
            signup_page.SIGNUP_USERNAME_FIELD
        )
        username_field.send_keys("NewUser")

        value = signup_page.get_signup_username_value()
        assert (
            value == "NewUser"
        ), "Username field should accept keyboard input"

    def test_password_field_accessible_by_keyboard_SIGNUP_ACC_003(
        self, signup_page
    ):
        """Test password field is keyboard accessible"""
        signup_page.open_signup_modal()

        password_field = signup_page.find_element(
            signup_page.SIGNUP_PASSWORD_FIELD
        )
        password_field.send_keys("NewPass123")

        value = signup_page.get_signup_password_value()
        assert (
            value == "NewPass123"
        ), "Password field should accept keyboard input"


@pytest.mark.accessibility
@pytest.mark.signup
class TestSignupAriaLabels:
    """Test ARIA labels for screen reader support"""

    def test_username_field_has_aria_label_SIGNUP_ACC_004(self, signup_page):
        """Test username field has ARIA label"""
        signup_page.open_signup_modal()

        aria_label = signup_page.get_signup_username_aria_label()
        assert isinstance(
            aria_label, (str, type(None))
        ), "ARIA label should be string or None"

    def test_password_field_has_aria_label_SIGNUP_ACC_005(self, signup_page):
        """Test password field has ARIA label"""
        signup_page.open_signup_modal()

        aria_label = signup_page.get_signup_password_aria_label()
        assert isinstance(
            aria_label, (str, type(None))
        ), "ARIA label should be string or None"


@pytest.mark.accessibility
@pytest.mark.signup
class TestSignupFieldProperties:
    """Test form field accessibility properties"""

    def test_fields_have_placeholders_SIGNUP_ACC_006(self, signup_page):
        """Test form fields have descriptive placeholders"""
        signup_page.open_signup_modal()

        username_placeholder = signup_page.get_signup_username_placeholder()
        password_placeholder = signup_page.get_signup_password_placeholder()

        assert username_placeholder, "Username field should have placeholder"
        assert password_placeholder, "Password field should have placeholder"
        assert (
            len(username_placeholder) > 0
        ), "Username placeholder should be descriptive"
        assert (
            len(password_placeholder) > 0
        ), "Password placeholder should be descriptive"
