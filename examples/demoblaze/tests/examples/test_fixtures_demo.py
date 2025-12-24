"""
Test Fixtures Demo - DemoBlaze Test Automation
Author: Marc Arévalo
Version: 1.0 - Phase 6

Demonstration of using test data fixtures from conftest.py
Shows how fixtures simplify test code and improve maintainability.

This file contains examples only - not meant for production test runs.
"""

import logging

import pytest


@pytest.mark.skip(reason="Demo example - not a real test")
def test_login_with_valid_user_fixture(login_page, valid_user):
    """
    Example: Using login_page and valid_user fixtures.

    Benefits:
    - No need to initialize page object
    - No need to define credentials
    - Cleaner, more readable code
    """
    login_page.login(**valid_user)

    assert login_page.is_user_logged_in()
    assert valid_user["username"] in login_page.get_welcome_message()

    logging.info("✓ Login test using fixtures - PASSED")


@pytest.mark.skip(reason="Demo example - not a real test")
def test_login_failure_with_invalid_user(login_page, invalid_user_username):
    """
    Example: Using invalid user fixture.

    Shows how to test negative scenarios easily.
    """
    login_page.login(**invalid_user_username)

    alert_text = login_page.get_alert_text(timeout=5)

    assert alert_text is not None
    assert not login_page.is_user_logged_in()

    logging.info("✓ Invalid login test - PASSED")


@pytest.mark.skip(reason="Demo example - not a real test")
def test_add_product_to_cart(logged_in_user, catalog_page, product_phone):
    """
    Example: Using logged_in_user fixture.

    Benefits:
    - User is already logged in (no setup needed)
    - User will be logged out after test (automatic cleanup)
    """
    catalog_page.select_product(product_phone)

    # Product page actions...
    from pages.product_page import ProductPage

    prod_page = ProductPage(catalog_page.driver)
    prod_page.add_to_cart()

    alert = prod_page.get_alert_text(timeout=3)
    assert alert is not None
    assert "added" in alert.lower()

    logging.info("✓ Add to cart test - PASSED")


@pytest.mark.skip(reason="Demo example - not a real test")
def test_complete_purchase(prepared_checkout, purchase_data):
    """
    Example: Using prepared_checkout fixture.

    Benefits:
    - User logged in (automatic)
    - Product added to cart (automatic)
    - Checkout modal opened (automatic)
    - Only need to test the purchase flow
    """
    prepared_checkout.fill_form(**purchase_data)
    prepared_checkout.confirm_purchase()

    success_msg = prepared_checkout.get_confirmation_message()
    assert success_msg is not None

    logging.info("✓ Purchase test - PASSED")


@pytest.mark.skip(reason="Demo example - not a real test")
def test_signup_with_new_user(signup_page, new_user):
    """
    Example: Using new_user fixture.

    Benefits:
    - Generates unique username each time (no conflicts)
    - No manual timestamp generation needed
    """
    signup_page.signup(**new_user)

    alert = signup_page.get_alert_text(timeout=5)

    # Should succeed with unique username
    assert alert is not None
    assert "success" in alert.lower() or "signed up" in alert.lower()

    logging.info(f"✓ Signup test with user: {new_user['username']} - PASSED")


@pytest.mark.skip(reason="Demo example - not a real test")
def test_random_product_selection(catalog_page, random_product):
    """
    Example: Using random_product fixture.

    Benefits:
    - Tests with different products each run
    - Helps find product-specific bugs
    """
    catalog_page.select_product(random_product)

    from pages.product_page import ProductPage

    prod_page = ProductPage(catalog_page.driver)

    assert prod_page.is_product_page_loaded()
    product_name = prod_page.get_product_name()

    assert random_product.lower() in product_name.lower()

    logging.info(f"✓ Random product test: {random_product} - PASSED")


# ============================================================================
# COMPARISON: Before vs After Fixtures
# ============================================================================


@pytest.mark.skip(reason="Demo comparison - old style")
def test_login_OLD_STYLE(browser, base_url):
    """
    OLD STYLE (Before Phase 6):
    - Manual page initialization
    - Hardcoded credentials
    - More boilerplate code
    """
    from pages.login_page import LoginPage

    browser.get(base_url)
    login_page = LoginPage(browser)

    # Hardcoded credentials
    username = "Apolo2025"
    password = "apolo2025"

    login_page.login(username, password)

    assert login_page.is_user_logged_in()
    assert username in login_page.get_welcome_message()


@pytest.mark.skip(reason="Demo comparison - new style")
def test_login_NEW_STYLE(login_page, valid_user):
    """
    NEW STYLE (Phase 6 with fixtures):
    - Automatic page initialization
    - Centralized test data
    - Less boilerplate, cleaner code
    """
    login_page.login(**valid_user)

    assert login_page.is_user_logged_in()
    assert valid_user["username"] in login_page.get_welcome_message()


# ============================================================================
# PARAMETRIZED TESTS WITH FIXTURES
# ============================================================================


@pytest.mark.skip(reason="Demo example - parametrized")
@pytest.mark.parametrize(
    "user_fixture",
    [
        "invalid_user_username",
        "invalid_user_password",
    ],
)
def test_login_failures_parametrized(login_page, user_fixture, request):
    """
    Example: Parametrized test using multiple fixtures.

    Benefits:
    - Test same logic with different data
    - DRY principle (Don't Repeat Yourself)
    """
    user_data = request.getfixturevalue(user_fixture)

    login_page.login(**user_data)

    assert not login_page.is_user_logged_in()
    assert login_page.get_alert_text(timeout=5) is not None

    logging.info(f"✓ Parametrized login failure test: {user_fixture} - PASSED")
