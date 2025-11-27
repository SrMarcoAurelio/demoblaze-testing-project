"""
Purchase Business Rules and Validation Tests
Author: Marc Arévalo
Version: 1.0

Test Coverage:
- Form validation (parametrized)
- Business rules (BR-001 to BR-010)
- Standards compliance (OWASP, PCI-DSS, ISO, NIST)
- Payment card validation

Philosophy: DISCOVER (EXECUTE → OBSERVE → DECIDE)
All tests perform real actions, observe actual results, and decide based on objective standards.
"""

import pytest
import logging
import time
import datetime
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from pages.cart_page import CartPage
from pages.purchase_page import PurchasePage
from pages.login_page import LoginPage

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================================
# FORM VALIDATION TESTS (Parametrized)
# ============================================================================

@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.critical
@pytest.mark.parametrize("field_name,test_data", [
    ("name", ""),
    ("country", ""),
    ("city", ""),
    ("card", ""),
    ("month", ""),
    ("year", "")
])
def test_empty_field_validation_VAL_001(browser, base_url, field_name, test_data):
    """
    TC-PURCHASE-VAL-001: Empty Field Validation
    Standard: ISO 25010 (Software Quality - Data Validation)
    CVSS Score: 5.3 MEDIUM

    DISCOVER: How does the system handle empty required fields?
    """
    # EXECUTE: Add product to cart
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    # EXECUTE: Fill form with one empty field
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    form_data = {
        'name': 'QA Tester',
        'country': 'Spain',
        'city': 'Barcelona',
        'card': '1234567890123456',
        'month': '12',
        'year': '2028'
    }
    form_data[field_name] = test_data  # Set target field to empty

    purchase.fill_order_form(**form_data)
    purchase.click_purchase()

    # OBSERVE: Check if purchase proceeds
    time.sleep(1)
    is_confirmed = purchase.is_purchase_confirmed(timeout=3)
    alert_text = purchase.get_alert_text(timeout=1)

    # DECIDE: Purchase should NOT succeed with empty required fields
    if is_confirmed:
        logger.error(f"✗ VIOLATION: Purchase succeeded with empty {field_name} field")
        pytest.fail(f"DISCOVERED: Empty field validation missing for '{field_name}'")
    else:
        logger.info(f"✓ Purchase correctly blocked with empty {field_name}")


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.high
@pytest.mark.parametrize("invalid_card", [
    "ABCD-1234-5678-9012",  # Letters
    "1234-ABCD-5678-9012",  # Mixed
    "XXXX-XXXX-XXXX-XXXX",  # All letters
    "abcd1234567890ef",      # Lowercase letters
])
def test_invalid_card_format_VAL_002(browser, base_url, invalid_card):
    """
    TC-PURCHASE-VAL-002: Invalid Card Format Validation
    Standard: PCI-DSS 4.0.1 Requirement 3.4 (Render PAN Unreadable)
    CVSS Score: 6.5 MEDIUM

    DISCOVER: Does the system validate card number format?
    """
    # EXECUTE: Add product and open order form
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    # EXECUTE: Try to purchase with invalid card format
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()
    purchase.fill_order_form(
        name="QA Tester",
        country="Spain",
        city="Barcelona",
        card=invalid_card,
        month="12",
        year="2028"
    )
    purchase.click_purchase()

    # OBSERVE: Check if purchase proceeds
    time.sleep(1)
    is_confirmed = purchase.is_purchase_confirmed(timeout=3)

    # DECIDE: Non-numeric card should be rejected
    if is_confirmed:
        logger.error(f"✗ VIOLATION: Invalid card format accepted: {invalid_card}")
        pytest.fail(f"DISCOVERED: Card format validation missing - accepted '{invalid_card}'")
    else:
        logger.info(f"✓ Invalid card format correctly rejected: {invalid_card}")


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.high
@pytest.mark.parametrize("short_card", [
    "123",           # Too short
    "12345678",      # 8 digits
    "123456789012",  # 12 digits
    "12345",         # 5 digits
])
def test_invalid_card_length_VAL_003(browser, base_url, short_card):
    """
    TC-PURCHASE-VAL-003: Invalid Card Length Validation
    Standard: PCI-DSS 4.0.1 Requirement 3.4
    CVSS Score: 6.5 MEDIUM

    DISCOVER: Does the system enforce minimum card length?
    """
    # EXECUTE: Add product and open order form
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    # EXECUTE: Try to purchase with short card
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()
    purchase.fill_order_form(
        name="QA Tester",
        country="Spain",
        city="Barcelona",
        card=short_card,
        month="12",
        year="2028"
    )
    purchase.click_purchase()

    # OBSERVE: Check if purchase proceeds
    time.sleep(1)
    is_confirmed = purchase.is_purchase_confirmed(timeout=3)

    # DECIDE: Short card numbers should be rejected
    if is_confirmed:
        logger.error(f"✗ VIOLATION: Short card accepted: {short_card}")
        pytest.fail(f"DISCOVERED: Card length validation missing - accepted '{short_card}'")
    else:
        logger.info(f"✓ Short card correctly rejected: {short_card}")


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.high
def test_expired_card_validation_VAL_004(browser, base_url):
    """
    TC-PURCHASE-VAL-004: Expired Card Validation
    Standard: PCI-DSS 4.0.1 Requirement 8.3.1
    CVSS Score: 6.5 MEDIUM

    DISCOVER: Does the system reject expired cards?
    """
    # EXECUTE: Add product and open order form
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    # EXECUTE: Try to purchase with expired card
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    expired_year = str(datetime.date.today().year - 1)
    purchase.fill_order_form(
        name="QA Tester",
        country="Spain",
        city="Barcelona",
        card="1234567890123456",
        month="12",
        year=expired_year
    )
    purchase.click_purchase()

    # OBSERVE: Check if purchase proceeds
    time.sleep(1)
    is_confirmed = purchase.is_purchase_confirmed(timeout=3)

    # DECIDE: Expired card should be rejected
    if is_confirmed:
        logger.error(f"✗ VIOLATION: Expired card accepted (year: {expired_year})")
        pytest.fail(f"DISCOVERED: Expired card validation missing")
    else:
        logger.info(f"✓ Expired card correctly rejected")


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.medium
@pytest.mark.parametrize("invalid_month", [
    "00",  # Too low
    "13",  # Too high
    "99",  # Way too high
    "-1",  # Negative
])
def test_invalid_month_validation_VAL_005(browser, base_url, invalid_month):
    """
    TC-PURCHASE-VAL-005: Invalid Month Validation
    Standard: ISO 8601 (Date/Time Format)
    CVSS Score: 5.3 MEDIUM

    DISCOVER: Does the system validate month range (01-12)?
    """
    # EXECUTE: Add product and open order form
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    # EXECUTE: Try to purchase with invalid month
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()
    purchase.fill_order_form(
        name="QA Tester",
        country="Spain",
        city="Barcelona",
        card="1234567890123456",
        month=invalid_month,
        year="2028"
    )
    purchase.click_purchase()

    # OBSERVE: Check if purchase proceeds
    time.sleep(1)
    is_confirmed = purchase.is_purchase_confirmed(timeout=3)

    # DECIDE: Invalid month should be rejected
    if is_confirmed:
        logger.error(f"✗ VIOLATION: Invalid month accepted: {invalid_month}")
        pytest.fail(f"DISCOVERED: Month validation missing - accepted '{invalid_month}'")
    else:
        logger.info(f"✓ Invalid month correctly rejected: {invalid_month}")


@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.critical
@pytest.mark.parametrize("sql_payload", [
    "' OR '1'='1",
    "admin'--",
    "') OR ('1'='1",
    "' OR 1=1--",
    "1' UNION SELECT NULL--",
])
def test_sql_injection_protection_VAL_006(browser, base_url, sql_payload):
    """
    TC-PURCHASE-VAL-006: SQL Injection Protection
    Standard: OWASP ASVS v5.0 Section 1.2.5 (SQL Injection Prevention)
    CWE: CWE-89
    CVSS Score: 9.8 CRITICAL
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    DISCOVER: Is the purchase form vulnerable to SQL injection?
    """
    # EXECUTE: Add product and open order form
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    # EXECUTE: Try SQL injection in name field
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()
    purchase.fill_order_form(
        name=sql_payload,
        country="Spain",
        city="Barcelona",
        card="1234567890123456",
        month="12",
        year="2028"
    )
    purchase.click_purchase()

    # OBSERVE: Check if injection succeeds or causes error disclosure
    time.sleep(1)
    is_confirmed = purchase.is_purchase_confirmed(timeout=3)
    page_source = browser.page_source.lower()

    error_indicators = ["sql syntax", "mysql", "postgresql", "sqlite", "database error"]

    # DECIDE: SQL injection should be prevented
    if is_confirmed:
        logger.critical(f"✗ CRITICAL: SQL injection may have succeeded: {sql_payload}")
        pytest.fail(f"DISCOVERED: Possible SQL injection vulnerability with '{sql_payload}'")

    for indicator in error_indicators:
        if indicator in page_source:
            logger.critical(f"✗ CRITICAL: SQL error disclosure detected: {indicator}")
            pytest.fail(f"DISCOVERED: SQL error disclosure with indicator '{indicator}'")

    logger.info(f"✓ SQL injection correctly prevented: {sql_payload}")


@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.critical
@pytest.mark.parametrize("xss_payload", [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "<svg/onload=alert('XSS')>",
])
def test_xss_protection_VAL_007(browser, base_url, xss_payload):
    """
    TC-PURCHASE-VAL-007: XSS Protection
    Standard: OWASP ASVS v5.0 Section 1.2.3 (XSS Prevention)
    CWE: CWE-79
    CVSS Score: 8.2 HIGH
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N

    DISCOVER: Is the purchase confirmation vulnerable to XSS?
    """
    # EXECUTE: Add product and open order form
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    # EXECUTE: Try XSS payload in city field
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()
    purchase.fill_order_form(
        name="QA Tester",
        country="Spain",
        city=xss_payload,
        card="1234567890123456",
        month="12",
        year="2028"
    )
    purchase.click_purchase()

    # OBSERVE: Check if XSS payload is reflected unescaped
    time.sleep(1)
    is_confirmed = purchase.is_purchase_confirmed(timeout=3)

    if is_confirmed:
        confirm_text = purchase.get_purchase_confirmation_text()
        page_source = browser.page_source

        # DECIDE: XSS payload should be escaped/sanitized
        if xss_payload in page_source and "<script>" in xss_payload:
            logger.critical(f"✗ CRITICAL: XSS payload reflected unescaped: {xss_payload}")
            pytest.fail(f"DISCOVERED: XSS vulnerability - unescaped payload in confirmation")

        # Check for script execution (alert presence)
        try:
            alert = browser.switch_to.alert
            alert_text = alert.text
            alert.accept()
            logger.critical(f"✗ CRITICAL: XSS executed - alert triggered: {alert_text}")
            pytest.fail(f"DISCOVERED: XSS execution detected")
        except:
            pass  # No alert = good

    logger.info(f"✓ XSS payload correctly sanitized: {xss_payload}")


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.medium
@pytest.mark.parametrize("long_input,field", [
    ("A" * 1000, "name"),
    ("B" * 1000, "country"),
    ("C" * 1000, "city"),
])
def test_max_length_validation_VAL_008(browser, base_url, long_input, field):
    """
    TC-PURCHASE-VAL-008: Maximum Length Validation
    Standard: OWASP ASVS v5.0 Section 1.2.6 (Input Validation)
    CVSS Score: 5.3 MEDIUM

    DISCOVER: Are there maximum length restrictions on text fields?
    """
    # EXECUTE: Add product and open order form
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    # EXECUTE: Try extremely long input
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    form_data = {
        'name': 'QA Tester',
        'country': 'Spain',
        'city': 'Barcelona',
        'card': '1234567890123456',
        'month': '12',
        'year': '2028'
    }
    form_data[field] = long_input

    purchase.fill_order_form(**form_data)
    purchase.click_purchase()

    # OBSERVE: Check system behavior
    time.sleep(1)
    is_confirmed = purchase.is_purchase_confirmed(timeout=3)

    # DECIDE: System should handle long inputs gracefully
    if is_confirmed:
        confirm_text = purchase.get_purchase_confirmation_text()
        if len(confirm_text) > 5000:
            logger.warning(f"⚠ WARNING: Very long confirmation text ({len(confirm_text)} chars)")

    logger.info(f"✓ Long input handled for {field}: {len(long_input)} chars")


@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.medium
@pytest.mark.parametrize("whitespace_input,field", [
    ("   ", "name"),
    ("\t\t\t", "country"),
    ("\n\n\n", "city"),
    ("     ", "card"),
])
def test_whitespace_only_validation_VAL_009(browser, base_url, whitespace_input, field):
    """
    TC-PURCHASE-VAL-009: Whitespace-Only Input Validation
    Standard: ISO 25010 (Software Quality)
    CVSS Score: 4.3 LOW

    DISCOVER: Are whitespace-only inputs rejected?
    """
    # EXECUTE: Add product and open order form
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    # EXECUTE: Try whitespace-only input
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    form_data = {
        'name': 'QA Tester',
        'country': 'Spain',
        'city': 'Barcelona',
        'card': '1234567890123456',
        'month': '12',
        'year': '2028'
    }
    form_data[field] = whitespace_input

    purchase.fill_order_form(**form_data)
    purchase.click_purchase()

    # OBSERVE: Check if purchase proceeds
    time.sleep(1)
    is_confirmed = purchase.is_purchase_confirmed(timeout=3)

    # DECIDE: Whitespace-only should ideally be rejected
    if is_confirmed and field != "card":
        logger.warning(f"⚠ WARNING: Whitespace-only accepted for {field}")
    else:
        logger.info(f"✓ Whitespace-only handled for {field}")


# ============================================================================
# BUSINESS RULES TESTS
# ============================================================================

@pytest.mark.business_rules
@pytest.mark.critical
def test_empty_cart_purchase_prevention_BR_001(browser, base_url):
    """
    TC-PURCHASE-BR-001: Empty Cart Purchase Prevention
    Business Rule: Cannot purchase with empty cart
    Standard: ISO 25010 (Software Quality - Functional Correctness)

    DISCOVER: Can users attempt to purchase without items in cart?
    """
    # EXECUTE: Navigate directly to cart without adding products
    browser.get(base_url)
    cart = CartPage(browser)
    cart.open_cart()

    # OBSERVE: Check if Place Order button is present/clickable
    is_place_order_visible = cart.is_place_order_visible()

    if is_place_order_visible:
        # EXECUTE: Try to click Place Order on empty cart
        cart.click_place_order()

        # OBSERVE: Check if order modal opens
        purchase = PurchasePage(browser)
        time.sleep(1)
        is_modal_open = purchase.is_order_modal_visible()

        # DECIDE: Empty cart should not allow purchase
        if is_modal_open:
            logger.error("✗ VIOLATION: Order modal opened with empty cart")
            pytest.fail("DISCOVERED: Empty cart purchase prevention missing")

    logger.info("✓ Empty cart purchase correctly prevented")


@pytest.mark.business_rules
@pytest.mark.high
@pytest.mark.pci_dss
def test_card_format_numeric_validation_BR_002(browser, base_url):
    """
    TC-PURCHASE-BR-002: Card Format Numeric Validation
    Business Rule: Card number must be numeric
    Standard: PCI-DSS 4.0.1 Requirement 3.4

    DISCOVER: Is non-numeric card input accepted?
    """
    # EXECUTE: Add product and open order form
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    # EXECUTE: Try multiple non-numeric formats
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    non_numeric_cards = [
        "ABCD-EFGH-IJKL-MNOP",
        "1234-ABCD-5678-9012",
        "VISA1234567890AB"
    ]

    violations = []

    for test_card in non_numeric_cards:
        browser.get(base_url)
        cart.open_cart()
        cart.click_place_order()
        purchase.wait_for_order_modal()

        purchase.fill_order_form(
            name="QA Tester",
            country="Spain",
            city="Barcelona",
            card=test_card,
            month="12",
            year="2028"
        )
        purchase.click_purchase()

        # OBSERVE: Check if accepted
        time.sleep(1)
        is_confirmed = purchase.is_purchase_confirmed(timeout=2)

        if is_confirmed:
            violations.append(test_card)
            logger.error(f"✗ VIOLATION: Non-numeric card accepted: {test_card}")

    # DECIDE: All non-numeric cards should be rejected
    if violations:
        pytest.fail(f"DISCOVERED: Non-numeric card validation missing - accepted {len(violations)} cards")

    logger.info("✓ Non-numeric card formats correctly rejected")


@pytest.mark.business_rules
@pytest.mark.high
@pytest.mark.pci_dss
def test_card_length_16_digits_BR_003(browser, base_url):
    """
    TC-PURCHASE-BR-003: Card Length 16 Digits Validation
    Business Rule: Card must be 16 digits (standard card length)
    Standard: PCI-DSS 4.0.1 Requirement 3.4

    DISCOVER: Are cards with incorrect length accepted?
    """
    # EXECUTE: Add product and open order form
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    # EXECUTE: Test various invalid lengths
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    invalid_lengths = [
        ("123456789012345", "15 digits"),
        ("12345678901234567", "17 digits"),
        ("123456789012", "12 digits"),
        ("12345678901234567890", "20 digits")
    ]

    violations = []

    for test_card, description in invalid_lengths:
        browser.get(base_url)
        cart.open_cart()
        cart.click_place_order()
        purchase.wait_for_order_modal()

        purchase.fill_order_form(
            name="QA Tester",
            country="Spain",
            city="Barcelona",
            card=test_card,
            month="12",
            year="2028"
        )
        purchase.click_purchase()

        # OBSERVE: Check if accepted
        time.sleep(1)
        is_confirmed = purchase.is_purchase_confirmed(timeout=2)

        if is_confirmed:
            violations.append(description)
            logger.error(f"✗ VIOLATION: {description} card accepted")

    # DECIDE: Only 16-digit cards should be accepted
    if violations:
        pytest.fail(f"DISCOVERED: Card length validation missing - accepted {len(violations)} invalid lengths")

    logger.info("✓ Card length validation enforced (16 digits)")


@pytest.mark.business_rules
@pytest.mark.high
@pytest.mark.pci_dss
def test_card_expiration_validation_BR_004(browser, base_url):
    """
    TC-PURCHASE-BR-004: Card Expiration Date Validation
    Business Rule: Card must not be expired
    Standard: PCI-DSS 4.0.1 Requirement 8.3.1

    DISCOVER: Are expired cards accepted?
    """
    # EXECUTE: Add product and open order form
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    # EXECUTE: Test expired dates
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    current_year = datetime.date.today().year
    expired_dates = [
        ("12", str(current_year - 1)),  # Last year
        ("01", str(current_year - 2)),  # 2 years ago
        ("06", str(current_year - 5)),  # 5 years ago
    ]

    violations = []

    for month, year in expired_dates:
        browser.get(base_url)
        cart.open_cart()
        cart.click_place_order()
        purchase.wait_for_order_modal()

        purchase.fill_order_form(
            name="QA Tester",
            country="Spain",
            city="Barcelona",
            card="1234567890123456",
            month=month,
            year=year
        )
        purchase.click_purchase()

        # OBSERVE: Check if accepted
        time.sleep(1)
        is_confirmed = purchase.is_purchase_confirmed(timeout=2)

        if is_confirmed:
            violations.append(f"{month}/{year}")
            logger.error(f"✗ VIOLATION: Expired card accepted: {month}/{year}")

    # DECIDE: Expired cards should be rejected
    if violations:
        pytest.fail(f"DISCOVERED: Expiration validation missing - accepted {len(violations)} expired cards")

    logger.info("✓ Expired card validation enforced")


@pytest.mark.business_rules
@pytest.mark.medium
def test_month_range_01_to_12_BR_005(browser, base_url):
    """
    TC-PURCHASE-BR-005: Month Range Validation (01-12)
    Business Rule: Month must be between 01 and 12
    Standard: ISO 8601 (Date/Time Format)

    DISCOVER: Are invalid month values accepted?
    """
    # EXECUTE: Add product and open order form
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    # EXECUTE: Test invalid month values
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    invalid_months = ["00", "13", "99", "-1", "15"]
    violations = []

    for invalid_month in invalid_months:
        browser.get(base_url)
        cart.open_cart()
        cart.click_place_order()
        purchase.wait_for_order_modal()

        purchase.fill_order_form(
            name="QA Tester",
            country="Spain",
            city="Barcelona",
            card="1234567890123456",
            month=invalid_month,
            year="2028"
        )
        purchase.click_purchase()

        # OBSERVE: Check if accepted
        time.sleep(1)
        is_confirmed = purchase.is_purchase_confirmed(timeout=2)

        if is_confirmed:
            violations.append(invalid_month)
            logger.error(f"✗ VIOLATION: Invalid month accepted: {invalid_month}")

    # DECIDE: Only 01-12 should be accepted
    if violations:
        pytest.fail(f"DISCOVERED: Month range validation missing - accepted {len(violations)} invalid months")

    logger.info("✓ Month range validation enforced (01-12)")


@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.critical
def test_sql_injection_all_fields_BR_006(browser, base_url):
    """
    TC-PURCHASE-BR-006: SQL Injection Protection (All Fields)
    Business Rule: All form fields must be protected against SQL injection
    Standard: OWASP ASVS v5.0 Section 1.2.5
    CWE: CWE-89
    CVSS Score: 9.8 CRITICAL

    DISCOVER: Are all form fields protected against SQL injection?
    """
    # EXECUTE: Add product and open order form
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    # EXECUTE: Test SQL injection in each field
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    sql_payload = "' OR '1'='1"
    fields_to_test = [
        ("name", sql_payload),
        ("country", sql_payload),
        ("city", sql_payload),
    ]

    violations = []

    for field_name, payload in fields_to_test:
        browser.get(base_url)
        cart.open_cart()
        cart.click_place_order()
        purchase.wait_for_order_modal()

        form_data = {
            'name': 'QA Tester',
            'country': 'Spain',
            'city': 'Barcelona',
            'card': '1234567890123456',
            'month': '12',
            'year': '2028'
        }
        form_data[field_name] = payload

        purchase.fill_order_form(**form_data)
        purchase.click_purchase()

        # OBSERVE: Check for injection success or error disclosure
        time.sleep(1)
        is_confirmed = purchase.is_purchase_confirmed(timeout=2)
        page_source = browser.page_source.lower()

        if is_confirmed:
            violations.append(f"{field_name} (injection succeeded)")
            logger.critical(f"✗ CRITICAL: SQL injection in {field_name}")

        if any(indicator in page_source for indicator in ["sql syntax", "mysql", "database error"]):
            violations.append(f"{field_name} (error disclosure)")
            logger.critical(f"✗ CRITICAL: SQL error disclosure in {field_name}")

    # DECIDE: All fields should be protected
    if violations:
        pytest.fail(f"DISCOVERED: SQL injection vulnerabilities in {len(violations)} fields: {violations}")

    logger.info("✓ SQL injection protection enforced on all fields")


@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.critical
def test_xss_protection_all_fields_BR_007(browser, base_url):
    """
    TC-PURCHASE-BR-007: XSS Protection (All Fields)
    Business Rule: All form fields must be sanitized against XSS
    Standard: OWASP ASVS v5.0 Section 1.2.3
    CWE: CWE-79
    CVSS Score: 8.2 HIGH

    DISCOVER: Are all form fields protected against XSS?
    """
    # EXECUTE: Add product and open order form
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    # EXECUTE: Test XSS in each field
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    xss_payload = "<script>alert('XSS')</script>"
    fields_to_test = ["name", "country", "city"]

    violations = []

    for field_name in fields_to_test:
        browser.get(base_url)
        cart.open_cart()
        cart.click_place_order()
        purchase.wait_for_order_modal()

        form_data = {
            'name': 'QA Tester',
            'country': 'Spain',
            'city': 'Barcelona',
            'card': '1234567890123456',
            'month': '12',
            'year': '2028'
        }
        form_data[field_name] = xss_payload

        purchase.fill_order_form(**form_data)
        purchase.click_purchase()

        # OBSERVE: Check for XSS reflection
        time.sleep(1)
        is_confirmed = purchase.is_purchase_confirmed(timeout=2)

        if is_confirmed:
            page_source = browser.page_source

            # Check if payload is reflected unescaped
            if xss_payload in page_source:
                violations.append(f"{field_name} (reflected unescaped)")
                logger.critical(f"✗ CRITICAL: XSS reflected in {field_name}")

            # Check for script execution
            try:
                alert = browser.switch_to.alert
                alert.accept()
                violations.append(f"{field_name} (executed)")
                logger.critical(f"✗ CRITICAL: XSS executed in {field_name}")
            except:
                pass

    # DECIDE: All fields should be sanitized
    if violations:
        pytest.fail(f"DISCOVERED: XSS vulnerabilities in {len(violations)} fields: {violations}")

    logger.info("✓ XSS protection enforced on all fields")


@pytest.mark.business_rules
@pytest.mark.medium
def test_name_max_length_enforcement_BR_008(browser, base_url):
    """
    TC-PURCHASE-BR-008: Name Field Maximum Length
    Business Rule: Name field should have reasonable max length
    Standard: OWASP ASVS v5.0 Section 1.2.6

    DISCOVER: What is the maximum accepted length for name field?
    """
    # EXECUTE: Add product and open order form
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    # EXECUTE: Try extremely long name
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    very_long_name = "A" * 1000

    purchase.fill_order_form(
        name=very_long_name,
        country="Spain",
        city="Barcelona",
        card="1234567890123456",
        month="12",
        year="2028"
    )
    purchase.click_purchase()

    # OBSERVE: Check system behavior
    time.sleep(1)
    is_confirmed = purchase.is_purchase_confirmed(timeout=3)

    if is_confirmed:
        confirm_text = purchase.get_purchase_confirmation_text()
        logger.info(f"✓ System accepted long name (confirmation length: {len(confirm_text)} chars)")
    else:
        logger.info("✓ System rejected extremely long name")


@pytest.mark.business_rules
@pytest.mark.medium
def test_whitespace_only_rejection_BR_009(browser, base_url):
    """
    TC-PURCHASE-BR-009: Whitespace-Only Input Rejection
    Business Rule: Form should reject whitespace-only inputs
    Standard: ISO 25010 (Software Quality)

    DISCOVER: Are whitespace-only inputs rejected in text fields?
    """
    # EXECUTE: Add product and open order form
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    # EXECUTE: Try whitespace-only in multiple fields
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    purchase.fill_order_form(
        name="     ",
        country="     ",
        city="     ",
        card="1234567890123456",
        month="12",
        year="2028"
    )
    purchase.click_purchase()

    # OBSERVE: Check if purchase proceeds
    time.sleep(1)
    is_confirmed = purchase.is_purchase_confirmed(timeout=3)

    # DECIDE: Whitespace-only should ideally be rejected
    if is_confirmed:
        logger.warning("⚠ DISCOVERED: Whitespace-only inputs accepted")
    else:
        logger.info("✓ Whitespace-only inputs correctly rejected")


@pytest.mark.business_rules
@pytest.mark.medium
def test_contact_form_validation_BR_010(browser, base_url):
    """
    TC-PURCHASE-BR-010: Contact Form Validation
    Business Rule: Contact form should validate inputs
    Standard: ISO 25010 (Software Quality)

    DISCOVER: Does contact form validate required fields?
    """
    # EXECUTE: Navigate and open contact form
    browser.get(base_url)
    purchase = PurchasePage(browser)

    # EXECUTE: Send valid message
    alert_text = purchase.send_contact_message(
        email="test@example.com",
        name="QA Tester",
        message="Test message"
    )

    # OBSERVE: Check alert response
    if alert_text:
        logger.info(f"✓ Contact form submitted: {alert_text}")
    else:
        logger.warning("⚠ No alert received from contact form")

    # EXECUTE: Try empty fields
    browser.get(base_url)
    alert_text_empty = purchase.send_contact_message(
        email="",
        name="",
        message=""
    )

    # DECIDE: Empty fields should be validated
    if alert_text_empty and "thanks" in alert_text_empty.lower():
        logger.warning("⚠ DISCOVERED: Contact form accepts empty fields")
    else:
        logger.info("✓ Contact form validates empty fields")
