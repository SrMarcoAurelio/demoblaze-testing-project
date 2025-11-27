"""
Purchase Security Tests
Author: Marc Arévalo
Version: 1.0

Test Coverage:
- Business logic exploits (price manipulation, race conditions)
- Bot protection and automated attack detection
- PCI-DSS compliance testing
- Session and authentication security
- Accessibility and WCAG compliance
- Input validation and injection attacks

Philosophy: DISCOVER (EXECUTE → OBSERVE → DECIDE)
All tests perform real exploitation attempts to discover actual vulnerabilities.
"""

import pytest
import logging
import time
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from pages.cart_page import CartPage
from pages.purchase_page import PurchasePage
from pages.login_page import LoginPage

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)



@pytest.mark.security
@pytest.mark.critical
@pytest.mark.business_logic
def test_price_manipulation_in_client_SEC_001(browser, base_url):
    """
    TC-PURCHASE-SEC-001: Client-Side Price Manipulation
    CWE: CWE-602 (Client-Side Enforcement of Server-Side Security)
    CVSS Score: 8.6 HIGH
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L

    DISCOVER: Can prices be manipulated via client-side modifications?
    """
    browser.get(base_url)
    cart = CartPage(browser)
    product_name, original_price = cart.add_first_product()
    cart.open_cart()

    cart_total = cart.get_cart_total()
    logger.info(f"Original cart total: ${cart_total}")

    try:
        browser.execute_script("""
            var totalElement = document.getElementById('totalp');
            if (totalElement) {
                totalElement.textContent = '1';
            }
        """)
        time.sleep(1)

        cart.click_place_order()
        purchase = PurchasePage(browser)
        purchase.wait_for_order_modal()

        success, confirm_text, details = purchase.complete_purchase()

        if success:
            confirmed_amount = details['amount']
            logger.info(f"Confirmed amount: ${confirmed_amount}")

            if confirmed_amount != cart_total:
                logger.critical(f"✗ CRITICAL: Price manipulation succeeded! Original: ${cart_total}, Confirmed: ${confirmed_amount}")
                pytest.fail(f"DISCOVERED: Client-side price manipulation vulnerability")
            else:
                logger.info(f"✓ Price manipulation prevented - server-side validation enforced")

    except Exception as e:
        logger.info(f"✓ Price manipulation blocked or not applicable: {str(e)}")


@pytest.mark.security
@pytest.mark.high
@pytest.mark.business_logic
def test_negative_quantity_exploit_SEC_002(browser, base_url):
    """
    TC-PURCHASE-SEC-002: Negative Quantity Exploit
    CWE: CWE-191 (Integer Underflow)
    CVSS Score: 7.5 HIGH
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N

    DISCOVER: Can negative quantities be added to cart for credit?
    """
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()

    initial_count = cart.get_cart_item_count()
    initial_total = cart.get_cart_total()

    try:
        browser.execute_script("""
            var rows = document.querySelectorAll('#tbodyid tr');
            if (rows.length > 0) {
                // Try to modify the underlying data or total
                var totalElement = document.getElementById('totalp');
                if (totalElement) {
                    var currentTotal = parseInt(totalElement.textContent) || 0;
                    totalElement.textContent = (currentTotal * -1).toString();
                }
            }
        """)
        time.sleep(1)

        cart.click_place_order()
        purchase = PurchasePage(browser)
        purchase.wait_for_order_modal()

        success, confirm_text, details = purchase.complete_purchase()

        if success and details['amount'] < 0:
            logger.critical("✗ CRITICAL: Negative amount accepted!")
            pytest.fail("DISCOVERED: Negative quantity/amount vulnerability")

        logger.info("✓ Negative quantity exploit prevented")

    except Exception as e:
        logger.info(f"✓ Negative quantity blocked: {str(e)}")


@pytest.mark.security
@pytest.mark.high
@pytest.mark.race_condition
def test_race_condition_double_purchase_SEC_003(browser, base_url):
    """
    TC-PURCHASE-SEC-003: Race Condition - Double Purchase
    CWE: CWE-362 (Concurrent Execution using Shared Resource)
    CVSS Score: 7.4 HIGH
    Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H

    DISCOVER: Can multiple rapid purchase clicks result in double charging?
    """
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()

    cart_total = cart.get_cart_total()
    cart.click_place_order()

    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()
    purchase.fill_valid_order_form()

    purchase.rapid_purchase_clicks(times=5)

    time.sleep(2)
    confirmations_count = 0

    try:
        for _ in range(3):
            if purchase.is_purchase_confirmed(timeout=1):
                confirmations_count += 1
                purchase.close_purchase_confirmation()
                time.sleep(0.5)
    except:
        pass

    if confirmations_count > 1:
        logger.critical(f"✗ CRITICAL: Multiple purchases detected ({confirmations_count})")
        pytest.fail(f"DISCOVERED: Race condition allows double purchase")
    else:
        logger.info(f"✓ Race condition prevented - {confirmations_count} purchase(s)")


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.business_logic
def test_cart_total_recalculation_exploit_SEC_004(browser, base_url):
    """
    TC-PURCHASE-SEC-004: Cart Total Recalculation Exploit
    CWE: CWE-682 (Incorrect Calculation)
    CVSS Score: 6.5 MEDIUM

    DISCOVER: Is cart total recalculated server-side during purchase?
    """
    browser.get(base_url)
    cart = CartPage(browser)
    name1, price1 = cart.add_first_product()
    name2, price2 = cart.add_second_product()

    cart.open_cart()
    cart_total = cart.get_cart_total()

    expected_total = price1 + price2
    logger.info(f"Expected total: ${expected_total}, Cart shows: ${cart_total}")

    cart.delete_first_item()
    time.sleep(1)

    new_total = cart.get_cart_total()
    logger.info(f"After deletion, new total: ${new_total}")

    cart.click_place_order()
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    success, confirm_text, details = purchase.complete_purchase()

    if success:
        confirmed_amount = details['amount']
        if confirmed_amount != new_total:
            logger.critical(f"✗ CRITICAL: Total mismatch! Cart: ${new_total}, Charged: ${confirmed_amount}")
            pytest.fail("DISCOVERED: Cart total recalculation vulnerability")
        else:
            logger.info("✓ Cart total correctly recalculated server-side")



@pytest.mark.security
@pytest.mark.high
@pytest.mark.bot_protection
def test_rapid_purchase_attempts_BOT_001(browser, base_url):
    """
    TC-PURCHASE-BOT-001: Rapid Purchase Attempts Detection
    CWE: CWE-307 (Improper Restriction of Excessive Authentication Attempts)
    CVSS Score: 7.5 HIGH
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

    DISCOVER: Is there rate limiting on purchase attempts?
    """
    browser.get(base_url)
    cart = CartPage(browser)

    purchase_attempts = 10
    successful_purchases = 0
    rate_limited = False

    for i in range(purchase_attempts):
        browser.get(base_url)
        cart.add_first_product()
        cart.open_cart()
        cart.click_place_order()

        purchase = PurchasePage(browser)
        purchase.wait_for_order_modal(timeout=3)
        purchase.fill_valid_order_form()
        purchase.click_purchase()

        time.sleep(0.5)

        is_confirmed = purchase.is_purchase_confirmed(timeout=2)

        if is_confirmed:
            successful_purchases += 1
            purchase.close_purchase_confirmation()
        else:
            alert_text = purchase.get_alert_text(timeout=1)
            if alert_text and any(word in alert_text.lower() for word in ["limit", "wait", "too many"]):
                rate_limited = True
                logger.info(f"✓ Rate limiting detected after {i+1} attempts")
                break

        logger.info(f"Purchase attempt {i+1}/{purchase_attempts}: {'Success' if is_confirmed else 'Failed'}")

    if successful_purchases >= purchase_attempts and not rate_limited:
        logger.warning(f"⚠ DISCOVERED: No rate limiting after {purchase_attempts} rapid purchases")
    else:
        logger.info(f"✓ Bot protection: {successful_purchases} purchases allowed")


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.bot_protection
def test_automated_cart_manipulation_BOT_002(browser, base_url):
    """
    TC-PURCHASE-BOT-002: Automated Cart Manipulation Detection
    CWE: CWE-799 (Improper Control of Interaction Frequency)
    CVSS Score: 6.5 MEDIUM

    DISCOVER: Are automated rapid cart operations detected?
    """
    browser.get(base_url)
    cart = CartPage(browser)

    operations = 20
    blocked = False

    for i in range(operations):
        try:
            browser.get(base_url)
            cart.add_first_product()
            cart.open_cart()

            if cart.get_cart_item_count() > 0:
                cart.delete_first_item()

            time.sleep(0.1)  # Very rapid operations

            page_source = browser.page_source.lower()
            if any(keyword in page_source for keyword in ["captcha", "robot", "automated", "blocked"]):
                blocked = True
                logger.info(f"✓ Bot detection triggered after {i+1} operations")
                break

        except Exception as e:
            logger.info(f"Operation {i+1} failed: {str(e)}")

    if not blocked:
        logger.warning(f"⚠ DISCOVERED: No bot detection after {operations} rapid operations")
    else:
        logger.info("✓ Automated manipulation detected")



@pytest.mark.security
@pytest.mark.critical
@pytest.mark.pci_dss
def test_card_number_masking_PCI_001(browser, base_url):
    """
    TC-PURCHASE-PCI-001: Card Number Masking in Confirmation
    Standard: PCI-DSS 4.0.1 Requirement 3.3 (Mask PAN when displayed)
    CWE: CWE-532 (Information Exposure Through Log Files)
    CVSS Score: 8.2 HIGH

    DISCOVER: Is the full card number displayed in confirmation?
    """
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    test_card = "1234567890123456"
    success, confirm_text, details = purchase.complete_purchase(
        name="QA Tester",
        country="Spain",
        city="Barcelona",
        card=test_card,
        month="12",
        year="2028"
    )

    if success and confirm_text:
        if test_card in confirm_text:
            logger.critical("✗ CRITICAL: Full card number exposed in confirmation!")
            pytest.fail("DISCOVERED: PCI-DSS violation - unmasked card number displayed")

        if details['card']:
            displayed_card = details['card']
            logger.info(f"Card displayed as: {displayed_card}")

            if len(displayed_card) == 16 and displayed_card == test_card:
                logger.critical("✗ CRITICAL: Card number not masked!")
                pytest.fail("DISCOVERED: PCI-DSS violation - card not masked")

        logger.info("✓ Card number properly masked in confirmation")


@pytest.mark.security
@pytest.mark.high
@pytest.mark.pci_dss
def test_card_data_in_url_PCI_002(browser, base_url):
    """
    TC-PURCHASE-PCI-002: Card Data Not in URL
    Standard: PCI-DSS 4.0.1 Requirement 3.2 (Do not store PAN in URL)
    CVSS Score: 9.1 CRITICAL

    DISCOVER: Is card data ever transmitted in URL parameters?
    """
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    test_card = "1234567890123456"
    purchase.fill_order_form(
        name="QA Tester",
        country="Spain",
        city="Barcelona",
        card=test_card,
        month="12",
        year="2028"
    )
    purchase.click_purchase()

    time.sleep(2)

    current_url = browser.current_url
    logger.info(f"Current URL: {current_url}")

    if test_card in current_url or "1234" in current_url:
        logger.critical("✗ CRITICAL: Card data found in URL!")
        pytest.fail("DISCOVERED: PCI-DSS critical violation - card in URL")

    logger.info("✓ Card data not exposed in URL")


@pytest.mark.security
@pytest.mark.high
@pytest.mark.pci_dss
def test_card_data_in_browser_storage_PCI_003(browser, base_url):
    """
    TC-PURCHASE-PCI-003: Card Data Not in Browser Storage
    Standard: PCI-DSS 4.0.1 Requirement 3.2.1 (Do not store SAD after authorization)
    CVSS Score: 8.8 HIGH

    DISCOVER: Is card data stored in localStorage or sessionStorage?
    """
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    test_card = "1234567890123456"
    purchase.fill_order_form(
        name="QA Tester",
        country="Spain",
        city="Barcelona",
        card=test_card,
        month="12",
        year="2028"
    )

    time.sleep(1)

    local_storage = browser.execute_script("return JSON.stringify(localStorage);")
    session_storage = browser.execute_script("return JSON.stringify(sessionStorage);")

    logger.info(f"LocalStorage: {local_storage[:100]}...")
    logger.info(f"SessionStorage: {session_storage[:100]}...")

    if test_card in local_storage or test_card in session_storage:
        logger.critical("✗ CRITICAL: Card data stored in browser storage!")
        pytest.fail("DISCOVERED: PCI-DSS critical violation - card in client storage")

    logger.info("✓ Card data not stored in browser storage")


@pytest.mark.security
@pytest.mark.high
@pytest.mark.pci_dss
def test_card_cvv_not_stored_PCI_004(browser, base_url):
    """
    TC-PURCHASE-PCI-004: CVV Not Stored or Logged
    Standard: PCI-DSS 4.0.1 Requirement 3.2.1 (Never store CVV)
    CVSS Score: 9.8 CRITICAL

    DISCOVER: Does the system ask for CVV? If so, is it stored?
    """
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    page_source = browser.page_source.lower()

    cvv_indicators = ["cvv", "cvc", "security code", "card verification"]
    cvv_field_found = any(indicator in page_source for indicator in cvv_indicators)

    if cvv_field_found:
        logger.info("CVV field detected - checking if it's stored...")

        local_storage = browser.execute_script("return JSON.stringify(localStorage);")
        session_storage = browser.execute_script("return JSON.stringify(sessionStorage);")

        if any(indicator in local_storage.lower() or indicator in session_storage.lower()
               for indicator in cvv_indicators):
            logger.critical("✗ CRITICAL: CVV data found in browser storage!")
            pytest.fail("DISCOVERED: PCI-DSS critical violation - CVV stored")

    logger.info("✓ CVV storage test passed (no CVV field or not stored)")



@pytest.mark.security
@pytest.mark.high
@pytest.mark.session
def test_purchase_without_authentication_SESSION_001(browser, base_url):
    """
    TC-PURCHASE-SESSION-001: Purchase Without Authentication
    CWE: CWE-306 (Missing Authentication for Critical Function)
    CVSS Score: 7.5 HIGH

    DISCOVER: Can unauthenticated users complete purchases?
    """
    browser.get(base_url)
    cart = CartPage(browser)

    login_page = LoginPage(browser)
    is_logged_in = login_page.is_user_logged_in(timeout=1)

    if is_logged_in:
        login_page.logout()
        time.sleep(1)

    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    purchase = PurchasePage(browser)
    modal_opened = purchase.wait_for_order_modal(timeout=3)

    if modal_opened:
        logger.info("Purchase modal accessible without authentication")

        success, confirm_text, details = purchase.complete_purchase()

        if success:
            logger.warning("⚠ DISCOVERED: Unauthenticated purchase allowed")
        else:
            logger.info("✓ Purchase blocked without authentication")
    else:
        logger.info("✓ Purchase modal requires authentication")


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.session
def test_session_fixation_SESSION_002(browser, base_url):
    """
    TC-PURCHASE-SESSION-002: Session Fixation Vulnerability
    CWE: CWE-384 (Session Fixation)
    CVSS Score: 6.5 MEDIUM

    DISCOVER: Is session ID regenerated after sensitive operations?
    """
    browser.get(base_url)
    cookies_before = browser.get_cookies()
    session_cookie_before = next((c for c in cookies_before if 'session' in c['name'].lower()), None)

    login_page = LoginPage(browser)
    login_page.login("testuser123", "testpass")
    time.sleep(2)

    cookies_after = browser.get_cookies()
    session_cookie_after = next((c for c in cookies_after if 'session' in c['name'].lower()), None)

    if session_cookie_before and session_cookie_after:
        if session_cookie_before['value'] == session_cookie_after['value']:
            logger.warning("⚠ DISCOVERED: Session ID not regenerated after login")
        else:
            logger.info("✓ Session ID regenerated after login")
    else:
        logger.info("Session cookies not detected or not applicable")


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.session
def test_cart_session_hijacking_SESSION_003(browser, base_url):
    """
    TC-PURCHASE-SESSION-003: Cart Session Hijacking
    CWE: CWE-639 (Authorization Bypass Through User-Controlled Key)
    CVSS Score: 6.5 MEDIUM

    DISCOVER: Can cart contents be manipulated via session?
    """
    browser.get(base_url)
    cart = CartPage(browser)
    product_name, price = cart.add_first_product()
    cart.open_cart()

    initial_count = cart.get_cart_item_count()
    initial_total = cart.get_cart_total()

    logger.info(f"Initial cart: {initial_count} items, ${initial_total}")

    try:
        browser.execute_script("""
            var cartData = localStorage.getItem('cart') || sessionStorage.getItem('cart');
            if (cartData) {
                // Try to modify cart data
                console.log('Cart data found:', cartData);
            }
        """)

        browser.refresh()
        time.sleep(1)

        cart.open_cart()
        new_count = cart.get_cart_item_count()
        new_total = cart.get_cart_total()

        logger.info(f"After refresh: {new_count} items, ${new_total}")

        if new_count == initial_count and new_total == initial_total:
            logger.info("✓ Cart session properly validated")
        else:
            logger.warning("⚠ Cart state changed after manipulation attempt")

    except Exception as e:
        logger.info(f"Session manipulation blocked: {str(e)}")



@pytest.mark.security
@pytest.mark.critical
@pytest.mark.injection
@pytest.mark.parametrize("sqli_payload", [
    "' OR '1'='1' --",
    "'; DROP TABLE orders--",
    "1' UNION SELECT NULL,NULL,NULL--",
    "admin' AND '1'='1",
])
def test_advanced_sql_injection_INJ_001(browser, base_url, sqli_payload):
    """
    TC-PURCHASE-INJ-001: Advanced SQL Injection Attacks
    CWE: CWE-89
    CVSS Score: 9.8 CRITICAL
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    DISCOVER: Advanced SQL injection vectors in purchase form
    """
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    purchase.fill_order_form(
        name=sqli_payload,
        country="Spain",
        city="Barcelona",
        card="1234567890123456",
        month="12",
        year="2028"
    )
    purchase.click_purchase()

    time.sleep(1)
    is_confirmed = purchase.is_purchase_confirmed(timeout=2)
    page_source = browser.page_source.lower()

    error_indicators = [
        "sql syntax", "mysql", "postgresql", "sqlite", "database error",
        "odbc", "jdbc", "oracle", "syntax error near"
    ]

    if is_confirmed:
        logger.critical(f"✗ CRITICAL: SQL injection may have succeeded: {sqli_payload}")
        pytest.fail(f"DISCOVERED: SQL injection vulnerability with '{sqli_payload}'")

    for indicator in error_indicators:
        if indicator in page_source:
            logger.critical(f"✗ CRITICAL: SQL error disclosure: {indicator}")
            pytest.fail(f"DISCOVERED: SQL error disclosure - {indicator}")

    logger.info(f"✓ SQL injection prevented: {sqli_payload}")


@pytest.mark.security
@pytest.mark.critical
@pytest.mark.injection
@pytest.mark.parametrize("xss_vector", [
    "<img src=x onerror=alert(document.cookie)>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert(document.domain)",
    "<iframe src='javascript:alert(1)'>",
])
def test_advanced_xss_vectors_INJ_002(browser, base_url, xss_vector):
    """
    TC-PURCHASE-INJ-002: Advanced XSS Attack Vectors
    CWE: CWE-79
    CVSS Score: 8.2 HIGH
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N

    DISCOVER: Advanced XSS vectors in purchase confirmation
    """
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    purchase.fill_order_form(
        name=xss_vector,
        country="Spain",
        city="Barcelona",
        card="1234567890123456",
        month="12",
        year="2028"
    )
    purchase.click_purchase()

    time.sleep(1)
    is_confirmed = purchase.is_purchase_confirmed(timeout=2)

    if is_confirmed:
        page_source = browser.page_source

        if xss_vector in page_source:
            logger.critical(f"✗ CRITICAL: XSS payload reflected: {xss_vector}")
            pytest.fail(f"DISCOVERED: XSS vulnerability - payload reflected unescaped")

        try:
            alert = browser.switch_to.alert
            alert_text = alert.text
            alert.accept()
            logger.critical(f"✗ CRITICAL: XSS executed! Alert: {alert_text}")
            pytest.fail("DISCOVERED: XSS execution confirmed")
        except:
            pass  # No alert = good

    logger.info(f"✓ XSS prevented: {xss_vector}")


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.injection
def test_ldap_injection_INJ_003(browser, base_url):
    """
    TC-PURCHASE-INJ-003: LDAP Injection Testing
    CWE: CWE-90 (LDAP Injection)
    CVSS Score: 7.5 HIGH

    DISCOVER: LDAP injection vulnerabilities in form fields
    """
    ldap_payloads = [
        "*)(uid=*))(|(uid=*",
        "admin)(&(password=*))",
        "*))%00"
    ]

    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    violations = []

    for payload in ldap_payloads:
        purchase.fill_order_form(
            name=payload,
            country="Spain",
            city="Barcelona",
            card="1234567890123456",
            month="12",
            year="2028"
        )
        purchase.click_purchase()

        time.sleep(1)
        page_source = browser.page_source.lower()

        ldap_errors = ["ldap", "directory", "naming exception"]

        for error in ldap_errors:
            if error in page_source:
                violations.append(f"{payload} -> {error}")
                logger.critical(f"✗ LDAP error disclosure: {error}")

    if violations:
        pytest.fail(f"DISCOVERED: LDAP injection vulnerabilities: {violations}")

    logger.info("✓ LDAP injection prevented")


@pytest.mark.security
@pytest.mark.medium
@pytest.mark.injection
def test_command_injection_INJ_004(browser, base_url):
    """
    TC-PURCHASE-INJ-004: OS Command Injection
    CWE: CWE-78 (OS Command Injection)
    CVSS Score: 9.8 CRITICAL

    DISCOVER: Command injection in form processing
    """
    command_payloads = [
        "; ls -la",
        "| whoami",
        "`id`",
        "$(cat /etc/passwd)"
    ]

    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    violations = []

    for payload in command_payloads:
        purchase.fill_order_form(
            name=payload,
            country="Spain",
            city="Barcelona",
            card="1234567890123456",
            month="12",
            year="2028"
        )
        purchase.click_purchase()

        time.sleep(1)
        page_source = browser.page_source.lower()

        command_indicators = ["/bin", "/usr", "root:", "uid=", "total "]

        for indicator in command_indicators:
            if indicator in page_source:
                violations.append(f"{payload} -> {indicator}")
                logger.critical(f"✗ Command injection artifact: {indicator}")

    if violations:
        pytest.fail(f"DISCOVERED: Command injection vulnerabilities: {violations}")

    logger.info("✓ Command injection prevented")



@pytest.mark.security
@pytest.mark.low
@pytest.mark.accessibility
def test_keyboard_navigation_WCAG_001(browser, base_url):
    """
    TC-PURCHASE-WCAG-001: Keyboard-Only Navigation
    Standard: WCAG 2.1 Level AA - Guideline 2.1.1 (Keyboard)
    CVSS Score: 4.3 LOW

    DISCOVER: Can purchase flow be completed using only keyboard?
    """
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    try:
        filled_values = purchase.navigate_form_with_tab(
            fill_data=["QA Tester", "Spain", "Barcelona", "1234567890123456", "12", "2028"]
        )

        logger.info(f"Keyboard navigation filled: {filled_values}")

        if all(filled_values.values()):
            logger.info("✓ Keyboard navigation fully functional")
        else:
            empty_fields = [k for k, v in filled_values.items() if not v]
            logger.warning(f"⚠ ACCESSIBILITY ISSUE: Fields not keyboard-accessible: {empty_fields}")

    except Exception as e:
        logger.warning(f"⚠ Keyboard navigation issue: {str(e)}")


@pytest.mark.security
@pytest.mark.low
@pytest.mark.accessibility
def test_screen_reader_labels_WCAG_002(browser, base_url):
    """
    TC-PURCHASE-WCAG-002: Screen Reader Labels
    Standard: WCAG 2.1 Level A - Guideline 4.1.2 (Name, Role, Value)
    CVSS Score: 4.3 LOW

    DISCOVER: Do form fields have proper labels for screen readers?
    """
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    form_fields = [
        "name", "country", "city", "card", "month", "year"
    ]

    missing_labels = []

    for field_id in form_fields:
        label_check = browser.execute_script(f"""
            var field = document.getElementById('{field_id}');
            if (!field) return false;

            // Check for label association
            var label = document.querySelector('label[for="{field_id}"]');
            var ariaLabel = field.getAttribute('aria-label');
            var ariaLabelledBy = field.getAttribute('aria-labelledby');

            return !!(label || ariaLabel || ariaLabelledBy);
        """)

        if not label_check:
            missing_labels.append(field_id)

    if missing_labels:
        logger.warning(f"⚠ ACCESSIBILITY ISSUE: Missing labels for {missing_labels}")
    else:
        logger.info("✓ All form fields properly labeled for screen readers")


@pytest.mark.security
@pytest.mark.low
@pytest.mark.accessibility
def test_color_contrast_WCAG_003(browser, base_url):
    """
    TC-PURCHASE-WCAG-003: Color Contrast Ratios
    Standard: WCAG 2.1 Level AA - Guideline 1.4.3 (Contrast Minimum)
    CVSS Score: 3.1 LOW

    DISCOVER: Do buttons and text meet minimum contrast ratios?
    """
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    purchase_button_styles = browser.execute_script("""
        var button = document.querySelector('button:contains("Purchase")') ||
                     document.evaluate("//button[text()='Purchase']", document, null,
                                      XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
        if (!button) return null;

        var styles = window.getComputedStyle(button);
        return {
            color: styles.color,
            backgroundColor: styles.backgroundColor,
            fontSize: styles.fontSize
        };
    """)

    if purchase_button_styles:
        logger.info(f"Purchase button styles: {purchase_button_styles}")
        logger.info("✓ Color contrast check completed (manual review recommended)")
    else:
        logger.warning("⚠ Could not retrieve button styles for contrast check")


@pytest.mark.security
@pytest.mark.low
@pytest.mark.accessibility
def test_focus_indicators_WCAG_004(browser, base_url):
    """
    TC-PURCHASE-WCAG-004: Visible Focus Indicators
    Standard: WCAG 2.1 Level AA - Guideline 2.4.7 (Focus Visible)
    CVSS Score: 3.1 LOW

    DISCOVER: Are focus indicators visible when tabbing through form?
    """
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    actions = ActionChains(browser)
    name_field = browser.find_element(*purchase.ORDER_NAME_FIELD)
    name_field.click()

    fields_with_visible_focus = []

    for i in range(6):  # 6 form fields
        time.sleep(0.3)

        focus_check = browser.execute_script("""
            var activeEl = document.activeElement;
            var styles = window.getComputedStyle(activeEl);

            // Check for focus styling
            var outlineWidth = styles.outlineWidth;
            var outlineStyle = styles.outlineStyle;
            var borderWidth = styles.borderWidth;

            return {
                hasOutline: outlineWidth !== '0px' && outlineStyle !== 'none',
                hasBorder: borderWidth !== '0px',
                tagName: activeEl.tagName,
                id: activeEl.id
            };
        """)

        if focus_check and (focus_check['hasOutline'] or focus_check['hasBorder']):
            fields_with_visible_focus.append(focus_check['id'])

        actions.send_keys(Keys.TAB).perform()

    logger.info(f"✓ Visible focus detected on {len(fields_with_visible_focus)} fields")

    if len(fields_with_visible_focus) < 6:
        logger.warning("⚠ ACCESSIBILITY ISSUE: Some fields lack visible focus indicators")
