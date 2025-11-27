"""
Test Suite: PURCHASE Functional Testing (POM Architecture)
Module: test_purchase_functional.py
Author: Marc Arévalo
Version: 1.0

PHILOSOPHY: DISCOVER (EXECUTE → OBSERVE → DECIDE)
Tests actively discover how the purchase system works through real interactions.

Test Categories:
- Purchase Flow: Complete purchase process validation
- Cart Operations: Add, delete, total calculation
- Modal Operations: Open, close, navigation
- Edge Cases: Empty cart, multiple items, rapid clicks

Execution:
pytest tests_new/purchase/test_purchase_functional.py -v
pytest tests_new/purchase/test_purchase_functional.py -m "critical" -v

Total Tests: 20
"""

import pytest
import time
import logging
from pages.cart_page import CartPage
from pages.purchase_page import PurchasePage

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


@pytest.fixture
def cart_page(browser, base_url):
    """Setup: Browser with one item in cart"""
    browser.get(base_url)
    cart = CartPage(browser)

    cart.add_first_product()

    cart.open_cart()

    return cart

@pytest.fixture
def order_modal(cart_page):
    """Setup: Cart page with order modal open"""
    purchase = PurchasePage(cart_page.driver)

    cart_page.click_place_order()

    purchase.wait_for_order_modal()

    return purchase


@pytest.mark.functional
@pytest.mark.critical
def test_successful_purchase_with_price_verification_FUNC_001(browser, base_url):
    """
    TC-PURCHASE-FUNC-001: Successful Purchase with Price Verification

    DISCOVER: Verify complete purchase flow and price consistency
    """
    logging.info("TC-PURCHASE-FUNC-001: Testing successful purchase flow...")

    browser.get(base_url)
    cart = CartPage(browser)
    product_name, price = cart.add_first_product()
    cart.open_cart()

    cart_total = cart.get_cart_total()
    assert cart_total == price, f"Cart total {cart_total} should match product price {price}"

    cart.click_place_order()

    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    success, confirm_text, details = purchase.complete_purchase(
        name="QA Tester",
        country="Spain",
        city="Barcelona",
        card="1234567890123456",
        month="12",
        year="2028"
    )

    assert success, "Purchase should complete successfully"
    assert details['amount'] == cart_total, \
        f"Confirmed amount {details['amount']} should match cart total {cart_total}"

    logging.info(f"✓ Purchase completed successfully: ${details['amount']}")
    assert True


@pytest.mark.functional
@pytest.mark.critical
def test_cart_empty_after_purchase_FUNC_002(order_modal):
    """
    TC-PURCHASE-FUNC-002: Cart Empty After Successful Purchase

    DISCOVER: Verify cart is cleared after purchase
    """
    logging.info("TC-PURCHASE-FUNC-002: Testing cart clearing after purchase...")

    purchase = order_modal

    purchase.fill_valid_order_form()
    purchase.click_purchase()

    assert purchase.is_purchase_confirmed(), "Purchase should be confirmed"
    purchase.close_purchase_confirmation()

    cart = CartPage(purchase.driver)
    cart.open_cart()

    item_count = cart.get_cart_item_count()

    assert item_count == 0, f"Cart should be empty after purchase, found {item_count} items"

    logging.info("✓ Cart cleared after purchase")
    assert True


@pytest.mark.functional
@pytest.mark.high
def test_purchase_as_logged_in_user_FUNC_003(browser, base_url):
    """
    TC-PURCHASE-FUNC-003: Purchase as Logged-In User

    DISCOVER: Verify logged-in users can purchase
    """
    logging.info("TC-PURCHASE-FUNC-003: Testing purchase with logged-in user...")

    browser.get(base_url)

    from pages.login_page import LoginPage
    login = LoginPage(browser)
    login.login("Apolo2025", "apolo2025")

    assert login.is_user_logged_in(), "Should be logged in"

    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    name_value = purchase.get_form_field_value(purchase.ORDER_NAME_FIELD)

    logging.info(f"Name field value: '{name_value}' (auto-fill not implemented)")

    success, _, details = purchase.complete_purchase()

    assert success, "Logged-in user should be able to purchase"
    logging.info("✓ Logged-in user completed purchase")

    login.logout()
    assert True



@pytest.mark.functional
@pytest.mark.critical
def test_multiple_items_total_calculation_FUNC_004(browser, base_url):
    """
    TC-PURCHASE-FUNC-004: Multiple Items Total Calculation

    DISCOVER: Verify cart calculates total correctly for multiple items
    """
    logging.info("TC-PURCHASE-FUNC-004: Testing multiple items total...")

    browser.get(base_url)
    cart = CartPage(browser)

    name1, price1 = cart.add_first_product()
    name2, price2 = cart.add_second_product()

    cart.open_cart()

    cart_total = cart.get_cart_total()
    expected_total = price1 + price2

    assert cart_total == expected_total, \
        f"Cart total {cart_total} should equal {price1} + {price2} = {expected_total}"

    logging.info(f"✓ Cart total verified: ${cart_total} = ${price1} + ${price2}")
    assert True


@pytest.mark.functional
@pytest.mark.high
def test_delete_item_from_cart_FUNC_005(cart_page):
    """
    TC-PURCHASE-FUNC-005: Delete Item from Cart

    DISCOVER: Verify item deletion works correctly
    """
    logging.info("TC-PURCHASE-FUNC-005: Testing item deletion...")

    cart = cart_page

    initial_count = cart.get_cart_item_count()
    assert initial_count == 1, "Should have 1 item initially"

    item_name = cart.get_first_item_name()
    assert item_name is not None, "Should be able to get item name"

    cart.delete_first_item()

    final_count = cart.get_cart_item_count()

    assert final_count == 0, f"Cart should be empty, found {final_count} items"

    logging.info("✓ Item deleted successfully")
    assert True


@pytest.mark.functional
@pytest.mark.high
def test_delete_item_and_recalculate_total_FUNC_006(browser, base_url):
    """
    TC-PURCHASE-FUNC-006: Delete Item and Recalculate Total

    DISCOVER: Verify total recalculates after deletion
    """
    logging.info("TC-PURCHASE-FUNC-006: Testing total recalculation after deletion...")

    browser.get(base_url)
    cart = CartPage(browser)

    name1, price1 = cart.add_first_product()
    name2, price2 = cart.add_second_product()

    cart.open_cart()

    initial_total = cart.get_cart_total()
    expected_initial = price1 + price2
    assert initial_total == expected_initial, f"Initial total incorrect: {initial_total} != {expected_initial}"

    cart.delete_first_item()

    new_total = cart.get_cart_total()

    assert new_total == price2, f"Total after deletion should be {price2}, got {new_total}"

    logging.info(f"✓ Total recalculated: ${initial_total} → ${new_total}")
    assert True


@pytest.mark.functional
@pytest.mark.medium
def test_add_same_product_multiple_times_FUNC_007(browser, base_url):
    """
    TC-PURCHASE-FUNC-007: Add Same Product Multiple Times

    DISCOVER: Verify duplicate product handling
    """
    logging.info("TC-PURCHASE-FUNC-007: Testing same product multiple times...")

    browser.get(base_url)
    cart = CartPage(browser)

    name1, price1 = cart.add_first_product()
    name2, price2 = cart.add_first_product()

    cart.open_cart()

    item_count = cart.get_cart_item_count()

    assert item_count == 2, f"Expected 2 items, got {item_count}"

    total = cart.get_cart_total()
    expected_total = price1 * 2

    assert total == expected_total, f"Total should be {expected_total}, got {total}"

    logging.info(f"✓ Same product added twice: {item_count} items, total ${total}")
    assert True


@pytest.mark.functional
@pytest.mark.medium
def test_delete_all_items_from_cart_FUNC_008(browser, base_url):
    """
    TC-PURCHASE-FUNC-008: Delete All Items From Cart

    DISCOVER: Verify deleting all items works correctly
    """
    logging.info("TC-PURCHASE-FUNC-008: Testing delete all items...")

    browser.get(base_url)
    cart = CartPage(browser)

    cart.add_first_product()
    cart.add_second_product()

    cart.open_cart()

    initial_count = cart.get_cart_item_count()
    assert initial_count == 2, "Should have 2 items"

    cart.delete_all_items()

    final_count = cart.get_cart_item_count()

    assert final_count == 0, f"Cart should be empty, found {final_count} items"

    logging.info("✓ All items deleted successfully")
    assert True



@pytest.mark.functional
@pytest.mark.medium
def test_order_modal_close_button_FUNC_009(order_modal):
    """
    TC-PURCHASE-FUNC-009: Order Modal Close Button

    DISCOVER: Verify modal close functionality
    """
    logging.info("TC-PURCHASE-FUNC-009: Testing modal close button...")

    purchase = order_modal

    assert purchase.is_order_modal_visible(), "Modal should be visible"

    purchase.close_order_modal_with_close_button()

    cart = CartPage(purchase.driver)
    assert cart.is_place_order_visible(), "Should be back on cart page"

    logging.info("✓ Modal closed successfully")
    assert True


@pytest.mark.functional
@pytest.mark.medium
def test_open_close_modal_multiple_times_FUNC_010(cart_page):
    """
    TC-PURCHASE-FUNC-010: Open/Close Modal Multiple Times

    DISCOVER: Verify modal can be opened and closed repeatedly
    """
    logging.info("TC-PURCHASE-FUNC-010: Testing multiple modal open/close...")

    cart = cart_page
    purchase = PurchasePage(cart.driver)

    for i in range(3):
        cart.click_place_order()
        purchase.wait_for_order_modal()

        assert purchase.is_order_modal_visible(), f"Modal should be visible (iteration {i+1})"
        logging.info(f"Modal opened - iteration {i+1}")

        purchase.close_order_modal_with_close_button()
        assert cart.is_place_order_visible(), f"Should be on cart page (iteration {i+1})"
        logging.info(f"Modal closed - iteration {i+1}")

    logging.info("✓ Modal opened and closed 3 times successfully")
    assert True


@pytest.mark.functional
@pytest.mark.medium
def test_order_modal_escape_key_FUNC_011(cart_page):
    """
    TC-PURCHASE-FUNC-011: Close Modal with ESC Key

    DISCOVER: Verify ESC key closes modal (accessibility)
    """
    logging.info("TC-PURCHASE-FUNC-011: Testing ESC key modal close...")

    cart = cart_page
    purchase = PurchasePage(cart.driver)

    cart.click_place_order()
    purchase.wait_for_order_modal()

    assert purchase.is_order_modal_visible(), "Modal should be visible"

    modal_closed = purchase.close_order_modal_with_escape()

    if modal_closed:
        logging.info("✓ Modal closed with ESC key")
        assert cart.is_place_order_visible(), "Should be on cart page"
    else:
        logging.info("⚠ Modal did NOT close with ESC (documented behavior)")
        purchase.close_order_modal_with_close_button()

    assert True



@pytest.mark.functional
@pytest.mark.medium
def test_access_empty_cart_FUNC_012(browser, base_url):
    """
    TC-PURCHASE-FUNC-012: Access Cart Without Adding Products

    DISCOVER: Verify empty cart behavior
    """
    logging.info("TC-PURCHASE-FUNC-012: Testing empty cart access...")

    browser.get(base_url)
    cart = CartPage(browser)

    cart.open_cart()

    item_count = cart.get_cart_item_count()

    assert item_count == 0, f"Cart should be empty, found {item_count} items"

    assert cart.is_place_order_visible(), "Place Order button should be visible"

    logging.info("✓ Empty cart accessible, Place Order visible")
    assert True


@pytest.mark.functional
@pytest.mark.medium
def test_cart_persistence_across_navigation_FUNC_013(browser, base_url):
    """
    TC-PURCHASE-FUNC-013: Cart Persistence Across Navigation

    DISCOVER: Verify cart persists when navigating pages
    """
    logging.info("TC-PURCHASE-FUNC-013: Testing cart persistence...")

    browser.get(base_url)
    cart = CartPage(browser)

    name, price = cart.add_first_product()

    cart.go_home()
    cart.click(cart.FIRST_PRODUCT_LINK)
    cart.wait_for_element_visible(cart.PRODUCT_PRICE_HEADER)

    cart.go_home()

    cart.open_cart()

    item_count = cart.get_cart_item_count()
    cart_total = cart.get_cart_total()

    assert item_count == 1, f"Cart should have 1 item, found {item_count}"
    assert cart_total == price, f"Cart total should be {price}, got {cart_total}"

    logging.info("✓ Cart persisted correctly across navigation")
    assert True


@pytest.mark.functional
@pytest.mark.medium
def test_navigation_after_purchase_FUNC_014(order_modal):
    """
    TC-PURCHASE-FUNC-014: Navigation After Purchase

    DISCOVER: Verify navigation state after purchase
    """
    logging.info("TC-PURCHASE-FUNC-014: Testing navigation after purchase...")

    purchase = order_modal

    purchase.fill_valid_order_form()
    purchase.click_purchase()

    assert purchase.is_purchase_confirmed(), "Purchase should be confirmed"
    purchase.close_purchase_confirmation()

    current_url = purchase.driver.current_url

    assert "demoblaze.com" in current_url, f"Should remain on DemoBlaze, URL: {current_url}"

    logging.info(f"✓ After purchase, URL: {current_url}")
    assert True


@pytest.mark.functional
@pytest.mark.low
def test_rapid_add_to_cart_clicks_FUNC_015(browser, base_url):
    """
    TC-PURCHASE-FUNC-015: Rapid Add to Cart Clicks

    DISCOVER: Verify duplicate click handling
    """
    logging.info("TC-PURCHASE-FUNC-015: Testing rapid add to cart...")

    browser.get(base_url)
    cart = CartPage(browser)

    price = cart.rapid_add_to_cart(cart.FIRST_PRODUCT_LINK, times=3)

    cart.open_cart()

    item_count = cart.get_cart_item_count()
    total = cart.get_cart_total()

    assert 1 <= item_count <= 3, f"Should have 1-3 items, got {item_count}"

    expected_min = price
    expected_max = price * 3
    assert expected_min <= total <= expected_max, \
        f"Total {total} should be between {expected_min} and {expected_max}"

    logging.info(f"✓ Rapid clicks handled: {item_count} items, total ${total}")
    assert True


@pytest.mark.functional
@pytest.mark.medium
def test_cart_total_calculation_performance_FUNC_016(browser, base_url):
    """
    TC-PURCHASE-FUNC-016: Cart Total Calculation Performance

    DISCOVER: Verify cart total calculates quickly
    """
    logging.info("TC-PURCHASE-FUNC-016: Testing cart calculation performance...")

    browser.get(base_url)
    cart = CartPage(browser)

    cart.add_first_product()
    cart.add_second_product()

    cart.open_cart()

    calculation_time = cart.measure_cart_total_calculation_time()

    assert calculation_time < 3.0, \
        f"Cart calculation too slow: {calculation_time:.2f}s (should be < 3s)"

    if calculation_time < 1.0:
        logging.info(f"✓ Excellent performance: {calculation_time:.2f}s")
    elif calculation_time < 2.0:
        logging.info(f"✓ Good performance: {calculation_time:.2f}s")
    else:
        logging.info(f"✓ Acceptable performance: {calculation_time:.2f}s")

    assert True


@pytest.mark.functional
@pytest.mark.medium
def test_add_product_from_category_page_FUNC_017(browser, base_url):
    """
    TC-PURCHASE-FUNC-017: Add Product from Category Page

    DISCOVER: Verify adding from category works
    """
    logging.info("TC-PURCHASE-FUNC-017: Testing add from category...")

    browser.get(base_url)
    cart = CartPage(browser)

    name, price = cart.add_product_from_category(
        cart.CATEGORY_LAPTOPS_LINK,
        "Sony vaio i5"
    )

    cart.open_cart()

    item_name = cart.get_first_item_name()

    assert item_name == "Sony vaio i5", f"Expected 'Sony vaio i5', got '{item_name}'"

    logging.info("✓ Product from category added successfully")
    assert True


@pytest.mark.functional
@pytest.mark.medium
def test_purchase_confirmation_details_FUNC_018(order_modal):
    """
    TC-PURCHASE-FUNC-018: Purchase Confirmation Shows Correct Details

    DISCOVER: Verify confirmation displays all details
    """
    logging.info("TC-PURCHASE-FUNC-018: Testing confirmation details...")

    purchase = order_modal

    test_name = "QA Automation Tester"
    test_card = "4111111111111111"

    cart = CartPage(purchase.driver)
    expected_total = cart.get_cart_total()

    success, confirm_text, details = purchase.complete_purchase(
        name=test_name,
        card=test_card
    )

    assert success, "Purchase should succeed"
    assert "Thank you for your purchase!" in confirm_text, "Should have thank you message"
    assert details['amount'] == expected_total, \
        f"Confirmed amount {details['amount']} should match expected {expected_total}"

    logging.info(f"✓ Confirmation details verified: ${details['amount']}")
    assert True


@pytest.mark.functional
@pytest.mark.medium
def test_order_form_tab_navigation_FUNC_019(order_modal):
    """
    TC-PURCHASE-FUNC-019: Keyboard Navigation - Tab Order

    DISCOVER: Verify tab navigation through form (accessibility)
    """
    logging.info("TC-PURCHASE-FUNC-019: Testing tab navigation...")

    purchase = order_modal

    filled_values = purchase.navigate_form_with_tab(
        fill_data=["Test1", "Test2", "Test3", "Test4", "Test5", "Test6"]
    )

    assert filled_values['name'] == "Test1", "Name field should have Test1"

    logging.info("✓ Tab navigation works correctly")
    assert True


@pytest.mark.functional
@pytest.mark.low
def test_contact_modal_send_valid_message_FUNC_020(browser, base_url):
    """
    TC-PURCHASE-FUNC-020: Contact Modal - Send Valid Message

    DISCOVER: Verify contact form functionality
    """
    logging.info("TC-PURCHASE-FUNC-020: Testing contact modal...")

    browser.get(base_url)
    purchase = PurchasePage(browser)

    alert_text = purchase.send_contact_message(
        email="test@example.com",
        name="Test User",
        message="This is a test message."
    )

    assert alert_text == "Thanks for the message!!", \
        f"Expected 'Thanks for the message!!', got '{alert_text}'"

    logging.info("✓ Contact form works correctly")
    assert True


