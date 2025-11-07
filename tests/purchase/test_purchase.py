"""
Test Suite: Purchase & Cart Functionality
Module: test_purchase.py
Author: Arévalo, Marc
Description: Comprehensive automated tests for DemoBlaze purchase and cart functionality.
             Includes functional tests, price verification, cart operations, security tests,
             and validation of purchase flow for both guest and logged-in users.
Related Bugs: #13
Version: 2.0 - Enhanced logging, improved waits, added docstrings
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
import pytest
import time
import re
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')

BASE_URL = "https://www.demoblaze.com/"
TIMEOUT = 10
EXPLICIT_WAIT = 5

TEST_USERNAME = "testuser_qa_2024"
TEST_PASSWORD = "SecurePass123!"

FIRST_PRODUCT_LINK = (By.XPATH, "(//a[@class='hrefch'])[1]")
SECOND_PRODUCT_LINK = (By.XPATH, "(//a[@class='hrefch'])[2]")
PRODUCT_NAME_HEADER = (By.TAG_NAME, "h2")
PRODUCT_PRICE_HEADER = (By.TAG_NAME, "h3")
ADD_TO_CART_BUTTON = (By.XPATH, "//a[text()='Add to cart']")

HOME_NAV_LINK = (By.XPATH, "//a[contains(text(), 'Home')]")
CART_NAV_LINK = (By.ID, "cartur")
LOGIN_BUTTON_NAV = (By.ID, "login2")
WELCOME_USER_TEXT = (By.ID, "nameofuser")

LOGIN_USERNAME_FIELD = (By.ID, "loginusername")
LOGIN_PASSWORD_FIELD = (By.ID, "loginpassword")
LOGIN_SUBMIT_BUTTON = (By.XPATH, "//button[text()='Log in']")

PLACE_ORDER_BUTTON = (By.XPATH, "//button[text()='Place Order']")
DELETE_ITEM_LINK = (By.XPATH, "(//a[text()='Delete'])[1]")
SECOND_DELETE_ITEM_LINK = (By.XPATH, "(//a[text()='Delete'])[2]")
CART_TOTAL_PRICE = (By.ID, "totalp")
FIRST_ITEM_IN_CART_NAME = (By.XPATH, "//tbody[@id='tbodyid']/tr[1]/td[2]")

ORDER_MODAL = (By.ID, "orderModal")
ORDER_NAME_FIELD = (By.ID, "name")
ORDER_COUNTRY_FIELD = (By.ID, "country")
ORDER_CITY_FIELD = (By.ID, "city")
ORDER_CARD_FIELD = (By.ID, "card")
ORDER_MONTH_FIELD = (By.ID, "month")
ORDER_YEAR_FIELD = (By.ID, "year")
PURCHASE_BUTTON = (By.XPATH, "//button[text()='Purchase']")
CLOSE_ORDER_MODAL_BUTTON = (By.XPATH, "//div[@id='orderModal']//button[text()='Close']")

PURCHASE_CONFIRM_MODAL = (By.CLASS_NAME, "sweet-alert")
PURCHASE_CONFIRM_MSG = (By.XPATH, "//h2[text()='Thank you for your purchase!']")
CONFIRM_OK_BUTTON = (By.XPATH, "//button[contains(@class, 'confirm')]")


def wait_for_alert_and_get_text(browser, timeout=EXPLICIT_WAIT):
    try:
        WebDriverWait(browser, timeout).until(EC.alert_is_present())
        alert = browser.switch_to.alert
        alert_text = alert.text
        logging.info(f"Alert detected: '{alert_text}'")
        alert.accept()
        return alert_text
    except TimeoutException:
        logging.debug("No alert found.")
        return None


def fill_order_form(browser, name="", country="", city="", card="", month="", year=""):
    try:
        WebDriverWait(browser, TIMEOUT).until(
            EC.visibility_of_element_located(ORDER_NAME_FIELD)
        )
        browser.find_element(*ORDER_NAME_FIELD).send_keys(name)
        browser.find_element(*ORDER_COUNTRY_FIELD).send_keys(country)
        browser.find_element(*ORDER_CITY_FIELD).send_keys(city)
        browser.find_element(*ORDER_CARD_FIELD).send_keys(card)
        browser.find_element(*ORDER_MONTH_FIELD).send_keys(month)
        browser.find_element(*ORDER_YEAR_FIELD).send_keys(year)
        logging.info(f"Order form filled: Name='{name}', Card='{card}'")
    except Exception as e:
        logging.error(f"Error filling order form: {e}")
        raise


def parse_price(price_str):
    try:
        match = re.search(r'\d+', price_str)
        if match:
            return int(match.group(0))
        return 0
    except (ValueError, TypeError):
        logging.warning(f"Could not parse price from: {price_str}")
        return 0


def add_product_to_cart(browser, product_locator):
    logging.info("Adding product to cart...")
    
    product_link = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(product_locator)
    )
    product_link.click()
    
    price_element = WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(PRODUCT_PRICE_HEADER)
    )
    price_text = price_element.text
    price = parse_price(price_text)
    logging.info(f"Product price: {price}")
    
    add_button = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(ADD_TO_CART_BUTTON)
    )
    add_button.click()
    
    wait_for_alert_and_get_text(browser, TIMEOUT)
    
    browser.find_element(*HOME_NAV_LINK).click()
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(FIRST_PRODUCT_LINK)
    )
    
    logging.info("Product added successfully and returned to home.")
    return price


def perform_login(browser, username, password):
    logging.info(f"Performing login for user: {username}")
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(LOGIN_BUTTON_NAV)
    ).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(LOGIN_USERNAME_FIELD)
    )
    
    browser.find_element(*LOGIN_USERNAME_FIELD).send_keys(username)
    browser.find_element(*LOGIN_PASSWORD_FIELD).send_keys(password)
    browser.find_element(*LOGIN_SUBMIT_BUTTON).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(WELCOME_USER_TEXT)
    )
    logging.info("Login successful.")


def wait_for_cart_total_update(browser, timeout=EXPLICIT_WAIT):
    total_element = WebDriverWait(browser, timeout).until(
        EC.visibility_of_element_located(CART_TOTAL_PRICE)
    )
    
    WebDriverWait(browser, timeout).until(
        lambda driver: driver.find_element(*CART_TOTAL_PRICE).text.strip() != ""
    )
    
    total_price = parse_price(total_element.text)
    logging.info(f"Cart total updated: {total_price}")
    return total_price


@pytest.fixture(scope="function")
def cart_page(browser):
    logging.info("Setting up cart_page fixture...")
    browser.get(BASE_URL)
    add_product_to_cart(browser, FIRST_PRODUCT_LINK)
    
    browser.find_element(*CART_NAV_LINK).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(PLACE_ORDER_BUTTON)
    )
    logging.info("Cart page ready.")
    return browser


@pytest.fixture(scope="function")
def order_modal_page(cart_page):
    logging.info("Opening order modal...")
    cart_page.find_element(*PLACE_ORDER_BUTTON).click()
    
    WebDriverWait(cart_page, TIMEOUT).until(
        EC.visibility_of_element_located(ORDER_NAME_FIELD)
    )
    logging.info("Order modal ready.")
    return cart_page


def test_successful_purchase_and_price_verification(order_modal_page):
    """TC-PURCH-001: Successful Purchase with Price Verification"""
    logging.info("🚀 TC-PURCH-001: Starting successful purchase test...")
    browser = order_modal_page
    
    try:
        total_price_text = browser.find_element(*CART_TOTAL_PRICE).text
        expected_price = parse_price(total_price_text)
        if expected_price == 0:
            pytest.fail("Cart price is 0 before purchase.")
    except Exception as e:
        pytest.fail(f"Could not read cart total: {e}")

    fill_order_form(browser, "QA Tester", "Spain", "Barcelona", "1234567890123456", "12", "2028")
    
    browser.find_element(*PURCHASE_BUTTON).click()
    
    try:
        confirm_modal = WebDriverWait(browser, TIMEOUT).until(
            EC.visibility_of_element_located(PURCHASE_CONFIRM_MODAL)
        )
        confirm_text = confirm_modal.text
        
        assert "Thank you for your purchase!" in confirm_text, \
            "Confirmation message not found"
        
        amount_match = re.search(r'Amount: (\d+) USD', confirm_text)
        
        assert amount_match is not None, "Amount not found in confirmation modal"
        
        confirmed_price = int(amount_match.group(1))
        
        assert confirmed_price == expected_price, \
            f"Price mismatch! Expected: {expected_price}, Confirmed: {confirmed_price}"
        
        logging.info(f"✅ Price verified: {confirmed_price} USD")
        
    except TimeoutException:
        pytest.fail("Purchase confirmation modal did not appear.")
    
    browser.find_element(*CONFIRM_OK_BUTTON).click()
    logging.info("✅ TC-PURCH-001: PASSED")


def test_multiple_items_total(browser):
    """TC-PURCH-002: Multiple Items Total Calculation"""
    logging.info("🚀 TC-PURCH-002: Starting multiple items total test...")
    browser.get(BASE_URL)
    
    price1 = add_product_to_cart(browser, FIRST_PRODUCT_LINK)
    price2 = add_product_to_cart(browser, SECOND_PRODUCT_LINK)
    
    browser.find_element(*CART_NAV_LINK).click()
    
    total_price = wait_for_cart_total_update(browser)
    expected_total = price1 + price2
    
    assert total_price == expected_total, \
        f"Cart total incorrect. Expected: {expected_total}, Got: {total_price}"
    
    logging.info(f"✅ Total verified: {total_price} = {price1} + {price2}")
    logging.info("✅ TC-PURCH-002: PASSED")


def test_delete_item_from_cart(cart_page):
    """TC-PURCH-003: Delete Item from Cart"""
    logging.info("🚀 TC-PURCH-003: Starting delete item test...")
    browser = cart_page
    
    item_name = WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(FIRST_ITEM_IN_CART_NAME)
    )
    assert item_name.is_displayed(), "Item was not added to cart"
    logging.info("Item verified in cart.")
    
    browser.find_element(*DELETE_ITEM_LINK).click()
    
    # Wait for item to be removed from DOM
    WebDriverWait(browser, TIMEOUT).until(
        EC.invisibility_of_element_located(FIRST_ITEM_IN_CART_NAME)
    )
    
    try:
        browser.find_element(*FIRST_ITEM_IN_CART_NAME)
        pytest.fail("Item was not deleted from cart")
    except NoSuchElementException:
        logging.info("✅ Item successfully deleted from cart")
    
    logging.info("✅ TC-PURCH-003: PASSED")


def test_delete_item_and_recalculate_total(browser):
    """TC-PURCH-003B: Delete Item and Recalculate Total"""
    logging.info("🚀 TC-PURCH-003B: Starting delete and recalculate test...")
    browser.get(BASE_URL)
    
    price1 = add_product_to_cart(browser, FIRST_PRODUCT_LINK)
    price2 = add_product_to_cart(browser, SECOND_PRODUCT_LINK)
    
    browser.find_element(*CART_NAV_LINK).click()
    
    expected_total_before = price1 + price2
    total_before = wait_for_cart_total_update(browser)
    
    assert total_before == expected_total_before, \
        f"Initial total incorrect. Expected: {expected_total_before}, Got: {total_before}"
    logging.info(f"Initial total verified: {total_before}")
    
    browser.find_element(*DELETE_ITEM_LINK).click()
    
    # Wait for DOM update and total recalculation
    WebDriverWait(browser, TIMEOUT).until(
        EC.invisibility_of_element_located(FIRST_ITEM_IN_CART_NAME)
    )
    
    total_after = wait_for_cart_total_update(browser)
    expected_total_after = price2
    
    assert total_after == expected_total_after, \
        f"Total not recalculated. Expected: {expected_total_after}, Got: {total_after}"
    
    logging.info(f"✅ Total recalculated correctly: {total_after}")
    logging.info("✅ TC-PURCH-003B: PASSED")


def test_purchase_as_logged_in_user(browser):
    """TC-PURCH-012: Purchase as Logged-In User"""
    logging.info("🚀 TC-PURCH-012: Starting logged-in user purchase test...")
    browser.get(BASE_URL)
    
    perform_login(browser, TEST_USERNAME, TEST_PASSWORD)
    
    price = add_product_to_cart(browser, FIRST_PRODUCT_LINK)
    
    browser.find_element(*CART_NAV_LINK).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(PLACE_ORDER_BUTTON)
    ).click()
    
    name_field = WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(ORDER_NAME_FIELD)
    )
    
    assert name_field.get_attribute("value") == "", \
        "Name field should NOT auto-fill (DemoBlaze does not implement this)"
    logging.info("Verified: Order form does not auto-fill for logged-in users")

    fill_order_form(browser, "QA Tester Logged", "Spain", "Barcelona", "987654321", "10", "2027")
    browser.find_element(*PURCHASE_BUTTON).click()
    
    confirm_modal = WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(PURCHASE_CONFIRM_MODAL)
    )
    confirm_text = confirm_modal.text
    
    assert "Thank you for your purchase!" in confirm_text
    
    amount_match = re.search(r'Amount: (\d+) USD', confirm_text)
    assert amount_match is not None, "Amount not found in confirmation"
    
    confirmed_price = int(amount_match.group(1))
    assert confirmed_price == price, "Purchase price mismatch for logged-in user"
    
    logging.info(f"✅ Logged-in user purchase verified: {confirmed_price} USD")
    browser.find_element(*CONFIRM_OK_BUTTON).click()
    logging.info("✅ TC-PURCH-012: PASSED")


def test_order_modal_close_button(order_modal_page):
    """TC-PURCH-013: Order Modal Close Button"""
    logging.info("🚀 TC-PURCH-013: Starting modal close button test...")
    browser = order_modal_page

    assert browser.find_element(*ORDER_MODAL).is_displayed(), \
        "Order modal not visible at start"
    logging.info("Order modal verified open.")
    
    browser.find_element(*CLOSE_ORDER_MODAL_BUTTON).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.invisibility_of_element_located(ORDER_MODAL)
    )
    logging.info("Order modal closed.")
    
    assert browser.find_element(*PLACE_ORDER_BUTTON).is_displayed(), \
        "Did not return to cart page"
    
    logging.info("✅ Returned to cart page successfully")
    logging.info("✅ TC-PURCH-013: PASSED")


@pytest.mark.xfail(reason="Bug #13: System allows purchasing with empty cart")
def test_purchase_empty_cart(browser):
    """TC-PURCH-014: Purchase with Empty Cart (Bug #13)"""
    logging.info("🚀 TC-PURCH-014: (XFAIL) Starting empty cart purchase test...")
    browser.get(BASE_URL)
    browser.find_element(*CART_NAV_LINK).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(PLACE_ORDER_BUTTON)
    ).click()
    
    fill_order_form(browser, "Bug Hunter", "Bugland", "Testville", "0000", "01", "2025")
    browser.find_element(*PURCHASE_BUTTON).click()
    
    confirm_msg_element = WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(PURCHASE_CONFIRM_MSG)
    )
    
    assert confirm_msg_element.is_displayed(), \
        "System allowed empty cart purchase (Bug confirmed)"
    
    confirm_text = browser.find_element(*PURCHASE_CONFIRM_MODAL).text
    assert "Amount: 0 USD" in confirm_text or "Amount: null USD" in confirm_text, \
        "Empty purchase shows 0 or null amount"
    
    logging.critical("="*50)
    logging.critical("🚨 BUG #13 CONFIRMED 🚨")
    logging.critical("System allows purchasing empty cart")
    logging.critical("="*50)
    
    browser.find_element(*CONFIRM_OK_BUTTON).click()
    
    pytest.fail("Bug #13: System should NOT allow purchasing empty cart")


@pytest.mark.parametrize("test_id, name, country, city, card, month, year, expected_alert", [
    ("TC-PURCH-004", "", "", "", "", "", "", "Please fill out Name and Creditcard."),
    ("TC-PURCH-005", "QA Tester", "", "", "", "", "", "Please fill out Name and Creditcard."),
    ("TC-PURCH-006", "", "", "", "1234567890", "", "", "Please fill out Name and Creditcard."),
    ("TC-PURCH-007", "QA Tester", "Spain", "Bcn", "abcdefg", "12", "2028", None),
    ("TC-PURCH-008", "QA Tester", "Spain", "Bcn", "123456", "abc", "def", None),
    ("TC-PURCH-009", "a"*1000, "Spain", "Bcn", "123456", "12", "2028", None),
    ("TC-PURCH-010", "' OR '1'='1", "Spain", "Bcn", "123456", "12", "2028", None),
    ("TC-PURCH-011", "QA Tester", "Spain", "<script>alert(1)</script>", "123456", "12", "2028", None),
])
def test_order_form_validation_robustness_security(order_modal_page, test_id, name, country, city, card, month, year, expected_alert):
    """TC-PURCH-004 to TC-PURCH-011: Order Form Validation, Robustness & Security"""
    logging.info(f"🚀 {test_id}: Starting parametrized validation test...")
    logging.info(f"   Payload: Name='{name[:50]}...', Card='{card}'")
    
    browser = order_modal_page
    
    fill_order_form(browser, name, country, city, card, month, year)
    
    browser.find_element(*PURCHASE_BUTTON).click()
    
    if expected_alert:
        alert_text = wait_for_alert_and_get_text(browser, EXPLICIT_WAIT)
        assert alert_text == expected_alert, \
            f"Incorrect alert. Expected: '{expected_alert}', Got: '{alert_text}'"
        logging.info(f"✅ {test_id}: Validation alert verified")
    else:
        alert_text = wait_for_alert_and_get_text(browser, 2)
        assert alert_text is None, \
            f"Unexpected alert appeared: {alert_text}"
        
        try:
            WebDriverWait(browser, TIMEOUT).until(
                EC.visibility_of_element_located(PURCHASE_CONFIRM_MSG)
            )
            logging.info(f"✅ {test_id}: Purchase completed (system handled payload)")
            browser.find_element(*CONFIRM_OK_BUTTON).click()
        except TimeoutException:
            pytest.fail(f"{test_id}: Purchase failed or crashed unexpectedly")
    
    logging.info(f"✅ {test_id}: PASSED")


def test_add_same_product_multiple_times(browser):
    """TC-PURCH-015: Add Same Product Multiple Times"""
    logging.info("🚀 TC-PURCH-015: Starting same product multiple times test...")
    browser.get(BASE_URL)
    
    price = add_product_to_cart(browser, FIRST_PRODUCT_LINK)
    add_product_to_cart(browser, FIRST_PRODUCT_LINK)
    
    browser.find_element(*CART_NAV_LINK).click()
    
    cart_items = WebDriverWait(browser, TIMEOUT).until(
        EC.presence_of_all_elements_located((By.XPATH, "//tbody[@id='tbodyid']/tr"))
    )
    
    assert len(cart_items) == 2, f"Expected 2 items in cart, got {len(cart_items)}"
    
    total = wait_for_cart_total_update(browser)
    expected_total = price * 2
    
    assert total == expected_total, \
        f"Total incorrect. Expected: {expected_total}, Got: {total}"
    
    logging.info(f"✅ Same product added twice: {len(cart_items)} items, total: {total}")
    logging.info("✅ TC-PURCH-015: PASSED")


def test_navigation_after_purchase(order_modal_page):
    """TC-PURCH-016: Navigation After Purchase"""
    logging.info("🚀 TC-PURCH-016: Starting navigation after purchase test...")
    browser = order_modal_page
    
    fill_order_form(browser, "QA Tester", "Spain", "Barcelona", "1234567890", "12", "2028")
    browser.find_element(*PURCHASE_BUTTON).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(PURCHASE_CONFIRM_MSG)
    )
    
    browser.find_element(*CONFIRM_OK_BUTTON).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.invisibility_of_element_located(PURCHASE_CONFIRM_MODAL)
    )
    
    current_url = browser.current_url
    logging.info(f"After purchase, URL: {current_url}")
    
    assert BASE_URL in current_url, "Should remain on DemoBlaze site"
    
    logging.info("✅ TC-PURCH-016: PASSED")


def test_cart_empty_after_purchase(order_modal_page):
    """TC-PURCH-017: Cart Empty After Successful Purchase"""
    logging.info("🚀 TC-PURCH-017: Starting cart empty after purchase test...")
    browser = order_modal_page
    
    fill_order_form(browser, "QA Tester", "Spain", "Barcelona", "1234567890", "12", "2028")
    browser.find_element(*PURCHASE_BUTTON).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(PURCHASE_CONFIRM_MSG)
    )
    browser.find_element(*CONFIRM_OK_BUTTON).click()
    
    browser.find_element(*CART_NAV_LINK).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(PLACE_ORDER_BUTTON)
    )
    
    cart_items = browser.find_elements(By.XPATH, "//tbody[@id='tbodyid']/tr")
    
    assert len(cart_items) == 0, f"Cart should be empty after purchase, but has {len(cart_items)} items"
    
    logging.info("✅ Cart is empty after purchase")
    logging.info("✅ TC-PURCH-017: PASSED")


def test_add_many_products_to_cart(browser):
    """TC-PURCH-018: Add Many Products to Cart (Boundary Test)"""
    logging.info("🚀 TC-PURCH-018: Starting boundary test - adding 10 products...")
    browser.get(BASE_URL)
    
    total_expected = 0
    items_to_add = 10
    
    for i in range(items_to_add):
        price = add_product_to_cart(browser, FIRST_PRODUCT_LINK)
        total_expected += price
        logging.info(f"Added product {i+1}/{items_to_add}")
    
    browser.find_element(*CART_NAV_LINK).click()
    
    cart_items = WebDriverWait(browser, TIMEOUT).until(
        EC.presence_of_all_elements_located((By.XPATH, "//tbody[@id='tbodyid']/tr"))
    )
    
    assert len(cart_items) == items_to_add, \
        f"Expected {items_to_add} items, got {len(cart_items)}"
    
    total_actual = wait_for_cart_total_update(browser)
    
    assert total_actual == total_expected, \
        f"Total mismatch. Expected: {total_expected}, Got: {total_actual}"
    
    logging.info(f"✅ Successfully added {items_to_add} products, total: {total_actual}")
    logging.info("✅ TC-PURCH-018: PASSED")


def test_delete_all_items_from_cart(browser):
    """TC-PURCH-019: Delete All Items From Cart"""
    logging.info("🚀 TC-PURCH-019: Starting delete all items test...")
    browser.get(BASE_URL)
    
    add_product_to_cart(browser, FIRST_PRODUCT_LINK)
    add_product_to_cart(browser, SECOND_PRODUCT_LINK)
    
    browser.find_element(*CART_NAV_LINK).click()
    
    cart_items = WebDriverWait(browser, TIMEOUT).until(
        EC.presence_of_all_elements_located((By.XPATH, "//tbody[@id='tbodyid']/tr"))
    )
    initial_count = len(cart_items)
    logging.info(f"Initial cart items: {initial_count}")
    
    for i in range(initial_count):
        browser.find_element(*DELETE_ITEM_LINK).click()
        WebDriverWait(browser, TIMEOUT).until(
            lambda d: len(d.find_elements(By.XPATH, "//tbody[@id='tbodyid']/tr")) == initial_count - (i + 1)
        )
        logging.info(f"Deleted item {i+1}/{initial_count}")
    
    remaining_items = browser.find_elements(By.XPATH, "//tbody[@id='tbodyid']/tr")
    
    assert len(remaining_items) == 0, "Cart should be empty after deleting all items"
    
    logging.info("✅ All items deleted successfully")
    logging.info("✅ TC-PURCH-019: PASSED")


def test_open_close_order_modal_multiple_times(cart_page):
    """TC-PURCH-020: Open and Close Order Modal Multiple Times"""
    logging.info("🚀 TC-PURCH-020: Starting modal open/close multiple times test...")
    browser = cart_page
    
    for i in range(3):
        logging.info(f"Iteration {i+1}/3")
        
        browser.find_element(*PLACE_ORDER_BUTTON).click()
        
        WebDriverWait(browser, TIMEOUT).until(
            EC.visibility_of_element_located(ORDER_NAME_FIELD)
        )
        
        assert browser.find_element(*ORDER_MODAL).is_displayed(), \
            f"Modal should be open on iteration {i+1}"
        
        browser.find_element(*CLOSE_ORDER_MODAL_BUTTON).click()
        
        WebDriverWait(browser, TIMEOUT).until(
            EC.invisibility_of_element_located(ORDER_MODAL)
        )
        
        assert browser.find_element(*PLACE_ORDER_BUTTON).is_displayed(), \
            f"Should be back on cart page on iteration {i+1}"
    
    logging.info("✅ Modal opened and closed 3 times successfully")
    logging.info("✅ TC-PURCH-020: PASSED")


def test_access_empty_cart(browser):
    """TC-PURCH-021: Access Cart Without Adding Products"""
    logging.info("🚀 TC-PURCH-021: Starting empty cart access test...")
    browser.get(BASE_URL)
    
    browser.find_element(*CART_NAV_LINK).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(PLACE_ORDER_BUTTON)
    )
    
    cart_items = browser.find_elements(By.XPATH, "//tbody[@id='tbodyid']/tr")
    
    assert len(cart_items) == 0, "Cart should be empty"
    
    place_order_btn = browser.find_element(*PLACE_ORDER_BUTTON)
    assert place_order_btn.is_displayed(), "Place Order button should still be visible"
    
    logging.info("✅ Empty cart accessible, Place Order button visible (Bug #13)")
    logging.info("✅ TC-PURCH-021: PASSED")


@pytest.mark.parametrize("field_name, field_locator, payload", [
    ("name", ORDER_NAME_FIELD, "' OR '1'='1"),
    ("name", ORDER_NAME_FIELD, "admin'--"),
    ("country", ORDER_COUNTRY_FIELD, "' OR '1'='1"),
    ("city", ORDER_CITY_FIELD, "' OR '1'='1"),
    ("card", ORDER_CARD_FIELD, "' OR '1'='1"),
])
def test_sql_injection_all_order_fields(order_modal_page, field_name, field_locator, payload):
    """TC-PURCH-022: SQL Injection in All Order Form Fields"""
    logging.info(f"🚀 TC-PURCH-022: SQL injection in {field_name} field")
    logging.info(f"   Payload: {payload}")
    browser = order_modal_page
    
    browser.find_element(*ORDER_NAME_FIELD).send_keys("QA Tester")
    browser.find_element(*ORDER_COUNTRY_FIELD).send_keys("Spain")
    browser.find_element(*ORDER_CITY_FIELD).send_keys("Barcelona")
    browser.find_element(*ORDER_CARD_FIELD).send_keys("1234567890")
    browser.find_element(*ORDER_MONTH_FIELD).send_keys("12")
    browser.find_element(*ORDER_YEAR_FIELD).send_keys("2028")
    
    target_field = browser.find_element(*field_locator)
    target_field.clear()
    target_field.send_keys(payload)
    
    browser.find_element(*PURCHASE_BUTTON).click()
    
    try:
        WebDriverWait(browser, TIMEOUT).until(
            EC.visibility_of_element_located(PURCHASE_CONFIRM_MSG)
        )
        logging.info(f"✅ Purchase completed safely with SQL payload in {field_name}")
        browser.find_element(*CONFIRM_OK_BUTTON).click()
    except TimeoutException:
        logging.info(f"✅ Purchase blocked or failed safely with SQL payload in {field_name}")
    
    logging.info(f"✅ TC-PURCH-022 ({field_name}): PASSED")


@pytest.mark.parametrize("field_name, field_locator, payload", [
    ("name", ORDER_NAME_FIELD, "<script>alert('XSS')</script>"),
    ("country", ORDER_COUNTRY_FIELD, "<img src=x onerror=alert('XSS')>"),
    ("city", ORDER_CITY_FIELD, "<svg/onload=alert('XSS')>"),
    ("card", ORDER_CARD_FIELD, "javascript:alert('XSS')"),
])
def test_xss_all_order_fields(order_modal_page, field_name, field_locator, payload):
    """TC-PURCH-023: XSS in All Order Form Fields"""
    logging.info(f"🚀 TC-PURCH-023: XSS in {field_name} field")
    logging.info(f"   Payload: {payload}")
    browser = order_modal_page
    
    browser.find_element(*ORDER_NAME_FIELD).send_keys("QA Tester")
    browser.find_element(*ORDER_COUNTRY_FIELD).send_keys("Spain")
    browser.find_element(*ORDER_CITY_FIELD).send_keys("Barcelona")
    browser.find_element(*ORDER_CARD_FIELD).send_keys("1234567890")
    browser.find_element(*ORDER_MONTH_FIELD).send_keys("12")
    browser.find_element(*ORDER_YEAR_FIELD).send_keys("2028")
    
    target_field = browser.find_element(*field_locator)
    target_field.clear()
    target_field.send_keys(payload)
    
    browser.find_element(*PURCHASE_BUTTON).click()
    
    alert_text = wait_for_alert_and_get_text(browser, 2)
    
    if alert_text and 'XSS' in alert_text:
        logging.critical("="*50)
        logging.critical("🚨 XSS VULNERABILITY DETECTED 🚨")
        logging.critical(f"XSS payload executed in {field_name} field")
        logging.critical("="*50)
        pytest.fail(f"XSS vulnerability in {field_name} field")
    
    try:
        WebDriverWait(browser, TIMEOUT).until(
            EC.visibility_of_element_located(PURCHASE_CONFIRM_MSG)
        )
        logging.info(f"✅ XSS payload sanitized in {field_name}, purchase completed safely")
        browser.find_element(*CONFIRM_OK_BUTTON).click()
    except TimeoutException:
        logging.info(f"✅ Purchase blocked safely with XSS payload in {field_name}")
    
    logging.info(f"✅ TC-PURCH-023 ({field_name}): PASSED")


@pytest.mark.parametrize("field_name, field_locator, payload", [
    ("name", ORDER_NAME_FIELD, "Test@#$%^&*()"),
    ("country", ORDER_COUNTRY_FIELD, "España™®©"),
    ("city", ORDER_CITY_FIELD, "Test<>?:|\\"),
    ("card", ORDER_CARD_FIELD, "1234-5678-9012-3456"),
])
def test_special_characters_all_order_fields(order_modal_page, field_name, field_locator, payload):
    """TC-PURCH-024: Special Characters in All Order Form Fields"""
    logging.info(f"🚀 TC-PURCH-024: Special characters in {field_name} field")
    logging.info(f"   Payload: {payload}")
    browser = order_modal_page
    
    browser.find_element(*ORDER_NAME_FIELD).send_keys("QA Tester")
    browser.find_element(*ORDER_COUNTRY_FIELD).send_keys("Spain")
    browser.find_element(*ORDER_CITY_FIELD).send_keys("Barcelona")
    browser.find_element(*ORDER_CARD_FIELD).send_keys("1234567890")
    browser.find_element(*ORDER_MONTH_FIELD).send_keys("12")
    browser.find_element(*ORDER_YEAR_FIELD).send_keys("2028")
    
    target_field = browser.find_element(*field_locator)
    target_field.clear()
    target_field.send_keys(payload)
    
    browser.find_element(*PURCHASE_BUTTON).click()
    
    alert_text = wait_for_alert_and_get_text(browser, 2)
    assert alert_text is None, f"Unexpected alert: {alert_text}"
    
    try:
        WebDriverWait(browser, TIMEOUT).until(
            EC.visibility_of_element_located(PURCHASE_CONFIRM_MSG)
        )
        logging.info(f"✅ Special characters handled in {field_name}")
        browser.find_element(*CONFIRM_OK_BUTTON).click()
    except TimeoutException:
        pytest.fail(f"Purchase failed with special characters in {field_name}")
    
    logging.info(f"✅ TC-PURCH-024 ({field_name}): PASSED")


@pytest.mark.parametrize("test_input", [
    "Test\x00User",
    "\x00Test",
    "Test\x00",
])
def test_null_bytes_order_form(order_modal_page, test_input):
    """TC-PURCH-025: Null Bytes in Order Form"""
    logging.info(f"🚀 TC-PURCH-025: Null bytes test - {repr(test_input)}")
    browser = order_modal_page
    
    try:
        fill_order_form(browser, test_input, "Spain", "Barcelona", "1234567890", "12", "2028")
        browser.find_element(*PURCHASE_BUTTON).click()
        
        alert_text = wait_for_alert_and_get_text(browser, 2)
        
        try:
            WebDriverWait(browser, TIMEOUT).until(
                EC.visibility_of_element_located(PURCHASE_CONFIRM_MSG)
            )
            logging.info("✅ Null bytes handled safely")
            browser.find_element(*CONFIRM_OK_BUTTON).click()
        except TimeoutException:
            logging.info("✅ Purchase blocked or handled safely")
        
    except Exception as e:
        logging.info(f"✅ Exception caught (expected for null bytes): {e}")
    
    logging.info(f"✅ TC-PURCH-025 ({repr(test_input)}): PASSED")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])
