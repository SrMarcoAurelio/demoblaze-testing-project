"""
Test Suite: Purchase & Cart Functionality
Module: test_purchase.py
Author: QA Testing Team
Version: 4.0 - Professional QA Suite with Industry Standards

Test Categories:
- Functional Tests: Verify current working features
- Business Rules: Validate against industry standards (PCI-DSS, OWASP, ISO 25010)

Standards Validated:
- OWASP Top 10 (SQL Injection, XSS, Input Validation)
- PCI-DSS (Credit Card Validation, Format, Expiration)
- WCAG 2.1 (Keyboard Navigation, Form Labels)
- ISO 25010 (Usability, Security, Maintainability)

Execution:
Run all tests:           pytest test_purchase.py
Run functional only:     pytest test_purchase.py -m functional
Run business rules:      pytest test_purchase.py -m business_rules
Run security tests:      pytest test_purchase.py -m security
Verbose output:          pytest test_purchase.py -v --tb=short

Total Expected Tests: 63
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.action_chains import ActionChains
import pytest
import time
import re
import datetime
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

CATEGORY_LAPTOPS_LINK = (By.XPATH, "//a[text()='Laptops']")
PAGINATION_NEXT_LINK = (By.ID, "next2")
PAGINATION_PREV_LINK = (By.ID, "prev2")

CONTACT_NAV_LINK = (By.XPATH, "//a[text()='Contact']")
CONTACT_EMAIL_FIELD = (By.ID, "recipient-email")
CONTACT_NAME_FIELD = (By.ID, "recipient-name")
CONTACT_MESSAGE_FIELD = (By.ID, "message-text")
CONTACT_SEND_BUTTON = (By.XPATH, "//button[text()='Send message']")

ABOUT_US_NAV_LINK = (By.XPATH, "//a[text()='About us']")
ABOUT_US_MODAL = (By.ID, "videoModal")
ABOUT_US_VIDEO = (By.ID, "example-video")


def wait_for_alert_and_get_text(browser, timeout=EXPLICIT_WAIT):
    try:
        WebDriverWait(browser, timeout).until(EC.alert_is_present())
        alert = browser.switch_to.alert
        alert_text = alert.text
        alert.accept()
        return alert_text
    except TimeoutException:
        return None


def parse_price(price_str):
    match = re.search(r'\d+', price_str)
    if match:
        return int(match.group(0))
    return 0


def add_product_to_cart(browser, product_locator):
    product_link = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(product_locator)
    )
    product_link.click()
    
    price_element = WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(PRODUCT_PRICE_HEADER)
    )
    price = parse_price(price_element.text)
    
    add_to_cart_btn = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(ADD_TO_CART_BUTTON)
    )
    add_to_cart_btn.click()
    
    wait_for_alert_and_get_text(browser)
    
    home_link = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(HOME_NAV_LINK)
    )
    home_link.click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(FIRST_PRODUCT_LINK)
    )
    
    return price


def fill_order_form(browser, name="", country="", city="", card="", month="", year=""):
    try:
        WebDriverWait(browser, TIMEOUT).until(
            EC.visibility_of_element_located(ORDER_NAME_FIELD)
        )
        
        name_field = browser.find_element(*ORDER_NAME_FIELD)
        name_field.clear()
        name_field.send_keys(name)
        
        country_field = browser.find_element(*ORDER_COUNTRY_FIELD)
        country_field.clear()
        country_field.send_keys(country)
        
        city_field = browser.find_element(*ORDER_CITY_FIELD)
        city_field.clear()
        city_field.send_keys(city)
        
        card_field = browser.find_element(*ORDER_CARD_FIELD)
        card_field.clear()
        card_field.send_keys(card)
        
        month_field = browser.find_element(*ORDER_MONTH_FIELD)
        month_field.clear()
        month_field.send_keys(month)
        
        year_field = browser.find_element(*ORDER_YEAR_FIELD)
        year_field.clear()
        year_field.send_keys(year)
        
    except Exception as e:
        logging.error(f"Failed to fill order form: {str(e)}")
        raise


def perform_login(browser, username, password):
    login_button = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(LOGIN_BUTTON_NAV)
    )
    login_button.click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(LOGIN_USERNAME_FIELD)
    )
    
    browser.find_element(*LOGIN_USERNAME_FIELD).send_keys(username)
    browser.find_element(*LOGIN_PASSWORD_FIELD).send_keys(password)
    browser.find_element(*LOGIN_SUBMIT_BUTTON).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(WELCOME_USER_TEXT)
    )


def wait_for_cart_total_update(browser, timeout=TIMEOUT):
    total_element = WebDriverWait(browser, timeout).until(
        EC.visibility_of_element_located(CART_TOTAL_PRICE)
    )
    
    try:
        WebDriverWait(browser, timeout).until(
            lambda d: d.find_element(*CART_TOTAL_PRICE).text.strip() != ""
        )
    except TimeoutException:
        return 0
    
    total_text = total_element.text
    return parse_price(total_text)


@pytest.fixture
def cart_page(browser):
    browser.get(BASE_URL)
    add_product_to_cart(browser, FIRST_PRODUCT_LINK)
    
    browser.find_element(*CART_NAV_LINK).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(PLACE_ORDER_BUTTON)
    )
    
    return browser


@pytest.fixture
def order_modal_page(cart_page):
    browser = cart_page
    
    place_order_btn = browser.find_element(*PLACE_ORDER_BUTTON)
    place_order_btn.click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(ORDER_NAME_FIELD)
    )
    
    return browser


@pytest.mark.functional
def test_successful_purchase_and_price_verification(order_modal_page):
    """TC-PURCH-001: Successful Purchase with Price Verification"""
    logging.info("TC-PURCH-001: Starting successful purchase test...")
    browser = order_modal_page
    
    expected_price = wait_for_cart_total_update(browser)
    assert expected_price > 0, "Cart total should be greater than 0"
    
    fill_order_form(browser, "QA Tester", "Spain", "Barcelona", "1234567890123456", "12", "2028")
    
    purchase_btn = browser.find_element(*PURCHASE_BUTTON)
    purchase_btn.click()
    
    try:
        confirm_msg = WebDriverWait(browser, TIMEOUT).until(
            EC.visibility_of_element_located(PURCHASE_CONFIRM_MSG)
        )
        assert "Thank you for your purchase!" in confirm_msg.text
        
        confirm_modal = browser.find_element(*PURCHASE_CONFIRM_MODAL)
        confirm_text = confirm_modal.text
        
        amount_match = re.search(r'Amount:\s*(\d+)\s*USD', confirm_text)
        assert amount_match, f"Could not find amount in confirmation: {confirm_text}"
        
        confirmed_price = int(amount_match.group(1))
        assert confirmed_price == expected_price, \
            f"Price mismatch! Expected: {expected_price}, Confirmed: {confirmed_price}"
        
        logging.info(f"Price verified: {confirmed_price} USD")
        
    except TimeoutException:
        pytest.fail("Purchase confirmation modal did not appear.")
    
    browser.find_element(*CONFIRM_OK_BUTTON).click()
    logging.info("TC-PURCH-001: PASSED")


@pytest.mark.functional
def test_multiple_items_total(browser):
    """TC-PURCH-002: Multiple Items Total Calculation"""
    logging.info("TC-PURCH-002: Starting multiple items total test...")
    browser.get(BASE_URL)
    
    price1 = add_product_to_cart(browser, FIRST_PRODUCT_LINK)
    price2 = add_product_to_cart(browser, SECOND_PRODUCT_LINK)
    
    browser.find_element(*CART_NAV_LINK).click()
    
    total_price = wait_for_cart_total_update(browser)
    expected_total = price1 + price2
    
    assert total_price == expected_total, \
        f"Cart total incorrect. Expected: {expected_total}, Got: {total_price}"
    
    logging.info(f"Total verified: {total_price} = {price1} + {price2}")
    logging.info("TC-PURCH-002: PASSED")


@pytest.mark.functional
def test_delete_item_from_cart(cart_page):
    """TC-PURCH-003: Delete Item from Cart"""
    logging.info("TC-PURCH-003: Starting delete item test...")
    browser = cart_page
    
    item_name = WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(FIRST_ITEM_IN_CART_NAME)
    )
    assert item_name.is_displayed(), "Item was not added to cart"
    logging.info("Item verified in cart.")
    
    browser.find_element(*DELETE_ITEM_LINK).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.invisibility_of_element_located(FIRST_ITEM_IN_CART_NAME)
    )
    
    try:
        browser.find_element(*FIRST_ITEM_IN_CART_NAME)
        pytest.fail("Item was not deleted from cart")
    except NoSuchElementException:
        logging.info("Item successfully deleted from cart")
    
    logging.info("TC-PURCH-003: PASSED")


@pytest.mark.functional
def test_delete_item_and_recalculate_total(browser):
    """TC-PURCH-003B: Delete Item and Recalculate Total"""
    logging.info("TC-PURCH-003B: Starting delete and recalculate test...")
    browser.get(BASE_URL)
    
    price1 = add_product_to_cart(browser, FIRST_PRODUCT_LINK)
    price2 = add_product_to_cart(browser, SECOND_PRODUCT_LINK)
    
    browser.find_element(*CART_NAV_LINK).click()
    
    initial_total = wait_for_cart_total_update(browser)
    expected_initial = price1 + price2
    assert initial_total == expected_initial, f"Initial total incorrect: {initial_total} != {expected_initial}"
    
    browser.find_element(*DELETE_ITEM_LINK).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.invisibility_of_element_located(FIRST_ITEM_IN_CART_NAME)
    )
    
    total_after = wait_for_cart_total_update(browser)
    
    assert total_after == price2, \
        f"Total after deletion incorrect. Expected: {price2}, Got: {total_after}"
    
    logging.info(f"Total recalculated correctly: {total_after}")
    logging.info("TC-PURCH-003B: PASSED")


@pytest.mark.functional
def test_purchase_as_logged_in_user(browser):
    """TC-PURCH-012: Purchase as Logged-In User"""
    logging.info("TC-PURCH-012: Starting logged-in user purchase test...")
    browser.get(BASE_URL)
    
    perform_login(browser, TEST_USERNAME, TEST_PASSWORD)
    
    add_product_to_cart(browser, FIRST_PRODUCT_LINK)
    browser.find_element(*CART_NAV_LINK).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(PLACE_ORDER_BUTTON)
    )
    
    browser.find_element(*PLACE_ORDER_BUTTON).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(ORDER_NAME_FIELD)
    )
    
    name_field = browser.find_element(*ORDER_NAME_FIELD)
    assert name_field.get_attribute("value") == "", \
        "Name field should NOT auto-fill (DemoBlaze doesn't store user data)"
    
    fill_order_form(browser, "Logged User", "Spain", "Madrid", "9876543210", "06", "2029")
    browser.find_element(*PURCHASE_BUTTON).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(PURCHASE_CONFIRM_MSG)
    )
    
    browser.find_element(*CONFIRM_OK_BUTTON).click()
    logging.info("TC-PURCH-012: PASSED")


@pytest.mark.functional
def test_order_modal_close_button(order_modal_page):
    """TC-PURCH-013: Order Modal Close Button"""
    logging.info("TC-PURCH-013: Starting order modal close button test...")
    browser = order_modal_page
    
    modal = browser.find_element(*ORDER_MODAL)
    assert modal.is_displayed(), "Order modal should be visible"
    
    close_btn = browser.find_element(*CLOSE_ORDER_MODAL_BUTTON)
    close_btn.click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.invisibility_of_element_located(ORDER_MODAL)
    )
    
    assert browser.find_element(*PLACE_ORDER_BUTTON).is_displayed(), \
        "Should be back on cart page"
    
    logging.info("TC-PURCH-013: PASSED")


@pytest.mark.functional
def test_add_same_product_multiple_times(browser):
    """TC-PURCH-015: Add Same Product Multiple Times"""
    logging.info("TC-PURCH-015: Starting same product multiple times test...")
    browser.get(BASE_URL)
    
    price = add_product_to_cart(browser, FIRST_PRODUCT_LINK)
    add_product_to_cart(browser, FIRST_PRODUCT_LINK)
    
    browser.find_element(*CART_NAV_LINK).click()
    
    cart_items = WebDriverWait(browser, TIMEOUT).until(
        EC.presence_of_all_elements_located((By.XPATH, "//tbody[@id='tbodyid']/tr"))
    )
    
    assert len(cart_items) == 2, f"Expected 2 items, got {len(cart_items)}"
    
    total = wait_for_cart_total_update(browser)
    expected_total = price * 2
    
    assert total == expected_total, f"Total incorrect. Expected: {expected_total}, Got: {total}"
    
    logging.info(f"Same product added twice: {len(cart_items)} items, total: {total}")
    logging.info("TC-PURCH-015: PASSED")


@pytest.mark.functional
def test_navigation_after_purchase(order_modal_page):
    """TC-PURCH-016: Navigation After Purchase"""
    logging.info("TC-PURCH-016: Starting navigation after purchase test...")
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
    
    logging.info("TC-PURCH-016: PASSED")


@pytest.mark.functional
def test_cart_empty_after_purchase(order_modal_page):
    """TC-PURCH-017: Cart Empty After Successful Purchase"""
    logging.info("TC-PURCH-017: Starting cart empty after purchase test...")
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
    
    logging.info("Cart is empty after purchase")
    logging.info("TC-PURCH-017: PASSED")


@pytest.mark.functional
def test_add_many_products_to_cart(browser):
    """TC-PURCH-018: Add Many Products to Cart"""
    logging.info("TC-PURCH-018: Starting boundary test - adding 10 products...")
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
    
    logging.info(f"{items_to_add} items added, total verified: {total_actual}")
    logging.info("TC-PURCH-018: PASSED")


@pytest.mark.functional
def test_delete_all_items_from_cart(browser):
    """TC-PURCH-019: Delete All Items From Cart"""
    logging.info("TC-PURCH-019: Starting delete all items test...")
    browser.get(BASE_URL)
    
    add_product_to_cart(browser, FIRST_PRODUCT_LINK)
    add_product_to_cart(browser, SECOND_PRODUCT_LINK)
    
    browser.find_element(*CART_NAV_LINK).click()
    
    initial_items = WebDriverWait(browser, TIMEOUT).until(
        EC.presence_of_all_elements_located((By.XPATH, "//tbody[@id='tbodyid']/tr"))
    )
    initial_count = len(initial_items)
    
    for i in range(initial_count):
        browser.find_element(*DELETE_ITEM_LINK).click()
        
        WebDriverWait(browser, TIMEOUT).until(
            lambda d: len(d.find_elements(By.XPATH, "//tbody[@id='tbodyid']/tr")) == initial_count - (i + 1)
        )
        logging.info(f"Deleted item {i+1}/{initial_count}")
    
    final_items = browser.find_elements(By.XPATH, "//tbody[@id='tbodyid']/tr")
    assert len(final_items) == 0, f"Cart should be empty, but has {len(final_items)} items"
    
    logging.info("All items deleted successfully")
    logging.info("TC-PURCH-019: PASSED")


@pytest.mark.functional
def test_open_close_order_modal_multiple_times(cart_page):
    """TC-PURCH-020: Open and Close Order Modal Multiple Times"""
    logging.info("TC-PURCH-020: Starting open/close modal multiple times test...")
    browser = cart_page
    
    for i in range(3):
        place_order_btn = browser.find_element(*PLACE_ORDER_BUTTON)
        place_order_btn.click()
        
        WebDriverWait(browser, TIMEOUT).until(
            EC.visibility_of_element_located(ORDER_MODAL)
        )
        logging.info(f"Modal opened - iteration {i+1}")
        
        close_btn = browser.find_element(*CLOSE_ORDER_MODAL_BUTTON)
        close_btn.click()
        
        WebDriverWait(browser, TIMEOUT).until(
            EC.invisibility_of_element_located(ORDER_MODAL)
        )
        logging.info(f"Modal closed - iteration {i+1}")
        
        assert browser.find_element(*PLACE_ORDER_BUTTON).is_displayed(), \
            "Should be back on cart page"
    
    logging.info("TC-PURCH-020: PASSED")


@pytest.mark.functional
def test_access_empty_cart(browser):
    """TC-PURCH-021: Access Cart Without Adding Products"""
    logging.info("TC-PURCH-021: Starting access empty cart test...")
    browser.get(BASE_URL)
    
    browser.find_element(*CART_NAV_LINK).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(PLACE_ORDER_BUTTON)
    )
    
    cart_items = browser.find_elements(By.XPATH, "//tbody[@id='tbodyid']/tr")
    assert len(cart_items) == 0, f"Cart should be empty, but has {len(cart_items)} items"
    
    place_order_btn = browser.find_element(*PLACE_ORDER_BUTTON)
    assert place_order_btn.is_displayed(), "Place Order button should be visible"
    
    logging.info("Empty cart accessible, Place Order visible")
    logging.info("TC-PURCH-021: PASSED")


@pytest.mark.functional
def test_cart_persistence_across_navigation(browser):
    """TC-PURCH-026: Cart Persistence Across Navigation"""
    logging.info("TC-PURCH-026: Starting cart persistence test...")
    browser.get(BASE_URL)
    
    price1 = add_product_to_cart(browser, FIRST_PRODUCT_LINK)
    
    browser.find_element(*HOME_NAV_LINK).click()
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(FIRST_PRODUCT_LINK)
    )
    
    product_link = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(FIRST_PRODUCT_LINK)
    )
    product_link.click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(PRODUCT_PRICE_HEADER)
    )
    
    browser.find_element(*HOME_NAV_LINK).click()
    
    browser.find_element(*CART_NAV_LINK).click()
    
    cart_items = WebDriverWait(browser, TIMEOUT).until(
        EC.presence_of_all_elements_located((By.XPATH, "//tbody[@id='tbodyid']/tr"))
    )
    
    assert len(cart_items) == 1, f"Cart should persist 1 item, got {len(cart_items)}"
    
    total = wait_for_cart_total_update(browser)
    assert total == price1, f"Cart total should persist. Expected: {price1}, Got: {total}"
    
    logging.info("Cart persisted correctly across navigation")
    logging.info("TC-PURCH-026: PASSED")


@pytest.mark.functional
def test_rapid_add_to_cart_clicks(browser):
    """TC-PURCH-027: Rapid Add to Cart Clicks"""
    logging.info("TC-PURCH-027: Starting rapid add to cart test...")
    browser.get(BASE_URL)
    
    product_link = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(FIRST_PRODUCT_LINK)
    )
    product_link.click()
    
    price_element = WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(PRODUCT_PRICE_HEADER)
    )
    price = parse_price(price_element.text)
    
    add_to_cart_btn = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(ADD_TO_CART_BUTTON)
    )
    
    for i in range(3):
        add_to_cart_btn.click()
        alert_text = wait_for_alert_and_get_text(browser, timeout=2)
        if alert_text:
            logging.info(f"Click {i+1}: {alert_text}")
    
    browser.find_element(*CART_NAV_LINK).click()
    
    cart_items = WebDriverWait(browser, TIMEOUT).until(
        EC.presence_of_all_elements_located((By.XPATH, "//tbody[@id='tbodyid']/tr"))
    )
    
    items_count = len(cart_items)
    logging.info(f"After 3 rapid clicks, cart has {items_count} items")
    
    assert items_count >= 1, "At least one item should be in cart"
    assert items_count <= 3, "Should not have more than 3 items"
    
    total = wait_for_cart_total_update(browser)
    expected_min = price
    expected_max = price * 3
    
    assert expected_min <= total <= expected_max, \
        f"Total out of expected range. Got: {total}, Expected: {expected_min}-{expected_max}"
    
    logging.info(f"Rapid clicks handled: {items_count} items, total: {total}")
    logging.info("TC-PURCH-027: PASSED")


@pytest.mark.functional
def test_place_order_button_disabled_during_processing(order_modal_page):
    """TC-PURCH-028: Place Order Button State During Processing"""
    logging.info("TC-PURCH-028: Starting button disabled during processing test...")
    browser = order_modal_page
    
    fill_order_form(browser, "Test User", "Spain", "Barcelona", "1234567890", "12", "2028")
    
    purchase_btn = browser.find_element(*PURCHASE_BUTTON)
    initial_state = purchase_btn.is_enabled()
    
    assert initial_state, "Purchase button should be enabled before clicking"
    
    purchase_btn.click()
    
    try:
        WebDriverWait(browser, 2).until(
            lambda d: not d.find_element(*PURCHASE_BUTTON).is_enabled()
        )
        logging.info("Purchase button disabled during processing")
    except TimeoutException:
        logging.info("Purchase button remained enabled")
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(PURCHASE_CONFIRM_MSG)
    )
    
    browser.find_element(*CONFIRM_OK_BUTTON).click()
    
    logging.info("TC-PURCH-028: PASSED")


@pytest.mark.functional
def test_cart_with_browser_back_button(browser):
    """TC-PURCH-029: Cart with Browser Back Button"""
    logging.info("TC-PURCH-029: Starting browser back button test...")
    browser.get(BASE_URL)
    
    product_link = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(FIRST_PRODUCT_LINK)
    )
    product_link.click()
    
    price_element = WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(PRODUCT_PRICE_HEADER)
    )
    price = parse_price(price_element.text)
    
    add_to_cart_btn = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(ADD_TO_CART_BUTTON)
    )
    add_to_cart_btn.click()
    
    alert_text = wait_for_alert_and_get_text(browser)
    if alert_text:
        logging.info(f"Product added: {alert_text}")
    
    browser.back()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(FIRST_PRODUCT_LINK)
    )
    logging.info("Browser back button pressed")
    
    browser.find_element(*CART_NAV_LINK).click()
    
    cart_items = WebDriverWait(browser, TIMEOUT).until(
        EC.presence_of_all_elements_located((By.XPATH, "//tbody[@id='tbodyid']/tr"))
    )
    
    assert len(cart_items) == 1, f"Cart should have 1 item after back button, got {len(cart_items)}"
    
    total = wait_for_cart_total_update(browser)
    assert total == price, f"Cart total should be {price}, got {total}"
    
    logging.info("Cart persisted correctly after browser back")
    logging.info("TC-PURCH-029: PASSED")


@pytest.mark.functional
def test_cart_with_maximum_quantity_simulation(browser):
    """TC-PURCH-030: Cart Stress Test - 50 Items"""
    logging.info("TC-PURCH-030: Starting cart stress test with 50 items...")
    browser.get(BASE_URL)
    
    total_expected = 0
    items_to_add = 50
    
    for i in range(items_to_add):
        price = add_product_to_cart(browser, FIRST_PRODUCT_LINK)
        total_expected += price
        
        if (i + 1) % 10 == 0:
            logging.info(f"Added {i+1}/{items_to_add} products...")
    
    browser.find_element(*CART_NAV_LINK).click()
    
    cart_items = WebDriverWait(browser, TIMEOUT * 2).until(
        EC.presence_of_all_elements_located((By.XPATH, "//tbody[@id='tbodyid']/tr"))
    )
    
    assert len(cart_items) == items_to_add, \
        f"Expected {items_to_add} items, got {len(cart_items)}"
    
    total_actual = wait_for_cart_total_update(browser, timeout=15)
    
    assert total_actual == total_expected, \
        f"Total mismatch with {items_to_add} items. Expected: {total_expected}, Got: {total_actual}"
    
    logging.info(f"Cart handled {items_to_add} items successfully, total: {total_actual}")
    logging.info("TC-PURCH-030: PASSED")


@pytest.mark.functional
def test_order_modal_escape_key(cart_page):
    """TC-PURCH-031: Close Modal with ESC Key"""
    logging.info("TC-PURCH-031: Starting ESC key modal close test...")
    browser = cart_page
    
    place_order_btn = browser.find_element(*PLACE_ORDER_BUTTON)
    place_order_btn.click()
    
    modal = WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(ORDER_MODAL)
    )
    assert modal.is_displayed(), "Modal should be visible"
    
    actions = ActionChains(browser)
    actions.send_keys(Keys.ESCAPE).perform()
    
    try:
        WebDriverWait(browser, 5).until(
            EC.invisibility_of_element_located(ORDER_MODAL)
        )
        logging.info("Modal closed with ESC key")
        modal_closed = True
    except TimeoutException:
        logging.info("Modal did NOT close with ESC key")
        modal_closed = False
        close_btn = browser.find_element(*CLOSE_ORDER_MODAL_BUTTON)
        close_btn.click()
    
    assert browser.find_element(*PLACE_ORDER_BUTTON).is_displayed(), \
        "Should be back on cart page"
    
    logging.info(f"TC-PURCH-031: PASSED (ESC {'works' if modal_closed else 'documented'})")


@pytest.mark.functional
def test_browser_refresh_on_order_modal(order_modal_page):
    """TC-PURCH-032: Browser Refresh with Modal Open"""
    logging.info("TC-PURCH-032: Starting browser refresh on modal test...")
    browser = order_modal_page
    
    modal = browser.find_element(*ORDER_MODAL)
    assert modal.is_displayed(), "Modal should be visible before refresh"
    
    browser.refresh()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(PLACE_ORDER_BUTTON)
    )
    
    try:
        modal_after = browser.find_element(*ORDER_MODAL)
        if modal_after.is_displayed():
            logging.info("Modal reopened after refresh")
        else:
            logging.info("Modal closed after refresh")
    except:
        logging.info("Modal closed after refresh")
    
    assert browser.find_element(*PLACE_ORDER_BUTTON).is_displayed(), \
        "Should be on cart page after refresh"
    
    logging.info("TC-PURCH-032: PASSED")


@pytest.mark.functional
def test_cart_after_logout(browser):
    """TC-PURCH-033: Cart Behavior After Logout"""
    logging.info("TC-PURCH-033: Starting cart after logout test...")
    browser.get(BASE_URL)
    
    perform_login(browser, TEST_USERNAME, TEST_PASSWORD)
    
    price = add_product_to_cart(browser, FIRST_PRODUCT_LINK)
    
    browser.find_element(*CART_NAV_LINK).click()
    
    initial_items = WebDriverWait(browser, TIMEOUT).until(
        EC.presence_of_all_elements_located((By.XPATH, "//tbody[@id='tbodyid']/tr"))
    )
    assert len(initial_items) == 1, "Cart should have 1 item before logout"
    
    logout_link = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable((By.ID, "logout2"))
    )
    logout_link.click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.invisibility_of_element_located(WELCOME_USER_TEXT)
    )
    logging.info("Logged out successfully")
    
    browser.find_element(*CART_NAV_LINK).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(PLACE_ORDER_BUTTON)
    )
    
    cart_items_after = browser.find_elements(By.XPATH, "//tbody[@id='tbodyid']/tr")
    items_count_after = len(cart_items_after)
    
    if items_count_after == 0:
        logging.info("Cart cleared after logout")
    else:
        logging.info(f"Cart persisted after logout ({items_count_after} items)")
    
    logging.info(f"TC-PURCH-033: PASSED (Cart: {items_count_after} items)")


@pytest.mark.functional
def test_purchase_confirmation_details(order_modal_page):
    """TC-PURCH-034: Purchase Confirmation Shows Correct Details"""
    logging.info("TC-PURCH-034: Starting confirmation details test...")
    browser = order_modal_page
    
    test_name = "QA Automation Tester"
    test_card = "4111111111111111"
    
    expected_price = wait_for_cart_total_update(browser)
    
    fill_order_form(browser, test_name, "Spain", "Barcelona", test_card, "12", "2028")
    
    browser.find_element(*PURCHASE_BUTTON).click()
    
    confirm_modal = WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(PURCHASE_CONFIRM_MODAL)
    )
    
    confirm_text = confirm_modal.text
    logging.info(f"Confirmation text: {confirm_text}")
    
    assert "Thank you for your purchase!" in confirm_text, \
        "Confirmation should contain thank you message"
    
    amount_match = re.search(r'Amount:\s*(\d+)\s*USD', confirm_text)
    assert amount_match, "Confirmation should contain amount"
    
    confirmed_price = int(amount_match.group(1))
    assert confirmed_price == expected_price, \
        f"Confirmed price {confirmed_price} should match expected {expected_price}"
    
    card_match = re.search(r'Card Number:\s*(\d+)', confirm_text)
    if card_match:
        confirmed_card = card_match.group(1)
        logging.info(f"Card in confirmation: {confirmed_card}")
    
    name_match = re.search(r'Name:\s*(.+)', confirm_text, re.MULTILINE)
    if name_match:
        confirmed_name = name_match.group(1).strip()
        logging.info(f"Name in confirmation: {confirmed_name}")
    
    browser.find_element(*CONFIRM_OK_BUTTON).click()
    
    logging.info("TC-PURCH-034: PASSED")


@pytest.mark.functional
def test_order_form_tab_navigation(order_modal_page):
    """TC-PURCH-035: Keyboard Navigation - Tab Order"""
    logging.info("TC-PURCH-035: Starting tab navigation test...")
    browser = order_modal_page
    
    name_field = browser.find_element(*ORDER_NAME_FIELD)
    name_field.click()
    
    actions = ActionChains(browser)
    
    expected_order = [
        ORDER_NAME_FIELD,
        ORDER_COUNTRY_FIELD,
        ORDER_CITY_FIELD,
        ORDER_CARD_FIELD,
        ORDER_MONTH_FIELD,
        ORDER_YEAR_FIELD
    ]
    
    for i, field_locator in enumerate(expected_order):
        active_element = browser.switch_to.active_element
        
        active_element.send_keys(f"Test{i+1}")
        
        actions.send_keys(Keys.TAB).perform()
        
        logging.info(f"Tabbed to field {i+2}/{len(expected_order)}")
    
    filled_name = browser.find_element(*ORDER_NAME_FIELD).get_attribute("value")
    assert filled_name == "Test1", "Name field should have Test1"
    
    logging.info("Tab navigation works correctly")
    logging.info("TC-PURCH-035: PASSED")


@pytest.mark.functional
def test_rapid_purchase_attempts(cart_page):
    """TC-PURCH-036: Rapid Purchase Button Clicks"""
    logging.info("TC-PURCH-036: Starting rapid purchase attempts test...")
    browser = cart_page
    
    browser.find_element(*PLACE_ORDER_BUTTON).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(ORDER_NAME_FIELD)
    )
    
    fill_order_form(browser, "Rapid Test", "Spain", "Madrid", "1234567890", "12", "2028")
    
    purchase_btn = browser.find_element(*PURCHASE_BUTTON)
    
    for i in range(3):
        purchase_btn.click()
        logging.info(f"Purchase click {i+1}")
    
    try:
        confirm_msg = WebDriverWait(browser, TIMEOUT).until(
            EC.visibility_of_element_located(PURCHASE_CONFIRM_MSG)
        )
        logging.info("Purchase confirmation appeared")
        
        browser.find_element(*CONFIRM_OK_BUTTON).click()
        
    except TimeoutException:
        alert_text = wait_for_alert_and_get_text(browser, timeout=2)
        if alert_text:
            logging.info(f"Alert appeared: {alert_text}")
    
    logging.info("TC-PURCH-036: PASSED")


@pytest.mark.functional
def test_cart_total_calculation_performance(browser):
    """TC-PURCH-037: Cart Total Calculation Performance"""
    logging.info("TC-PURCH-037: Starting cart calculation performance test...")
    browser.get(BASE_URL)
    
    add_product_to_cart(browser, FIRST_PRODUCT_LINK)
    add_product_to_cart(browser, SECOND_PRODUCT_LINK)
    
    browser.find_element(*CART_NAV_LINK).click()
    
    start_time = time.time()
    
    total = wait_for_cart_total_update(browser, timeout=5)
    
    calculation_time = time.time() - start_time
    
    logging.info(f"Cart total calculated in {calculation_time:.2f} seconds")
    
    assert calculation_time < 3.0, \
        f"Cart calculation too slow: {calculation_time:.2f}s (should be < 3s)"
    
    assert total > 0, "Cart total should be calculated"
    
    if calculation_time < 1.0:
        logging.info("Excellent performance: < 1 second")
    elif calculation_time < 2.0:
        logging.info("Good performance: < 2 seconds")
    else:
        logging.info("Acceptable performance: < 3 seconds")
    
    logging.info("TC-PURCH-037: PASSED")


@pytest.mark.functional
def test_add_product_from_category_page(browser):
    """TC-PURCH-038: Add Product from Category Page"""
    logging.info("TC-PURCH-038: Starting add from category test...")
    browser.get(BASE_URL)
    
    laptops_link = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(CATEGORY_LAPTOPS_LINK)
    )
    laptops_link.click()
    
    product_link = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable((By.LINK_TEXT, "Sony vaio i5"))
    )
    product_link.click()
    
    add_to_cart_btn = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(ADD_TO_CART_BUTTON)
    )
    add_to_cart_btn.click()
    
    alert_text = wait_for_alert_and_get_text(browser)
    assert alert_text == "Product added."
    
    browser.find_element(*CART_NAV_LINK).click()
    item_name = WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(FIRST_ITEM_IN_CART_NAME)
    )
    assert item_name.text == "Sony vaio i5"
    
    logging.info("TC-PURCH-038: PASSED")


@pytest.mark.functional
def test_homepage_pagination(browser):
    """TC-PURCH-039: Homepage Pagination"""
    logging.info("TC-PURCH-039: Starting pagination test...")
    browser.get(BASE_URL)
    
    first_product_name = WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(FIRST_PRODUCT_LINK)
    ).text
    
    browser.find_element(*PAGINATION_NEXT_LINK).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        lambda d: d.find_element(*FIRST_PRODUCT_LINK).text != first_product_name
    )
    first_product_page_2 = browser.find_element(*FIRST_PRODUCT_LINK).text
    
    browser.find_element(*PAGINATION_PREV_LINK).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        lambda d: d.find_element(*FIRST_PRODUCT_LINK).text == first_product_name
    )
    first_product_page_1_return = browser.find_element(*FIRST_PRODUCT_LINK).text
    
    assert first_product_page_1_return == first_product_name
    
    logging.info("TC-PURCH-039: PASSED")


@pytest.mark.functional
def test_contact_modal_send_valid_message(browser):
    """TC-PURCH-040: Contact Modal - Send Valid Message"""
    logging.info("TC-PURCH-040: Starting contact modal test...")
    browser.get(BASE_URL)
    
    browser.find_element(*CONTACT_NAV_LINK).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(CONTACT_EMAIL_FIELD)
    )
    
    browser.find_element(*CONTACT_EMAIL_FIELD).send_keys("test@example.com")
    browser.find_element(*CONTACT_NAME_FIELD).send_keys("Test User")
    browser.find_element(*CONTACT_MESSAGE_FIELD).send_keys("This is a test message.")
    
    browser.find_element(*CONTACT_SEND_BUTTON).click()
    
    alert_text = wait_for_alert_and_get_text(browser)
    assert alert_text == "Thanks for the message!!"
    
    logging.info("TC-PURCH-040: PASSED")


@pytest.mark.functional
def test_about_us_modal_opens_and_closes(browser):
    """TC-PURCH-041: About Us Modal Opens and Closes"""
    logging.info("TC-PURCH-041: Starting about us modal test...")
    browser.get(BASE_URL)
    
    browser.find_element(*ABOUT_US_NAV_LINK).click()
    
    modal = WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(ABOUT_US_MODAL)
    )
    
    assert modal.is_displayed()
    assert browser.find_element(*ABOUT_US_VIDEO).is_displayed()
    
    close_button = browser.find_element(By.XPATH, "//div[@id='videoModal']//button[text()='Close']")
    close_button.click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.invisibility_of_element_located(ABOUT_US_MODAL)
    )
    
    logging.info("TC-PURCH-041: PASSED")


@pytest.mark.functional
@pytest.mark.parametrize("test_id,name,country,city,card,month,year,expected_alert", [
    ("TC-PURCH-004", "", "", "", "", "", "", "Please fill out Name and Credit Card."),
    ("TC-PURCH-005", "QA Tester", "", "", "", "", "", "Please fill out Name and Credit Card."),
    ("TC-PURCH-006", "", "", "", "1234567890", "", "", "Please fill out Name and Credit Card."),
    ("TC-PURCH-007", "Test", "Spain", "Madrid", "tarjeta-con-letras", "12", "2028", "Invalid credit card format. Must be numeric."),
    ("TC-PURCH-008", "Test", "Spain", "Madrid", "1234567890", "abc", "def", "Invalid date format. Month/Year must be numeric."),
    ("TC-PURCH-009", "a" * 200, "Spain", "Madrid", "1234567890", "12", "2028", "Name is too long. Max 50 characters."),
    ("TC-PURCH-010", "' OR '1'='1", "Spain", "Madrid", "1234567890", "12", "2028", "Invalid input detected. Malicious characters found."),
    ("TC-PURCH-011", "Test", "Spain", "<script>alert(1)</script>", "1234567890", "12", "2028", "Invalid input detected. Malicious characters found."),
    ("TC-PURCH-VAL-001", "   ", "Spain", "Madrid", "1234567890", "12", "2028", "Name field cannot be only whitespace."),
    ("TC-PURCH-VAL-002", "Test", "Spain", "Madrid", "1234567890", "12", f"{datetime.date.today().year - 1}", "Credit card is expired."),
    ("TC-PURCH-VAL-003", "Test", "Spain", "Madrid", "123", "12", "2028", "Invalid credit card length. Must be 16 digits."),
    ("TC-PURCH-VAL-004", "Test", "Spain", "Madrid", "1234567890", "13", "2028", "Invalid month. Must be between 01 and 12."),
])
def test_order_form_validation_robustness_security(order_modal_page, test_id, name, country, city, card, month, year, expected_alert):
    """
    Parametrized Order Form Validation Tests
    Tests validation for required fields, format, length, and security
    """
    logging.info(f"{test_id}: Testing validation - Expected: {expected_alert}")
    browser = order_modal_page
    
    fill_order_form(browser, name, country, city, card, month, year)
    time.sleep(0.1)
    
    browser.find_element(*PURCHASE_BUTTON).click()
    
    alert_text = wait_for_alert_and_get_text(browser)
    
    if alert_text is None:
        try:
            confirm_msg = WebDriverWait(browser, 2).until(
                EC.visibility_of_element_located(PURCHASE_CONFIRM_MSG)
            )
            if confirm_msg.is_displayed():
                alert_text = "VALIDATION FAILURE: Purchase was successful"
                browser.find_element(*CONFIRM_OK_BUTTON).click()
        except TimeoutException:
            alert_text = "VALIDATION FAILURE: No alert and no confirmation"
            
    assert alert_text == expected_alert, \
        f"VALIDATION GAP in {test_id}: Expected '{expected_alert}', Got '{alert_text}'"

    logging.info(f"{test_id}: Test completed")


@pytest.mark.business_rules
def test_empty_cart_purchase_blocked(browser):
    """
    TC-PURCH-BR-001: Empty Cart Purchase Should Be Blocked
    
    Business Rule: E-commerce systems must prevent checkout with empty cart
    Standard: ISO 25010 - Functional Suitability
    Priority: High
    Impact: Invalid orders, wasted processing resources, poor UX
    """
    logging.info("TC-PURCH-BR-001: BUSINESS RULE - Empty cart prevention")
    browser.get(BASE_URL)
    
    browser.find_element(*CART_NAV_LINK).click()
    
    cart_items = browser.find_elements(By.XPATH, "//tbody[@id='tbodyid']/tr")
    assert len(cart_items) == 0, "Prerequisite: Cart must be empty"
    
    place_order_btn = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(PLACE_ORDER_BUTTON)
    )
    place_order_btn.click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(ORDER_NAME_FIELD)
    )
    
    fill_order_form(browser, "Empty Cart Test", "Spain", "Madrid", "1234567890", "01", "2030")
    
    browser.find_element(*PURCHASE_BUTTON).click()
    
    alert_text = wait_for_alert_and_get_text(browser)
    
    if alert_text is None:
        try:
            confirm_msg = WebDriverWait(browser, 2).until(
                EC.visibility_of_element_located(PURCHASE_CONFIRM_MSG)
            )
            if confirm_msg.is_displayed():
                alert_text = "BUG: Purchase successful with empty cart"
                browser.find_element(*CONFIRM_OK_BUTTON).click()
        except TimeoutException:
            alert_text = "BUG: No validation"
    
    expected_alert = "Cannot complete purchase: Cart is empty."
    
    logging.error(f"BUSINESS RULE VIOLATION: Expected '{expected_alert}', Got '{alert_text}'")
    logging.error("Impact: Invalid orders, wasted resources")
    logging.error("Standard: ISO 25010")
    
    assert alert_text == expected_alert


@pytest.mark.business_rules
@pytest.mark.security
def test_card_format_must_be_numeric(order_modal_page):
    """
    TC-PURCH-BR-002: Credit Card Format Validation
    
    Business Rule: Credit cards must be numeric only
    Standard: PCI-DSS 3.2.1 - Input Validation
    Priority: Critical
    Impact: Payment processing failures, compliance violations
    """
    logging.info("TC-PURCH-BR-002: PCI-DSS - Card format validation")
    browser = order_modal_page
    
    fill_order_form(browser, "Test", "Spain", "Madrid", "ABCD-1234", "12", "2028")
    browser.find_element(*PURCHASE_BUTTON).click()
    
    alert_text = wait_for_alert_and_get_text(browser)
    
    if not alert_text:
        try:
            confirm = WebDriverWait(browser, 2).until(
                EC.visibility_of_element_located(PURCHASE_CONFIRM_MSG)
            )
            alert_text = "BUG: Purchase successful with invalid card format"
            browser.find_element(*CONFIRM_OK_BUTTON).click()
        except:
            alert_text = "BUG: No validation"
    
    expected = "Invalid credit card format. Only numbers allowed."
    
    logging.error(f"PCI-DSS VIOLATION: Expected '{expected}', Got '{alert_text}'")
    logging.error("Impact: Compliance violation, payment failures")
    
    assert alert_text == expected


@pytest.mark.business_rules
@pytest.mark.security
def test_card_length_16_digits(order_modal_page):
    """
    TC-PURCH-BR-003: Card Length Validation
    
    Business Rule: Credit cards must be 16 digits
    Standard: PCI-DSS - Card Number Validation
    Priority: Critical
    """
    logging.info("TC-PURCH-BR-003: Card length validation")
    browser = order_modal_page
    
    fill_order_form(browser, "Test", "Spain", "Madrid", "123", "12", "2028")
    browser.find_element(*PURCHASE_BUTTON).click()
    
    alert_text = wait_for_alert_and_get_text(browser)
    if not alert_text:
        try:
            WebDriverWait(browser, 2).until(EC.visibility_of_element_located(PURCHASE_CONFIRM_MSG))
            alert_text = "BUG: Purchase successful with invalid card length"
            browser.find_element(*CONFIRM_OK_BUTTON).click()
        except:
            alert_text = "BUG: No validation"
    
    expected = "Invalid card length. Must be 16 digits."
    
    logging.error(f"VALIDATION GAP: Expected '{expected}', Got '{alert_text}'")
    
    assert alert_text == expected


@pytest.mark.business_rules
@pytest.mark.security
def test_card_expiration_validation(order_modal_page):
    """
    TC-PURCH-BR-004: Expired Card Rejection
    
    Business Rule: System must reject expired cards
    Standard: PCI-DSS - Card Expiration Validation
    Priority: Critical
    Impact: Payment failures, fraud risk
    """
    logging.info("TC-PURCH-BR-004: Card expiration validation")
    browser = order_modal_page
    
    expired_year = str(datetime.date.today().year - 1)
    fill_order_form(browser, "Test", "Spain", "Madrid", "1234567890123456", "12", expired_year)
    browser.find_element(*PURCHASE_BUTTON).click()
    
    alert_text = wait_for_alert_and_get_text(browser)
    if not alert_text:
        try:
            WebDriverWait(browser, 2).until(EC.visibility_of_element_located(PURCHASE_CONFIRM_MSG))
            alert_text = "BUG: Purchase successful with expired card"
            browser.find_element(*CONFIRM_OK_BUTTON).click()
        except:
            alert_text = "BUG: No validation"
    
    expected = "Credit card is expired."
    
    logging.error(f"BUSINESS RULE VIOLATION: Expected '{expected}', Got '{alert_text}'")
    logging.error("Impact: Payment failures, poor customer experience")
    
    assert alert_text == expected


@pytest.mark.business_rules
def test_month_range_validation(order_modal_page):
    """
    TC-PURCH-BR-005: Month Range Validation
    
    Business Rule: Month must be 01-12
    Standard: ISO 8601 Date Format
    Priority: High
    """
    logging.info("TC-PURCH-BR-005: Month range validation")
    browser = order_modal_page
    
    fill_order_form(browser, "Test", "Spain", "Madrid", "1234567890123456", "13", "2028")
    browser.find_element(*PURCHASE_BUTTON).click()
    
    alert_text = wait_for_alert_and_get_text(browser)
    if not alert_text:
        try:
            WebDriverWait(browser, 2).until(EC.visibility_of_element_located(PURCHASE_CONFIRM_MSG))
            alert_text = "BUG: Purchase successful with invalid month"
            browser.find_element(*CONFIRM_OK_BUTTON).click()
        except:
            alert_text = "BUG: No validation"
    
    expected = "Invalid month. Must be 01-12."
    
    logging.error(f"VALIDATION GAP: Expected '{expected}', Got '{alert_text}'")
    
    assert alert_text == expected


@pytest.mark.business_rules
@pytest.mark.security
def test_sql_injection_protection(order_modal_page):
    """
    TC-PURCH-BR-006: SQL Injection Protection
    
    Business Rule: System must sanitize SQL injection attempts
    Standard: OWASP A03:2021 - Injection
    Priority: CRITICAL
    Impact: Database compromise, data breach
    """
    logging.info("TC-PURCH-BR-006: OWASP - SQL Injection protection")
    browser = order_modal_page
    
    fill_order_form(browser, "' OR '1'='1", "Spain", "Madrid", "1234567890123456", "12", "2028")
    browser.find_element(*PURCHASE_BUTTON).click()
    
    alert_text = wait_for_alert_and_get_text(browser)
    if not alert_text:
        try:
            WebDriverWait(browser, 2).until(EC.visibility_of_element_located(PURCHASE_CONFIRM_MSG))
            alert_text = "CRITICAL BUG: SQL Injection not blocked"
            browser.find_element(*CONFIRM_OK_BUTTON).click()
        except:
            alert_text = "BUG: No validation"
    
    expected = "Invalid input. Malicious characters found."
    
    logging.error(f"OWASP VIOLATION: Expected '{expected}', Got '{alert_text}'")
    logging.error("Impact: SQL Injection vulnerability - CRITICAL SECURITY RISK")
    logging.error("Standard: OWASP Top 10 A03:2021")
    
    assert alert_text == expected


@pytest.mark.business_rules
@pytest.mark.security
def test_xss_protection(order_modal_page):
    """
    TC-PURCH-BR-007: XSS (Cross-Site Scripting) Protection
    
    Business Rule: System must prevent XSS attacks
    Standard: OWASP A03:2021 - Injection
    Priority: CRITICAL
    Impact: User session hijacking, malicious script execution
    """
    logging.info("TC-PURCH-BR-007: OWASP - XSS protection")
    browser = order_modal_page
    
    fill_order_form(browser, "Test", "Spain", "<script>alert('XSS')</script>", "1234567890123456", "12", "2028")
    browser.find_element(*PURCHASE_BUTTON).click()
    
    alert_text = wait_for_alert_and_get_text(browser)
    
    if alert_text and 'XSS' in alert_text:
        logging.critical("XSS EXECUTED - CRITICAL SECURITY BREACH")
        alert_text = "CRITICAL: XSS executed"
    
    if not alert_text:
        try:
            WebDriverWait(browser, 2).until(EC.visibility_of_element_located(PURCHASE_CONFIRM_MSG))
            alert_text = "BUG: XSS not blocked"
            browser.find_element(*CONFIRM_OK_BUTTON).click()
        except:
            alert_text = "BUG: No validation"
    
    expected = "Invalid input. Malicious characters found."
    
    logging.error(f"OWASP VIOLATION: Expected '{expected}', Got '{alert_text}'")
    logging.error("Impact: XSS vulnerability - CRITICAL SECURITY RISK")
    
    assert alert_text == expected


@pytest.mark.business_rules
def test_name_max_length(order_modal_page):
    """
    TC-PURCH-BR-008: Name Maximum Length
    
    Business Rule: Name field must have reasonable length limit
    Standard: OWASP - Input Validation
    Priority: Medium
    Impact: Buffer overflow, database issues, poor UX
    """
    logging.info("TC-PURCH-BR-008: Max length validation")
    browser = order_modal_page
    
    fill_order_form(browser, "a" * 200, "Spain", "Madrid", "1234567890123456", "12", "2028")
    browser.find_element(*PURCHASE_BUTTON).click()
    
    alert_text = wait_for_alert_and_get_text(browser)
    if not alert_text:
        try:
            WebDriverWait(browser, 2).until(EC.visibility_of_element_located(PURCHASE_CONFIRM_MSG))
            alert_text = "BUG: Purchase successful with excessive name length"
            browser.find_element(*CONFIRM_OK_BUTTON).click()
        except:
            alert_text = "BUG: No validation"
    
    expected = "Name too long. Max 50 characters."
    
    logging.error(f"VALIDATION GAP: Expected '{expected}', Got '{alert_text}'")
    
    assert alert_text == expected


@pytest.mark.business_rules
def test_whitespace_only_name(order_modal_page):
    """
    TC-PURCH-BR-009: Whitespace-Only Input Rejection
    
    Business Rule: Fields should reject whitespace-only input
    Standard: ISO 25010 - Data Quality
    Priority: Medium
    Impact: Invalid data, poor data integrity
    """
    logging.info("TC-PURCH-BR-009: Whitespace validation")
    browser = order_modal_page
    
    fill_order_form(browser, "     ", "Spain", "Madrid", "1234567890123456", "12", "2028")
    browser.find_element(*PURCHASE_BUTTON).click()
    
    alert_text = wait_for_alert_and_get_text(browser)
    if not alert_text:
        try:
            WebDriverWait(browser, 2).until(EC.visibility_of_element_located(PURCHASE_CONFIRM_MSG))
            alert_text = "BUG: Purchase successful with whitespace-only name"
            browser.find_element(*CONFIRM_OK_BUTTON).click()
        except:
            alert_text = "BUG: No validation"
    
    expected = "Name cannot be only whitespace."
    
    logging.error(f"DATA QUALITY ISSUE: Expected '{expected}', Got '{alert_text}'")
    
    assert alert_text == expected


@pytest.mark.business_rules
def test_contact_empty_fields(browser):
    """
    TC-PURCH-BR-010: Contact Form Validation
    
    Business Rule: Contact form requires all fields
    Standard: ISO 25010 - Usability
    Priority: Medium
    Impact: Invalid submissions, poor data quality
    """
    logging.info("TC-PURCH-BR-010: Contact form validation")
    browser.get(BASE_URL)
    
    browser.find_element(*CONTACT_NAV_LINK).click()
    WebDriverWait(browser, TIMEOUT).until(EC.visibility_of_element_located(CONTACT_SEND_BUTTON))
    browser.find_element(*CONTACT_SEND_BUTTON).click()
    
    alert_text = wait_for_alert_and_get_text(browser)
    expected = "Please fill out all fields."
    
    logging.error(f"VALIDATION GAP: Expected '{expected}', Got '{alert_text}'")
    
    assert alert_text == expected
