from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
import pytest
import time
import re

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
        alert.accept()
        return alert_text
    except TimeoutException:
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
    except Exception as e:
        print(f"Error al rellenar el formulario de orden: {e}")

def parse_price(price_str):
    try:
        match = re.search(r'\d+', price_str)
        if match:
            return int(match.group(0))
        return 0
    except (ValueError, TypeError):
        return 0

def add_product_to_cart(browser, product_locator):
    product_link = WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(product_locator)
    )
    product_link.click()
    
    price_element = WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(PRODUCT_PRICE_HEADER)
    )
    price_text = price_element.text
    price = parse_price(price_text)
    
    browser.find_element(*ADD_TO_CART_BUTTON).click()
    wait_for_alert_and_get_text(browser, TIMEOUT)
    
    browser.find_element(*HOME_NAV_LINK).click()
    WebDriverWait(browser, TIMEOUT).until(EC.visibility_of_element_located(FIRST_PRODUCT_LINK))
    
    return price

def perform_login(browser, username, password):
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


@pytest.fixture(scope="function")
def cart_page(browser):
    browser.get(BASE_URL)
    add_product_to_cart(browser, FIRST_PRODUCT_LINK)
    
    browser.find_element(*CART_NAV_LINK).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(PLACE_ORDER_BUTTON)
    )
    return browser

@pytest.fixture(scope="function")
def order_modal_page(cart_page):
    cart_page.find_element(*PLACE_ORDER_BUTTON).click()
    
    WebDriverWait(cart_page, TIMEOUT).until(
        EC.visibility_of_element_located(ORDER_NAME_FIELD)
    )
    return cart_page


def test_successful_purchase_and_price_verification(order_modal_page):
    browser = order_modal_page
    
    try:
        total_price_text = browser.find_element(*CART_TOTAL_PRICE).text
        expected_price = parse_price(total_price_text)
        if expected_price == 0:
            pytest.fail("El precio del carrito es 0 antes de la compra.")
    except Exception as e:
        pytest.fail(f"No se pudo leer el precio total del carrito: {e}")

    fill_order_form(browser, "QA Tester", "Spain", "Barcelona", "1234567890123456", "12", "2028")
    
    browser.find_element(*PURCHASE_BUTTON).click()
    
    try:
        confirm_modal = WebDriverWait(browser, TIMEOUT).until(
            EC.visibility_of_element_located(PURCHASE_CONFIRM_MODAL)
        )
        confirm_text = confirm_modal.text
        
        assert "Thank you for your purchase!" in confirm_text
        
        amount_match = re.search(r'Amount: (\d+) USD', confirm_text)
        
        assert amount_match is not None, "No se encontró el 'Amount:' en el modal de confirmación."
        
        confirmed_price = int(amount_match.group(1))
        
        assert confirmed_price == expected_price, \
            f"¡Discrepancia de precio! Esperado: {expected_price}, Confirmado: {confirmed_price}"
        
    except TimeoutException:
        assert False, "El modal de confirmación de compra no apareció."
    
    browser.find_element(*CONFIRM_OK_BUTTON).click()


def test_multiple_items_total(browser):
    browser.get(BASE_URL)
    price1 = add_product_to_cart(browser, FIRST_PRODUCT_LINK)
    price2 = add_product_to_cart(browser, SECOND_PRODUCT_LINK)
    
    browser.find_element(*CART_NAV_LINK).click()
    
    total_element = WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(CART_TOTAL_PRICE)
    )
    time.sleep(2) 
    total_price = parse_price(total_element.text)
    expected_total = price1 + price2
    
    assert total_price == expected_total, \
        f"Total del carrito incorrecto. Esperado: {expected_total}, Obtenido: {total_price}"


def test_delete_item_from_cart(cart_page):
    browser = cart_page
    
    item_name = WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(FIRST_ITEM_IN_CART_NAME)
    )
    assert item_name.is_displayed(), "El ítem no se añadió al carrito"
    
    browser.find_element(*DELETE_ITEM_LINK).click()
    
    time.sleep(2) 
    
    try:
        browser.find_element(*FIRST_ITEM_IN_CART_NAME)
        assert False, "El ítem no fue eliminado del carrito"
    except NoSuchElementException:
        assert True


def test_delete_item_and_recalculate_total(browser):
    browser.get(BASE_URL)
    price1 = add_product_to_cart(browser, FIRST_PRODUCT_LINK)
    price2 = add_product_to_cart(browser, SECOND_PRODUCT_LINK)
    
    browser.find_element(*CART_NAV_LINK).click()
    
    total_element = WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(CART_TOTAL_PRICE)
    )
    time.sleep(2)
    
    expected_total_before_delete = price1 + price2
    total_before_delete = parse_price(total_element.text)
    assert total_before_delete == expected_total_before_delete, "El total inicial es incorrecto."
    
    browser.find_element(*DELETE_ITEM_LINK).click()
    
    time.sleep(2) 
    
    total_after_delete = parse_price(total_element.text)
    expected_total_after_delete = price2
    
    assert total_after_delete == expected_total_after_delete, \
        f"El total no se recalculó correctamente. Esperado: {expected_total_after_delete}, Obtenido: {total_after_delete}"


def test_purchase_as_logged_in_user(browser):
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
    
    assert name_field.get_attribute("value") == "", "El campo 'Name' no debería auto-rellenarse."

    fill_order_form(browser, "QA Tester Logueado", "Spain", "Barcelona", "987654321", "10", "2027")
    browser.find_element(*PURCHASE_BUTTON).click()
    
    confirm_modal = WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(PURCHASE_CONFIRM_MODAL)
    )
    confirm_text = confirm_modal.text
    
    assert "Thank you for your purchase!" in confirm_text
    
    amount_match = re.search(r'Amount: (\d+) USD', confirm_text)
    assert amount_match is not None, "No se encontró el 'Amount:' en el modal de confirmación."
    
    confirmed_price = int(amount_match.group(1))
    assert confirmed_price == price, "El precio de compra logueado no coincide."
    
    browser.find_element(*CONFIRM_OK_BUTTON).click()


def test_order_modal_close_button(order_modal_page):
    browser = order_modal_page

    assert browser.find_element(*ORDER_MODAL).is_displayed(), "El modal de orden no está visible al inicio."
    
    browser.find_element(*CLOSE_ORDER_MODAL_BUTTON).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.invisibility_of_element_located(ORDER_MODAL)
    )
    
    assert browser.find_element(*PLACE_ORDER_BUTTON).is_displayed(), "No se volvió a la página del carrito."


@pytest.mark.xfail(reason="Bug #13: Es posible 'comprar' con un carrito vacío.")
def test_purchase_empty_cart(browser):
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
    
    assert confirm_msg_element.is_displayed(), "El sistema permitió la compra con carrito vacío"
    
    confirm_text = browser.find_element(*PURCHASE_CONFIRM_MODAL).text
    assert "Amount: 0 USD" in confirm_text or "Amount: null USD" in confirm_text, \
        "El total de la compra fantasma no fue 0 o nulo"
    
    browser.find_element(*CONFIRM_OK_BUTTON).click()
    
    assert False, "Bug #13: El sistema no debería permitir comprar un carrito vacío."


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
    browser = order_modal_page
    
    fill_order_form(browser, name, country, city, card, month, year)
    
    browser.find_element(*PURCHASE_BUTTON).click()
    
    if expected_alert:
        alert_text = wait_for_alert_and_get_text(browser, EXPLICIT_WAIT)
        assert alert_text == expected_alert, f"Alerta incorrecta. Esperada: '{expected_alert}', Obtenida: '{alert_text}'"
    else:
        alert_text = wait_for_alert_and_get_text(browser, 2)
        assert alert_text is None, f"Apareció una alerta inesperada: {alert_text}"
        
        try:
            WebDriverWait(browser, TIMEOUT).until(
                EC.visibility_of_element_located(PURCHASE_CONFIRM_MSG)
            )
            browser.find_element(*CONFIRM_OK_BUTTON).click()
        except TimeoutException:
            assert False, f"La compra falló o crasheó inesperadamente para el payload: {test_id}"
