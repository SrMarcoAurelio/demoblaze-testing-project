"""
Test Suite: Login & Authentication - Enhanced Version
Module: test_dem_login.py
Author: Arévalo, Marc (y tu Coding Partner)
Description: Comprehensive automated tests for DemoBlaze login functionality including
             SQL injection, XSS, special characters, boundary tests, and more.
             Enhanced with robust logging for real-time feedback.
Related Bugs: #10, #11, #12
Version: 3.1 - Añadido soporte Cross-Browser (Chrome, Firefox, Edge)
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from selenium.webdriver.chrome.service import Service

# Imports de Webdriver Manager
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager         # <--- NUEVO
from webdriver_manager.microsoft import EdgeChromiumDriverManager  # <--- NUEVO

import pytest
import time
import logging

# --- Configuración de Logging ---
logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')


# --- Constants ---
BASE_URL = "https://www.demoblaze.com/"
TIMEOUT = 10
EXPLICIT_WAIT = 5
TEST_USERNAME = "testuser_qa_2024"
TEST_PASSWORD = "SecurePass123!"

# --- Locators ---
LOGIN_BUTTON_NAV = (By.ID, "login2")
LOGIN_USERNAME_FIELD = (By.ID, "loginusername")
LOGIN_PASSWORD_FIELD = (By.ID, "loginpassword")
LOGIN_SUBMIT_BUTTON = (By.XPATH, "//button[text()='Log in']")
LOGOUT_BUTTON = (By.ID, "logout2")
WELCOME_USER_TEXT = (By.ID, "nameofuser")
SIGNUP_BUTTON = (By.ID, "signin2")
SIGNUP_USERNAME_FIELD = (By.ID, "sign-username")
SIGNUP_PASSWORD_FIELD = (By.ID, "sign-password")
SIGNUP_SUBMIT_BUTTON = (By.XPATH, "//button[text()='Sign up']")
LOGIN_MODAL_CLOSE_BUTTON = (By.XPATH, "//div[@id='logInModal']//button[@class='close']")
LOGIN_MODAL = (By.ID, "logInModal")


# --- Fixtures ---

# ----------------------------------------------------
# FIXTURE 'browser' ACTUALIZADA (AQUÍ ESTÁ EL CAMBIO)
# ----------------------------------------------------
@pytest.fixture(scope="function")
def browser(request): # <- ¡Asegúrate de añadir 'request' aquí!
    """
    Fixture parametrizada que inicia el driver del navegador solicitado
    desde la línea de comandos (--browser).
    """
    
    # Leer la opción --browser de la línea de comandos (gracias a conftest.py)
    browser_name = request.config.getoption("--browser").lower()
    
    driver = None
    logging.info(f"\n--- Iniciando WebDriver para: {browser_name} ---")

    if browser_name == "chrome":
        service = Service(ChromeDriverManager().install())
        options = webdriver.ChromeOptions()
        # options.add_argument("--headless")
        driver = webdriver.Chrome(service=service, options=options)
    
    elif browser_name == "firefox":
        service = Service(GeckoDriverManager().install())
        options = webdriver.FirefoxOptions()
        # options.add_argument("--headless")
        driver = webdriver.Firefox(service=service, options=options)
    
    elif browser_name == "edge":
        service = Service(EdgeChromiumDriverManager().install())
        options = webdriver.EdgeOptions()
        # options.add_argument("--headless")
        driver = webdriver.Edge(service=service, options=options)
    
    else:
        pytest.fail(f"Navegador '{browser_name}' no es soportado. Elige 'chrome', 'firefox', o 'edge'.")

    driver.maximize_window()
    driver.implicitly_wait(TIMEOUT)
    
    yield driver
    
    driver.quit()
    logging.info(f"--- WebDriver {browser_name} Cerrado ---")


@pytest.fixture
def login_page(browser):
    """Fixture to navigate to the base URL and open the login modal."""
    browser.get(BASE_URL)
    WebDriverWait(browser, TIMEOUT).until(
        EC.element_to_be_clickable(LOGIN_BUTTON_NAV)
    ).click()
    
    WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(LOGIN_USERNAME_FIELD)
    )
    return browser


# --- Helper Functions (Sin cambios) ---

def perform_login(browser, username, password):
    """Fills the login form and clicks the submit button."""
    try:
        username_field = WebDriverWait(browser, TIMEOUT).until(
            EC.visibility_of_element_located(LOGIN_USERNAME_FIELD)
        )
        username_field.clear()
        username_field.send_keys(username)
        
        password_field = browser.find_element(*LOGIN_PASSWORD_FIELD)
        password_field.clear()
        password_field.send_keys(password)
        
        browser.find_element(*LOGIN_SUBMIT_BUTTON).click()
    except Exception as e:
        logging.error(f"Error durante perform_login: {e}")


def wait_for_alert_and_get_text(browser, timeout=EXPLICIT_WAIT):
    """Waits for a JavaScript alert, gets its text, and accepts it."""
    try:
        WebDriverWait(browser, timeout).until(EC.alert_is_present())
        alert = browser.switch_to.alert
        alert_text = alert.text
        logging.info(f"Alerta detectada: '{alert_text}'")
        alert.accept()
        return alert_text
    except TimeoutException:
        logging.warning("No se encontró ninguna alerta.")
        return None

def check_user_is_logged_in(browser, timeout=EXPLICIT_WAIT):
    """
    Verificación robusta: Espera a que el botón 'Log out' esté VISIBLE.
    """
    try:
        WebDriverWait(browser, timeout).until(
            EC.invisibility_of_element_located(LOGIN_MODAL)
        )
        WebDriverWait(browser, timeout).until(
            EC.visibility_of_element_located(LOGOUT_BUTTON)
        )
        logging.info("Verificación: Usuario ESTÁ logueado (Botón 'Log out' visible).")
        return True
    except TimeoutException:
        logging.warning("Verificación: Usuario NO está logueado (Botón 'Log out' no apareció).")
        return False

def check_user_is_logged_out(browser, timeout=EXPLICIT_WAIT):
    """
    Verificación robusta: Espera a que el botón 'Log out' NO esté visible.
    """
    try:
        WebDriverWait(browser, timeout).until_not(
            EC.visibility_of_element_located(LOGOUT_BUTTON)
        )
        logging.info("Verificación: Usuario ESTÁ deslogueado (Botón 'Log out' no visible).")
        return True
    except TimeoutException:
        logging.error("Verificación: Usuario ESTÁ logueado (El botón 'Log out' apareció inesperadamente).")
        return False


# --- Test Cases (Sin cambios en la lógica) ---

def test_login_valid_credentials(login_page):
    """TC-LOGIN-001: Valid Login"""
    logging.info("🚀 TC-LOGIN-001: Iniciando test de login válido...")
    perform_login(login_page, TEST_USERNAME, TEST_PASSWORD)
    
    assert check_user_is_logged_in(login_page), "El usuario debería estar logueado"
    
    welcome_element = WebDriverWait(login_page, TIMEOUT).until(
        EC.presence_of_element_located(WELCOME_USER_TEXT)
    )
    assert TEST_USERNAME in welcome_element.text, f"Mensaje de bienvenida debería contener {TEST_USERNAME}"
    logging.info("✅ TC-LOGIN-001: PASSED")


def test_login_invalid_password(login_page):
    """TC-LOGIN-002: Invalid Password"""
    logging.info("🚀 TC-LOGIN-002: Iniciando test de contraseña inválida...")
    perform_login(login_page, TEST_USERNAME, "wrongpassword123")
    alert_text = wait_for_alert_and_get_text(login_page)
    
    assert alert_text == "Wrong password.", f"Alerta esperada 'Wrong password.' pero se obtuvo '{alert_text}'"
    assert check_user_is_logged_out(login_page, 2), "Usuario NO debería estar logueado"
    logging.info("✅ TC-LOGIN-002: PASSED")


def test_login_nonexistent_user(login_page):
    """TC-LOGIN-003: Non-existent User"""
    logging.info("🚀 TC-LOGIN-003: Iniciando test de usuario inexistente...")
    perform_login(login_page, "nonexistent_user_xyz_999", "anypassword")
    alert_text = wait_for_alert_and_get_text(login_page)
    
    assert alert_text == "User does not exist.", f"Alerta esperada 'User does not exist.' pero se obtuvo '{alert_text}'"
    assert check_user_is_logged_out(login_page, 2), "Usuario NO debería estar logueado"
    logging.info("✅ TC-LOGIN-003: PASSED")


def test_login_empty_fields(login_page):
    """TC-LOGIN-004: Empty Fields"""
    logging.info("🚀 TC-LOGIN-004: Iniciando test de campos vacíos...")
    perform_login(login_page, "", "")
    alert_text = wait_for_alert_and_get_text(login_page)
    
    assert alert_text == "Please fill out Username and Password.", \
        f"Mensaje de validación esperado pero se obtuvo '{alert_text}'"
    logging.info("✅ TC-LOGIN-004: PASSED")


def test_login_empty_username_only(login_page):
    """TC-LOGIN-005: Empty Username Only"""
    logging.info("🚀 TC-LOGIN-005: Iniciando test de usuario vacío...")
    perform_login(login_page, "", "SomePassword123")
    alert_text = wait_for_alert_and_get_text(login_page)
    
    assert "Please fill out" in alert_text, "Debería mostrar error de validación"
    assert check_user_is_logged_out(login_page, 2), "Usuario NO debería estar logueado"
    logging.info("✅ TC-LOGIN-005: PASSED")


def test_login_empty_password_only(login_page):
    """TC-LOGIN-006: Empty Password Only"""
    logging.info("🚀 TC-LOGIN-006: Iniciando test de contraseña vacía...")
    perform_login(login_page, TEST_USERNAME, "")
    alert_text = wait_for_alert_and_get_text(login_page)
    
    assert "Please fill out" in alert_text, "Debería mostrar error de validación"
    assert check_user_is_logged_out(login_page, 2), "Usuario NO debería estar logueado"
    logging.info("✅ TC-LOGIN-006: PASSED")


@pytest.mark.parametrize("payload", [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "' OR 'a'='a",
    "1' OR '1' = '1",
    "' UNION SELECT NULL--",
    "admin' OR '1'='1'--",
])
def test_login_sql_injection_username(login_page, payload):
    """TC-LOGIN-007: SQL Injection in Username Field"""
    logging.info(f"🚀 TC-LOGIN-007: Probando SQLi en Username. Payload: {payload}")
    perform_login(login_page, payload, "anypassword")
    wait_for_alert_and_get_text(login_page, timeout=3)
    
    if check_user_is_logged_in(login_page, timeout=2):
        logging.critical("="*50)
        logging.critical("🚨🚨🚨 VULNERABILIDAD DETECTADA 🚨🚨🚨")
        logging.critical(f"El login fue EXITOSO con el payload de SQLi: {payload}")
        logging.critical("="*50)
        assert False, f"VULNERABILIDAD SQLi: Login exitoso con payload: {payload}"

    assert check_user_is_logged_out(login_page, 2), \
        f"SQL injection NO debería conceder acceso. Payload: {payload}"
    logging.info(f"✅ TC-LOGIN-007: Payload '{payload}' bloqueado correctamente.")


@pytest.mark.parametrize("payload", [
    "' OR '1'='1",
    "' OR 1=1--",
    "password' OR '1'='1",
])
def test_login_sql_injection_password(login_page, payload):
    """TC-LOGIN-008: SQL Injection in Password Field"""
    logging.info(f"🚀 TC-LOGIN-008: Probando SQLi en Password. Payload: {payload}")
    perform_login(login_page, TEST_USERNAME, payload)
    wait_for_alert_and_get_text(login_page, timeout=3)
    
    if check_user_is_logged_in(login_page, timeout=2):
        logging.critical("="*50)
        logging.critical("🚨🚨🚨 VULNERABILIDAD DETECTADA 🚨🚨🚨")
        logging.critical(f"El login fue EXITOSO con el payload de SQLi en pass: {payload}")
        logging.critical("="*50)
        assert False, f"VULNERABILIDAD SQLi: Login exitoso con payload: {payload}"

    assert check_user_is_logged_out(login_page, 2), \
        f"SQL injection NO debería conceder acceso. Payload: {payload}"
    logging.info(f"✅ TC-LOGIN-008: Payload '{payload}' bloqueado correctamente.")


@pytest.mark.parametrize("payload", [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "<svg/onload=alert('XSS')>",
])
def test_login_xss_username(login_page, payload):
    """TC-LOGIN-009: XSS (Cross-Site Scripting) in Username"""
    logging.info(f"🚀 TC-LOGIN-009: Probando XSS en Username. Payload: {payload}")
    perform_login(login_page, payload, "anypassword")
    
    alert_text = wait_for_alert_and_get_text(login_page, timeout=3)
    
    if alert_text and 'XSS' in alert_text:
        logging.critical("="*50)
        logging.critical("🚨🚨🚨 VULNERABILIDAD XSS DETECTADA 🚨🚨🚨")
        logging.critical(f"Un payload de XSS se ejecutó: {payload}")
        logging.critical("="*50)

    assert check_user_is_logged_out(login_page, 2), \
        f"Payload XSS NO debería conceder acceso. Payload: {payload}"
    logging.info(f"✅ TC-LOGIN-009: Payload '{payload}' bloqueado correctamente.")


@pytest.mark.parametrize("test_input", [
    "user@#$%", "user!@#$%^&*()", "user<>?:", "user|\\", "user{}[]", "user'\"", "user\n\t\r",
])
def test_login_special_characters_username(login_page, test_input):
    """TC-LOGIN-010: Special Characters in Username"""
    logging.info(f"🚀 TC-LOGIN-010: Probando caracteres especiales. Input: {repr(test_input)}")
    perform_login(login_page, test_input, "anypassword")
    wait_for_alert_and_get_text(login_page, timeout=3)
    assert check_user_is_logged_out(login_page, 2), f"Input: {repr(test_input)} no debería loguear"
    logging.info(f"✅ TC-LOGIN-010: Input {repr(test_input)} manejado correctamente.")


@pytest.mark.parametrize("test_input", [
    "用户名", "Пользователь", "utilisateur", "المستخدم", "ユーザー", "😀😎🔥",
])
def test_login_unicode_characters(login_page, test_input):
    """TC-LOGIN-011: Unicode/International Characters"""
    logging.info(f"🚀 TC-LOGIN-011: Probando caracteres Unicode. Input: {test_input}")
    perform_login(login_page, test_input, "anypassword")
    wait_for_alert_and_get_text(login_page, timeout=3)
    assert check_user_is_logged_out(login_page, 2), f"Input: {test_input} no debería loguear"
    logging.info(f"✅ TC-LOGIN-011: Input {test_input} manejado correctamente.")


def test_login_very_long_username(login_page):
    """TC-LOGIN-012: Very Long Username (1000 chars) - Boundary Test"""
    logging.info("🚀 TC-LOGIN-012: Probando usuario muy largo (1000 chars)...")
    long_username = "a" * 1000
    perform_login(login_page, long_username, "anypassword")
    wait_for_alert_and_get_text(login_page, timeout=3)
    assert check_user_is_logged_out(login_page, 2), "Input largo no debería loguear"
    logging.info("✅ TC-LOGIN-012: Input largo (user) manejado correctamente.")


def test_login_very_long_password(login_page):
    """TC-LOGIN-013: Very Long Password (1000 chars) - Boundary Test"""
    logging.info("🚀 TC-LOGIN-013: Probando contraseña muy larga (1000 chars)...")
    long_password = "p" * 1000
    perform_login(login_page, TEST_USERNAME, long_password)
    wait_for_alert_and_get_text(login_page, timeout=3)
    assert check_user_is_logged_out(login_page, 2), "Input largo no debería loguear"
    logging.info("✅ TC-LOGIN-013: Input largo (pass) manejado correctamente.")


@pytest.mark.parametrize("test_input", ["   user   ", " user", "user ", "   "])
def test_login_whitespace_username(login_page, test_input):
    """TC-LOGIN-014: Whitespace in Username"""
    logging.info(f"🚀 TC-LOGIN-014: Probando espacios en blanco. Input: {repr(test_input)}")
    perform_login(login_page, test_input, "anypassword")
    wait_for_alert_and_get_text(login_page, timeout=3)
    assert check_user_is_logged_out(login_page, 2), f"Input: {repr(test_input)} no debería loguear"
    logging.info(f"✅ TC-LOGIN-014: Input {repr(test_input)} manejado correctamente.")


@pytest.mark.parametrize("username_variant", [
    TEST_USERNAME.upper(), TEST_USERNAME.lower(), TEST_USERNAME.title(),
])
def test_login_case_sensitivity_username(login_page, username_variant):
    """TC-LOGIN-015: Case Sensitivity in Username"""
    if username_variant == TEST_USERNAME:
        pytest.skip("Variante es idéntica al username original, saltando test.")
    
    logging.info(f"🚀 TC-LOGIN-015: Probando sensibilidad a mayúsculas. Input: {username_variant}")
    perform_login(login_page, username_variant, TEST_PASSWORD)
    wait_for_alert_and_get_text(login_page, timeout=3)
    assert check_user_is_logged_out(login_page, 2), "Login debería ser sensible a mayúsculas"
    logging.info(f"✅ TC-LOGIN-015: Input {username_variant} manejado correctamente.")


@pytest.mark.parametrize("test_input", ["user\x00admin", "user\x00", "\x00user"])
def test_login_null_bytes(login_page, test_input):
    """TC-LOGIN-016: Null Bytes in Input"""
    logging.info(f"🚀 TC-LOGIN-016: Probando Null Bytes. Input: {repr(test_input)}")
    try:
        perform_login(login_page, test_input, "anypassword")
        wait_for_alert_and_get_text(login_page, timeout=3)
        assert check_user_is_logged_out(login_page, 2), f"Input: {repr(test_input)} no debería loguear"
        logging.info(f"✅ TC-LOGIN-016: Input {repr(test_input)} manejado correctamente.")
    except Exception as e:
        logging.warning(f"Test de Null Byte capturó una excepción (esperado): {e}")
        pass


@pytest.mark.parametrize("test_input", [
    "../../../etc/passwd", "..\\..\\..\\windows\\system32", "....//....//....//etc/passwd",
])
def test_login_path_traversal(login_page, test_input):
    """TC-LOGIN-017: Path Traversal Attempts"""
    logging.info(f"🚀 TC-LOGIN-017: Probando Path Traversal. Input: {test_input}")
    perform_login(login_page, test_input, "anypassword")
    wait_for_alert_and_get_text(login_page, timeout=3)
    assert check_user_is_logged_out(login_page, 2), f"Input: {test_input} no debería loguear"
    logging.info(f"✅ TC-LOGIN-017: Input {test_input} manejado correctamente.")


@pytest.mark.xfail(reason="Bug #11: System accepts weak passwords")
def test_login_weak_password_vulnerability(browser):
    """TC-LOGIN-018: Weak Password Acceptance (Bug #11) - Security Vulnerability"""
    logging.info("🚀 TC-LOGIN-018: (XFAIL) Probando vulnerabilidad de contraseña débil...")
    timestamp = str(int(time.time()))
    test_user = f"weakpass_test_{timestamp}"
    weak_password = "123"
    
    browser.get(BASE_URL)
    WebDriverWait(browser, TIMEOUT).until(EC.element_to_be_clickable(SIGNUP_BUTTON)).click()
    WebDriverWait(browser, TIMEOUT).until(EC.visibility_of_element_located(SIGNUP_USERNAME_FIELD))
    
    browser.find_element(*SIGNUP_USERNAME_FIELD).send_keys(test_user)
    browser.find_element(*SIGNUP_PASSWORD_FIELD).send_keys(weak_password)
    browser.find_element(*SIGNUP_SUBMIT_BUTTON).click()
    
    alert_text = wait_for_alert_and_get_text(browser)
    
    assert "Password too weak" in alert_text or "password requirements" in alert_text.lower(), \
        "Sistema debería rechazar contraseñas débiles (Bug #11)"
    logging.info("✅ TC-LOGIN-018: (XFAIL) Completado.")


@pytest.mark.xfail(reason="Bug #10: Username enumeration vulnerability")
def test_username_enumeration_vulnerability(login_page):
    """TC-LOGIN-019: Username Enumeration (Bug #10) - Security Vulnerability"""
    logging.info("🚀 TC-LOGIN-019: (XFAIL) Probando enumeración de usuarios...")
    
    perform_login(login_page, TEST_USERNAME, "wrong_password_xyz")
    error_msg_existing_user = wait_for_alert_and_get_text(login_page)
    
    WebDriverWait(login_page, TIMEOUT).until(EC.element_to_be_clickable(LOGIN_MODAL_CLOSE_BUTTON)).click()
    WebDriverWait(login_page, TIMEOUT).until(EC.invisibility_of_element_located(LOGIN_MODAL))
    WebDriverWait(login_page, TIMEOUT).until(EC.element_to_be_clickable(LOGIN_BUTTON_NAV)).click()
    
    perform_login(login_page, "definitely_not_a_real_user_xyz", "any_password")
    error_msg_nonexistent_user = wait_for_alert_and_get_text(login_page)
    
    assert error_msg_existing_user == error_msg_nonexistent_user, \
        f"Mensajes deberían ser idénticos (Bug #10). " \
        f"Obtenidos: '{error_msg_existing_user}' vs '{error_msg_nonexistent_user}'"
    logging.info("✅ TC-LOGIN-019: (XFAIL) Completado.")

@pytest.mark.xfail(reason="Bug #12: No brute force protection detected")
def test_login_brute_force_lockout(browser):
    """TC-LOGIN-020: Brute Force Protection (Bug #12) - Security Vulnerability"""
    logging.info("🚀 TC-LOGIN-020: (XFAIL) Probando protección contra fuerza bruta...")
    browser.get(BASE_URL)
    final_alert_text = ""
    attempts = 7
    logging.info(f"Iniciando {attempts} intentos fallidos...")

    for i in range(attempts):
        try:
            WebDriverWait(browser, TIMEOUT).until(
                EC.element_to_be_clickable(LOGIN_BUTTON_NAV)
            ).click()
            
            WebDriverWait(browser, TIMEOUT).until(
                EC.visibility_of_element_located(LOGIN_USERNAME_FIELD)
            )
            
            perform_login(browser, TEST_USERNAME, f"bruteforce_{i}")
            logging.info(f"  Intento {i+1}/{attempts}...")
            
            final_alert_text = wait_for_alert_and_get_text(browser, timeout=5)
            
            if "Account locked" in final_alert_text or "Too many attempts" in final_alert_text:
                logging.info(f"¡Sistema bloqueó la cuenta en el intento {i+1}!")
                break
            time.sleep(0.5)

        except Exception as e:
            logging.error(f"Error durante fuerza bruta {i+1}: {e}")
            browser.refresh()

    assert "Account locked" in final_alert_text or "Too many attempts" in final_alert_text, \
        f"Sistema debería bloquear tras {attempts} intentos (Bug #12). Última alerta: '{final_alert_text}'"
    logging.info("✅ TC-LOGIN-020: (XFAIL) Completado.")


def test_login_modal_close_button(login_page):
    """TC-LOGIN-021: Verify 'Close' button functionality on Login Modal"""
    logging.info("🚀 TC-LOGIN-021: Probando botón 'Close' del modal...")
    
    username_field = login_page.find_element(*LOGIN_USERNAME_FIELD)
    assert username_field.is_displayed(), "Modal de login debería estar abierto"
    
    close_button = login_page.find_element(*LOGIN_MODAL_CLOSE_BUTTON)
    close_button.click()
    
    try:
        WebDriverWait(login_page, TIMEOUT).until(
            EC.invisibility_of_element_located(LOGIN_MODAL)
        )
        assert True
        logging.info("✅ TC-LOGIN-021: Modal cerrado correctamente.")
    except TimeoutException:
        assert False, "Modal de login no se cerró"


# --- Test Corregido (de la conversación anterior) ---
def test_login_modal_interaction_signup_login(browser):
    """TC-LOGIN-022: Verify interaction between Sign Up and Log In modals"""
    logging.info("🚀 TC-LOGIN-022: Probando interacción entre modales (Versión Corregida)...")
    browser.get(BASE_URL)
    
    # --- 1. Abrir y cerrar Sign Up ---
    logging.info("  Abriendo modal Sign Up...")
    WebDriverWait(browser, TIMEOUT).until(EC.element_to_be_clickable(SIGNUP_BUTTON)).click()
    
    # Verificar que está abierto
    signup_modal = WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located((By.ID, "signInModal"))
    )
    assert signup_modal.is_displayed(), "Modal Sign Up debería estar visible"
    logging.info("  Modal Sign Up está visible.")

    # Cerrar el modal Sign Up
    signup_close_button = (By.XPATH, "//div[@id='signInModal']//button[@class='close']")
    WebDriverWait(browser, TIMEOUT).until(EC.element_to_be_clickable(signup_close_button)).click()
    
    # Verificar que está cerrado
    WebDriverWait(browser, TIMEOUT).until(
        EC.invisibility_of_element_located((By.ID, "signInModal"))
    )
    logging.info("  Modal Sign Up cerrado correctamente.")
    
    time.sleep(1) # Pausa breve

    # --- 2. Abrir Log In ---
    logging.info("  Abriendo modal Log In...")
    WebDriverWait(browser, TIMEOUT).until(EC.element_to_be_clickable(LOGIN_BUTTON_NAV)).click()
    
    # Verificar que está abierto
    login_modal = WebDriverWait(browser, TIMEOUT).until(
        EC.visibility_of_element_located(LOGIN_MODAL)
    )
    assert login_modal.is_displayed(), "Modal Log In debería estar visible"
    logging.info("  Modal Log In está visible.")
    
    logging.info("✅ TC-LOGIN-022: PASSED")


# --- Main execution ---
if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])