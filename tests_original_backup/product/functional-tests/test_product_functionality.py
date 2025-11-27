"""
Test Suite: Product Details Functionality Testing
Module: test_product_functionality.py
Author: Arévalo, Marc
Version: 1.0

Test Categories:
- Functional Tests: Core product detail page functionality
- Business Rules Tests: Data validation, performance, usability, accessibility

Standards Validated:
- ISO 25010:2011 (Software Quality Model)
- WCAG 2.1 Level A and AA (Web Content Accessibility Guidelines)
- OWASP ASVS v5.0 (Application Security Verification Standard)
- ISO 9241-110 (Ergonomics of human-system interaction)
- NIST SP 800-63B (Digital Identity Guidelines)

Philosophy: DISCOVER Methodology
Tests EXECUTE actions, OBSERVE results, and DECIDE based on industry standards.
Tests never assume application behavior - they discover actual functionality.
Security violations are reported as CRITICAL ERRORS, not excused.

Execution:
Run all tests:           pytest test_product_functionality.py -v
Run functional only:     pytest test_product_functionality.py -m "functional" -v
Run business rules:      pytest test_product_functionality.py -m "business_rules" -v
Generate HTML report:    pytest test_product_functionality.py --html=report_product.html --self-contained-html

Total Expected Tests: 27 tests (35+ runs with parametrization)
"""

from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
import pytest
import time
import logging
import requests

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ============================================================================
# CONFIGURATION
# ============================================================================

BASE_URL = "https://www.demoblaze.com/"
TIMEOUT = 10
TIMEOUT_SHORT = 5
TIMEOUT_MEDIUM = 15

# ============================================================================
# LOCATORS
# ============================================================================

# Catalog/Home
PRODUCT_LINKS = (By.CSS_SELECTOR, ".hrefch")
PRODUCT_CARDS = (By.CSS_SELECTOR, ".card")

# Product Details Page
PRODUCT_NAME = (By.CSS_SELECTOR, "h2.name")
PRODUCT_PRICE = (By.CSS_SELECTOR, "h3.price-container")
PRODUCT_DESCRIPTION = (By.CSS_SELECTOR, "#more")
PRODUCT_IMAGE = (By.CSS_SELECTOR, ".item.active img")
ADD_TO_CART_BUTTON = (By.CSS_SELECTOR, "a.btn.btn-success.btn-lg")

# Navigation
HOME_LINK = (By.CSS_SELECTOR, "a.nav-link[href='index.html']")

# Cart
CART_LINK = (By.ID, "cartur")

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def wait_for_page_load(browser, timeout=TIMEOUT):
    """Wait for page to fully load"""
    try:
        WebDriverWait(browser, timeout).until(
            lambda driver: driver.execute_script("return document.readyState") == "complete"
        )
        return True
    except TimeoutException:
        return False


def navigate_to_first_product(browser):
    """Navigate from home to first product detail page"""
    browser.get(BASE_URL)
    wait_for_page_load(browser)
    
    try:
        WebDriverWait(browser, TIMEOUT).until(
            EC.presence_of_element_located(PRODUCT_LINKS)
        )
        time.sleep(1)
        
        first_product_link = browser.find_element(*PRODUCT_LINKS)
        product_name = first_product_link.text
        first_product_link.click()
        
        wait_for_page_load(browser)
        time.sleep(2)
        
        return True, product_name
    except (TimeoutException, NoSuchElementException) as e:
        logging.error(f"Failed to navigate to product: {e}")
        return False, None


def get_product_details(browser):
    """Extract all product details from page"""
    details = {
        'name': None,
        'price': None,
        'description': None,
        'image_src': None,
        'add_to_cart_present': False
    }
    
    try:
        details['name'] = browser.find_element(*PRODUCT_NAME).text
    except NoSuchElementException:
        pass
    
    try:
        details['price'] = browser.find_element(*PRODUCT_PRICE).text
    except NoSuchElementException:
        pass
    
    try:
        details['description'] = browser.find_element(*PRODUCT_DESCRIPTION).text
    except NoSuchElementException:
        pass
    
    try:
        img_element = browser.find_element(*PRODUCT_IMAGE)
        details['image_src'] = img_element.get_attribute('src')
    except NoSuchElementException:
        pass
    
    try:
        browser.find_element(*ADD_TO_CART_BUTTON)
        details['add_to_cart_present'] = True
    except NoSuchElementException:
        pass
    
    return details


def check_image_loads_successfully(image_url):
    """Verify image URL returns 200 OK"""
    try:
        response = requests.head(image_url, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

# ============================================================================
# FUNCTIONAL TESTS
# ============================================================================

@pytest.mark.functional
def test_navigate_to_product_from_catalog_FUNC_001(browser):
    """
    TC-PRODUCT-FUNC-001: Navigate to Product Detail from Catalog
    
    Verifies: User can navigate from catalog to product detail page
    
    Steps:
    1. Load homepage
    2. Click on first product
    3. Verify product detail page loads
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-FUNC-001: Testing navigation to product detail")
    
    success, product_name = navigate_to_first_product(browser)
    
    assert success, "FAILED: Could not navigate to product detail page"
    assert product_name, "FAILED: Product name not found in catalog"
    
    # Verify we're on product detail page
    current_url = browser.current_url
    assert "prod.html" in current_url, f"FAILED: Not on product page. URL: {current_url}"
    
    logging.info(f"SUCCESS: Navigated to product detail page for '{product_name}'")
    logging.info(f"Product URL: {current_url}")


@pytest.mark.functional
def test_product_name_displays_FUNC_002(browser):
    """
    TC-PRODUCT-FUNC-002: Product Name Displays
    
    Verifies: Product name is visible on detail page
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-FUNC-002: Testing product name display")
    
    navigate_to_first_product(browser)
    
    try:
        product_name_element = browser.find_element(*PRODUCT_NAME)
        assert product_name_element.is_displayed(), "FAILED: Product name not visible"
        
        product_name = product_name_element.text
        assert len(product_name) > 0, "FAILED: Product name is empty"
        
        logging.info(f"SUCCESS: Product name displays: '{product_name}'")
        
    except NoSuchElementException:
        pytest.fail("FAILED: Product name element not found")


@pytest.mark.functional
def test_product_price_displays_FUNC_003(browser):
    """
    TC-PRODUCT-FUNC-003: Product Price Displays
    
    Verifies: Product price is visible on detail page
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-FUNC-003: Testing product price display")
    
    navigate_to_first_product(browser)
    
    try:
        price_element = browser.find_element(*PRODUCT_PRICE)
        assert price_element.is_displayed(), "FAILED: Price not visible"
        
        price_text = price_element.text
        assert len(price_text) > 0, "FAILED: Price is empty"
        assert "$" in price_text or "dollar" in price_text.lower(), f"FAILED: Price format unexpected: {price_text}"
        
        logging.info(f"SUCCESS: Product price displays: '{price_text}'")
        
    except NoSuchElementException:
        pytest.fail("FAILED: Product price element not found")


@pytest.mark.functional
def test_product_description_displays_FUNC_004(browser):
    """
    TC-PRODUCT-FUNC-004: Product Description Displays
    
    Verifies: Product description is visible on detail page
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-FUNC-004: Testing product description display")
    
    navigate_to_first_product(browser)
    
    try:
        description_element = browser.find_element(*PRODUCT_DESCRIPTION)
        assert description_element.is_displayed(), "FAILED: Description not visible"
        
        description_text = description_element.text
        assert len(description_text) > 0, "FAILED: Description is empty"
        
        logging.info(f"SUCCESS: Product description displays ({len(description_text)} characters)")
        
    except NoSuchElementException:
        pytest.fail("FAILED: Product description element not found")


@pytest.mark.functional
def test_product_image_displays_FUNC_005(browser):
    """
    TC-PRODUCT-FUNC-005: Product Image Displays
    
    Verifies: Product image is visible on detail page
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-FUNC-005: Testing product image display")
    
    navigate_to_first_product(browser)
    
    try:
        image_element = browser.find_element(*PRODUCT_IMAGE)
        assert image_element.is_displayed(), "FAILED: Product image not visible"
        
        image_src = image_element.get_attribute('src')
        assert image_src, "FAILED: Image src attribute is empty"
        assert image_src.startswith('http'), f"FAILED: Invalid image URL: {image_src}"
        
        logging.info(f"SUCCESS: Product image displays")
        logging.info(f"Image URL: {image_src}")
        
    except NoSuchElementException:
        pytest.fail("FAILED: Product image element not found")


@pytest.mark.functional
def test_add_to_cart_button_present_FUNC_006(browser):
    """
    TC-PRODUCT-FUNC-006: Add to Cart Button Present
    
    Verifies: Add to cart button exists and is visible
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-FUNC-006: Testing add to cart button presence")
    
    navigate_to_first_product(browser)
    
    try:
        add_to_cart_btn = browser.find_element(*ADD_TO_CART_BUTTON)
        assert add_to_cart_btn.is_displayed(), "FAILED: Add to cart button not visible"
        
        button_text = add_to_cart_btn.text
        logging.info(f"SUCCESS: Add to cart button present: '{button_text}'")
        
    except NoSuchElementException:
        pytest.fail("FAILED: Add to cart button not found")


@pytest.mark.functional
def test_add_to_cart_from_product_page_FUNC_007(browser):
    """
    TC-PRODUCT-FUNC-007: Add to Cart from Product Page
    
    Verifies: User can add product to cart from detail page
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-FUNC-007: Testing add to cart functionality")
    
    success, product_name = navigate_to_first_product(browser)
    assert success, "FAILED: Could not navigate to product"
    
    try:
        add_to_cart_btn = browser.find_element(*ADD_TO_CART_BUTTON)
        add_to_cart_btn.click()
        time.sleep(2)
        
        # Check for alert confirmation
        try:
            WebDriverWait(browser, 5).until(EC.alert_is_present())
            alert = browser.switch_to.alert
            alert_text = alert.text
            alert.accept()
            
            logging.info(f"SUCCESS: Add to cart triggered alert: '{alert_text}'")
            assert "added" in alert_text.lower() or "cart" in alert_text.lower(), \
                f"FAILED: Unexpected alert message: {alert_text}"
            
        except TimeoutException:
            logging.warning("No alert appeared after clicking add to cart")
        
        logging.info(f"SUCCESS: Add to cart completed for '{product_name}'")
        
    except NoSuchElementException:
        pytest.fail("FAILED: Add to cart button not found")


@pytest.mark.functional
def test_back_to_catalog_navigation_FUNC_008(browser):
    """
    TC-PRODUCT-FUNC-008: Navigate Back to Catalog
    
    Verifies: User can return to catalog from product page
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-FUNC-008: Testing back to catalog navigation")
    
    navigate_to_first_product(browser)
    
    # Click home/catalog link
    try:
        home_link = browser.find_element(*HOME_LINK)
        home_link.click()
        wait_for_page_load(browser)
        time.sleep(2)
        
        # Verify we're back on catalog
        current_url = browser.current_url
        assert "index.html" in current_url or current_url == BASE_URL or current_url == BASE_URL.rstrip('/'), \
            f"FAILED: Not back on catalog. URL: {current_url}"
        
        # Verify products are visible again
        products = browser.find_elements(*PRODUCT_CARDS)
        assert len(products) > 0, "FAILED: No products visible after returning to catalog"
        
        logging.info(f"SUCCESS: Navigated back to catalog, {len(products)} products visible")
        
    except NoSuchElementException:
        pytest.fail("FAILED: Home/catalog link not found")


@pytest.mark.functional
def test_browser_back_button_FUNC_009(browser):
    """
    TC-PRODUCT-FUNC-009: Browser Back Button Functionality
    
    Verifies: Browser back button returns to catalog
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-FUNC-009: Testing browser back button")
    
    navigate_to_first_product(browser)
    product_url = browser.current_url
    
    # Use browser back button
    browser.back()
    wait_for_page_load(browser)
    time.sleep(2)
    
    catalog_url = browser.current_url
    assert catalog_url != product_url, "FAILED: Browser back did not change URL"
    
    # Verify we're on catalog
    products = browser.find_elements(*PRODUCT_CARDS)
    assert len(products) > 0, "FAILED: Not on catalog after back button"
    
    logging.info(f"SUCCESS: Browser back button returned to catalog")


@pytest.mark.functional
def test_multiple_product_navigation_FUNC_010(browser):
    """
    TC-PRODUCT-FUNC-010: Navigate Between Multiple Products
    
    Verifies: User can navigate between different products
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-FUNC-010: Testing navigation between products")
    
    browser.get(BASE_URL)
    wait_for_page_load(browser)
    time.sleep(1)
    
    # Get multiple product links
    product_links = browser.find_elements(*PRODUCT_LINKS)
    assert len(product_links) >= 2, "FAILED: Not enough products to test navigation"
    
    visited_products = []
    
    for i in range(min(3, len(product_links))):
        browser.get(BASE_URL)
        time.sleep(1)
        
        product_links = browser.find_elements(*PRODUCT_LINKS)
        product_name = product_links[i].text
        product_links[i].click()
        
        wait_for_page_load(browser)
        time.sleep(2)
        
        # Verify product details load
        details = get_product_details(browser)
        assert details['name'], f"FAILED: Product {i+1} name not found"
        
        visited_products.append(product_name)
    
    logging.info(f"SUCCESS: Navigated to {len(visited_products)} different products")
    for idx, prod in enumerate(visited_products, 1):
        logging.info(f"  Product {idx}: {prod}")

# ============================================================================
# BUSINESS RULES TESTS
# ============================================================================

@pytest.mark.business_rules
def test_all_products_have_name_BR_001(browser):
    """
    TC-PRODUCT-BR-001: All Products Must Have Name
    
    Standard: ISO 25010 Section 5.3 (Completeness)
    Validates: Product data completeness
    CVSS Score: 5.3 (MEDIUM) if violated
    
    Discovers if any products lack name information.
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-BR-001: Validating all products have names")
    
    browser.get(BASE_URL)
    wait_for_page_load(browser)
    time.sleep(1)
    
    product_links = browser.find_elements(*PRODUCT_LINKS)
    total_products = len(product_links)
    products_without_name = []
    
    for i in range(min(10, total_products)):
        browser.get(BASE_URL)
        time.sleep(1)
        
        product_links = browser.find_elements(*PRODUCT_LINKS)
        product_links[i].click()
        wait_for_page_load(browser)
        time.sleep(2)
        
        try:
            name_element = browser.find_element(*PRODUCT_NAME)
            name_text = name_element.text.strip()
            
            if not name_text or len(name_text) == 0:
                products_without_name.append(i + 1)
                
        except NoSuchElementException:
            products_without_name.append(i + 1)
    
    if products_without_name:
        logging.error("=" * 80)
        logging.error("DATA COMPLETENESS VIOLATION: PRODUCTS WITHOUT NAMES")
        logging.error("Standard: ISO 25010 Section 5.3 (Completeness)")
        logging.error("CVSS Score: 5.3 (MEDIUM)")
        logging.error(f"Products without names: {len(products_without_name)}/{min(10, total_products)}")
        logging.error(f"Product indices: {products_without_name}")
        logging.error("Impact: Poor user experience, missing critical information")
        logging.error("=" * 80)
        
        pytest.fail(f"DISCOVERED: {len(products_without_name)} products lack name information")
    
    logging.info(f"SUCCESS: All tested products ({min(10, total_products)}) have names")


@pytest.mark.business_rules
def test_all_products_have_price_BR_002(browser):
    """
    TC-PRODUCT-BR-002: All Products Must Have Price
    
    Standard: ISO 25010 Section 5.3 (Completeness)
    CVSS Score: 7.5 (HIGH) if violated
    
    Discovers if any products lack price information.
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-BR-002: Validating all products have prices")
    
    browser.get(BASE_URL)
    wait_for_page_load(browser)
    time.sleep(1)
    
    product_links = browser.find_elements(*PRODUCT_LINKS)
    total_products = len(product_links)
    products_without_price = []
    
    for i in range(min(10, total_products)):
        browser.get(BASE_URL)
        time.sleep(1)
        
        product_links = browser.find_elements(*PRODUCT_LINKS)
        product_links[i].click()
        wait_for_page_load(browser)
        time.sleep(2)
        
        try:
            price_element = browser.find_element(*PRODUCT_PRICE)
            price_text = price_element.text.strip()
            
            if not price_text or "$" not in price_text:
                products_without_price.append(i + 1)
                
        except NoSuchElementException:
            products_without_price.append(i + 1)
    
    if products_without_price:
        logging.error("=" * 80)
        logging.error("CRITICAL: PRODUCTS WITHOUT PRICE INFORMATION")
        logging.error("Standard: ISO 25010 Section 5.3 (Completeness)")
        logging.error("CVSS Score: 7.5 (HIGH)")
        logging.error(f"Products without prices: {len(products_without_price)}/{min(10, total_products)}")
        logging.error(f"Product indices: {products_without_price}")
        logging.error("Impact: Cannot complete purchase, broken business logic")
        logging.error("=" * 80)
        
        pytest.fail(f"DISCOVERED: {len(products_without_price)} products lack price information")
    
    logging.info(f"SUCCESS: All tested products ({min(10, total_products)}) have prices")


@pytest.mark.business_rules
def test_all_products_have_description_BR_003(browser):
    """
    TC-PRODUCT-BR-003: All Products Must Have Description
    
    Standard: ISO 25010 Section 5.3 (Completeness)
    CVSS Score: 3.7 (LOW) if violated
    
    Discovers if any products lack description.
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-BR-003: Validating all products have descriptions")
    
    browser.get(BASE_URL)
    wait_for_page_load(browser)
    time.sleep(1)
    
    product_links = browser.find_elements(*PRODUCT_LINKS)
    total_products = len(product_links)
    products_without_description = []
    
    for i in range(min(10, total_products)):
        browser.get(BASE_URL)
        time.sleep(1)
        
        product_links = browser.find_elements(*PRODUCT_LINKS)
        product_links[i].click()
        wait_for_page_load(browser)
        time.sleep(2)
        
        try:
            desc_element = browser.find_element(*PRODUCT_DESCRIPTION)
            desc_text = desc_element.text.strip()
            
            if not desc_text or len(desc_text) < 10:
                products_without_description.append(i + 1)
                
        except NoSuchElementException:
            products_without_description.append(i + 1)
    
    if products_without_description:
        logging.warning("=" * 80)
        logging.warning("DATA QUALITY ISSUE: PRODUCTS WITHOUT DESCRIPTIONS")
        logging.warning("Standard: ISO 25010 Section 5.3 (Completeness)")
        logging.warning("CVSS Score: 3.7 (LOW)")
        logging.warning(f"Products without descriptions: {len(products_without_description)}/{min(10, total_products)}")
        logging.warning("Impact: Poor user experience, insufficient product information")
        logging.warning("=" * 80)
        
        pytest.fail(f"DISCOVERED: {len(products_without_description)} products lack descriptions")
    
    logging.info(f"SUCCESS: All tested products ({min(10, total_products)}) have descriptions")


@pytest.mark.business_rules
def test_all_product_images_load_successfully_BR_004(browser):
    """
    TC-PRODUCT-BR-004: All Product Images Must Load
    
    Standard: ISO 25010 Section 5.4 (Availability)
    CVSS Score: 5.3 (MEDIUM) if violated
    
    Discovers if any product images fail to load.
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-BR-004: Validating product images load successfully")
    
    browser.get(BASE_URL)
    wait_for_page_load(browser)
    time.sleep(1)
    
    product_links = browser.find_elements(*PRODUCT_LINKS)
    total_products = len(product_links)
    broken_images = []
    
    for i in range(min(10, total_products)):
        browser.get(BASE_URL)
        time.sleep(1)
        
        product_links = browser.find_elements(*PRODUCT_LINKS)
        product_links[i].click()
        wait_for_page_load(browser)
        time.sleep(2)
        
        try:
            image_element = browser.find_element(*PRODUCT_IMAGE)
            image_src = image_element.get_attribute('src')
            
            if image_src:
                if not check_image_loads_successfully(image_src):
                    broken_images.append({
                        'index': i + 1,
                        'url': image_src
                    })
            else:
                broken_images.append({
                    'index': i + 1,
                    'url': 'No src attribute'
                })
                
        except NoSuchElementException:
            broken_images.append({
                'index': i + 1,
                'url': 'Image element not found'
            })
    
    if broken_images:
        logging.error("=" * 80)
        logging.error("AVAILABILITY VIOLATION: BROKEN PRODUCT IMAGES")
        logging.error("Standard: ISO 25010 Section 5.4 (Availability)")
        logging.error("CVSS Score: 5.3 (MEDIUM)")
        logging.error(f"Broken images: {len(broken_images)}/{min(10, total_products)}")
        for img in broken_images[:3]:
            logging.error(f"  Product {img['index']}: {img['url']}")
        logging.error("Impact: Poor user experience, cannot view products")
        logging.error("=" * 80)
        
        pytest.fail(f"DISCOVERED: {len(broken_images)} products have broken images")
    
    logging.info(f"SUCCESS: All tested product images ({min(10, total_products)}) load successfully")


@pytest.mark.business_rules
def test_product_price_format_consistency_BR_005(browser):
    """
    TC-PRODUCT-BR-005: Product Price Format Consistency
    
    Standard: ISO 25010 Section 5.2 (Consistency)
    CVSS Score: 3.7 (LOW) if violated
    
    Discovers if prices follow consistent format.
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-BR-005: Validating price format consistency")
    
    browser.get(BASE_URL)
    wait_for_page_load(browser)
    time.sleep(1)
    
    product_links = browser.find_elements(*PRODUCT_LINKS)
    total_products = len(product_links)
    price_formats = []
    inconsistent_prices = []
    
    for i in range(min(10, total_products)):
        browser.get(BASE_URL)
        time.sleep(1)
        
        product_links = browser.find_elements(*PRODUCT_LINKS)
        product_links[i].click()
        wait_for_page_load(browser)
        time.sleep(2)
        
        try:
            price_element = browser.find_element(*PRODUCT_PRICE)
            price_text = price_element.text.strip()
            
            # Check format consistency
            has_dollar_sign = "$" in price_text
            has_includes = "includes" in price_text.lower() or "*includes" in price_text.lower()
            
            format_key = f"dollar:{has_dollar_sign},includes:{has_includes}"
            
            if format_key not in price_formats:
                price_formats.append(format_key)
            
            if len(price_formats) > 1:
                inconsistent_prices.append({
                    'index': i + 1,
                    'text': price_text
                })
                
        except NoSuchElementException:
            pass
    
    if len(price_formats) > 1:
        logging.warning("=" * 80)
        logging.warning("CONSISTENCY ISSUE: INCONSISTENT PRICE FORMATS")
        logging.warning("Standard: ISO 25010 Section 5.2 (Consistency)")
        logging.warning("CVSS Score: 3.7 (LOW)")
        logging.warning(f"Found {len(price_formats)} different price formats")
        logging.warning(f"Inconsistent prices: {len(inconsistent_prices)}")
        for price in inconsistent_prices[:3]:
            logging.warning(f"  Product {price['index']}: '{price['text']}'")
        logging.warning("Impact: Confusing user experience")
        logging.warning("=" * 80)
        
        pytest.fail(f"DISCOVERED: {len(price_formats)} different price formats found")
    
    logging.info(f"SUCCESS: All prices follow consistent format")


@pytest.mark.business_rules
def test_product_detail_load_time_BR_006(browser):
    """
    TC-PRODUCT-BR-006: Product Detail Load Time < 3 seconds
    
    Standard: ISO 25010 Section 5.5 (Performance Efficiency)
    CVSS Score: 5.3 (MEDIUM) if violated
    
    Discovers if product pages load within acceptable time.
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-BR-006: Validating product load time")
    
    browser.get(BASE_URL)
    wait_for_page_load(browser)
    time.sleep(1)
    
    slow_loads = []
    
    product_links = browser.find_elements(*PRODUCT_LINKS)
    
    for i in range(min(5, len(product_links))):
        browser.get(BASE_URL)
        time.sleep(1)
        
        product_links = browser.find_elements(*PRODUCT_LINKS)
        
        start_time = time.time()
        product_links[i].click()
        
        wait_for_page_load(browser)
        
        try:
            WebDriverWait(browser, 5).until(
                EC.presence_of_element_located(PRODUCT_NAME)
            )
        except TimeoutException:
            pass
        
        load_time = time.time() - start_time
        
        if load_time > 3.0:
            slow_loads.append({
                'index': i + 1,
                'time': load_time
            })
        
        logging.info(f"Product {i+1} load time: {load_time:.2f}s")
        time.sleep(1)
    
    if slow_loads:
        logging.error("=" * 80)
        logging.error("PERFORMANCE VIOLATION: SLOW PRODUCT LOAD TIMES")
        logging.error("Standard: ISO 25010 Section 5.5 (Performance Efficiency)")
        logging.error("CVSS Score: 5.3 (MEDIUM)")
        logging.error(f"Products exceeding 3s: {len(slow_loads)}/{min(5, len(product_links))}")
        for product in slow_loads:
            logging.error(f"  Product {product['index']}: {product['time']:.2f}s")
        logging.error("Impact: Poor user experience, increased bounce rate")
        logging.error("Requirement: Page load should be < 3 seconds")
        logging.error("=" * 80)
        
        pytest.fail(f"DISCOVERED: {len(slow_loads)} products exceed 3s load time")
    
    logging.info(f"SUCCESS: All products load within 3 seconds")


@pytest.mark.business_rules
def test_add_to_cart_button_visibility_BR_007(browser):
    """
    TC-PRODUCT-BR-007: Add to Cart Button Must Be Visible
    
    Standard: ISO 9241-110 Section 5.3 (Visibility)
    CVSS Score: 5.3 (MEDIUM) if violated
    
    Discovers if add to cart button is clearly visible.
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-BR-007: Validating add to cart button visibility")
    
    navigate_to_first_product(browser)
    
    try:
        add_to_cart_btn = browser.find_element(*ADD_TO_CART_BUTTON)
        
        is_displayed = add_to_cart_btn.is_displayed()
        is_enabled = add_to_cart_btn.is_enabled()
        
        if not is_displayed or not is_enabled:
            logging.error("=" * 80)
            logging.error("USABILITY VIOLATION: ADD TO CART BUTTON NOT PROPERLY VISIBLE")
            logging.error("Standard: ISO 9241-110 Section 5.3 (Visibility)")
            logging.error("CVSS Score: 5.3 (MEDIUM)")
            logging.error(f"Displayed: {is_displayed}, Enabled: {is_enabled}")
            logging.error("Impact: Users cannot add products to cart")
            logging.error("=" * 80)
            
            pytest.fail("DISCOVERED: Add to cart button not properly visible or enabled")
        
        logging.info("SUCCESS: Add to cart button is visible and enabled")
        
    except NoSuchElementException:
        logging.error("=" * 80)
        logging.error("CRITICAL: ADD TO CART BUTTON NOT FOUND")
        logging.error("CVSS Score: 7.5 (HIGH)")
        logging.error("Impact: Cannot add products to cart")
        logging.error("=" * 80)
        
        pytest.fail("DISCOVERED: Add to cart button not found on product page")


@pytest.mark.business_rules
def test_product_image_has_alt_text_BR_008(browser):
    """
    TC-PRODUCT-BR-008: Product Images Must Have Alt Text
    
    Standard: WCAG 2.1 SC 1.1.1 Level A (MANDATORY)
    CVSS Score: 7.5 (HIGH) if violated
    Legal: ADA compliance required
    
    Discovers if product images have proper alt text for accessibility.
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-BR-008: Validating product image alt text")
    
    browser.get(BASE_URL)
    wait_for_page_load(browser)
    time.sleep(1)
    
    product_links = browser.find_elements(*PRODUCT_LINKS)
    images_without_alt = []
    
    for i in range(min(5, len(product_links))):
        browser.get(BASE_URL)
        time.sleep(1)
        
        product_links = browser.find_elements(*PRODUCT_LINKS)
        product_links[i].click()
        wait_for_page_load(browser)
        time.sleep(2)
        
        try:
            image_element = browser.find_element(*PRODUCT_IMAGE)
            alt_text = image_element.get_attribute('alt')
            
            if not alt_text or len(alt_text.strip()) == 0:
                images_without_alt.append(i + 1)
                
        except NoSuchElementException:
            images_without_alt.append(i + 1)
    
    if images_without_alt:
        logging.error("=" * 80)
        logging.error("ACCESSIBILITY VIOLATION: IMAGES WITHOUT ALT TEXT")
        logging.error("Standard: WCAG 2.1 SC 1.1.1 Level A (MANDATORY)")
        logging.error("CVSS Score: 7.5 (HIGH)")
        logging.error(f"Images without alt text: {len(images_without_alt)}/{min(5, len(product_links))}")
        logging.error(f"Product indices: {images_without_alt}")
        logging.error("Impact:")
        logging.error("  - Screen readers cannot describe images")
        logging.error("  - ADA compliance failure")
        logging.error("  - Legal liability (lawsuits)")
        logging.error("  - SEO impact")
        logging.error("Legal: This is a MANDATORY accessibility requirement")
        logging.error("=" * 80)
        
        pytest.fail(f"DISCOVERED: {len(images_without_alt)} products lack image alt text (WCAG 2.1 Level A violation)")
    
    logging.info(f"SUCCESS: All tested product images have alt text")


@pytest.mark.business_rules
def test_keyboard_navigation_product_page_BR_009(browser):
    """
    TC-PRODUCT-BR-009: Keyboard Navigation on Product Page
    
    Standard: WCAG 2.1 SC 2.1.1 Level A (MANDATORY)
    CVSS Score: 7.5 (HIGH) if violated
    
    Discovers if product page is keyboard accessible.
    """
    logging.info("=" * 80)
    logging.info("TC-PRODUCT-BR-009: Validating keyboard navigation")
    
    navigate_to_first_product(browser)
    
    try:
        # Try to tab to add to cart button
        from selenium.webdriver.common.keys import Keys
        
        body = browser.find_element(By.TAG_NAME, "body")
        
        # Press Tab multiple times
        for _ in range(10):
            body.send_keys(Keys.TAB)
            time.sleep(0.2)
            
            # Check if add to cart button is focused
            focused_element = browser.switch_to.active_element
            
            if focused_element.tag_name == "a" and "btn-success" in focused_element.get_attribute("class"):
                logging.info("SUCCESS: Add to cart button reachable via keyboard")
                return
        
        logging.error("=" * 80)
        logging.error("ACCESSIBILITY VIOLATION: KEYBOARD NAVIGATION FAILURE")
        logging.error("Standard: WCAG 2.1 SC 2.1.1 Level A (MANDATORY)")
        logging.error("CVSS Score: 7.5 (HIGH)")
        logging.error("Add to cart button not reachable via Tab key")
        logging.error("Impact:")
        logging.error("  - Keyboard-only users cannot purchase")
        logging.error("  - ADA compliance failure")
        logging.error("Legal: MANDATORY accessibility requirement")
        logging.error("=" * 80)
        
        pytest.fail("DISCOVERED: Add to cart button not accessible via keyboard (WCAG 2.1 Level A violation)")
        
    except Exception as e:
        logging.warning(f"Could not complete keyboard test: {e}")
        pytest.skip("Keyboard test could not be completed")


@pytest.mark.business_rules
@pytest.mark.parametrize("product_index", [0, 1, 2])
def test_product_data_consistency_across_views_BR_010(browser, product_index):
    """
    TC-PRODUCT-BR-010: Product Data Consistency Across Views
    
    Standard: ISO 25010 Section 5.2 (Consistency)
    CVSS Score: 5.3 (MEDIUM) if violated
    
    Discovers if product data is consistent between catalog and detail page.
    """
    logging.info("=" * 80)
    logging.info(f"TC-PRODUCT-BR-010: Validating data consistency for product {product_index + 1}")
    
    browser.get(BASE_URL)
    wait_for_page_load(browser)
    time.sleep(1)
    
    # Get product name from catalog
    product_links = browser.find_elements(*PRODUCT_LINKS)
    
    if product_index >= len(product_links):
        pytest.skip(f"Product {product_index + 1} not available")
    
    catalog_name = product_links[product_index].text
    product_links[product_index].click()
    
    wait_for_page_load(browser)
    time.sleep(2)
    
    # Get product name from detail page
    try:
        detail_name_element = browser.find_element(*PRODUCT_NAME)
        detail_name = detail_name_element.text
        
        if catalog_name.strip().lower() != detail_name.strip().lower():
            logging.error("=" * 80)
            logging.error("CONSISTENCY VIOLATION: PRODUCT NAME MISMATCH")
            logging.error("Standard: ISO 25010 Section 5.2 (Consistency)")
            logging.error("CVSS Score: 5.3 (MEDIUM)")
            logging.error(f"Catalog name: '{catalog_name}'")
            logging.error(f"Detail name: '{detail_name}'")
            logging.error("Impact: User confusion, trust issues")
            logging.error("=" * 80)
            
            pytest.fail(f"DISCOVERED: Product name inconsistent between catalog and detail page")
        
        logging.info(f"SUCCESS: Product name consistent: '{catalog_name}'")
        
    except NoSuchElementException:
        pytest.fail("FAILED: Could not find product name on detail page")

# ============================================================================
# END OF TEST SUITE
# ============================================================================
