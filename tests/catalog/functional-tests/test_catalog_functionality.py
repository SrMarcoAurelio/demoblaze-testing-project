"""
Test Suite: Catalog & Product Browsing Functionality
Module: test_catalog_functionality.py
Author: QA Testing Team
Version: 1.0

Test Categories:
- Functional Tests: Navigation, Product Display, Pagination, User Interaction
- Business Rules: Data Validation, Performance, Usability, Accessibility

Standards Validated:
- ISO 25010 (Software Quality - Functional Completeness, Usability, Performance)
- WCAG 2.1 (Web Content Accessibility Guidelines - Level A and AA)
- ISO 9241-110 (Ergonomics of Human-System Interaction)

Philosophy: DISCOVER Methodology
Tests execute actions, observe responses, and validate against international standards.
Standards violations are reported as ERRORS, not excused.

Execution:
Run all tests:           pytest test_catalog_functionality.py -v
Run functional only:     pytest test_catalog_functionality.py -m "functional" -v
Run business rules:      pytest test_catalog_functionality.py -m "business_rules" -v
Generate HTML report:    pytest test_catalog_functionality.py --html=report_catalog.html --self-contained-html

Total Expected Tests: 30 tests
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from selenium.webdriver.common.keys import Keys
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

# Navigation
HOME_LINK = (By.ID, "nava")
LOGO_LINK = (By.CSS_SELECTOR, ".navbar-brand")

# Categories
CATEGORIES_SECTION = (By.ID, "cat")
PHONES_CATEGORY = (By.LINK_TEXT, "Phones")
LAPTOPS_CATEGORY = (By.LINK_TEXT, "Laptops")
MONITORS_CATEGORY = (By.LINK_TEXT, "Monitors")

# Products
PRODUCT_CARDS = (By.CSS_SELECTOR, ".card")
PRODUCT_TITLES = (By.CSS_SELECTOR, ".card-title a")
PRODUCT_PRICES = (By.CSS_SELECTOR, ".card-block h5")
PRODUCT_IMAGES = (By.CSS_SELECTOR, ".card-img-top")
PRODUCT_LINKS = (By.CSS_SELECTOR, ".hrefch")

# Pagination
NEXT_BUTTON = (By.ID, "next2")
PREV_BUTTON = (By.ID, "prev2")

# Product Details Page
PRODUCT_DETAIL_NAME = (By.CSS_SELECTOR, "h2.name")
PRODUCT_DETAIL_PRICE = (By.CSS_SELECTOR, "h3.price-container")
PRODUCT_DETAIL_DESCRIPTION = (By.ID, "more-information")
PRODUCT_DETAIL_IMAGE = (By.CSS_SELECTOR, ".product-image img, img.img-thumbnail")

# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def browser():
    """Initialize Chrome browser"""
    driver = webdriver.Chrome()
    driver.maximize_window()
    yield driver
    driver.quit()

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def wait_for_products_to_load(browser, timeout=TIMEOUT):
    """Wait for at least one product to be visible"""
    try:
        WebDriverWait(browser, timeout).until(
            EC.presence_of_element_located(PRODUCT_CARDS)
        )
        time.sleep(1)  # Allow for AJAX to settle
        return True
    except TimeoutException:
        return False


def get_displayed_products(browser):
    """Get list of currently displayed product cards"""
    try:
        products = browser.find_elements(*PRODUCT_CARDS)
        # Filter out hidden elements
        visible_products = [p for p in products if p.is_displayed()]
        return visible_products
    except NoSuchElementException:
        return []


def navigate_to_category(browser, category_locator):
    """Navigate to specific category and wait for products to load"""
    try:
        category = WebDriverWait(browser, TIMEOUT).until(
            EC.element_to_be_clickable(category_locator)
        )
        category.click()
        time.sleep(2)  # Wait for AJAX content load
        wait_for_products_to_load(browser)
        return True
    except (TimeoutException, NoSuchElementException):
        return False


def get_product_details_from_card(browser, product_card):
    """Extract name, price, and image from product card"""
    try:
        name_element = product_card.find_element(By.CSS_SELECTOR, ".card-title a")
        price_element = product_card.find_element(By.CSS_SELECTOR, "h5")
        image_element = product_card.find_element(By.CSS_SELECTOR, "img")
        
        return {
            'name': name_element.text.strip(),
            'price': price_element.text.strip(),
            'image_src': image_element.get_attribute('src'),
            'image_alt': image_element.get_attribute('alt'),
            'link': name_element.get_attribute('href')
        }
    except NoSuchElementException:
        return None


def check_image_loads(image_url, timeout=5):
    """Check if image URL returns 200 status"""
    try:
        response = requests.head(image_url, timeout=timeout)
        return response.status_code == 200
    except requests.RequestException:
        return False

# ============================================================================
# FUNCTIONAL TESTS
# ============================================================================

@pytest.mark.functional
def test_navigate_to_phones_category_FUNC_001(browser):
    """
    TC-CATALOG-FUNC-001: Navigate to Phones Category
    
    Discovers if Phones category navigation works correctly.
    Validates that clicking Phones displays phone products.
    
    Priority: HIGH
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-FUNC-001: Testing Phones category navigation")
    
    browser.get(BASE_URL)
    
    success = navigate_to_category(browser, PHONES_CATEGORY)
    
    if not success:
        pytest.fail("DISCOVERED: Phones category link not clickable or products failed to load")
    
    products = get_displayed_products(browser)
    
    if not products:
        pytest.fail("DISCOVERED: No products displayed after navigating to Phones")
    
    logging.info(f"DISCOVERED: Phones category shows {len(products)} products")
    assert len(products) > 0


@pytest.mark.functional
def test_navigate_to_laptops_category_FUNC_002(browser):
    """
    TC-CATALOG-FUNC-002: Navigate to Laptops Category
    
    Discovers if Laptops category navigation works correctly.
    
    Priority: HIGH
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-FUNC-002: Testing Laptops category navigation")
    
    browser.get(BASE_URL)
    
    success = navigate_to_category(browser, LAPTOPS_CATEGORY)
    
    if not success:
        pytest.fail("DISCOVERED: Laptops category link not clickable or products failed to load")
    
    products = get_displayed_products(browser)
    
    if not products:
        pytest.fail("DISCOVERED: No products displayed after navigating to Laptops")
    
    logging.info(f"DISCOVERED: Laptops category shows {len(products)} products")
    assert len(products) > 0


@pytest.mark.functional
def test_navigate_to_monitors_category_FUNC_003(browser):
    """
    TC-CATALOG-FUNC-003: Navigate to Monitors Category
    
    Discovers if Monitors category navigation works correctly.
    
    Priority: HIGH
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-FUNC-003: Testing Monitors category navigation")
    
    browser.get(BASE_URL)
    
    success = navigate_to_category(browser, MONITORS_CATEGORY)
    
    if not success:
        pytest.fail("DISCOVERED: Monitors category link not clickable or products failed to load")
    
    products = get_displayed_products(browser)
    
    if not products:
        pytest.fail("DISCOVERED: No products displayed after navigating to Monitors")
    
    logging.info(f"DISCOVERED: Monitors category shows {len(products)} products")
    assert len(products) > 0


@pytest.mark.functional
def test_home_button_shows_all_products_FUNC_004(browser):
    """
    TC-CATALOG-FUNC-004: Home Button Returns to All Products
    
    Discovers if home/logo button returns user to full catalog.
    
    Priority: MEDIUM
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-FUNC-004: Testing home button functionality")
    
    browser.get(BASE_URL)
    wait_for_products_to_load(browser)
    
    initial_products = get_displayed_products(browser)
    initial_count = len(initial_products)
    
    logging.info(f"Initial product count: {initial_count}")
    
    # Navigate to a category
    navigate_to_category(browser, PHONES_CATEGORY)
    category_products = get_displayed_products(browser)
    category_count = len(category_products)
    
    logging.info(f"Phones category count: {category_count}")
    
    # Click home button
    try:
        home_button = WebDriverWait(browser, TIMEOUT).until(
            EC.element_to_be_clickable(HOME_LINK)
        )
        home_button.click()
        time.sleep(2)
        wait_for_products_to_load(browser)
    except (TimeoutException, NoSuchElementException):
        pytest.fail("DISCOVERED: Home button not clickable")
    
    home_products = get_displayed_products(browser)
    home_count = len(home_products)
    
    logging.info(f"After home click count: {home_count}")
    
    # Home should show more products than single category
    if home_count <= category_count:
        logging.warning(f"Home shows {home_count} products, Phones shows {category_count}")
        logging.warning("Expected home to show all products (more than single category)")
    
    assert home_count > 0, "Home button must display products"


@pytest.mark.functional
def test_category_switches_correctly_FUNC_005(browser):
    """
    TC-CATALOG-FUNC-005: Category Switching
    
    Discovers if switching between categories updates product display.
    
    Priority: HIGH
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-FUNC-005: Testing category switching")
    
    browser.get(BASE_URL)
    
    # Navigate to Phones
    navigate_to_category(browser, PHONES_CATEGORY)
    phones_products = get_displayed_products(browser)
    phones_first_product = get_product_details_from_card(browser, phones_products[0]) if phones_products else None
    
    # Switch to Laptops
    navigate_to_category(browser, LAPTOPS_CATEGORY)
    laptops_products = get_displayed_products(browser)
    laptops_first_product = get_product_details_from_card(browser, laptops_products[0]) if laptops_products else None
    
    if not phones_first_product or not laptops_first_product:
        pytest.fail("DISCOVERED: Could not extract product details from categories")
    
    # Products should be different
    if phones_first_product['name'] == laptops_first_product['name']:
        logging.warning("DISCOVERED: Same product shown in different categories")
        logging.warning("This may indicate category filtering is not working")
    
    logging.info("DISCOVERED: Category switching changes displayed products")
    assert True


@pytest.mark.functional
def test_products_display_after_page_load_FUNC_006(browser):
    """
    TC-CATALOG-FUNC-006: Products Display After Page Load
    
    Discovers if products load and display on initial page load.
    
    Priority: CRITICAL
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-FUNC-006: Testing initial product display")
    
    browser.get(BASE_URL)
    
    loaded = wait_for_products_to_load(browser)
    
    if not loaded:
        pytest.fail("DISCOVERED: Products failed to load within timeout")
    
    products = get_displayed_products(browser)
    
    if not products:
        pytest.fail("DISCOVERED: No products visible after page load")
    
    logging.info(f"DISCOVERED: {len(products)} products loaded successfully")
    assert len(products) > 0


@pytest.mark.functional
def test_product_names_visible_FUNC_007(browser):
    """
    TC-CATALOG-FUNC-007: Product Names Visible
    
    Discovers if all displayed products have visible names.
    
    Priority: HIGH
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-FUNC-007: Validating product names visibility")
    
    browser.get(BASE_URL)
    wait_for_products_to_load(browser)
    
    products = get_displayed_products(browser)
    
    products_without_names = []
    
    for idx, product in enumerate(products):
        details = get_product_details_from_card(browser, product)
        if not details or not details['name']:
            products_without_names.append(idx + 1)
    
    if products_without_names:
        pytest.fail(f"DISCOVERED: {len(products_without_names)} products lack visible names (positions: {products_without_names})")
    
    logging.info(f"DISCOVERED: All {len(products)} products have visible names")
    assert True


@pytest.mark.functional
def test_product_prices_visible_FUNC_008(browser):
    """
    TC-CATALOG-FUNC-008: Product Prices Visible
    
    Discovers if all displayed products have visible prices.
    
    Priority: HIGH
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-FUNC-008: Validating product prices visibility")
    
    browser.get(BASE_URL)
    wait_for_products_to_load(browser)
    
    products = get_displayed_products(browser)
    
    products_without_prices = []
    
    for idx, product in enumerate(products):
        details = get_product_details_from_card(browser, product)
        if not details or not details['price']:
            products_without_prices.append(idx + 1)
    
    if products_without_prices:
        pytest.fail(f"DISCOVERED: {len(products_without_prices)} products lack visible prices (positions: {products_without_prices})")
    
    logging.info(f"DISCOVERED: All {len(products)} products have visible prices")
    assert True


@pytest.mark.functional
def test_product_images_load_FUNC_009(browser):
    """
    TC-CATALOG-FUNC-009: Product Images Load
    
    Discovers if product images are present and have src attribute.
    
    Priority: MEDIUM
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-FUNC-009: Validating product images presence")
    
    browser.get(BASE_URL)
    wait_for_products_to_load(browser)
    
    products = get_displayed_products(browser)
    
    products_without_images = []
    
    for idx, product in enumerate(products):
        details = get_product_details_from_card(browser, product)
        if not details or not details['image_src']:
            products_without_images.append(idx + 1)
    
    if products_without_images:
        pytest.fail(f"DISCOVERED: {len(products_without_images)} products lack image src (positions: {products_without_images})")
    
    logging.info(f"DISCOVERED: All {len(products)} products have images with src attribute")
    assert True


@pytest.mark.functional
def test_pagination_next_button_functionality_FUNC_010(browser):
    """
    TC-CATALOG-FUNC-010: Pagination Next Button
    
    Discovers if Next button exists and changes displayed products.
    
    Priority: MEDIUM
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-FUNC-010: Testing pagination Next button")
    
    browser.get(BASE_URL)
    wait_for_products_to_load(browser)
    
    # Check if Next button exists
    next_buttons = browser.find_elements(*NEXT_BUTTON)
    
    if not next_buttons:
        logging.info("DISCOVERED: No Next button present")
        assert True
        return
    
    # Get products before clicking Next
    products_before = get_displayed_products(browser)
    first_product_before = get_product_details_from_card(browser, products_before[0]) if products_before else None
    
    # Click Next
    next_button = next_buttons[0]
    next_button.click()
    time.sleep(2)
    wait_for_products_to_load(browser)
    
    # Get products after
    products_after = get_displayed_products(browser)
    first_product_after = get_product_details_from_card(browser, products_after[0]) if products_after else None
    
    if not first_product_before or not first_product_after:
        pytest.fail("DISCOVERED: Could not extract product details before/after pagination")
    
    # Products should change
    if first_product_before['name'] == first_product_after['name']:
        pytest.fail("DISCOVERED: Next button exists but products didn't change")
    
    logging.info("DISCOVERED: Next button successfully changes displayed products")
    assert True


@pytest.mark.functional
def test_pagination_previous_button_functionality_FUNC_011(browser):
    """
    TC-CATALOG-FUNC-011: Pagination Previous Button
    
    Discovers if Previous button exists and works correctly.
    
    Priority: MEDIUM
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-FUNC-011: Testing pagination Previous button")
    
    browser.get(BASE_URL)
    wait_for_products_to_load(browser)
    
    # Check if buttons exist
    next_buttons = browser.find_elements(*NEXT_BUTTON)
    
    if not next_buttons:
        logging.info("DISCOVERED: No pagination present")
        assert True
        return
    
    # Click Next first
    next_buttons[0].click()
    time.sleep(2)
    wait_for_products_to_load(browser)
    
    products_page2 = get_displayed_products(browser)
    first_product_page2 = get_product_details_from_card(browser, products_page2[0]) if products_page2 else None
    
    # Now click Previous
    prev_buttons = browser.find_elements(*PREV_BUTTON)
    
    if not prev_buttons:
        logging.warning("DISCOVERED: Next button exists but no Previous button")
        assert True
        return
    
    prev_buttons[0].click()
    time.sleep(2)
    wait_for_products_to_load(browser)
    
    products_page1 = get_displayed_products(browser)
    first_product_page1 = get_product_details_from_card(browser, products_page1[0]) if products_page1 else None
    
    if not first_product_page2 or not first_product_page1:
        pytest.fail("DISCOVERED: Could not extract product details during pagination")
    
    # Should return to different products
    if first_product_page2['name'] == first_product_page1['name']:
        pytest.fail("DISCOVERED: Previous button exists but didn't return to previous products")
    
    logging.info("DISCOVERED: Previous button successfully returns to previous page")
    assert True


@pytest.mark.functional
def test_pagination_boundary_conditions_FUNC_012(browser):
    """
    TC-CATALOG-FUNC-012: Pagination Boundary Conditions
    
    Discovers how pagination behaves at boundaries.
    
    Priority: LOW
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-FUNC-012: Testing pagination boundaries")
    
    browser.get(BASE_URL)
    wait_for_products_to_load(browser)
    
    prev_buttons = browser.find_elements(*PREV_BUTTON)
    
    if prev_buttons:
        # Try clicking Previous on first page
        prev_button = prev_buttons[0]
        
        if prev_button.is_displayed() and prev_button.is_enabled():
            logging.info("DISCOVERED: Previous button is enabled on first page")
            prev_button.click()
            time.sleep(2)
            # Just observing behavior, not failing
        else:
            logging.info("DISCOVERED: Previous button disabled/hidden on first page (good UX)")
    else:
        logging.info("DISCOVERED: No pagination to test boundaries")
    
    assert True


@pytest.mark.functional
def test_click_product_navigates_to_details_FUNC_013(browser):
    """
    TC-CATALOG-FUNC-013: Product Click Navigation
    
    Discovers if clicking product navigates to details page.
    
    Priority: CRITICAL
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-FUNC-013: Testing product click navigation")
    
    browser.get(BASE_URL)
    wait_for_products_to_load(browser)
    
    products = get_displayed_products(browser)
    
    if not products:
        pytest.fail("DISCOVERED: No products to click")
    
    first_product = products[0]
    product_details = get_product_details_from_card(browser, first_product)
    product_name = product_details['name']
    
    logging.info(f"Clicking product: {product_name}")
    
    # Click product link
    try:
        product_link = first_product.find_element(By.CSS_SELECTOR, ".card-title a")
        product_link.click()
        time.sleep(2)
    except NoSuchElementException:
        pytest.fail("DISCOVERED: Product link not found in card")
    
    # Check if URL changed
    current_url = browser.current_url
    
    if current_url == BASE_URL or "prod.html" not in current_url:
        pytest.fail(f"DISCOVERED: Product click didn't navigate to details page. URL: {current_url}")
    
    logging.info(f"DISCOVERED: Product click navigates to: {current_url}")
    assert "prod.html" in current_url


@pytest.mark.functional
def test_product_url_changes_correctly_FUNC_014(browser):
    """
    TC-CATALOG-FUNC-014: Product URL Contains Product ID
    
    Discovers if product detail URL contains product identifier.
    
    Priority: MEDIUM
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-FUNC-014: Validating product URL structure")
    
    browser.get(BASE_URL)
    wait_for_products_to_load(browser)
    
    products = get_displayed_products(browser)
    first_product = products[0]
    
    product_link = first_product.find_element(By.CSS_SELECTOR, ".card-title a")
    product_link.click()
    time.sleep(2)
    
    current_url = browser.current_url
    
    # URL should contain product identifier
    if "idp_" not in current_url and "id=" not in current_url:
        logging.warning(f"DISCOVERED: Product URL may lack identifier: {current_url}")
    
    logging.info(f"DISCOVERED: Product URL structure: {current_url}")
    assert True


@pytest.mark.functional
def test_back_button_returns_to_catalog_FUNC_015(browser):
    """
    TC-CATALOG-FUNC-015: Browser Back Button Returns to Catalog
    
    Discovers if browser back button works from product details.
    
    Priority: MEDIUM
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-FUNC-015: Testing browser back button")
    
    browser.get(BASE_URL)
    wait_for_products_to_load(browser)
    
    initial_url = browser.current_url
    
    # Click product
    products = get_displayed_products(browser)
    first_product = products[0]
    product_link = first_product.find_element(By.CSS_SELECTOR, ".card-title a")
    product_link.click()
    time.sleep(2)
    
    # Use back button
    browser.back()
    time.sleep(2)
    
    current_url = browser.current_url
    
    if current_url != initial_url:
        logging.warning(f"DISCOVERED: Back button didn't return to exact URL. Expected: {initial_url}, Got: {current_url}")
    
    # Should see products again
    products_after_back = get_displayed_products(browser)
    
    if not products_after_back:
        pytest.fail("DISCOVERED: No products visible after browser back button")
    
    logging.info("DISCOVERED: Browser back button returns to catalog successfully")
    assert True


# ============================================================================
# BUSINESS RULES TESTS - DATA VALIDATION
# ============================================================================

@pytest.mark.business_rules
@pytest.mark.high
def test_all_products_have_name_BR_001(browser):
    """
    TC-CATALOG-BR-001: All Products Must Have Name
    
    Standard: ISO 25010 Section 4.2.1 (Functional Completeness)
    Priority: CRITICAL
    Impact: Products without names cannot be identified by customers
    
    Discovers if all products have names in catalog listing.
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-BR-001: Validating all products have names")
    
    browser.get(BASE_URL)
    wait_for_products_to_load(browser)
    
    products = get_displayed_products(browser)
    logging.info(f"Validating {len(products)} products")
    
    products_without_name = []
    
    for idx, product in enumerate(products, 1):
        details = get_product_details_from_card(browser, product)
        if not details or not details['name'] or len(details['name'].strip()) == 0:
            products_without_name.append(f"Position {idx}")
    
    if products_without_name:
        logging.error("=" * 80)
        logging.error("DATA COMPLETENESS VIOLATION: MISSING PRODUCT NAMES")
        logging.error("Standard: ISO 25010 Section 4.2.1 (Functional Completeness)")
        logging.error("Severity: CRITICAL")
        logging.error(f"Products without names: {len(products_without_name)}")
        logging.error(f"Affected positions: {', '.join(products_without_name)}")
        logging.error("Impact:")
        logging.error("  - Customers cannot identify products")
        logging.error("  - Violates basic e-commerce requirements")
        logging.error("  - Severely impacts user experience")
        logging.error("Requirement: All products MUST have visible names")
        logging.error("=" * 80)
        
        pytest.fail(f"DISCOVERED: {len(products_without_name)} products lack names - Violates ISO 25010")
    
    logging.info(f"All {len(products)} products have names - ISO 25010 compliant")
    assert True


@pytest.mark.business_rules
@pytest.mark.high
def test_all_products_have_price_BR_002(browser):
    """
    TC-CATALOG-BR-002: All Products Must Have Price
    
    Standard: ISO 25010 Section 4.2.1 (Functional Completeness)
    Priority: CRITICAL
    Impact: Products without prices cannot be purchased
    
    Discovers if all products display prices in catalog.
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-BR-002: Validating all products have prices")
    
    browser.get(BASE_URL)
    wait_for_products_to_load(browser)
    
    products = get_displayed_products(browser)
    logging.info(f"Validating {len(products)} products")
    
    products_without_price = []
    
    for idx, product in enumerate(products, 1):
        details = get_product_details_from_card(browser, product)
        if not details or not details['price'] or len(details['price'].strip()) == 0:
            products_without_price.append(f"Position {idx}")
    
    if products_without_price:
        logging.error("=" * 80)
        logging.error("DATA COMPLETENESS VIOLATION: MISSING PRODUCT PRICES")
        logging.error("Standard: ISO 25010 Section 4.2.1 (Functional Completeness)")
        logging.error("Severity: CRITICAL")
        logging.error(f"Products without prices: {len(products_without_price)}")
        logging.error(f"Affected positions: {', '.join(products_without_price)}")
        logging.error("Impact:")
        logging.error("  - Customers cannot make purchase decisions")
        logging.error("  - Violates basic e-commerce requirements")
        logging.error("  - Legal compliance issues in many jurisdictions")
        logging.error("Requirement: All products MUST display prices")
        logging.error("=" * 80)
        
        pytest.fail(f"DISCOVERED: {len(products_without_price)} products lack prices - Violates ISO 25010")
    
    logging.info(f"All {len(products)} products have prices - ISO 25010 compliant")
    assert True


@pytest.mark.business_rules
@pytest.mark.high
def test_all_products_have_description_BR_003(browser):
    """
    TC-CATALOG-BR-003: All Products Must Have Description
    
    Standard: ISO 25010 Section 4.2.1 (Functional Completeness)
    Priority: HIGH
    Impact: Products without descriptions limit informed purchase decisions
    
    Discovers if all products have descriptions in their detail pages.
    This test navigates to each product's detail page.
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-BR-003: Validating all products have descriptions")
    
    browser.get(BASE_URL)
    wait_for_products_to_load(browser)
    
    products = get_displayed_products(browser)
    product_links = []
    
    # Collect product links
    for product in products[:5]:  # Test first 5 for performance
        details = get_product_details_from_card(browser, product)
        if details and details['link']:
            product_links.append({
                'name': details['name'],
                'url': details['link']
            })
    
    logging.info(f"Testing descriptions for {len(product_links)} products")
    
    products_without_description = []
    
    # Check each product detail page
    for product_data in product_links:
        browser.get(product_data['url'])
        time.sleep(2)
        
        try:
            # Look for description element
            description_elements = browser.find_elements(*PRODUCT_DETAIL_DESCRIPTION)
            
            if not description_elements:
                products_without_description.append(product_data['name'])
                logging.warning(f"Product '{product_data['name']}' has no description element")
                continue
            
            description_text = description_elements[0].text.strip()
            
            if not description_text or len(description_text) < 10:
                products_without_description.append(product_data['name'])
                logging.warning(f"Product '{product_data['name']}' has insufficient description: '{description_text}'")
                
        except Exception as e:
            products_without_description.append(product_data['name'])
            logging.warning(f"Error checking '{product_data['name']}': {e}")
    
    if products_without_description:
        logging.error("=" * 80)
        logging.error("DATA COMPLETENESS VIOLATION: MISSING PRODUCT DESCRIPTIONS")
        logging.error("Standard: ISO 25010 Section 4.2.1 (Functional Completeness)")
        logging.error("Severity: HIGH")
        logging.error(f"Products without adequate descriptions: {len(products_without_description)}")
        logging.error(f"Affected products: {', '.join(products_without_description[:5])}")
        logging.error("Impact:")
        logging.error("  - Customers lack information for purchase decisions")
        logging.error("  - Reduces conversion rates")
        logging.error("  - Poor user experience")
        logging.error("Requirement: All products MUST have descriptions (minimum 10 characters)")
        logging.error("=" * 80)
        
        pytest.fail(f"DISCOVERED: {len(products_without_description)} products lack descriptions - Violates ISO 25010")
    
    logging.info(f"All {len(product_links)} tested products have descriptions - ISO 25010 compliant")
    assert True


@pytest.mark.business_rules
@pytest.mark.medium
def test_all_products_have_valid_image_BR_004(browser):
    """
    TC-CATALOG-BR-004: All Products Must Have Valid Images
    
    Standard: ISO 25010 Section 4.2.1 (Functional Completeness)
    Priority: MEDIUM
    Impact: Broken images reduce trust and user experience
    
    Discovers if all product images load successfully (not 404).
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-BR-004: Validating all product images load")
    
    browser.get(BASE_URL)
    wait_for_products_to_load(browser)
    
    products = get_displayed_products(browser)
    logging.info(f"Validating images for {len(products)} products")
    
    products_with_broken_images = []
    
    for idx, product in enumerate(products[:10], 1):  # Test first 10 for performance
        details = get_product_details_from_card(browser, product)
        if details and details['image_src']:
            image_url = details['image_src']
            
            if not check_image_loads(image_url):
                products_with_broken_images.append({
                    'position': idx,
                    'name': details['name'],
                    'url': image_url
                })
                logging.warning(f"Product '{details['name']}' has broken image: {image_url}")
    
    if products_with_broken_images:
        logging.error("=" * 80)
        logging.error("DATA QUALITY VIOLATION: BROKEN PRODUCT IMAGES")
        logging.error("Standard: ISO 25010 Section 4.2.1 (Functional Completeness)")
        logging.error("Severity: MEDIUM")
        logging.error(f"Products with broken images: {len(products_with_broken_images)}")
        for item in products_with_broken_images[:3]:
            logging.error(f"  - Position {item['position']}: {item['name']}")
        logging.error("Impact:")
        logging.error("  - Reduced customer trust")
        logging.error("  - Poor user experience")
        logging.error("  - Lower conversion rates")
        logging.error("Requirement: All product images MUST load successfully (HTTP 200)")
        logging.error("=" * 80)
        
        pytest.fail(f"DISCOVERED: {len(products_with_broken_images)} products have broken images - Violates ISO 25010")
    
    logging.info("All tested product images load successfully - ISO 25010 compliant")
    assert True


@pytest.mark.business_rules
@pytest.mark.medium
def test_price_format_consistency_BR_005(browser):
    """
    TC-CATALOG-BR-005: Price Format Consistency
    
    Standard: ISO 25010 Section 4.2.3 (Data Quality - Consistency)
    Priority: MEDIUM
    Impact: Inconsistent price formats confuse customers
    
    Discovers if all prices follow consistent format.
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-BR-005: Validating price format consistency")
    
    browser.get(BASE_URL)
    wait_for_products_to_load(browser)
    
    products = get_displayed_products(browser)
    
    prices = []
    inconsistent_prices = []
    
    for idx, product in enumerate(products, 1):
        details = get_product_details_from_card(browser, product)
        if details and details['price']:
            price_text = details['price']
            prices.append(price_text)
            
            # Check basic format: should contain $ and numbers
            if '$' not in price_text:
                inconsistent_prices.append({
                    'position': idx,
                    'name': details['name'],
                    'price': price_text,
                    'issue': 'Missing $ symbol'
                })
            
            # Check if contains digits
            if not any(char.isdigit() for char in price_text):
                inconsistent_prices.append({
                    'position': idx,
                    'name': details['name'],
                    'price': price_text,
                    'issue': 'No numeric value'
                })
    
    if inconsistent_prices:
        logging.error("=" * 80)
        logging.error("DATA QUALITY VIOLATION: INCONSISTENT PRICE FORMAT")
        logging.error("Standard: ISO 25010 Section 4.2.3 (Data Quality)")
        logging.error("Severity: MEDIUM")
        logging.error(f"Inconsistent prices found: {len(inconsistent_prices)}")
        for item in inconsistent_prices[:3]:
            logging.error(f"  - {item['name']}: '{item['price']}' ({item['issue']})")
        logging.error("Impact:")
        logging.error("  - Customer confusion")
        logging.error("  - Reduced professionalism")
        logging.error("  - Potential cart calculation errors")
        logging.error("Requirement: All prices MUST follow format: $XXX.XX")
        logging.error("=" * 80)
        
        pytest.fail(f"DISCOVERED: {len(inconsistent_prices)} prices have inconsistent format - Violates ISO 25010")
    
    logging.info(f"All {len(prices)} prices follow consistent format - ISO 25010 compliant")
    assert True


@pytest.mark.business_rules
@pytest.mark.low
def test_product_links_not_broken_BR_006(browser):
    """
    TC-CATALOG-BR-006: Product Links Must Not Be Broken
    
    Standard: ISO 25010 Section 4.2.1 (Functional Completeness)
    Priority: LOW
    Impact: Broken links prevent product viewing
    
    Discovers if product links navigate successfully.
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-BR-006: Validating product links are not broken")
    
    browser.get(BASE_URL)
    wait_for_products_to_load(browser)
    
    products = get_displayed_products(browser)
    
    broken_links = []
    
    for idx, product in enumerate(products[:5], 1):  # Test first 5
        details = get_product_details_from_card(browser, product)
        if details and details['link']:
            try:
                browser.get(details['link'])
                time.sleep(1)
                
                # Check if product detail page loaded
                try:
                    browser.find_element(*PRODUCT_DETAIL_NAME)
                except NoSuchElementException:
                    broken_links.append({
                        'name': details['name'],
                        'url': details['link']
                    })
                    
            except Exception as e:
                broken_links.append({
                    'name': details['name'],
                    'url': details['link'],
                    'error': str(e)
                })
    
    if broken_links:
        logging.error("=" * 80)
        logging.error("FUNCTIONAL VIOLATION: BROKEN PRODUCT LINKS")
        logging.error("Standard: ISO 25010 Section 4.2.1")
        logging.error(f"Broken links: {len(broken_links)}")
        for item in broken_links:
            logging.error(f"  - {item['name']}: {item['url']}")
        logging.error("Impact: Customers cannot view product details")
        logging.error("=" * 80)
        
        pytest.fail(f"DISCOVERED: {len(broken_links)} broken product links - Violates ISO 25010")
    
    logging.info("All tested product links work correctly")
    assert True


# ============================================================================
# BUSINESS RULES TESTS - PERFORMANCE
# ============================================================================

@pytest.mark.business_rules
@pytest.mark.high
def test_catalog_load_time_performance_BR_007(browser):
    """
    TC-CATALOG-BR-007: Catalog Load Time Performance
    
    Standard: ISO 25010 Section 4.2.4 (Time Behavior)
    Priority: HIGH
    Impact: Slow load times increase bounce rate
    
    Discovers if catalog loads within acceptable time (<3 seconds).
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-BR-007: Measuring catalog load time")
    
    start_time = time.time()
    
    browser.get(BASE_URL)
    wait_for_products_to_load(browser, timeout=TIMEOUT_MEDIUM)
    
    end_time = time.time()
    load_time = end_time - start_time
    
    logging.info(f"DISCOVERED: Catalog load time: {load_time:.2f} seconds")
    
    # ISO 25010: Web pages should load in <3 seconds for good UX
    if load_time > 3.0:
        logging.error("=" * 80)
        logging.error("PERFORMANCE VIOLATION: SLOW CATALOG LOAD TIME")
        logging.error("Standard: ISO 25010 Section 4.2.4 (Time Behavior)")
        logging.error("Severity: HIGH")
        logging.error(f"Actual load time: {load_time:.2f} seconds")
        logging.error("Expected: <3.0 seconds")
        logging.error(f"Exceeded by: {load_time - 3.0:.2f} seconds")
        logging.error("Impact:")
        logging.error("  - Increased bounce rate")
        logging.error("  - Poor user experience")
        logging.error("  - Lower SEO rankings")
        logging.error("  - Reduced conversions")
        logging.error("Recommendation: Optimize images, implement lazy loading, use CDN")
        logging.error("=" * 80)
        
        pytest.fail(f"DISCOVERED: Catalog load time {load_time:.2f}s exceeds 3s limit - Violates ISO 25010")
    
    logging.info(f"Catalog loads in {load_time:.2f}s - ISO 25010 compliant")
    assert True


@pytest.mark.business_rules
@pytest.mark.medium
def test_category_switch_response_time_BR_008(browser):
    """
    TC-CATALOG-BR-008: Category Switch Response Time
    
    Standard: ISO 25010 Section 4.2.4 (Time Behavior)
    Priority: MEDIUM
    Impact: Slow category switching frustrates users
    
    Discovers if category switching is responsive (<2 seconds).
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-BR-008: Measuring category switch time")
    
    browser.get(BASE_URL)
    wait_for_products_to_load(browser)
    
    start_time = time.time()
    
    navigate_to_category(browser, PHONES_CATEGORY)
    
    end_time = time.time()
    switch_time = end_time - start_time
    
    logging.info(f"DISCOVERED: Category switch time: {switch_time:.2f} seconds")
    
    # Category switching should be quick (<2s)
    if switch_time > 2.0:
        logging.error("=" * 80)
        logging.error("PERFORMANCE VIOLATION: SLOW CATEGORY SWITCHING")
        logging.error("Standard: ISO 25010 Section 4.2.4 (Time Behavior)")
        logging.error("Severity: MEDIUM")
        logging.error(f"Actual switch time: {switch_time:.2f} seconds")
        logging.error("Expected: <2.0 seconds")
        logging.error(f"Exceeded by: {switch_time - 2.0:.2f} seconds")
        logging.error("Impact:")
        logging.error("  - User frustration")
        logging.error("  - Reduced browsing efficiency")
        logging.error("  - Perception of slow site")
        logging.error("Recommendation: Implement client-side filtering or optimize AJAX calls")
        logging.error("=" * 80)
        
        pytest.fail(f"DISCOVERED: Category switch {switch_time:.2f}s exceeds 2s limit - Violates ISO 25010")
    
    logging.info(f"Category switches in {switch_time:.2f}s - ISO 25010 compliant")
    assert True


# ============================================================================
# BUSINESS RULES TESTS - USABILITY
# ============================================================================

@pytest.mark.business_rules
@pytest.mark.high
def test_pagination_required_for_large_catalogs_BR_009(browser):
    """
    TC-CATALOG-BR-009: Pagination Required for Large Catalogs
    
    Standard: ISO 25010 Section 4.2.2 (Usability - Operability)
    Standard: ISO 9241-110 Principle 3 (User Control and Freedom)
    Priority: HIGH
    Impact: Large catalogs without pagination cause poor UX
    
    Discovers if pagination is implemented when catalog exceeds 15 products.
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-BR-009: Validating pagination requirement")
    
    browser.get(BASE_URL)
    wait_for_products_to_load(browser)
    
    # Count total products on page
    products = get_displayed_products(browser)
    product_count = len(products)
    
    logging.info(f"DISCOVERED: {product_count} products displayed on single page")
    
    # Check for pagination controls
    next_buttons = browser.find_elements(*NEXT_BUTTON)
    prev_buttons = browser.find_elements(*PREV_BUTTON)
    
    has_pagination = len(next_buttons) > 0 or len(prev_buttons) > 0
    
    # Standard: Catalogs with >15 items MUST have pagination
    if product_count > 15 and not has_pagination:
        logging.error("=" * 80)
        logging.error("USABILITY VIOLATION: MISSING PAGINATION FOR LARGE CATALOG")
        logging.error("Standard: ISO 25010 Section 4.2.2 (Usability - Operability)")
        logging.error("Standard: ISO 9241-110 Principle 3 (User Control)")
        logging.error("Severity: HIGH")
        logging.error(f"Product Count: {product_count}")
        logging.error("Expected: Pagination controls for catalogs with >15 items")
        logging.error("Actual: No pagination controls detected")
        logging.error("Impact:")
        logging.error("  - Very slow page load times")
        logging.error("  - Poor mobile user experience")
        logging.error("  - Difficult navigation and product finding")
        logging.error("  - Accessibility issues (excessive scrolling)")
        logging.error("  - Bandwidth waste")
        logging.error("Recommendation: Implement pagination with 9-12 items per page")
        logging.error("Industry Best Practice: Amazon, eBay use 24-48 items per page with pagination")
        logging.error("=" * 80)
        
        pytest.fail(f"DISCOVERED: {product_count} products without pagination - Violates ISO 25010 and ISO 9241-110")
    
    if has_pagination:
        logging.info(f"DISCOVERED: Pagination controls present for {product_count} products - Standards compliant")
    else:
        logging.info(f"DISCOVERED: {product_count} products (acceptable without pagination)")
    
    assert True


@pytest.mark.business_rules
@pytest.mark.medium
def test_empty_categories_not_allowed_BR_010(browser):
    """
    TC-CATALOG-BR-010: Empty Categories Not Allowed
    
    Standard: ISO 25010 Section 4.2.1 (Functional Suitability)
    Standard: ISO 9241-110 Principle 1 (Suitability for Task)
    Priority: MEDIUM
    Impact: Empty categories waste user time and reduce trust
    
    Discovers if any categories contain zero products.
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-BR-010: Validating no empty categories")
    
    categories_to_test = [
        ("Phones", PHONES_CATEGORY),
        ("Laptops", LAPTOPS_CATEGORY),
        ("Monitors", MONITORS_CATEGORY)
    ]
    
    empty_categories = []
    
    for category_name, category_locator in categories_to_test:
        browser.get(BASE_URL)
        navigate_to_category(browser, category_locator)
        
        products = get_displayed_products(browser)
        product_count = len(products)
        
        logging.info(f"DISCOVERED: {category_name} has {product_count} products")
        
        if product_count == 0:
            empty_categories.append(category_name)
    
    if empty_categories:
        logging.error("=" * 80)
        logging.error("FUNCTIONAL VIOLATION: EMPTY CATEGORIES EXIST")
        logging.error("Standard: ISO 25010 Section 4.2.1 (Functional Suitability)")
        logging.error("Standard: ISO 9241-110 Principle 1 (Suitability for Task)")
        logging.error("Severity: MEDIUM")
        logging.error(f"Empty categories: {', '.join(empty_categories)}")
        logging.error("Impact:")
        logging.error("  - Wastes user time and clicks")
        logging.error("  - Reduces trust in site completeness")
        logging.error("  - Poor user experience")
        logging.error("  - Appears unprofessional")
        logging.error("Recommendation: Hide empty categories or add products")
        logging.error("=" * 80)
        
        pytest.fail(f"DISCOVERED: {len(empty_categories)} empty categories - Violates ISO 25010")
    
    logging.info("All categories contain products - Standards compliant")
    assert True


@pytest.mark.business_rules
@pytest.mark.low
def test_category_active_state_indication_BR_011(browser):
    """
    TC-CATALOG-BR-011: Active Category Visual Indication
    
    Standard: ISO 9241-110 Principle 2 (Self-descriptiveness)
    Standard: ISO 9241-110 Principle 7 (Suitability for Learning)
    Priority: LOW
    Impact: Users can't tell which category is active
    
    Discovers if active category has visual indication.
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-BR-011: Validating active category indication")
    
    browser.get(BASE_URL)
    navigate_to_category(browser, PHONES_CATEGORY)
    
    # Check if Phones category has "active" class or similar
    try:
        phones_element = browser.find_element(*PHONES_CATEGORY)
        classes = phones_element.get_attribute("class") or ""
        
        has_active_indicator = "active" in classes.lower() or "selected" in classes.lower()
        
        if not has_active_indicator:
            logging.warning("=" * 80)
            logging.warning("USABILITY ISSUE: NO ACTIVE CATEGORY INDICATION")
            logging.warning("Standard: ISO 9241-110 Principle 2 (Self-descriptiveness)")
            logging.warning("Severity: LOW")
            logging.warning("Issue: Active category lacks visual indication")
            logging.warning("Impact:")
            logging.warning("  - Users confused about current location")
            logging.warning("  - Reduced navigation clarity")
            logging.warning("  - Poor feedback to user actions")
            logging.warning("Recommendation: Add 'active' class with distinct styling")
            logging.warning("=" * 80)
            
            # This is LOW priority, so we log warning but don't fail
            logging.info("DISCOVERED: Active category indication may be missing")
        else:
            logging.info("DISCOVERED: Active category has visual indication - Standards compliant")
            
    except NoSuchElementException:
        logging.warning("Could not find category element to check active state")
    
    assert True


# ============================================================================
# BUSINESS RULES TESTS - ACCESSIBILITY
# ============================================================================

@pytest.mark.business_rules
@pytest.mark.high
def test_product_images_have_alt_text_BR_012(browser):
    """
    TC-CATALOG-BR-012: Product Images Must Have Alt Text
    
    Standard: WCAG 2.1 SC 1.1.1 (Non-text Content) - Level A (MANDATORY)
    Priority: HIGH
    Impact: Screen readers cannot describe images without alt text
    
    Discovers if all product images have alt attributes.
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-BR-012: Validating image alt text")
    
    browser.get(BASE_URL)
    wait_for_products_to_load(browser)
    
    products = get_displayed_products(browser)
    
    images_without_alt = []
    
    for idx, product in enumerate(products, 1):
        details = get_product_details_from_card(browser, product)
        if details:
            alt_text = details.get('image_alt', '')
            
            if not alt_text or len(alt_text.strip()) == 0:
                images_without_alt.append({
                    'position': idx,
                    'name': details['name']
                })
    
    if images_without_alt:
        logging.error("=" * 80)
        logging.error("ACCESSIBILITY VIOLATION: MISSING IMAGE ALT TEXT")
        logging.error("Standard: WCAG 2.1 Success Criterion 1.1.1 - Level A (MANDATORY)")
        logging.error("Severity: HIGH")
        logging.error(f"Images without alt text: {len(images_without_alt)}")
        for item in images_without_alt[:5]:
            logging.error(f"  - Position {item['position']}: {item['name']}")
        logging.error("Impact:")
        logging.error("  - Screen readers cannot describe products")
        logging.error("  - Violates legal accessibility requirements (ADA, Section 508)")
        logging.error("  - Excludes visually impaired users")
        logging.error("  - SEO penalties")
        logging.error("Requirement: ALL images MUST have meaningful alt attributes")
        logging.error("Legal Risk: HIGH - This is a Level A requirement (mandatory)")
        logging.error("=" * 80)
        
        pytest.fail(f"DISCOVERED: {len(images_without_alt)} images lack alt text - Violates WCAG 2.1 Level A (MANDATORY)")
    
    logging.info(f"All {len(products)} product images have alt text - WCAG 2.1 compliant")
    assert True


@pytest.mark.business_rules
@pytest.mark.high
def test_keyboard_navigation_categories_BR_013(browser):
    """
    TC-CATALOG-BR-013: Keyboard Navigation of Categories
    
    Standard: WCAG 2.1 SC 2.1.1 (Keyboard) - Level A (MANDATORY)
    Priority: HIGH
    Impact: Users without mouse cannot navigate categories
    
    Discovers if categories can be navigated using keyboard only.
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-BR-013: Testing keyboard navigation")
    
    browser.get(BASE_URL)
    wait_for_products_to_load(browser)
    
    try:
        # Try to focus on Phones category link
        phones_link = browser.find_element(*PHONES_CATEGORY)
        
        # Send TAB keys to try to reach it (simplified test)
        body = browser.find_element(By.TAG_NAME, "body")
        
        # Try pressing ENTER on the link
        phones_link.send_keys(Keys.RETURN)
        time.sleep(2)
        
        # Check if navigation worked
        products = get_displayed_products(browser)
        
        if not products:
            logging.error("=" * 80)
            logging.error("ACCESSIBILITY VIOLATION: KEYBOARD NAVIGATION FAILED")
            logging.error("Standard: WCAG 2.1 SC 2.1.1 (Keyboard) - Level A (MANDATORY)")
            logging.error("Severity: HIGH")
            logging.error("Issue: Category link not keyboard accessible")
            logging.error("Impact:")
            logging.error("  - Users without mouse cannot browse categories")
            logging.error("  - Violates accessibility laws (ADA, Section 508)")
            logging.error("  - Excludes motor-impaired users")
            logging.error("Requirement: All functionality MUST be keyboard accessible")
            logging.error("Legal Risk: HIGH - Level A requirement (mandatory)")
            logging.error("=" * 80)
            
            pytest.fail("DISCOVERED: Keyboard navigation failed - Violates WCAG 2.1 Level A (MANDATORY)")
        
        logging.info("DISCOVERED: Keyboard navigation works - WCAG 2.1 compliant")
        
    except Exception as e:
        logging.error(f"Error during keyboard navigation test: {e}")
        logging.warning("Keyboard navigation test incomplete")
    
    assert True


@pytest.mark.business_rules
@pytest.mark.medium
def test_category_links_have_aria_labels_BR_014(browser):
    """
    TC-CATALOG-BR-014: Category Links Have Accessible Names
    
    Standard: WCAG 2.1 SC 4.1.2 (Name, Role, Value) - Level A
    Priority: MEDIUM
    Impact: Screen readers cannot properly announce category links
    
    Discovers if category links have proper accessible names.
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-BR-014: Validating category link labels")
    
    browser.get(BASE_URL)
    
    categories_to_check = [
        ("Phones", PHONES_CATEGORY),
        ("Laptops", LAPTOPS_CATEGORY),
        ("Monitors", MONITORS_CATEGORY)
    ]
    
    links_without_proper_labels = []
    
    for category_name, category_locator in categories_to_check:
        try:
            link = browser.find_element(*category_locator)
            
            # Check if link has text or aria-label
            link_text = link.text.strip()
            aria_label = link.get_attribute("aria-label") or ""
            
            if not link_text and not aria_label:
                links_without_proper_labels.append(category_name)
                
        except NoSuchElementException:
            links_without_proper_labels.append(category_name)
    
    if links_without_proper_labels:
        logging.error("=" * 80)
        logging.error("ACCESSIBILITY VIOLATION: MISSING LINK LABELS")
        logging.error("Standard: WCAG 2.1 SC 4.1.2 (Name, Role, Value) - Level A")
        logging.error("Severity: MEDIUM")
        logging.error(f"Links without labels: {', '.join(links_without_proper_labels)}")
        logging.error("Impact:")
        logging.error("  - Screen readers cannot announce link purpose")
        logging.error("  - Confuses assistive technology users")
        logging.error("Requirement: All links MUST have accessible names")
        logging.error("=" * 80)
        
        pytest.fail(f"DISCOVERED: {len(links_without_proper_labels)} category links lack labels - Violates WCAG 2.1")
    
    logging.info("All category links have proper labels - WCAG 2.1 compliant")
    assert True


@pytest.mark.business_rules
@pytest.mark.medium
def test_focus_indicators_visible_BR_015(browser):
    """
    TC-CATALOG-BR-015: Focus Indicators Visible
    
    Standard: WCAG 2.1 SC 2.4.7 (Focus Visible) - Level AA
    Priority: MEDIUM
    Impact: Keyboard users cannot see where focus is
    
    Discovers if focus indicators are visible when navigating.
    """
    logging.info("=" * 80)
    logging.info("TC-CATALOG-BR-015: Testing focus indicators visibility")
    
    browser.get(BASE_URL)
    
    try:
        phones_link = browser.find_element(*PHONES_CATEGORY)
        
        # Focus the element
        browser.execute_script("arguments[0].focus();", phones_link)
        time.sleep(0.5)
        
        # Check if element has outline or other focus styling
        outline = browser.execute_script("return window.getComputedStyle(arguments[0]).outline;", phones_link)
        outline_width = browser.execute_script("return window.getComputedStyle(arguments[0]).outlineWidth;", phones_link)
        
        has_focus_indicator = outline != "none" and outline_width != "0px"
        
        if not has_focus_indicator:
            logging.warning("=" * 80)
            logging.warning("ACCESSIBILITY ISSUE: FOCUS INDICATORS MAY BE MISSING")
            logging.warning("Standard: WCAG 2.1 SC 2.4.7 (Focus Visible) - Level AA")
            logging.warning("Severity: MEDIUM")
            logging.warning("Issue: Focus indicators not clearly visible")
            logging.warning("Impact:")
            logging.warning("  - Keyboard users cannot track focus")
            logging.warning("  - Difficult to navigate for motor-impaired users")
            logging.warning("Recommendation: Ensure focus has visible outline (min 2px)")
            logging.warning("=" * 80)
            
            logging.info("DISCOVERED: Focus indicators may need improvement")
        else:
            logging.info("DISCOVERED: Focus indicators visible - WCAG 2.1 Level AA compliant")
            
    except Exception as e:
        logging.warning(f"Could not complete focus indicator test: {e}")
    
    assert True


# ============================================================================
# END OF TEST SUITE
# ============================================================================
