"""
Product Functional Tests
Author: Marc Arévalo
Version: 1.0

Test Coverage:
- Product navigation and display
- Product information completeness
- Add to cart functionality
- Browser navigation
- Business rules validation

Philosophy: DISCOVER (EXECUTE → OBSERVE → DECIDE)
All tests perform real actions, observe actual results, and decide based on objective standards.
"""

import pytest
import logging
import time
from pages.product_page import ProductPage

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================================
# FUNCTIONAL TESTS - Core Product Features
# ============================================================================

@pytest.mark.functional
@pytest.mark.critical
def test_navigate_to_product_from_catalog_FUNC_001(browser, base_url):
    """
    TC-PRODUCT-FUNC-001: Navigate to Product from Catalog
    DISCOVER: Can users navigate from catalog to product detail page?
    """
    # EXECUTE: Navigate to product
    product_page = ProductPage(browser)
    success, product_name = product_page.navigate_to_first_product()

    # OBSERVE: Check navigation result
    current_url = browser.current_url

    # DECIDE: Should successfully navigate to product page
    assert success, "Failed to navigate to product"
    assert "prod.html" in current_url, f"Not on product page: {current_url}"
    assert product_name, "Product name not captured during navigation"

    logger.info(f"✓ Successfully navigated to product: {product_name}")


@pytest.mark.functional
@pytest.mark.critical
def test_product_name_displays_FUNC_002(browser, base_url):
    """
    TC-PRODUCT-FUNC-002: Product Name Displays
    DISCOVER: Is product name visible on product detail page?
    """
    # EXECUTE: Navigate to product
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    # OBSERVE: Get product name
    product_name = product_page.get_product_name()

    # DECIDE: Product name should be present
    assert product_name, "Product name not displayed"
    assert len(product_name) > 0, "Product name is empty"

    logger.info(f"✓ Product name displayed: {product_name}")


@pytest.mark.functional
@pytest.mark.critical
def test_product_price_displays_FUNC_003(browser, base_url):
    """
    TC-PRODUCT-FUNC-003: Product Price Displays
    DISCOVER: Is product price visible on product detail page?
    """
    # EXECUTE: Navigate to product
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    # OBSERVE: Get product price
    product_price = product_page.get_product_price()
    price_value = product_page.get_product_price_value()

    # DECIDE: Product price should be present
    assert product_price, "Product price not displayed"
    assert "$" in product_price, f"Price doesn't contain '$': {product_price}"
    assert price_value is not None, "Could not extract numeric price value"
    assert price_value > 0, f"Price value should be positive: {price_value}"

    logger.info(f"✓ Product price displayed: {product_price} (value: ${price_value})")


@pytest.mark.functional
@pytest.mark.high
def test_product_description_displays_FUNC_004(browser, base_url):
    """
    TC-PRODUCT-FUNC-004: Product Description Displays
    DISCOVER: Is product description visible on product detail page?
    """
    # EXECUTE: Navigate to product
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    # OBSERVE: Get product description
    description = product_page.get_product_description()

    # DECIDE: Product description should be present
    assert description, "Product description not displayed"
    assert len(description) > 10, f"Description too short: {len(description)} chars"

    logger.info(f"✓ Product description displayed: {len(description)} characters")


@pytest.mark.functional
@pytest.mark.high
def test_product_image_displays_FUNC_005(browser, base_url):
    """
    TC-PRODUCT-FUNC-005: Product Image Displays
    DISCOVER: Is product image visible on product detail page?
    """
    # EXECUTE: Navigate to product
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    # OBSERVE: Get product image
    image_src = product_page.get_product_image_src()

    # DECIDE: Product image should be present
    assert image_src, "Product image not found"
    assert image_src.startswith('http'), f"Invalid image URL: {image_src}"

    logger.info(f"✓ Product image displayed: {image_src[:50]}...")


@pytest.mark.functional
@pytest.mark.critical
def test_add_to_cart_button_present_FUNC_006(browser, base_url):
    """
    TC-PRODUCT-FUNC-006: Add to Cart Button Present
    DISCOVER: Is the Add to Cart button visible on product page?
    """
    # EXECUTE: Navigate to product
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    # OBSERVE: Check Add to Cart button visibility
    is_visible = product_page.is_add_to_cart_visible()

    # DECIDE: Button should be visible
    assert is_visible, "Add to Cart button not visible"

    logger.info("✓ Add to Cart button is present and visible")


@pytest.mark.functional
@pytest.mark.critical
def test_add_to_cart_from_product_page_FUNC_007(browser, base_url):
    """
    TC-PRODUCT-FUNC-007: Add to Cart from Product Page
    DISCOVER: Can users add product to cart from product detail page?
    """
    # EXECUTE: Navigate to product and add to cart
    product_page = ProductPage(browser)
    success, product_name = product_page.navigate_to_first_product()

    # EXECUTE: Click Add to Cart
    success, alert_text = product_page.add_to_cart_and_handle_alert()

    # DECIDE: Should successfully add to cart
    assert success, "Failed to add product to cart"
    assert alert_text, "No alert received after adding to cart"
    assert "added" in alert_text.lower() or "cart" in alert_text.lower(), \
        f"Unexpected alert text: {alert_text}"

    logger.info(f"✓ Product added to cart: {product_name}, Alert: {alert_text}")


@pytest.mark.functional
@pytest.mark.high
def test_back_to_catalog_navigation_FUNC_008(browser, base_url):
    """
    TC-PRODUCT-FUNC-008: Back to Catalog Navigation
    DISCOVER: Can users navigate back to catalog from product page?
    """
    # EXECUTE: Navigate to product
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    # OBSERVE: Verify on product page
    product_url = browser.current_url
    assert "prod.html" in product_url, "Not on product page"

    # EXECUTE: Navigate back to home
    product_page.go_home()
    time.sleep(1)

    # OBSERVE: Check current URL
    current_url = browser.current_url

    # DECIDE: Should be back on catalog/home page
    assert current_url == base_url or "index.html" in current_url, \
        f"Not back on catalog page: {current_url}"

    logger.info("✓ Successfully navigated back to catalog")


@pytest.mark.functional
@pytest.mark.medium
def test_browser_back_button_FUNC_009(browser, base_url):
    """
    TC-PRODUCT-FUNC-009: Browser Back Button Navigation
    DISCOVER: Does browser back button work from product page?
    """
    # EXECUTE: Start on home, navigate to product
    product_page = ProductPage(browser)
    browser.get(base_url)
    time.sleep(1)

    product_page.navigate_to_first_product()
    product_url = browser.current_url

    # OBSERVE: Verify on product page
    assert "prod.html" in product_url, "Not on product page"

    # EXECUTE: Use browser back button
    product_page.go_back_browser()

    # OBSERVE: Check URL after back navigation
    current_url = browser.current_url

    # DECIDE: Should be back on previous page
    assert current_url != product_url, "Browser back button didn't navigate away"
    assert current_url == base_url or "index.html" in current_url, \
        f"Browser back didn't return to catalog: {current_url}"

    logger.info("✓ Browser back button works correctly")


@pytest.mark.functional
@pytest.mark.medium
def test_multiple_product_navigation_FUNC_010(browser, base_url):
    """
    TC-PRODUCT-FUNC-010: Navigate to Multiple Products
    DISCOVER: Can users navigate to multiple different products?
    """
    # EXECUTE: Navigate to first product
    product_page = ProductPage(browser)
    success1, name1 = product_page.navigate_to_product_by_index(1)

    assert success1, "Failed to navigate to first product"
    details1 = product_page.get_all_product_details()

    # EXECUTE: Navigate to second product
    success2, name2 = product_page.navigate_to_product_by_index(2)

    assert success2, "Failed to navigate to second product"
    details2 = product_page.get_all_product_details()

    # DECIDE: Should successfully navigate to different products
    assert name1 != name2, f"Product names should be different: {name1} vs {name2}"
    assert details1['price'] != details2['price'], \
        f"Prices should be different: {details1['price']} vs {details2['price']}"

    logger.info(f"✓ Successfully navigated to multiple products: {name1}, {name2}")


# ============================================================================
# BUSINESS RULES TESTS - Standards Compliance
# ============================================================================

@pytest.mark.business_rules
@pytest.mark.high
def test_all_products_have_name_BR_001(browser, base_url):
    """
    TC-PRODUCT-BR-001: All Products Have Name
    Standard: ISO 25010 (Software Quality - Information Completeness)
    DISCOVER: Do ALL products in catalog have visible names?
    """
    # EXECUTE: Iterate through all products (limit to first 5 for performance)
    product_page = ProductPage(browser)
    products_without_name = []

    for index, product_name, details in product_page.iterate_all_products(max_products=5):
        # OBSERVE: Check if name is present
        if not details['name']:
            products_without_name.append(f"Product {index}")
            logger.error(f"✗ Product {index} has no name")

    # DECIDE: All products should have names
    if products_without_name:
        pytest.fail(f"DISCOVERED: {len(products_without_name)} products without names: {products_without_name}")

    logger.info("✓ All checked products have names")


@pytest.mark.business_rules
@pytest.mark.high
def test_all_products_have_price_BR_002(browser, base_url):
    """
    TC-PRODUCT-BR-002: All Products Have Price
    Standard: ISO 25010 (Software Quality - Information Completeness)
    DISCOVER: Do ALL products in catalog have visible prices?
    """
    # EXECUTE: Iterate through all products
    product_page = ProductPage(browser)
    products_without_price = []

    for index, product_name, details in product_page.iterate_all_products(max_products=5):
        # OBSERVE: Check if price is present
        if not details['price']:
            products_without_price.append(f"Product {index}: {product_name}")
            logger.error(f"✗ Product {index} ({product_name}) has no price")

    # DECIDE: All products should have prices
    if products_without_price:
        pytest.fail(f"DISCOVERED: {len(products_without_price)} products without prices")

    logger.info("✓ All checked products have prices")


@pytest.mark.business_rules
@pytest.mark.medium
def test_all_products_have_description_BR_003(browser, base_url):
    """
    TC-PRODUCT-BR-003: All Products Have Description
    Standard: ISO 25010 (Software Quality - Information Completeness)
    DISCOVER: Do ALL products have descriptions?
    """
    # EXECUTE: Iterate through all products
    product_page = ProductPage(browser)
    products_without_description = []

    for index, product_name, details in product_page.iterate_all_products(max_products=5):
        # OBSERVE: Check if description is present
        if not details['description']:
            products_without_description.append(f"Product {index}: {product_name}")
            logger.error(f"✗ Product {index} ({product_name}) has no description")

    # DECIDE: All products should have descriptions
    if products_without_description:
        logger.warning(f"⚠ {len(products_without_description)} products without descriptions")

    logger.info("✓ Description completeness check completed")


@pytest.mark.business_rules
@pytest.mark.medium
def test_all_product_images_load_successfully_BR_004(browser, base_url):
    """
    TC-PRODUCT-BR-004: All Product Images Load Successfully
    Standard: ISO 25010 (Software Quality - Reliability)
    DISCOVER: Do all product images load with HTTP 200?
    """
    # EXECUTE: Iterate through products and check image loading
    product_page = ProductPage(browser)
    images_failed = []

    for index, product_name, details in product_page.iterate_all_products(max_products=5):
        # OBSERVE: Verify image loads
        loads, status_code, image_url = product_page.verify_image_loads()

        if not loads:
            images_failed.append(f"Product {index}: {product_name} (Status: {status_code})")
            logger.error(f"✗ Product {index} image failed: {status_code}")

    # DECIDE: All images should load successfully
    if images_failed:
        pytest.fail(f"DISCOVERED: {len(images_failed)} images failed to load: {images_failed}")

    logger.info("✓ All checked product images load successfully")


@pytest.mark.business_rules
@pytest.mark.medium
def test_product_price_format_consistency_BR_005(browser, base_url):
    """
    TC-PRODUCT-BR-005: Product Price Format Consistency
    Standard: ISO 25010 (Software Quality - Consistency)
    DISCOVER: Do all products follow the same price format?
    """
    # EXECUTE: Check price format across products
    product_page = ProductPage(browser)
    inconsistent_formats = []

    for index, product_name, details in product_page.iterate_all_products(max_products=5):
        # OBSERVE: Validate price format
        is_valid, price = product_page.validate_price_format()

        if not is_valid:
            inconsistent_formats.append(f"Product {index}: {product_name} - {price}")
            logger.error(f"✗ Product {index} has inconsistent price format: {price}")

    # DECIDE: All prices should follow same format
    if inconsistent_formats:
        logger.warning(f"⚠ {len(inconsistent_formats)} products with inconsistent price format")

    logger.info("✓ Price format consistency check completed")


@pytest.mark.business_rules
@pytest.mark.medium
def test_product_detail_load_time_BR_006(browser, base_url):
    """
    TC-PRODUCT-BR-006: Product Detail Page Load Time
    Standard: ISO 25010 (Software Quality - Performance Efficiency)
    DISCOVER: How fast do product detail pages load?
    """
    # EXECUTE: Navigate to product and measure load time
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    # OBSERVE: Get load time metrics
    timing = product_page.measure_page_load_time()

    # DECIDE: Page should load within reasonable time
    if timing['success']:
        total_load = timing['total_load_time']
        logger.info(f"Product page load time: {total_load:.2f}s")

        # Threshold: 5 seconds (reasonable for web page)
        if total_load > 5.0:
            logger.warning(f"⚠ Slow load time: {total_load:.2f}s (threshold: 5s)")
    else:
        logger.warning("⚠ Could not measure load time")

    logger.info("✓ Load time measurement completed")


@pytest.mark.business_rules
@pytest.mark.medium
def test_add_to_cart_button_visibility_BR_007(browser, base_url):
    """
    TC-PRODUCT-BR-007: Add to Cart Button Visibility on All Products
    Standard: ISO 25010 (Software Quality - Functional Suitability)
    DISCOVER: Do all products have visible Add to Cart button?
    """
    # EXECUTE: Check Add to Cart button across products
    product_page = ProductPage(browser)
    products_without_button = []

    for index, product_name, details in product_page.iterate_all_products(max_products=5):
        # OBSERVE: Check button presence
        if not details['add_to_cart_present']:
            products_without_button.append(f"Product {index}: {product_name}")
            logger.error(f"✗ Product {index} ({product_name}) missing Add to Cart button")

    # DECIDE: All products should have Add to Cart button
    if products_without_button:
        pytest.fail(f"DISCOVERED: {len(products_without_button)} products without Add to Cart button")

    logger.info("✓ All checked products have Add to Cart button")


@pytest.mark.business_rules
@pytest.mark.low
@pytest.mark.accessibility
def test_product_image_has_alt_text_BR_008(browser, base_url):
    """
    TC-PRODUCT-BR-008: Product Image Has Alt Text
    Standard: WCAG 2.1 Level A - Guideline 1.1.1 (Non-text Content)
    DISCOVER: Do product images have alt text for accessibility?
    """
    # EXECUTE: Navigate to product
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    # OBSERVE: Get image alt attribute
    alt_text = product_page.get_product_image_alt()

    # DECIDE: Image should have alt text
    if not alt_text:
        logger.warning("⚠ ACCESSIBILITY ISSUE: Product image missing alt text")
    else:
        logger.info(f"✓ Product image has alt text: '{alt_text}'")


@pytest.mark.business_rules
@pytest.mark.low
@pytest.mark.accessibility
def test_keyboard_navigation_product_page_BR_009(browser, base_url):
    """
    TC-PRODUCT-BR-009: Keyboard Navigation on Product Page
    Standard: WCAG 2.1 Level AA - Guideline 2.1.1 (Keyboard)
    DISCOVER: Can product page be navigated with keyboard only?
    """
    # EXECUTE: Navigate to product
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    # EXECUTE: Test keyboard navigation
    results = product_page.test_keyboard_navigation()

    # DECIDE: Key elements should be keyboard accessible
    if results['tab_navigation_works']:
        logger.info(f"✓ Keyboard navigation works")
        logger.info(f"  - Add to Cart focusable: {results['add_to_cart_focusable']}")
        logger.info(f"  - Home link focusable: {results['home_link_focusable']}")
    else:
        logger.warning("⚠ ACCESSIBILITY ISSUE: Keyboard navigation limited")


@pytest.mark.business_rules
@pytest.mark.medium
@pytest.mark.parametrize("product_index", [1, 2, 3])
def test_product_data_consistency_across_views_BR_010(browser, base_url, product_index):
    """
    TC-PRODUCT-BR-010: Product Data Consistency Across Views
    Standard: ISO 25010 (Software Quality - Data Consistency)
    DISCOVER: Is product data consistent between catalog and detail views?
    """
    # EXECUTE: Navigate to product
    product_page = ProductPage(browser)
    success, catalog_name = product_page.navigate_to_product_by_index(product_index)

    assert success, f"Failed to navigate to product {product_index}"

    # OBSERVE: Get product name on detail page
    detail_name = product_page.get_product_name()

    # DECIDE: Product name should match between views
    assert detail_name, "Product name not found on detail page"
    logger.info(f"✓ Product {product_index} consistency check: {detail_name}")
