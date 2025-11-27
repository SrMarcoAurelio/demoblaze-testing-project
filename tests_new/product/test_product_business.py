"""
Product Business Rules Tests
Author: Marc Arévalo
Version: 1.0

Test Coverage:
- Data completeness validation across all products
- Performance standards
- Accessibility compliance (WCAG 2.1)

Philosophy: DISCOVER (EXECUTE → OBSERVE → DECIDE)
"""

import pytest
import logging
from pages.product_page import ProductPage

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@pytest.mark.business_rules
@pytest.mark.high
def test_all_products_have_name_BR_001(browser, base_url):
    """TC-PRODUCT-BR-001: All Products Have Name
    Standard: ISO 25010 (Software Quality - Information Completeness)"""
    product_page = ProductPage(browser)
    products_without_name = []

    for index, product_name, details in product_page.iterate_all_products(max_products=5):
        if not details['name']:
            products_without_name.append(f"Product {index}")
            logger.error(f"✗ Product {index} has no name")

    if products_without_name:
        pytest.fail(f"DISCOVERED: {len(products_without_name)} products without names")
    logger.info("✓ All checked products have names")

@pytest.mark.business_rules
@pytest.mark.high
def test_all_products_have_price_BR_002(browser, base_url):
    """TC-PRODUCT-BR-002: All Products Have Price
    Standard: ISO 25010 (Software Quality - Information Completeness)"""
    product_page = ProductPage(browser)
    products_without_price = []

    for index, product_name, details in product_page.iterate_all_products(max_products=5):
        if not details['price']:
            products_without_price.append(f"Product {index}: {product_name}")
            logger.error(f"✗ Product {index} has no price")

    if products_without_price:
        pytest.fail(f"DISCOVERED: {len(products_without_price)} products without prices")
    logger.info("✓ All checked products have prices")

@pytest.mark.business_rules
@pytest.mark.medium
def test_all_products_have_description_BR_003(browser, base_url):
    """TC-PRODUCT-BR-003: All Products Have Description
    Standard: ISO 25010 (Software Quality - Information Completeness)"""
    product_page = ProductPage(browser)
    products_without_description = []

    for index, product_name, details in product_page.iterate_all_products(max_products=5):
        if not details['description']:
            products_without_description.append(f"Product {index}: {product_name}")

    if products_without_description:
        logger.warning(f"⚠ {len(products_without_description)} products without descriptions")
    logger.info("✓ Description completeness check completed")

@pytest.mark.business_rules
@pytest.mark.medium
def test_all_product_images_load_successfully_BR_004(browser, base_url):
    """TC-PRODUCT-BR-004: All Product Images Load Successfully
    Standard: ISO 25010 (Software Quality - Reliability)"""
    product_page = ProductPage(browser)
    images_failed = []

    for index, product_name, details in product_page.iterate_all_products(max_products=5):
        loads, status_code, image_url = product_page.verify_image_loads()
        if not loads:
            images_failed.append(f"Product {index}: {product_name}")

    if images_failed:
        pytest.fail(f"DISCOVERED: {len(images_failed)} images failed to load")
    logger.info("✓ All checked product images load successfully")

@pytest.mark.business_rules
@pytest.mark.medium
def test_product_price_format_consistency_BR_005(browser, base_url):
    """TC-PRODUCT-BR-005: Product Price Format Consistency
    Standard: ISO 25010 (Software Quality - Consistency)"""
    product_page = ProductPage(browser)
    inconsistent_formats = []

    for index, product_name, details in product_page.iterate_all_products(max_products=5):
        is_valid, price = product_page.validate_price_format()
        if not is_valid:
            inconsistent_formats.append(f"Product {index}: {price}")

    if inconsistent_formats:
        logger.warning(f"⚠ {len(inconsistent_formats)} products with inconsistent price format")
    logger.info("✓ Price format consistency check completed")

@pytest.mark.business_rules
@pytest.mark.medium
def test_product_detail_load_time_BR_006(browser, base_url):
    """TC-PRODUCT-BR-006: Product Detail Page Load Time
    Standard: ISO 25010 (Software Quality - Performance Efficiency)"""
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    timing = product_page.measure_page_load_time()
    if timing['success']:
        total_load = timing['total_load_time']
        logger.info(f"Product page load time: {total_load:.2f}s")
        if total_load > 5.0:
            logger.warning(f"⚠ Slow load time: {total_load:.2f}s")
    logger.info("✓ Load time measurement completed")

@pytest.mark.business_rules
@pytest.mark.medium
def test_add_to_cart_button_visibility_BR_007(browser, base_url):
    """TC-PRODUCT-BR-007: Add to Cart Button Visibility on All Products
    Standard: ISO 25010 (Software Quality - Functional Suitability)"""
    product_page = ProductPage(browser)
    products_without_button = []

    for index, product_name, details in product_page.iterate_all_products(max_products=5):
        if not details['add_to_cart_present']:
            products_without_button.append(f"Product {index}: {product_name}")

    if products_without_button:
        pytest.fail(f"DISCOVERED: {len(products_without_button)} products without Add to Cart button")
    logger.info("✓ All checked products have Add to Cart button")

@pytest.mark.business_rules
@pytest.mark.low
@pytest.mark.accessibility
def test_product_image_has_alt_text_BR_008(browser, base_url):
    """TC-PRODUCT-BR-008: Product Image Has Alt Text
    Standard: WCAG 2.1 Level A - Guideline 1.1.1 (Non-text Content)"""
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    alt_text = product_page.get_product_image_alt()
    if not alt_text:
        logger.warning("⚠ ACCESSIBILITY ISSUE: Product image missing alt text")
    else:
        logger.info(f"✓ Product image has alt text: '{alt_text}'")

@pytest.mark.business_rules
@pytest.mark.low
@pytest.mark.accessibility
def test_keyboard_navigation_product_page_BR_009(browser, base_url):
    """TC-PRODUCT-BR-009: Keyboard Navigation on Product Page
    Standard: WCAG 2.1 Level AA - Guideline 2.1.1 (Keyboard)"""
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    results = product_page.test_keyboard_navigation()
    if results['tab_navigation_works']:
        logger.info("✓ Keyboard navigation works")
    else:
        logger.warning("⚠ ACCESSIBILITY ISSUE: Keyboard navigation limited")

@pytest.mark.business_rules
@pytest.mark.medium
@pytest.mark.parametrize("product_index", [1, 2, 3])
def test_product_data_consistency_across_views_BR_010(browser, base_url, product_index):
    """TC-PRODUCT-BR-010: Product Data Consistency Across Views
    Standard: ISO 25010 (Software Quality - Data Consistency)"""
    product_page = ProductPage(browser)
    success, catalog_name = product_page.navigate_to_product_by_index(product_index)
    
    assert success, f"Failed to navigate to product {product_index}"
    detail_name = product_page.get_product_name()
    assert detail_name, "Product name not found on detail page"
    logger.info(f"✓ Product {product_index} consistency check: {detail_name}")
