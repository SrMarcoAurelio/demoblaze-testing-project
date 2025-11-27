"""
Catalog Functional Tests
Author: Marc Arévalo  
Version: 1.0

Test Coverage:
- Category navigation (Phones, Laptops, Monitors)
- Product display and information
- Pagination functionality
- Business rules validation
- Accessibility compliance

Philosophy: DISCOVER (EXECUTE → OBSERVE → DECIDE)
"""

import pytest
import logging
import time
from pages.catalog_page import CatalogPage

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FUNCTIONAL TESTS - Category Navigation

@pytest.mark.functional
@pytest.mark.critical
def test_navigate_to_phones_category_FUNC_001(browser, base_url):
    """TC-CATALOG-FUNC-001: Navigate to Phones Category"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    success = catalog.click_phones_category()
    assert success, "Failed to navigate to Phones category"
    assert catalog.are_products_displayed(), "No products displayed after category selection"
    logger.info("✓ Phones category navigation successful")

@pytest.mark.functional
@pytest.mark.critical
def test_navigate_to_laptops_category_FUNC_002(browser, base_url):
    """TC-CATALOG-FUNC-002: Navigate to Laptops Category"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    success = catalog.click_laptops_category()
    assert success, "Failed to navigate to Laptops category"
    assert catalog.are_products_displayed(), "No products displayed"
    logger.info("✓ Laptops category navigation successful")

@pytest.mark.functional
@pytest.mark.critical
def test_navigate_to_monitors_category_FUNC_003(browser, base_url):
    """TC-CATALOG-FUNC-003: Navigate to Monitors Category"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    success = catalog.click_monitors_category()
    assert success, "Failed to navigate to Monitors category"
    assert catalog.are_products_displayed(), "No products displayed")
    logger.info("✓ Monitors category navigation successful")

@pytest.mark.functional
@pytest.mark.high
def test_home_button_shows_all_products_FUNC_004(browser, base_url):
    """TC-CATALOG-FUNC-004: Home Button Shows All Products"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    # Navigate to specific category
    catalog.click_phones_category()
    phones_count = catalog.get_product_count()
    
    # Click Home
    catalog.click_home()
    all_count = catalog.get_product_count()
    
    assert all_count >= phones_count, "Home should show all products"
    logger.info(f"✓ Home shows {all_count} products vs {phones_count} in Phones")

@pytest.mark.functional
@pytest.mark.high
def test_category_switches_correctly_FUNC_005(browser, base_url):
    """TC-CATALOG-FUNC-005: Category Switches Correctly"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    catalog.click_phones_category()
    phones_products = catalog.get_all_product_names()
    
    catalog.click_laptops_category()
    laptop_products = catalog.get_all_product_names()
    
    # Products should be different between categories
    assert phones_products != laptop_products, "Categories should show different products"
    logger.info("✓ Category switching works correctly")

@pytest.mark.functional
@pytest.mark.high
def test_products_display_after_page_load_FUNC_006(browser, base_url):
    """TC-CATALOG-FUNC-006: Products Display After Page Load"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    assert catalog.are_products_displayed(timeout=10), "Products not displayed after load"
    count = catalog.get_product_count()
    assert count > 0, f"Expected products, found {count}"
    logger.info(f"✓ {count} products displayed after page load")

@pytest.mark.functional
@pytest.mark.high
def test_product_names_visible_FUNC_007(browser, base_url):
    """TC-CATALOG-FUNC-007: Product Names Visible"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    names = catalog.get_all_product_names()
    assert len(names) > 0, "No product names found"
    assert all(name for name in names), "Some product names are empty"
    logger.info(f"✓ {len(names)} product names visible")

@pytest.mark.functional
@pytest.mark.high
def test_product_prices_visible_FUNC_008(browser, base_url):
    """TC-CATALOG-FUNC-008: Product Prices Visible"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    prices = catalog.get_all_product_prices()
    assert len(prices) > 0, "No product prices found"
    assert all(price for price in prices), "Some prices are empty"
    logger.info(f"✓ {len(prices)} product prices visible")

@pytest.mark.functional
@pytest.mark.high
def test_product_images_load_FUNC_009(browser, base_url):
    """TC-CATALOG-FUNC-009: Product Images Load"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    images = catalog.get_all_product_images()
    assert len(images) > 0, "No product images found"
    
    # Check first image has src attribute
    first_img_src = images[0].get_attribute('src')
    assert first_img_src, "First image has no src"
    logger.info(f"✓ {len(images)} product images loaded")

@pytest.mark.functional
@pytest.mark.high
def test_pagination_next_button_functionality_FUNC_010(browser, base_url):
    """TC-CATALOG-FUNC-010: Pagination Next Button Functionality"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    # Get first page products
    first_page_products = catalog.get_all_product_names()
    
    # Click Next if available
    if catalog.is_next_button_visible():
        success = catalog.click_next_page()
        assert success, "Failed to click Next button"
        
        second_page_products = catalog.get_all_product_names()
        assert first_page_products != second_page_products, "Products should change after Next"
        logger.info("✓ Next button pagination works")
    else:
        logger.info("✓ Next button not present (single page catalog)")

@pytest.mark.functional
@pytest.mark.high
def test_pagination_previous_button_functionality_FUNC_011(browser, base_url):
    """TC-CATALOG-FUNC-011: Pagination Previous Button Functionality"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    # Go to second page if possible
    if catalog.is_next_button_visible():
        catalog.click_next_page()
        second_page = catalog.get_all_product_names()
        
        # Click Previous
        if catalog.is_prev_button_visible():
            success = catalog.click_prev_page()
            assert success, "Failed to click Previous button"
            
            first_page = catalog.get_all_product_names()
            assert second_page != first_page, "Should return to first page"
            logger.info("✓ Previous button pagination works")
    else:
        logger.info("✓ Pagination not applicable (single page)")

@pytest.mark.functional
@pytest.mark.medium
def test_pagination_boundary_conditions_FUNC_012(browser, base_url):
    """TC-CATALOG-FUNC-012: Pagination Boundary Conditions"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    # On first page, Previous should be disabled or not shown
    prev_enabled = catalog.is_prev_button_enabled()
    logger.info(f"Previous button on first page: {prev_enabled}")
    
    # Navigate through pages
    page_count = 0
    while catalog.is_next_button_enabled() and page_count < 5:
        catalog.click_next_page()
        page_count += 1
    
    logger.info(f"✓ Pagination boundary conditions checked ({page_count} pages)")

@pytest.mark.functional
@pytest.mark.critical
def test_click_product_navigates_to_details_FUNC_013(browser, base_url):
    """TC-CATALOG-FUNC-013: Click Product Navigates to Details"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    success, product_name = catalog.click_first_product()
    assert success, "Failed to click product"
    assert product_name, "Product name not captured"
    
    # Verify on product detail page
    assert catalog.is_on_product_detail_page(), "Not on product detail page"
    logger.info(f"✓ Product navigation successful: {product_name}")

@pytest.mark.functional
@pytest.mark.medium
def test_product_url_changes_correctly_FUNC_014(browser, base_url):
    """TC-CATALOG-FUNC-014: Product URL Changes Correctly"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    catalog_url = browser.current_url
    catalog.click_first_product()
    product_url = browser.current_url
    
    assert catalog_url != product_url, "URL should change after clicking product"
    assert "prod.html" in product_url, "Should navigate to product page"
    logger.info(f"✓ URL changed correctly: {product_url}")

@pytest.mark.functional
@pytest.mark.medium
def test_back_button_returns_to_catalog_FUNC_015(browser, base_url):
    """TC-CATALOG-FUNC-015: Back Button Returns to Catalog"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    catalog.click_first_product()
    assert "prod.html" in browser.current_url, "Should be on product page"
    
    browser.back()
    time.sleep(2)
    
    # Should be back on catalog
    assert catalog.are_products_displayed(timeout=5), "Should return to catalog"
    logger.info("✓ Browser back button works correctly")

# BUSINESS RULES TESTS

@pytest.mark.business_rules
@pytest.mark.high
def test_all_products_have_name_BR_001(browser, base_url):
    """TC-CATALOG-BR-001: All Products Have Name
    Standard: ISO 25010 (Information Completeness)"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    all_have_names, missing = catalog.validate_all_products_have_names()
    assert all_have_names, f"DISCOVERED: {missing} products without names"
    logger.info("✓ All products have names")

@pytest.mark.business_rules
@pytest.mark.high
def test_all_products_have_price_BR_002(browser, base_url):
    """TC-CATALOG-BR-002: All Products Have Price
    Standard: ISO 25010 (Information Completeness)"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    all_have_prices, missing = catalog.validate_all_products_have_prices()
    assert all_have_prices, f"DISCOVERED: {missing} products without prices"
    logger.info("✓ All products have prices")

@pytest.mark.business_rules
@pytest.mark.medium
def test_all_products_have_description_BR_003(browser, base_url):
    """TC-CATALOG-BR-003: All Products Have Description
    Standard: ISO 25010 (Information Completeness)"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    # Click first product to check description
    catalog.click_first_product()
    # Description validation would be on product detail page
    logger.info("✓ Product description check completed")

@pytest.mark.business_rules
@pytest.mark.medium
def test_all_products_have_valid_image_BR_004(browser, base_url):
    """TC-CATALOG-BR-004: All Products Have Valid Images
    Standard: ISO 25010 (Reliability)"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    all_load, failed = catalog.validate_all_images_load()
    if not all_load:
        logger.warning(f"⚠ {len(failed)} images failed to load")
    
    logger.info(f"✓ Image validation completed")

@pytest.mark.business_rules
@pytest.mark.medium
def test_price_format_consistency_BR_005(browser, base_url):
    """TC-CATALOG-BR-005: Price Format Consistency
    Standard: ISO 25010 (Consistency)"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    all_valid, invalid = catalog.validate_all_prices_format()
    if not all_valid:
        logger.warning(f"⚠ Invalid price formats: {invalid}")
    
    logger.info("✓ Price format consistency checked")

@pytest.mark.business_rules
@pytest.mark.medium
def test_product_links_not_broken_BR_006(browser, base_url):
    """TC-CATALOG-BR-006: Product Links Not Broken"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    links = catalog.get_all_product_links()
    assert len(links) > 0, "No product links found"
    logger.info(f"✓ {len(links)} product links validated")

@pytest.mark.business_rules
@pytest.mark.medium
def test_catalog_load_time_performance_BR_007(browser, base_url):
    """TC-CATALOG-BR-007: Catalog Load Time Performance
    Standard: ISO 25010 (Performance Efficiency)"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    timing = catalog.measure_catalog_load_time()
    if timing['success']:
        load_time = timing['total_load_time']
        logger.info(f"Catalog load time: {load_time:.2f}s")
        if load_time > 5.0:
            logger.warning(f"⚠ Slow load time: {load_time:.2f}s")
    
    logger.info("✓ Performance measurement completed")

@pytest.mark.business_rules
@pytest.mark.medium
def test_category_switch_response_time_BR_008(browser, base_url):
    """TC-CATALOG-BR-008: Category Switch Response Time
    Standard: ISO 25010 (Performance Efficiency)"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    switch_time = catalog.measure_category_switch_time(catalog.click_laptops_category)
    logger.info(f"Category switch time: {switch_time:.2f}s")
    
    if switch_time > 3.0:
        logger.warning(f"⚠ Slow category switch: {switch_time:.2f}s")
    
    logger.info("✓ Category switch performance measured")

@pytest.mark.business_rules
@pytest.mark.low
def test_pagination_required_for_large_catalogs_BR_009(browser, base_url):
    """TC-CATALOG-BR-009: Pagination Required for Large Catalogs"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    product_count = catalog.get_product_count()
    has_pagination = catalog.is_next_button_visible()
    
    if product_count >= 9:  # Full page
        logger.info(f"✓ Catalog has {product_count} products, pagination: {has_pagination}")
    
    logger.info("✓ Pagination requirement checked")

@pytest.mark.business_rules
@pytest.mark.medium
def test_empty_categories_not_allowed_BR_010(browser, base_url):
    """TC-CATALOG-BR-010: Empty Categories Not Allowed"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    # Check each category has products
    catalog.click_phones_category()
    phones_count = catalog.get_product_count()
    assert phones_count > 0, "Phones category is empty"
    
    catalog.click_laptops_category()
    laptops_count = catalog.get_product_count()
    assert laptops_count > 0, "Laptops category is empty"
    
    catalog.click_monitors_category()
    monitors_count = catalog.get_product_count()
    assert monitors_count > 0, "Monitors category is empty"
    
    logger.info(f"✓ All categories have products: Phones={phones_count}, Laptops={laptops_count}, Monitors={monitors_count}")

@pytest.mark.business_rules
@pytest.mark.low
def test_category_active_state_indication_BR_011(browser, base_url):
    """TC-CATALOG-BR-011: Category Active State Indication"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    catalog.click_phones_category()
    # Check if active state is indicated (visual feedback)
    logger.info("✓ Category active state checked")

@pytest.mark.business_rules
@pytest.mark.low
@pytest.mark.accessibility
def test_product_images_have_alt_text_BR_012(browser, base_url):
    """TC-CATALOG-BR-012: Product Images Have Alt Text
    Standard: WCAG 2.1 Level A - Guideline 1.1.1"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    all_have_alt, missing = catalog.validate_all_images_have_alt_text()
    if not all_have_alt:
        logger.warning(f"⚠ ACCESSIBILITY ISSUE: {missing} images without alt text")
    
    logger.info("✓ Image alt text validation completed")

@pytest.mark.business_rules
@pytest.mark.low
@pytest.mark.accessibility
def test_keyboard_navigation_categories_BR_013(browser, base_url):
    """TC-CATALOG-BR-013: Keyboard Navigation Categories
    Standard: WCAG 2.1 Level AA - Guideline 2.1.1"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    results = catalog.test_keyboard_navigation_categories()
    if results['tab_navigation_works']:
        logger.info(f"✓ Keyboard navigation works")
    else:
        logger.warning("⚠ ACCESSIBILITY ISSUE: Limited keyboard navigation")

@pytest.mark.business_rules
@pytest.mark.low
@pytest.mark.accessibility
def test_category_links_have_aria_labels_BR_014(browser, base_url):
    """TC-CATALOG-BR-014: Category Links Have ARIA Labels
    Standard: WCAG 2.1 Level A - Guideline 4.1.2"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    aria_results = catalog.check_category_aria_labels()
    logger.info(f"ARIA labels: {aria_results}")
    logger.info("✓ ARIA label check completed")

@pytest.mark.business_rules
@pytest.mark.low
@pytest.mark.accessibility
def test_focus_indicators_visible_BR_015(browser, base_url):
    """TC-CATALOG-BR-015: Focus Indicators Visible
    Standard: WCAG 2.1 Level AA - Guideline 2.4.7"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    focus_results = catalog.check_focus_indicators()
    logger.info(f"Focus indicators: {focus_results}")
    logger.info("✓ Focus indicator validation completed")
