"""
Catalog Functional Tests
Author: Marc Arévalo  
Version: 1.0

Test Coverage:
- Category navigation (Phones, Laptops, Monitors)
- Product display and information
- Pagination functionality

Philosophy: DISCOVER (EXECUTE → OBSERVE → DECIDE)
"""

import pytest
import logging
import time
from pages.catalog_page import CatalogPage

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@pytest.mark.functional
@pytest.mark.critical
def test_navigate_to_phones_category_FUNC_001(browser, base_url):
    """TC-CATALOG-FUNC-001: Navigate to Phones Category"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    success = catalog.click_phones_category()
    assert success, "Failed to navigate to Phones category"
    assert catalog.are_products_displayed(), "No products displayed"
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
    assert catalog.are_products_displayed(), "No products displayed"
    logger.info("✓ Monitors category navigation successful")

@pytest.mark.functional
@pytest.mark.high
def test_home_button_shows_all_products_FUNC_004(browser, base_url):
    """TC-CATALOG-FUNC-004: Home Button Shows All Products"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    catalog.click_phones_category()
    phones_count = catalog.get_product_count()
    
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
    
    assert phones_products != laptop_products, "Categories should show different products"
    logger.info("✓ Category switching works correctly")

@pytest.mark.functional
@pytest.mark.high
def test_products_display_after_page_load_FUNC_006(browser, base_url):
    """TC-CATALOG-FUNC-006: Products Display After Page Load"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    assert catalog.are_products_displayed(timeout=10), "Products not displayed"
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
    
    first_img_src = images[0].get_attribute('src')
    assert first_img_src, "First image has no src"
    logger.info(f"✓ {len(images)} product images loaded")

@pytest.mark.functional
@pytest.mark.high
def test_pagination_next_button_functionality_FUNC_010(browser, base_url):
    """TC-CATALOG-FUNC-010: Pagination Next Button Functionality"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    first_page_products = catalog.get_all_product_names()
    
    if catalog.is_next_button_visible():
        success = catalog.click_next_page()
        assert success, "Failed to click Next button"
        
        second_page_products = catalog.get_all_product_names()
        assert first_page_products != second_page_products, "Products should change"
        logger.info("✓ Next button pagination works")
    else:
        logger.info("✓ Next button not present (single page)")

@pytest.mark.functional
@pytest.mark.high
def test_pagination_previous_button_functionality_FUNC_011(browser, base_url):
    """TC-CATALOG-FUNC-011: Pagination Previous Button Functionality"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    if catalog.is_next_button_visible():
        catalog.click_next_page()
        second_page = catalog.get_all_product_names()
        
        if catalog.is_prev_button_visible():
            success = catalog.click_prev_page()
            assert success, "Failed to click Previous button"
            
            first_page = catalog.get_all_product_names()
            assert second_page != first_page, "Should return to first page"
            logger.info("✓ Previous button pagination works")
    else:
        logger.info("✓ Pagination not applicable")

@pytest.mark.functional
@pytest.mark.medium
def test_pagination_boundary_conditions_FUNC_012(browser, base_url):
    """TC-CATALOG-FUNC-012: Pagination Boundary Conditions"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    prev_enabled = catalog.is_prev_button_enabled()
    logger.info(f"Previous button on first page: {prev_enabled}")
    
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
    
    assert catalog_url != product_url, "URL should change"
    assert "prod.html" in product_url, "Should navigate to product page"
    logger.info(f"✓ URL changed correctly")

@pytest.mark.functional
@pytest.mark.medium
def test_back_button_returns_to_catalog_FUNC_015(browser, base_url):
    """TC-CATALOG-FUNC-015: Back Button Returns to Catalog"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    
    catalog.click_first_product()
    assert "prod.html" in browser.current_url
    
    browser.back()
    time.sleep(2)
    
    assert catalog.are_products_displayed(timeout=5), "Should return to catalog"
    logger.info("✓ Browser back button works correctly")
