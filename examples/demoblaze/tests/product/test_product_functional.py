"""
Product Functional Tests
Author: Marc Arévalo
Version: 1.0

Test Coverage:
- Product navigation and display
- Product information completeness
- Add to cart functionality
- Browser navigation

Philosophy: DISCOVER (EXECUTE → OBSERVE → DECIDE)
"""

import logging
import time

import pytest

from pages.product_page import ProductPage

logger = logging.getLogger(__name__)


@pytest.mark.functional
@pytest.mark.critical
def test_navigate_to_product_from_catalog_FUNC_001(browser, base_url):
    """TC-PRODUCT-FUNC-001: Navigate to Product from Catalog"""
    product_page = ProductPage(browser)
    success, product_name = product_page.navigate_to_first_product()

    assert success, "Failed to navigate to product"
    assert "prod.html" in browser.current_url
    assert product_name, "Product name not captured"
    logger.info(f"✓ Successfully navigated to product: {product_name}")


@pytest.mark.functional
@pytest.mark.critical
def test_product_name_displays_FUNC_002(browser, base_url):
    """TC-PRODUCT-FUNC-002: Product Name Displays"""
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    product_name = product_page.get_product_name()
    assert product_name, "Product name not displayed"
    assert len(product_name) > 0, "Product name is empty"
    logger.info(f"✓ Product name displayed: {product_name}")


@pytest.mark.functional
@pytest.mark.critical
def test_product_price_displays_FUNC_003(browser, base_url):
    """TC-PRODUCT-FUNC-003: Product Price Displays"""
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    product_price = product_page.get_product_price()
    price_value = product_page.get_product_price_value()

    assert product_price, "Product price not displayed"
    assert "$" in product_price, f"Price doesn't contain '$': {product_price}"
    assert price_value is not None, "Could not extract numeric price"
    assert price_value > 0, f"Price should be positive: {price_value}"
    logger.info(f"✓ Product price displayed: {product_price}")


@pytest.mark.functional
@pytest.mark.high
def test_product_description_displays_FUNC_004(browser, base_url):
    """TC-PRODUCT-FUNC-004: Product Description Displays"""
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    description = product_page.get_product_description()
    assert description, "Product description not displayed"
    assert len(description) > 10, f"Description too short"
    logger.info(f"✓ Product description displayed: {len(description)} chars")


@pytest.mark.functional
@pytest.mark.high
def test_product_image_displays_FUNC_005(browser, base_url):
    """TC-PRODUCT-FUNC-005: Product Image Displays"""
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    image_src = product_page.get_product_image_src()
    assert image_src, "Product image not found"
    assert image_src.startswith("http"), f"Invalid image URL"
    logger.info(f"✓ Product image displayed")


@pytest.mark.functional
@pytest.mark.critical
def test_add_to_cart_button_present_FUNC_006(browser, base_url):
    """TC-PRODUCT-FUNC-006: Add to Cart Button Present"""
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    is_visible = product_page.is_add_to_cart_visible()
    assert is_visible, "Add to Cart button not visible"
    logger.info("✓ Add to Cart button is present")


@pytest.mark.functional
@pytest.mark.critical
def test_add_to_cart_from_product_page_FUNC_007(browser, base_url):
    """TC-PRODUCT-FUNC-007: Add to Cart from Product Page"""
    product_page = ProductPage(browser)
    success, product_name = product_page.navigate_to_first_product()

    success, alert_text = product_page.add_to_cart_and_handle_alert()
    assert success, "Failed to add product to cart"
    assert alert_text, "No alert received"
    logger.info(f"✓ Product added to cart: {product_name}")


@pytest.mark.functional
@pytest.mark.high
def test_back_to_catalog_navigation_FUNC_008(browser, base_url):
    """TC-PRODUCT-FUNC-008: Back to Catalog Navigation"""
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    product_url = browser.current_url
    assert "prod.html" in product_url

    product_page.go_home()
    time.sleep(1)

    current_url = browser.current_url
    assert current_url == base_url or "index.html" in current_url
    logger.info("✓ Successfully navigated back to catalog")


@pytest.mark.functional
@pytest.mark.medium
def test_browser_back_button_FUNC_009(browser, base_url):
    """TC-PRODUCT-FUNC-009: Browser Back Button Navigation"""
    product_page = ProductPage(browser)
    browser.get(base_url)
    time.sleep(1)

    product_page.navigate_to_first_product()
    product_url = browser.current_url

    product_page.go_back_browser()
    current_url = browser.current_url

    assert current_url != product_url
    logger.info("✓ Browser back button works correctly")


@pytest.mark.functional
@pytest.mark.medium
def test_multiple_product_navigation_FUNC_010(browser, base_url):
    """TC-PRODUCT-FUNC-010: Navigate to Multiple Products"""
    product_page = ProductPage(browser)
    success1, name1 = product_page.navigate_to_product_by_index(1)

    assert success1, "Failed to navigate to first product"
    details1 = product_page.get_all_product_details()

    success2, name2 = product_page.navigate_to_product_by_index(2)

    assert success2, "Failed to navigate to second product"
    details2 = product_page.get_all_product_details()

    assert name1 != name2, f"Product names should be different"
    logger.info(f"✓ Successfully navigated to multiple products")
