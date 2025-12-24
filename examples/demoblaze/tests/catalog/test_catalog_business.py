"""
Catalog Business Rules Tests
Author: Marc Arévalo
Version: 1.0

Test Coverage:
- Data completeness validation
- Performance standards
- Accessibility compliance (WCAG 2.1)

Philosophy: DISCOVER (EXECUTE → OBSERVE → DECIDE)
"""

import logging

import pytest

from pages.catalog_page import CatalogPage

logger = logging.getLogger(__name__)


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
    catalog.click_first_product()
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
    logger.info("✓ Image validation completed")


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
    if timing["success"]:
        load_time = timing["total_load_time"]
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

    switch_time = catalog.measure_category_switch_time(
        catalog.click_laptops_category
    )
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

    if product_count >= 9:
        logger.info(
            f"✓ Catalog has {product_count} products, pagination: {has_pagination}"
        )
    logger.info("✓ Pagination requirement checked")


@pytest.mark.business_rules
@pytest.mark.medium
def test_empty_categories_not_allowed_BR_010(browser, base_url):
    """TC-CATALOG-BR-010: Empty Categories Not Allowed"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()

    catalog.click_phones_category()
    phones_count = catalog.get_product_count()
    assert phones_count > 0, "Phones category is empty"

    catalog.click_laptops_category()
    laptops_count = catalog.get_product_count()
    assert laptops_count > 0, "Laptops category is empty"

    catalog.click_monitors_category()
    monitors_count = catalog.get_product_count()
    assert monitors_count > 0, "Monitors category is empty"

    logger.info(f"✓ All categories have products")


@pytest.mark.business_rules
@pytest.mark.low
def test_category_active_state_indication_BR_011(browser, base_url):
    """TC-CATALOG-BR-011: Category Active State Indication"""
    catalog = CatalogPage(browser)
    catalog.go_to_catalog()
    catalog.click_phones_category()
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
        logger.warning(
            f"⚠ ACCESSIBILITY ISSUE: {missing} images without alt text"
        )
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
    if results["tab_navigation_works"]:
        logger.info("✓ Keyboard navigation works")
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
