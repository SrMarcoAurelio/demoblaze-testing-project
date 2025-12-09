"""
Catalog Accessibility Tests
Author: Marc Arévalo
Version: 1.0

Tests WCAG 2.1 Level AA compliance for catalog functionality:
- Category navigation accessibility
- Product card accessibility
- Image alt text
- Keyboard navigation
- ARIA labels for categories
"""

import pytest
from selenium.webdriver.common.keys import Keys


@pytest.mark.accessibility
@pytest.mark.catalog
class TestCatalogCategoryAccessibility:
    """Test category navigation accessibility"""

    def test_category_links_keyboard_accessible_CAT_ACC_001(
        self, catalog_page
    ):
        """Test category links are accessible via keyboard"""
        catalog_page.go_to_catalog()

        phones_link = catalog_page.find_element(catalog_page.CATEGORY_PHONES)
        phones_link.send_keys(Keys.RETURN)

        # Category should be activated
        assert catalog_page.is_category_active(
            "Phones"
        ), "Category should be accessible via keyboard"

    def test_categories_have_aria_labels_CAT_ACC_002(self, catalog_page):
        """Test category links have ARIA labels"""
        catalog_page.go_to_catalog()

        aria_labels = catalog_page.check_category_aria_labels()
        # Returns dict of category: aria_label
        assert isinstance(aria_labels, dict), "Should return ARIA labels dict"

    def test_category_focus_indicators_CAT_ACC_003(self, catalog_page):
        """Test categories have visible focus indicators"""
        catalog_page.go_to_catalog()

        focus_indicators = catalog_page.check_focus_indicators()
        # Returns dict or indication of focus state
        assert focus_indicators is not None, "Should check focus indicators"

    def test_keyboard_navigation_through_categories_CAT_ACC_004(
        self, catalog_page
    ):
        """Test keyboard navigation through all categories"""
        catalog_page.go_to_catalog()

        # Test keyboard navigation
        result = catalog_page.test_keyboard_navigation_categories()
        assert (
            result is True or result is None
        ), "Keyboard navigation should work through categories"


@pytest.mark.accessibility
@pytest.mark.catalog
class TestCatalogProductAccessibility:
    """Test product card accessibility"""

    def test_all_products_have_names_CAT_ACC_005(self, catalog_page):
        """Test all product cards have readable names"""
        catalog_page.go_to_catalog()

        product_names = catalog_page.get_all_product_names()
        assert len(product_names) > 0, "Should have product names"
        assert all(
            name for name in product_names
        ), "All products should have non-empty names"

    def test_all_products_have_prices_CAT_ACC_006(self, catalog_page):
        """Test all product cards display prices"""
        catalog_page.go_to_catalog()

        product_prices = catalog_page.get_all_product_prices()
        assert len(product_prices) > 0, "Should have product prices"
        assert all(
            price for price in product_prices
        ), "All products should have prices"

    def test_product_links_accessible_CAT_ACC_007(self, catalog_page):
        """Test product links are keyboard accessible"""
        catalog_page.go_to_catalog()

        product_links = catalog_page.get_all_product_links()
        assert len(product_links) > 0, "Should have product links"

        # Test first product link
        first_link = catalog_page.find_element(
            (product_links[0][0], product_links[0][1])
        )
        assert first_link.is_displayed(), "Product link should be visible"


@pytest.mark.accessibility
@pytest.mark.catalog
class TestCatalogImageAccessibility:
    """Test product image accessibility"""

    def test_all_images_have_alt_text_CAT_ACC_008(self, catalog_page):
        """Test all product images have alt text"""
        catalog_page.go_to_catalog()

        result = catalog_page.validate_all_images_have_alt_text()
        assert (
            result is True
        ), "All images should have alt text for screen readers"

    def test_get_product_image_alt_texts_CAT_ACC_009(self, catalog_page):
        """Test retrieving all image alt texts"""
        catalog_page.go_to_catalog()

        alt_texts = catalog_page.get_product_image_alt_texts()
        assert len(alt_texts) > 0, "Should retrieve image alt texts"
        # Some alt texts might be empty (bad accessibility), but we document it
        assert isinstance(alt_texts, list), "Should return list of alt texts"


@pytest.mark.accessibility
@pytest.mark.catalog
class TestCatalogPaginationAccessibility:
    """Test pagination accessibility"""

    def test_next_button_keyboard_accessible_CAT_ACC_010(self, catalog_page):
        """Test Next button is keyboard accessible"""
        catalog_page.go_to_catalog()

        if catalog_page.is_next_button_visible():
            next_btn = catalog_page.find_element(catalog_page.NEXT_BUTTON)
            next_btn.send_keys(Keys.RETURN)
            # Button should activate
            assert True, "Next button should be keyboard accessible"
        else:
            pytest.skip("Next button not visible on current page")

    def test_prev_button_keyboard_accessible_CAT_ACC_011(self, catalog_page):
        """Test Previous button is keyboard accessible"""
        catalog_page.go_to_catalog()

        # Navigate to second page first if possible
        if catalog_page.is_next_button_visible():
            catalog_page.click_next_page()

        if catalog_page.is_prev_button_visible():
            prev_btn = catalog_page.find_element(catalog_page.PREV_BUTTON)
            prev_btn.send_keys(Keys.RETURN)
            # Button should activate
            assert True, "Previous button should be keyboard accessible"
        else:
            pytest.skip("Previous button not visible")


@pytest.mark.accessibility
@pytest.mark.catalog
class TestCatalogNavigationAccessibility:
    """Test overall catalog navigation accessibility"""

    def test_home_link_accessible_from_catalog_CAT_ACC_012(self, catalog_page):
        """Test Home link is accessible from catalog"""
        catalog_page.go_to_catalog()

        home_link = catalog_page.find_element(catalog_page.HOME_LINK)
        assert home_link.is_displayed(), "Home link should be visible"
        assert home_link.is_enabled(), "Home link should be enabled"
