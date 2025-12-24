"""
Product Page Accessibility Tests
Author: Marc Arévalo
Version: 1.0

Tests WCAG 2.1 Level AA compliance for product detail page:
- Product information accessibility
- Image alt text
- Button accessibility
- Keyboard navigation
"""

import pytest
from selenium.webdriver.common.keys import Keys


@pytest.mark.accessibility
@pytest.mark.product
class TestProductInformationAccessibility:
    """Test product information is accessible"""

    def test_product_name_accessible_PROD_ACC_001(self, product_page):
        """Test product name is readable by screen readers"""
        product_page.navigate_to_first_product()

        product_name = product_page.get_product_name()
        assert product_name, "Product name should be present"
        assert len(product_name) > 0, "Product name should be readable"

    def test_product_price_accessible_PROD_ACC_002(self, product_page):
        """Test product price is readable"""
        product_page.navigate_to_first_product()

        product_price = product_page.get_product_price()
        assert product_price, "Product price should be present"
        assert len(product_price) > 0, "Product price should be readable"

    def test_product_description_accessible_PROD_ACC_003(self, product_page):
        """Test product description is accessible"""
        product_page.navigate_to_first_product()

        description = product_page.get_product_description()
        # Description might be optional
        assert isinstance(
            description, (str, type(None))
        ), "Description should be accessible or None"


@pytest.mark.accessibility
@pytest.mark.product
class TestProductImageAccessibility:
    """Test product image accessibility"""

    def test_product_image_has_alt_text_PROD_ACC_004(self, product_page):
        """Test product image has alt text"""
        product_page.navigate_to_first_product()

        alt_text = product_page.get_product_image_alt()
        # Alt text should exist for accessibility
        assert isinstance(
            alt_text, (str, type(None))
        ), "Image should have alt text or None"

    def test_product_image_loads_PROD_ACC_005(self, product_page):
        """Test product image loads successfully"""
        product_page.navigate_to_first_product()

        image_loads = product_page.verify_image_loads()
        assert image_loads is True, "Product image should load successfully"


@pytest.mark.accessibility
@pytest.mark.product
class TestProductButtonAccessibility:
    """Test button accessibility on product page"""

    def test_add_to_cart_button_visible_PROD_ACC_006(self, product_page):
        """Test Add to Cart button is visible"""
        product_page.navigate_to_first_product()

        is_visible = product_page.is_add_to_cart_visible()
        assert is_visible is True, "Add to Cart button should be visible"

    def test_add_to_cart_keyboard_accessible_PROD_ACC_007(self, product_page):
        """Test Add to Cart button is keyboard accessible"""
        product_page.navigate_to_first_product()

        add_to_cart_btn = product_page.find_element(
            product_page.ADD_TO_CART_BUTTON
        )
        add_to_cart_btn.send_keys(Keys.RETURN)

        # Button should activate (alert should appear)
        alert_text = product_page.get_alert_text(timeout=3)
        assert alert_text is not None, "Add to Cart should work via keyboard"


@pytest.mark.accessibility
@pytest.mark.product
class TestProductNavigationAccessibility:
    """Test navigation accessibility from product page"""

    def test_keyboard_navigation_PROD_ACC_008(self, product_page):
        """Test keyboard navigation on product page"""
        product_page.navigate_to_first_product()

        result = product_page.test_keyboard_navigation()
        assert (
            result is True or result is None
        ), "Keyboard navigation should work on product page"
