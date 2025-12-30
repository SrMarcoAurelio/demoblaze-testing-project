"""
Unit Tests for ElementFinder - Universal Test Automation Framework
Author: Marc Arévalo
Version: 1.0

Tests for the ElementFinder core component.
"""

import pytest
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from unittest.mock import Mock, MagicMock, patch

from framework.core.element_finder import ElementFinder


class TestElementFinder:
    """Test suite for ElementFinder class"""

    @pytest.fixture
    def mock_driver(self):
        """Create a mock WebDriver for testing"""
        driver = Mock()
        driver.name = "chrome"
        return driver

    @pytest.fixture
    def finder(self, mock_driver):
        """Create ElementFinder instance with mock driver"""
        return ElementFinder(mock_driver)

    def test_init(self, mock_driver):
        """Test ElementFinder initialization"""
        finder = ElementFinder(mock_driver)
        assert finder.driver == mock_driver
        assert finder.logger is not None

    def test_find_element_success(self, finder, mock_driver):
        """Test successful element finding"""
        mock_element = Mock()
        mock_driver.find_element.return_value = mock_element

        result = finder.find_element(By.ID, "test-id")

        assert result == mock_element
        mock_driver.find_element.assert_called_once_with(By.ID, "test-id")

    def test_find_element_not_found(self, finder, mock_driver):
        """Test element not found returns None"""
        mock_driver.find_element.side_effect = NoSuchElementException()

        result = finder.find_element(By.ID, "nonexistent")

        assert result is None

    def test_find_element_with_context(self, finder):
        """Test finding element within a parent context"""
        mock_context = Mock()
        mock_element = Mock()
        mock_context.find_element.return_value = mock_element

        result = finder.find_element(
            By.CSS_SELECTOR, ".child", context=mock_context
        )

        assert result == mock_element
        mock_context.find_element.assert_called_once_with(
            By.CSS_SELECTOR, ".child"
        )

    def test_find_elements_success(self, finder, mock_driver):
        """Test finding multiple elements"""
        mock_elements = [Mock(), Mock(), Mock()]
        mock_driver.find_elements.return_value = mock_elements

        result = finder.find_elements(By.CLASS_NAME, "product")

        assert result == mock_elements
        assert len(result) == 3
        mock_driver.find_elements.assert_called_once_with(
            By.CLASS_NAME, "product"
        )

    def test_find_elements_none_found(self, finder, mock_driver):
        """Test finding elements returns empty list when none found"""
        mock_driver.find_elements.return_value = []

        result = finder.find_elements(By.CLASS_NAME, "nonexistent")

        assert result == []
        assert len(result) == 0

    def test_find_element_with_fallback_first_succeeds(self, finder):
        """Test fallback when first strategy succeeds"""
        mock_element = Mock()
        finder.find_element = Mock(return_value=mock_element)

        locators = [
            (By.ID, "primary"),
            (By.NAME, "secondary"),
            (By.XPATH, "//backup"),
        ]

        result = finder.find_element_with_fallback(locators)

        assert result == mock_element
        finder.find_element.assert_called_once_with(By.ID, "primary")

    def test_find_element_with_fallback_second_succeeds(self, finder):
        """Test fallback when second strategy succeeds"""
        mock_element = Mock()
        finder.find_element = Mock(side_effect=[None, mock_element, None])

        locators = [
            (By.ID, "primary"),
            (By.NAME, "secondary"),
            (By.XPATH, "//backup"),
        ]

        result = finder.find_element_with_fallback(locators)

        assert result == mock_element
        assert finder.find_element.call_count == 2

    def test_find_element_with_fallback_all_fail(self, finder):
        """Test fallback when all strategies fail"""
        finder.find_element = Mock(return_value=None)

        locators = [
            (By.ID, "primary"),
            (By.NAME, "secondary"),
            (By.XPATH, "//backup"),
        ]

        result = finder.find_element_with_fallback(locators)

        assert result is None
        assert finder.find_element.call_count == 3

    def test_find_by_text_exact(self, finder):
        """Test finding element by exact text"""
        mock_element = Mock()
        finder.find_element = Mock(return_value=mock_element)

        result = finder.find_by_text("Login", tag="button", exact=True)

        expected_xpath = "//button[text()='Login']"
        finder.find_element.assert_called_once_with(
            By.XPATH, expected_xpath, None
        )
        assert result == mock_element

    def test_find_by_text_partial(self, finder):
        """Test finding element by partial text"""
        mock_element = Mock()
        finder.find_element = Mock(return_value=mock_element)

        result = finder.find_by_text("Welcome", exact=False)

        expected_xpath = "//*[contains(text(), 'Welcome')]"
        finder.find_element.assert_called_once_with(
            By.XPATH, expected_xpath, None
        )
        assert result == mock_element

    def test_find_by_attribute(self, finder):
        """Test finding element by attribute"""
        mock_element = Mock()
        finder.find_element = Mock(return_value=mock_element)

        result = finder.find_by_attribute("data-test", "login-btn")

        expected_xpath = "//*[@data-test='login-btn']"
        finder.find_element.assert_called_once_with(By.XPATH, expected_xpath)
        assert result == mock_element

    def test_find_by_partial_attribute(self, finder):
        """Test finding element by partial attribute"""
        mock_element = Mock()
        finder.find_element = Mock(return_value=mock_element)

        result = finder.find_by_partial_attribute("class", "btn-primary")

        expected_xpath = "//*[contains(@class, 'btn-primary')]"
        finder.find_element.assert_called_once_with(By.XPATH, expected_xpath)
        assert result == mock_element

    def test_find_clickable_elements(self, finder):
        """Test finding all clickable elements"""
        mock_links = [Mock(), Mock()]
        mock_buttons = [Mock()]

        def side_effect(by, value):
            if value == "a":
                return mock_links
            elif value == "button":
                return mock_buttons
            return []

        finder.find_elements = Mock(side_effect=side_effect)

        result = finder.find_clickable_elements()

        assert len(result) >= 3
        assert finder.find_elements.call_count >= 2

    def test_find_input_elements(self, finder):
        """Test finding all input elements"""
        mock_inputs = [Mock(), Mock()]
        mock_textareas = [Mock()]

        def side_effect(by, value):
            if value == "input":
                return mock_inputs
            elif value == "textarea":
                return mock_textareas
            elif value == "select":
                return []
            return []

        finder.find_elements = Mock(side_effect=side_effect)

        result = finder.find_input_elements()

        assert len(result) == 3
        assert finder.find_elements.call_count == 3

    def test_find_forms(self, finder):
        """Test finding all forms"""
        mock_forms = [Mock(), Mock()]
        finder.find_elements = Mock(return_value=mock_forms)

        result = finder.find_forms()

        assert result == mock_forms
        assert len(result) == 2
        finder.find_elements.assert_called_once_with(By.TAG_NAME, "form")

    def test_find_links(self, finder):
        """Test finding all links"""
        mock_links = [Mock(), Mock(), Mock()]
        finder.find_elements = Mock(return_value=mock_links)

        result = finder.find_links()

        assert result == mock_links
        assert len(result) == 3
        finder.find_elements.assert_called_once_with(By.TAG_NAME, "a")

    def test_is_element_present_true(self, finder):
        """Test element presence check when element exists"""
        mock_element = Mock()
        finder.find_element = Mock(return_value=mock_element)

        result = finder.is_element_present(By.ID, "exists")

        assert result is True
        finder.find_element.assert_called_once_with(By.ID, "exists")

    def test_is_element_present_false(self, finder):
        """Test element presence check when element doesn't exist"""
        finder.find_element = Mock(return_value=None)

        result = finder.is_element_present(By.ID, "nonexistent")

        assert result is False

    def test_get_element_count(self, finder):
        """Test counting elements"""
        mock_elements = [Mock(), Mock(), Mock()]
        finder.find_elements = Mock(return_value=mock_elements)

        result = finder.get_element_count(By.CLASS_NAME, "item")

        assert result == 3
        finder.find_elements.assert_called_once_with(By.CLASS_NAME, "item")

    def test_get_element_count_zero(self, finder):
        """Test counting when no elements found"""
        finder.find_elements = Mock(return_value=[])

        result = finder.get_element_count(By.CLASS_NAME, "nonexistent")

        assert result == 0

    def test_str_representation(self, finder):
        """Test string representation"""
        result = str(finder)
        assert "ElementFinder" in result
        assert "chrome" in result

    def test_repr_representation(self, finder, mock_driver):
        """Test detailed representation"""
        result = repr(finder)
        assert "ElementFinder" in result
        assert "driver=" in result
