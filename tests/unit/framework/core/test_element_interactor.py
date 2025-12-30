"""
Unit Tests for ElementInteractor - Universal Test Automation Framework
Author: Marc Arévalo
Version: 1.0

Tests for the ElementInteractor core component.
"""

import pytest
from selenium.common.exceptions import (
    ElementNotInteractableException,
    JavascriptException,
)
from selenium.webdriver.common.keys import Keys
from unittest.mock import Mock, MagicMock, patch, call

from framework.core.element_interactor import ElementInteractor


class TestElementInteractor:
    """Test suite for ElementInteractor class"""

    @pytest.fixture
    def mock_driver(self):
        """Create a mock WebDriver for testing"""
        driver = Mock()
        driver.execute_script = Mock()
        return driver

    @pytest.fixture
    def interactor(self, mock_driver):
        """Create ElementInteractor instance"""
        return ElementInteractor(mock_driver)

    @pytest.fixture
    def mock_element(self):
        """Create a mock WebElement"""
        element = Mock()
        element.click = Mock()
        element.send_keys = Mock()
        element.clear = Mock()
        element.text = "Test text"
        element.is_displayed = Mock(return_value=True)
        element.is_enabled = Mock(return_value=True)
        element.is_selected = Mock(return_value=False)
        element.get_attribute = Mock(return_value="test-value")
        return element

    def test_init(self, mock_driver):
        """Test ElementInteractor initialization"""
        interactor = ElementInteractor(mock_driver)
        assert interactor.driver == mock_driver
        assert interactor.logger is not None

    def test_click_success(self, interactor, mock_element):
        """Test successful element click"""
        result = interactor.click(mock_element)

        assert result is True
        mock_element.click.assert_called_once()

    def test_click_with_retry(self, interactor, mock_element):
        """Test click retry on failure then success"""
        mock_element.click.side_effect = [
            ElementNotInteractableException(),
            None,  # Success on second try
        ]

        result = interactor.click(mock_element, retry=3)

        assert result is True
        assert mock_element.click.call_count == 2

    def test_click_all_retries_fail(self, interactor, mock_element):
        """Test click failure after all retries"""
        mock_element.click.side_effect = ElementNotInteractableException()

        result = interactor.click(mock_element, retry=3, force=False)

        assert result is False
        assert mock_element.click.call_count == 3

    def test_click_force_js_fallback(
        self, interactor, mock_driver, mock_element
    ):
        """Test force click with JS fallback"""
        mock_element.click.side_effect = ElementNotInteractableException()

        result = interactor.click(mock_element, force=True, retry=2)

        assert result is True
        mock_driver.execute_script.assert_called_once()

    def test_click_with_js_success(self, interactor, mock_driver, mock_element):
        """Test JavaScript click success"""
        result = interactor.click_with_js(mock_element)

        assert result is True
        mock_driver.execute_script.assert_called_once_with(
            "arguments[0].click();", mock_element
        )

    def test_click_with_js_failure(self, interactor, mock_driver, mock_element):
        """Test JavaScript click failure"""
        mock_driver.execute_script.side_effect = JavascriptException()

        result = interactor.click_with_js(mock_element)

        assert result is False

    def test_type_success(self, interactor, mock_element):
        """Test typing text into element"""
        result = interactor.type(mock_element, "test input")

        assert result is True
        mock_element.clear.assert_called_once()
        mock_element.send_keys.assert_called_once_with("test input")

    def test_type_without_clear(self, interactor, mock_element):
        """Test typing without clearing first"""
        result = interactor.type(mock_element, "append", clear_first=False)

        assert result is True
        mock_element.clear.assert_not_called()
        mock_element.send_keys.assert_called_once_with("append")

    def test_type_failure(self, interactor, mock_element):
        """Test type failure handling"""
        mock_element.send_keys.side_effect = Exception("Send keys failed")

        result = interactor.type(mock_element, "test")

        assert result is False

    @patch("time.sleep")
    def test_type_slowly(self, mock_sleep, interactor, mock_element):
        """Test slow typing with delay"""
        result = interactor.type_slowly(mock_element, "abc", delay=0.1)

        assert result is True
        mock_element.clear.assert_called_once()
        assert mock_element.send_keys.call_count == 3
        assert mock_sleep.call_count == 3

    def test_clear_success(self, interactor, mock_element):
        """Test clearing element"""
        result = interactor.clear(mock_element)

        assert result is True
        mock_element.clear.assert_called_once()

    def test_clear_failure(self, interactor, mock_element):
        """Test clear failure"""
        mock_element.clear.side_effect = Exception("Clear failed")

        result = interactor.clear(mock_element)

        assert result is False

    @patch("framework.core.element_interactor.Select")
    def test_select_by_visible_text(
        self, mock_select_class, interactor, mock_element
    ):
        """Test selecting dropdown option by visible text"""
        mock_select = Mock()
        mock_select_class.return_value = mock_select

        result = interactor.select_by_visible_text(mock_element, "Option 1")

        assert result is True
        mock_select_class.assert_called_once_with(mock_element)
        mock_select.select_by_visible_text.assert_called_once_with("Option 1")

    @patch("framework.core.element_interactor.Select")
    def test_select_by_value(self, mock_select_class, interactor, mock_element):
        """Test selecting dropdown option by value"""
        mock_select = Mock()
        mock_select_class.return_value = mock_select

        result = interactor.select_by_value(mock_element, "value1")

        assert result is True
        mock_select.select_by_value.assert_called_once_with("value1")

    @patch("framework.core.element_interactor.Select")
    def test_select_by_index(self, mock_select_class, interactor, mock_element):
        """Test selecting dropdown option by index"""
        mock_select = Mock()
        mock_select_class.return_value = mock_select

        result = interactor.select_by_index(mock_element, 2)

        assert result is True
        mock_select.select_by_index.assert_called_once_with(2)

    @patch("framework.core.element_interactor.Select")
    def test_get_select_options(
        self, mock_select_class, interactor, mock_element
    ):
        """Test getting dropdown options"""
        mock_option1 = Mock()
        mock_option1.text = "Option 1"
        mock_option2 = Mock()
        mock_option2.text = "Option 2"

        mock_select = Mock()
        mock_select.options = [mock_option1, mock_option2]
        mock_select_class.return_value = mock_select

        result = interactor.get_select_options(mock_element)

        assert result == ["Option 1", "Option 2"]
        assert len(result) == 2

    @patch("framework.core.element_interactor.ActionChains")
    def test_hover(self, mock_action_chains, interactor, mock_element):
        """Test hovering over element"""
        mock_actions = Mock()
        mock_action_chains.return_value = mock_actions
        mock_actions.move_to_element.return_value = mock_actions

        result = interactor.hover(mock_element)

        assert result is True
        mock_actions.move_to_element.assert_called_once_with(mock_element)
        mock_actions.perform.assert_called_once()

    @patch("framework.core.element_interactor.ActionChains")
    def test_double_click(self, mock_action_chains, interactor, mock_element):
        """Test double-clicking element"""
        mock_actions = Mock()
        mock_action_chains.return_value = mock_actions
        mock_actions.double_click.return_value = mock_actions

        result = interactor.double_click(mock_element)

        assert result is True
        mock_actions.double_click.assert_called_once_with(mock_element)
        mock_actions.perform.assert_called_once()

    @patch("framework.core.element_interactor.ActionChains")
    def test_right_click(self, mock_action_chains, interactor, mock_element):
        """Test right-clicking element"""
        mock_actions = Mock()
        mock_action_chains.return_value = mock_actions
        mock_actions.context_click.return_value = mock_actions

        result = interactor.right_click(mock_element)

        assert result is True
        mock_actions.context_click.assert_called_once_with(mock_element)
        mock_actions.perform.assert_called_once()

    @patch("framework.core.element_interactor.ActionChains")
    def test_drag_and_drop(self, mock_action_chains, interactor):
        """Test drag and drop"""
        mock_source = Mock()
        mock_target = Mock()
        mock_actions = Mock()
        mock_action_chains.return_value = mock_actions
        mock_actions.drag_and_drop.return_value = mock_actions

        result = interactor.drag_and_drop(mock_source, mock_target)

        assert result is True
        mock_actions.drag_and_drop.assert_called_once_with(
            mock_source, mock_target
        )
        mock_actions.perform.assert_called_once()

    def test_scroll_to_element(self, interactor, mock_driver, mock_element):
        """Test scrolling to element"""
        result = interactor.scroll_to_element(mock_element)

        assert result is True
        mock_driver.execute_script.assert_called_once()
        call_args = mock_driver.execute_script.call_args[0]
        assert "scrollIntoView" in call_args[0]
        assert call_args[1] == mock_element

    def test_send_keys(self, interactor, mock_element):
        """Test sending special keys"""
        result = interactor.send_keys(mock_element, Keys.ENTER)

        assert result is True
        mock_element.send_keys.assert_called_once_with(Keys.ENTER)

    def test_send_multiple_keys(self, interactor, mock_element):
        """Test sending multiple keys"""
        result = interactor.send_keys(mock_element, Keys.CONTROL, "a")

        assert result is True
        mock_element.send_keys.assert_called_once_with(Keys.CONTROL, "a")

    def test_get_text(self, interactor, mock_element):
        """Test getting element text"""
        result = interactor.get_text(mock_element)

        assert result == "Test text"

    def test_get_text_failure(self, interactor, mock_element):
        """Test get text failure returns empty string"""
        mock_element.text = property(
            lambda self: (_ for _ in ()).throw(Exception())
        )

        result = interactor.get_text(mock_element)

        assert result == ""

    def test_get_attribute(self, interactor, mock_element):
        """Test getting element attribute"""
        result = interactor.get_attribute(mock_element, "href")

        assert result == "test-value"
        mock_element.get_attribute.assert_called_once_with("href")

    def test_get_attribute_failure(self, interactor, mock_element):
        """Test get attribute failure returns None"""
        mock_element.get_attribute.side_effect = Exception()

        result = interactor.get_attribute(mock_element, "href")

        assert result is None

    def test_is_displayed(self, interactor, mock_element):
        """Test checking if element is displayed"""
        result = interactor.is_displayed(mock_element)

        assert result is True
        mock_element.is_displayed.assert_called_once()

    def test_is_displayed_failure(self, interactor, mock_element):
        """Test is_displayed returns False on exception"""
        mock_element.is_displayed.side_effect = Exception()

        result = interactor.is_displayed(mock_element)

        assert result is False

    def test_is_enabled(self, interactor, mock_element):
        """Test checking if element is enabled"""
        result = interactor.is_enabled(mock_element)

        assert result is True
        mock_element.is_enabled.assert_called_once()

    def test_is_selected(self, interactor, mock_element):
        """Test checking if element is selected"""
        result = interactor.is_selected(mock_element)

        assert result is False
        mock_element.is_selected.assert_called_once()

    def test_str_representation(self, interactor):
        """Test string representation"""
        result = str(interactor)
        assert result == "ElementInteractor"

    def test_repr_representation(self, interactor, mock_driver):
        """Test detailed representation"""
        result = repr(interactor)
        assert "ElementInteractor" in result
        assert "driver=" in result
