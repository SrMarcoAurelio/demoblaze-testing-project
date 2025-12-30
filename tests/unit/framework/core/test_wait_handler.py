"""
Unit Tests for WaitHandler - Universal Test Automation Framework
Author: Marc Arévalo
Version: 1.0

Tests for the WaitHandler core component.
"""

import pytest
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from unittest.mock import Mock, MagicMock, patch

from framework.core.wait_handler import WaitHandler


class TestWaitHandler:
    """Test suite for WaitHandler class"""

    @pytest.fixture
    def mock_driver(self):
        """Create a mock WebDriver"""
        driver = Mock()
        return driver

    @pytest.fixture
    def wait_handler(self, mock_driver):
        """Create WaitHandler instance"""
        return WaitHandler(mock_driver, default_timeout=10, poll_frequency=0.5)

    def test_init(self, mock_driver):
        """Test WaitHandler initialization"""
        handler = WaitHandler(
            mock_driver, default_timeout=15, poll_frequency=0.25
        )

        assert handler.driver == mock_driver
        assert handler.default_timeout == 15
        assert handler.poll_frequency == 0.25
        assert handler.logger is not None

    @patch("framework.core.wait_handler.WebDriverWait")
    def test_wait_for_element_visible_success(
        self, mock_wait_class, wait_handler
    ):
        """Test waiting for visible element successfully"""
        mock_element = Mock()
        mock_wait = Mock()
        mock_wait.until.return_value = mock_element
        mock_wait_class.return_value = mock_wait

        result = wait_handler.wait_for_element_visible(By.ID, "test-id")

        assert result == mock_element
        mock_wait_class.assert_called_once()
        mock_wait.until.assert_called_once()

    @patch("framework.core.wait_handler.WebDriverWait")
    def test_wait_for_element_visible_timeout(
        self, mock_wait_class, wait_handler
    ):
        """Test waiting for visible element timeout"""
        mock_wait = Mock()
        mock_wait.until.side_effect = TimeoutException()
        mock_wait_class.return_value = mock_wait

        result = wait_handler.wait_for_element_visible(By.ID, "nonexistent")

        assert result is None

    @patch("framework.core.wait_handler.WebDriverWait")
    def test_wait_for_element_visible_custom_timeout(
        self, mock_wait_class, wait_handler
    ):
        """Test custom timeout parameter"""
        mock_element = Mock()
        mock_wait = Mock()
        mock_wait.until.return_value = mock_element
        mock_wait_class.return_value = mock_wait

        result = wait_handler.wait_for_element_visible(
            By.ID, "test-id", timeout=20
        )

        assert result == mock_element
        # Verify WebDriverWait was called with custom timeout
        call_args = mock_wait_class.call_args
        assert call_args[0][1] == 20  # timeout parameter

    @patch("framework.core.wait_handler.WebDriverWait")
    def test_wait_for_element_present(self, mock_wait_class, wait_handler):
        """Test waiting for element present in DOM"""
        mock_element = Mock()
        mock_wait = Mock()
        mock_wait.until.return_value = mock_element
        mock_wait_class.return_value = mock_wait

        result = wait_handler.wait_for_element_present(By.ID, "test-id")

        assert result == mock_element
        mock_wait.until.assert_called_once()

    @patch("framework.core.wait_handler.WebDriverWait")
    def test_wait_for_element_clickable(self, mock_wait_class, wait_handler):
        """Test waiting for element to be clickable"""
        mock_element = Mock()
        mock_wait = Mock()
        mock_wait.until.return_value = mock_element
        mock_wait_class.return_value = mock_wait

        result = wait_handler.wait_for_element_clickable(By.ID, "button")

        assert result == mock_element

    @patch("framework.core.wait_handler.WebDriverWait")
    def test_wait_for_element_invisible(self, mock_wait_class, wait_handler):
        """Test waiting for element to become invisible"""
        mock_wait = Mock()
        mock_wait.until.return_value = True
        mock_wait_class.return_value = mock_wait

        result = wait_handler.wait_for_element_invisible(By.ID, "modal")

        assert result is True

    @patch("framework.core.wait_handler.WebDriverWait")
    def test_wait_for_condition(self, mock_wait_class, wait_handler):
        """Test waiting for custom condition"""
        custom_condition = Mock(return_value=True)
        mock_wait = Mock()
        mock_wait.until.return_value = True
        mock_wait_class.return_value = mock_wait

        result = wait_handler.wait_for_condition(custom_condition, timeout=5)

        assert result is True
        mock_wait.until.assert_called_once_with(custom_condition)

    @patch("framework.core.wait_handler.WebDriverWait")
    def test_wait_for_condition_timeout(self, mock_wait_class, wait_handler):
        """Test custom condition timeout"""
        custom_condition = Mock()
        mock_wait = Mock()
        mock_wait.until.side_effect = TimeoutException()
        mock_wait_class.return_value = mock_wait

        result = wait_handler.wait_for_condition(custom_condition)

        assert result is False

    def test_str_representation(self, wait_handler):
        """Test string representation"""
        result = str(wait_handler)
        assert "WaitHandler" in result
        assert "10" in result  # default timeout

    def test_repr_representation(self, wait_handler):
        """Test detailed representation"""
        result = repr(wait_handler)
        assert "WaitHandler" in result
        assert "timeout=10" in result
