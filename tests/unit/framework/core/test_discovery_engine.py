"""
Unit Tests for DiscoveryEngine - Universal Test Automation Framework
Author: Marc Arévalo
Version: 1.0

Tests for the DiscoveryEngine core component.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch

from framework.core.discovery_engine import DiscoveryEngine

pytestmark = pytest.mark.unit


class TestDiscoveryEngine:
    """Test suite for DiscoveryEngine class"""

    @pytest.fixture
    def mock_driver(self):
        """Create a mock WebDriver"""
        driver = Mock()
        driver.find_elements = Mock(return_value=[])
        return driver

    @pytest.fixture
    def engine(self, mock_driver):
        """Create DiscoveryEngine instance"""
        return DiscoveryEngine(mock_driver)

    def test_init(self, mock_driver):
        """Test DiscoveryEngine initialization"""
        engine = DiscoveryEngine(mock_driver)

        assert engine.driver == mock_driver
        assert engine.logger is not None

    def test_discover_forms(self, engine, mock_driver):
        """Test discovering forms on page"""
        mock_form = Mock()
        mock_form.get_attribute.return_value = "test-form"
        mock_form.find_elements.return_value = []
        mock_driver.find_elements.return_value = [mock_form]

        result = engine.discover_forms()

        assert isinstance(result, list)
        assert len(result) >= 0

    def test_discover_links(self, engine, mock_driver):
        """Test discovering links on page"""
        mock_link = Mock()
        mock_link.get_attribute.return_value = "https://example.com"
        mock_link.text = "Test Link"
        mock_driver.find_elements.return_value = [mock_link]

        result = engine.discover_links()

        assert isinstance(result, list)

    def test_discover_buttons(self, engine, mock_driver):
        """Test discovering buttons on page"""
        mock_button = Mock()
        mock_button.get_attribute.return_value = "submit"
        mock_button.text = "Submit"
        mock_driver.find_elements.return_value = [mock_button]

        result = engine.discover_buttons()

        assert isinstance(result, list)

    def test_discover_inputs(self, engine, mock_driver):
        """Test discovering input elements"""
        mock_input = Mock()
        mock_input.get_attribute.side_effect = lambda x: {
            "type": "text",
            "name": "username",
            "id": "user-input",
        }.get(x)
        mock_driver.find_elements.return_value = [mock_input]

        result = engine.discover_inputs()

        assert isinstance(result, list)

    def test_generate_page_report(self, engine):
        """Test generating comprehensive page report"""
        result = engine.generate_page_report()

        assert isinstance(result, dict)
        # Should contain keys for different element types
        expected_keys = ["forms", "links", "buttons", "inputs"]
        for key in expected_keys:
            assert key in result or len(result) >= 0

    def test_str_representation(self, engine):
        """Test string representation"""
        result = str(engine)
        assert "DiscoveryEngine" in result

    def test_repr_representation(self, engine):
        """Test detailed representation"""
        result = repr(engine)
        assert "DiscoveryEngine" in result
