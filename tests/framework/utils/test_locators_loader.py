"""
Unit Tests for locators_loader
Author: Marc Arévalo
Version: 1.0

Tests for external locators configuration system.
"""

import json
import os
import tempfile

import pytest
from selenium.webdriver.common.by import By

from utils.locators_loader import LocatorsLoader, get_loader, load_locator


class TestLocatorsLoader:
    """Tests for LocatorsLoader class"""

    @pytest.fixture
    def temp_locators_file(self):
        """Create temporary locators JSON file for testing"""
        locators_data = {
            "test_page": {
                "test_button": {"by": "id", "value": "btn_test"},
                "test_input": {"by": "xpath", "value": "//input[@id='test']"},
                "test_link": {"by": "link_text", "value": "Click Here"},
            },
            "another_page": {"element1": {"by": "css", "value": ".my-class"}},
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(locators_data, f)
            temp_path = f.name

        yield temp_path

        # Cleanup
        if os.path.exists(temp_path):
            os.remove(temp_path)

    def test_load_locators_success(self, temp_locators_file):
        """Test successful loading of locators"""
        loader = LocatorsLoader(temp_locators_file)
        assert loader.locators is not None
        assert "test_page" in loader.locators

    def test_load_locators_file_not_found(self):
        """Test error when config file doesn't exist"""
        with pytest.raises(FileNotFoundError):
            LocatorsLoader("nonexistent_file.json")

    def test_get_locator_success(self, temp_locators_file):
        """Test getting a valid locator"""
        loader = LocatorsLoader(temp_locators_file)
        locator = loader.get_locator("test_page", "test_button")

        assert locator == (By.ID, "btn_test")

    def test_get_locator_page_not_found(self, temp_locators_file):
        """Test error when page not found"""
        loader = LocatorsLoader(temp_locators_file)
        with pytest.raises(KeyError):
            loader.get_locator("nonexistent_page", "element")

    def test_get_locator_element_not_found(self, temp_locators_file):
        """Test error when element not found"""
        loader = LocatorsLoader(temp_locators_file)
        with pytest.raises(KeyError):
            loader.get_locator("test_page", "nonexistent_element")

    def test_get_locator_xpath(self, temp_locators_file):
        """Test getting XPATH locator"""
        loader = LocatorsLoader(temp_locators_file)
        locator = loader.get_locator("test_page", "test_input")

        assert locator == (By.XPATH, "//input[@id='test']")

    def test_get_locator_link_text(self, temp_locators_file):
        """Test getting LINK_TEXT locator"""
        loader = LocatorsLoader(temp_locators_file)
        locator = loader.get_locator("test_page", "test_link")

        assert locator == (By.LINK_TEXT, "Click Here")

    def test_get_locator_css(self, temp_locators_file):
        """Test getting CSS selector locator"""
        loader = LocatorsLoader(temp_locators_file)
        locator = loader.get_locator("another_page", "element1")

        assert locator == (By.CSS_SELECTOR, ".my-class")

    def test_get_page_locators(self, temp_locators_file):
        """Test getting all locators for a page"""
        loader = LocatorsLoader(temp_locators_file)
        page_locators = loader.get_page_locators("test_page")

        assert len(page_locators) == 3
        assert "test_button" in page_locators
        assert "test_input" in page_locators
        assert "test_link" in page_locators

    def test_get_all_pages(self, temp_locators_file):
        """Test getting list of all pages"""
        loader = LocatorsLoader(temp_locators_file)
        pages = loader.get_all_pages()

        assert "test_page" in pages
        assert "another_page" in pages

    def test_by_type_mapping(self, temp_locators_file):
        """Test all By type mappings work correctly"""
        loader = LocatorsLoader(temp_locators_file)

        # Test various By types
        assert loader.BY_MAPPING["id"] == By.ID
        assert loader.BY_MAPPING["name"] == By.NAME
        assert loader.BY_MAPPING["xpath"] == By.XPATH
        assert loader.BY_MAPPING["css"] == By.CSS_SELECTOR
        assert loader.BY_MAPPING["class"] == By.CLASS_NAME
        assert loader.BY_MAPPING["tag"] == By.TAG_NAME
        assert loader.BY_MAPPING["link_text"] == By.LINK_TEXT
        assert loader.BY_MAPPING["partial_link_text"] == By.PARTIAL_LINK_TEXT


class TestLocatorsLoaderHelpers:
    """Tests for helper functions"""

    def test_get_loader_singleton(self):
        """Test that get_loader returns singleton instance"""
        loader1 = get_loader()
        loader2 = get_loader()

        assert loader1 is loader2
