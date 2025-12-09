"""
Base Page Tests
Author: Marc Arévalo
Version: 1.0

Unit tests for BasePage core functionality:
- Element finding and waiting
- Clicking and typing
- Alert handling
- Navigation operations
- JavaScript execution
- Modal operations
- Screenshot and page source operations
"""

import os
import tempfile
import time
from pathlib import Path

import pytest
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

from pages.base_page import BasePage


class TestBasePageInitialization:
    """Test BasePage initialization"""

    def test_init_with_default_values_BASE_001(self, browser):
        """Test BasePage initialization with default values"""
        page = BasePage(browser)
        assert page.driver == browser
        assert page.timeout == 10
        assert page.base_url is not None
        assert page.logger is not None

    def test_init_with_custom_timeout_BASE_002(self, browser):
        """Test BasePage initialization with custom timeout"""
        page = BasePage(browser, timeout=20)
        assert page.timeout == 20

    def test_init_with_custom_base_url_BASE_003(self, browser):
        """Test BasePage initialization with custom base_url"""
        custom_url = "https://example.com"
        page = BasePage(browser, base_url=custom_url)
        assert page.base_url == custom_url


class TestElementFinding:
    """Test element finding methods"""

    def test_find_element_success_BASE_004(self, browser):
        """Test finding an element successfully"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        element = page.find_element((By.ID, "narvbar"))
        assert element is not None

    def test_find_element_timeout_BASE_005(self, browser):
        """Test find_element raises TimeoutException"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        with pytest.raises(TimeoutException):
            page.find_element((By.ID, "nonexistent-element"), timeout=1)

    def test_find_elements_success_BASE_006(self, browser):
        """Test finding multiple elements"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        elements = page.find_elements((By.CLASS_NAME, "nav-link"))
        assert len(elements) > 0

    def test_find_elements_empty_BASE_007(self, browser):
        """Test find_elements returns empty list when not found"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        elements = page.find_elements(
            (By.CLASS_NAME, "nonexistent-class"), timeout=1
        )
        assert elements == []


class TestElementWaiting:
    """Test element waiting methods"""

    def test_wait_for_element_visible_BASE_008(self, browser):
        """Test waiting for element to be visible"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        element = page.wait_for_element_visible((By.ID, "narvbar"))
        assert element is not None
        assert element.is_displayed()

    def test_wait_for_element_clickable_BASE_009(self, browser):
        """Test waiting for element to be clickable"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        element = page.wait_for_element_clickable((By.ID, "login2"))
        assert element is not None
        assert element.is_enabled()

    def test_wait_for_element_invisible_timeout_BASE_010(self, browser):
        """Test wait_for_element_invisible raises TimeoutException"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        # Element is visible, so waiting for invisibility should timeout
        with pytest.raises(TimeoutException):
            page.wait_for_element_invisible((By.ID, "narvbar"), timeout=1)


class TestElementInteraction:
    """Test element interaction methods"""

    def test_click_element_BASE_011(self, browser):
        """Test clicking an element"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        page.click((By.ID, "login2"))
        # Modal should appear after click
        time.sleep(0.5)
        assert page.is_element_visible((By.ID, "logInModal"))

    def test_type_with_clear_BASE_012(self, browser):
        """Test typing text with clearing first"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        page.click((By.ID, "login2"))
        page.type((By.ID, "loginusername"), "testuser", clear_first=True)
        value = page.get_attribute((By.ID, "loginusername"), "value")
        assert value == "testuser"

    def test_type_without_clear_BASE_013(self, browser):
        """Test typing text without clearing"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        page.click((By.ID, "login2"))
        page.type((By.ID, "loginusername"), "test", clear_first=False)
        page.type((By.ID, "loginusername"), "user", clear_first=False)
        value = page.get_attribute((By.ID, "loginusername"), "value")
        assert "testuser" in value


class TestGetMethods:
    """Test get methods for retrieving element data"""

    def test_get_text_BASE_014(self, browser):
        """Test getting text from element"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        text = page.get_text((By.LINK_TEXT, "Home"))
        assert text == "Home"

    def test_get_attribute_BASE_015(self, browser):
        """Test getting attribute from element"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        href = page.get_attribute((By.LINK_TEXT, "Home"), "href")
        assert "index.html" in href

    def test_is_element_present_true_BASE_016(self, browser):
        """Test is_element_present returns True"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        assert page.is_element_present((By.ID, "narvbar")) is True

    def test_is_element_present_false_BASE_017(self, browser):
        """Test is_element_present returns False"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        assert (
            page.is_element_present((By.ID, "nonexistent"), timeout=1) is False
        )

    def test_is_element_visible_true_BASE_018(self, browser):
        """Test is_element_visible returns True"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        assert page.is_element_visible((By.ID, "narvbar")) is True

    def test_is_element_visible_false_BASE_019(self, browser):
        """Test is_element_visible returns False"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        assert (
            page.is_element_visible((By.ID, "nonexistent"), timeout=1) is False
        )


class TestAlertHandling:
    """Test alert handling methods"""

    def test_wait_for_alert_none_BASE_020(self, browser):
        """Test wait_for_alert returns None when no alert"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        alert = page.wait_for_alert(timeout=1)
        assert alert is None

    def test_get_alert_text_none_BASE_021(self, browser):
        """Test get_alert_text returns None when no alert"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        text = page.get_alert_text(timeout=1)
        assert text is None


class TestNavigationMethods:
    """Test navigation methods"""

    def test_navigate_to_BASE_022(self, browser):
        """Test navigating to URL"""
        page = BasePage(browser)
        test_url = page.base_url
        page.navigate_to(test_url)
        assert test_url in page.get_current_url()

    def test_get_current_url_BASE_023(self, browser):
        """Test getting current URL"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        url = page.get_current_url()
        assert "demoblaze.com" in url or "localhost" in url

    def test_get_page_title_BASE_024(self, browser):
        """Test getting page title"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        title = page.get_page_title()
        assert "STORE" in title

    def test_refresh_page_BASE_025(self, browser):
        """Test refreshing the page"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        initial_url = page.get_current_url()
        page.refresh_page()
        assert page.get_current_url() == initial_url


class TestJavaScriptMethods:
    """Test JavaScript execution methods"""

    def test_execute_script_BASE_026(self, browser):
        """Test executing JavaScript"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        result = page.execute_script("return document.title")
        assert result is not None
        assert "STORE" in result

    def test_scroll_to_element_BASE_027(self, browser):
        """Test scrolling to element"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        # Scroll to footer or bottom element
        page.scroll_to_bottom()
        scroll_position = page.execute_script("return window.pageYOffset")
        assert scroll_position > 0

    def test_scroll_to_bottom_BASE_028(self, browser):
        """Test scrolling to bottom of page"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        page.scroll_to_bottom()
        scroll_position = page.execute_script("return window.pageYOffset")
        assert scroll_position > 0


class TestKeyboardMethods:
    """Test keyboard interaction methods"""

    def test_send_keys_BASE_029(self, browser):
        """Test sending keys to element"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        page.click((By.ID, "login2"))
        page.send_keys((By.ID, "loginusername"), "test")
        value = page.get_attribute((By.ID, "loginusername"), "value")
        assert "test" in value

    def test_press_key_BASE_030(self, browser):
        """Test pressing a key"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        page.click((By.ID, "login2"))
        time.sleep(0.3)
        page.press_key(Keys.ESCAPE)
        time.sleep(0.3)
        # Modal should close after ESC
        assert (
            page.is_element_visible((By.ID, "logInModal"), timeout=1) is False
        )


class TestModalOperations:
    """Test modal operation methods"""

    def test_is_modal_visible_true_BASE_031(self, browser):
        """Test is_modal_visible returns True"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        page.click((By.ID, "login2"))
        time.sleep(0.3)
        assert page.is_modal_visible((By.ID, "logInModal")) is True

    def test_is_modal_visible_false_BASE_032(self, browser):
        """Test is_modal_visible returns False"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        assert page.is_modal_visible((By.ID, "logInModal"), timeout=1) is False

    def test_close_modal_with_esc_BASE_033(self, browser):
        """Test closing modal with ESC key"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)
        page.click((By.ID, "login2"))
        time.sleep(0.3)
        page.close_modal_with_esc((By.ID, "logInModal"))
        assert page.is_modal_visible((By.ID, "logInModal"), timeout=1) is False


class TestUtilityMethods:
    """Test utility methods"""

    def test_wait_BASE_034(self, browser):
        """Test explicit wait"""
        page = BasePage(browser)
        start_time = time.time()
        page.wait(0.5)
        elapsed = time.time() - start_time
        assert elapsed >= 0.5

    def test_take_screenshot_BASE_035(self, browser):
        """Test taking screenshot"""
        page = BasePage(browser)
        page.navigate_to(page.base_url)

        with tempfile.TemporaryDirectory() as tmpdir:
            screenshot_path = str(Path(tmpdir) / "test_screenshot.png")
            page.take_screenshot(screenshot_path)
            assert os.path.exists(screenshot_path)
            assert os.path.getsize(screenshot_path) > 0
