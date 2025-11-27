"""
Purchase/Order Page Object Model
Author: Marc Arévalo
Version: 1.0

This page object models the Purchase/Checkout functionality of DemoBlaze.
Contains all locators and actions related to order placement and payment.
"""

from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from pages.base_page import BasePage
import logging
import time
import re
import datetime

class PurchasePage(BasePage):
    """Purchase Page Object - handles order form and checkout"""

    # ============================================================================
    # LOCATORS
    # ============================================================================

    # Order Modal
    ORDER_MODAL = (By.ID, "orderModal")
    ORDER_MODAL_TITLE = (By.XPATH, "//div[@id='orderModal']//h5[@class='modal-title']")

    # Order Form Fields
    ORDER_NAME_FIELD = (By.ID, "name")
    ORDER_COUNTRY_FIELD = (By.ID, "country")
    ORDER_CITY_FIELD = (By.ID, "city")
    ORDER_CARD_FIELD = (By.ID, "card")
    ORDER_MONTH_FIELD = (By.ID, "month")
    ORDER_YEAR_FIELD = (By.ID, "year")

    # Order Form Buttons
    PURCHASE_BUTTON = (By.XPATH, "//button[text()='Purchase']")
    CLOSE_ORDER_MODAL_BUTTON = (By.XPATH, "//div[@id='orderModal']//button[@class='close']")
    CLOSE_ORDER_MODAL_BUTTON_TEXT = (By.XPATH, "//div[@id='orderModal']//button[text()='Close']")

    # Purchase Confirmation
    PURCHASE_CONFIRM_MODAL = (By.CLASS_NAME, "sweet-alert")
    PURCHASE_CONFIRM_MSG = (By.XPATH, "//h2[text()='Thank you for your purchase!']")
    PURCHASE_CONFIRM_TEXT = (By.CLASS_NAME, "sweet-alert")
    CONFIRM_OK_BUTTON = (By.XPATH, "//button[contains(@class, 'confirm')]")

    # Cart Total (visible in modal context)
    CART_TOTAL_PRICE = (By.ID, "totalp")

    # ============================================================================
    # ORDER MODAL OPERATIONS
    # ============================================================================

    def is_order_modal_visible(self):
        """Check if order modal is open"""
        try:
            modal = self.find_element(self.ORDER_MODAL)
            return modal.is_displayed()
        except:
            return False

    def wait_for_order_modal(self, timeout=10):
        """Wait for order modal to appear"""
        try:
            self.wait_for_element_visible(self.ORDER_NAME_FIELD, timeout=timeout)
            self.logger.info("Order modal opened")
            return True
        except TimeoutException:
            self.logger.error("Order modal did not appear")
            return False

    def close_order_modal_with_x(self):
        """Close order modal using X button"""
        close_btn = self.find_element(self.CLOSE_ORDER_MODAL_BUTTON)
        close_btn.click()

        # Wait for modal to close
        try:
            WebDriverWait(self.driver, 10).until(
                EC.invisibility_of_element_located(self.ORDER_MODAL)
            )
            self.logger.info("Order modal closed with X button")
            return True
        except TimeoutException:
            return False

    def close_order_modal_with_close_button(self):
        """Close order modal using Close button"""
        close_btn = self.find_element(self.CLOSE_ORDER_MODAL_BUTTON_TEXT)
        close_btn.click()

        try:
            WebDriverWait(self.driver, 10).until(
                EC.invisibility_of_element_located(self.ORDER_MODAL)
            )
            self.logger.info("Order modal closed with Close button")
            return True
        except TimeoutException:
            return False

    def close_order_modal_with_escape(self):
        """Close order modal using ESC key"""
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.ESCAPE).perform()

        try:
            WebDriverWait(self.driver, 5).until(
                EC.invisibility_of_element_located(self.ORDER_MODAL)
            )
            self.logger.info("Order modal closed with ESC key")
            return True
        except TimeoutException:
            self.logger.info("Order modal did NOT close with ESC key")
            return False

    # ============================================================================
    # FORM FILLING
    # ============================================================================

    def fill_order_form(self, name="", country="", city="", card="", month="", year=""):
        """Fill all order form fields"""
        try:
            # Wait for form to be ready
            self.wait_for_element_visible(self.ORDER_NAME_FIELD)

            # Fill Name
            name_field = self.find_element(self.ORDER_NAME_FIELD)
            name_field.clear()
            if name:
                name_field.send_keys(name)

            # Fill Country
            country_field = self.find_element(self.ORDER_COUNTRY_FIELD)
            country_field.clear()
            if country:
                country_field.send_keys(country)

            # Fill City
            city_field = self.find_element(self.ORDER_CITY_FIELD)
            city_field.clear()
            if city:
                city_field.send_keys(city)

            # Fill Card
            card_field = self.find_element(self.ORDER_CARD_FIELD)
            card_field.clear()
            if card:
                card_field.send_keys(card)

            # Fill Month
            month_field = self.find_element(self.ORDER_MONTH_FIELD)
            month_field.clear()
            if month:
                month_field.send_keys(month)

            # Fill Year
            year_field = self.find_element(self.ORDER_YEAR_FIELD)
            year_field.clear()
            if year:
                year_field.send_keys(year)

            self.logger.info(f"Filled order form: {name}, {country}, {city}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to fill order form: {str(e)}")
            return False

    def fill_valid_order_form(self, name="QA Tester", country="Spain", city="Barcelona"):
        """Fill form with valid test data"""
        return self.fill_order_form(
            name=name,
            country=country,
            city=city,
            card="1234567890123456",
            month="12",
            year="2028"
        )

    def get_form_field_value(self, field_locator):
        """Get current value of a form field"""
        try:
            field = self.find_element(field_locator)
            return field.get_attribute("value")
        except:
            return None

    # ============================================================================
    # FORM NAVIGATION (Tab Order Testing)
    # ============================================================================

    def navigate_form_with_tab(self, fill_data=None):
        """
        Navigate through form fields using Tab key
        Optionally fill data as you go
        Returns: List of field values
        """
        if fill_data is None:
            fill_data = ["Test1", "Test2", "Test3", "Test4", "Test5", "Test6"]

        # Click first field to start
        name_field = self.find_element(self.ORDER_NAME_FIELD)
        name_field.click()

        actions = ActionChains(self.driver)

        # Tab through fields and fill
        for i, data in enumerate(fill_data):
            active_element = self.driver.switch_to.active_element
            active_element.send_keys(data)
            actions.send_keys(Keys.TAB).perform()
            self.logger.info(f"Tabbed to field {i+2}/{len(fill_data)+1}")

        # Verify values
        filled_values = {
            'name': self.get_form_field_value(self.ORDER_NAME_FIELD),
            'country': self.get_form_field_value(self.ORDER_COUNTRY_FIELD),
            'city': self.get_form_field_value(self.ORDER_CITY_FIELD),
            'card': self.get_form_field_value(self.ORDER_CARD_FIELD),
            'month': self.get_form_field_value(self.ORDER_MONTH_FIELD),
            'year': self.get_form_field_value(self.ORDER_YEAR_FIELD)
        }

        return filled_values

    # ============================================================================
    # PURCHASE EXECUTION
    # ============================================================================

    def click_purchase(self):
        """Click Purchase button"""
        purchase_btn = self.find_element(self.PURCHASE_BUTTON)
        purchase_btn.click()
        self.logger.info("Clicked Purchase button")
        return True

    def is_purchase_button_enabled(self):
        """Check if Purchase button is enabled"""
        try:
            btn = self.find_element(self.PURCHASE_BUTTON)
            return btn.is_enabled()
        except:
            return False

    def rapid_purchase_clicks(self, times=3):
        """Click Purchase button multiple times rapidly"""
        purchase_btn = self.find_element(self.PURCHASE_BUTTON)

        for i in range(times):
            purchase_btn.click()
            self.logger.info(f"Purchase click {i+1}")

        return True

    def complete_purchase(self, name="QA Tester", country="Spain", city="Barcelona",
                         card="1234567890123456", month="12", year="2028"):
        """
        Complete entire purchase flow:
        1. Fill form
        2. Click Purchase
        3. Get confirmation
        4. Close confirmation
        Returns: (success, confirmation_text, confirmed_amount)
        """
        # Fill form
        self.fill_order_form(name, country, city, card, month, year)

        # Get expected total before purchase
        time.sleep(0.5)

        # Click purchase
        self.click_purchase()

        # Wait for confirmation
        try:
            confirm_msg = WebDriverWait(self.driver, 10).until(
                EC.visibility_of_element_located(self.PURCHASE_CONFIRM_MSG)
            )

            # Get confirmation details
            confirm_modal = self.find_element(self.PURCHASE_CONFIRM_MODAL)
            confirm_text = confirm_modal.text

            # Extract amount from confirmation
            amount_match = re.search(r'Amount:\s*(\d+)\s*USD', confirm_text)
            confirmed_amount = int(amount_match.group(1)) if amount_match else 0

            # Extract other details
            card_match = re.search(r'Card Number:\s*(\d+)', confirm_text)
            name_match = re.search(r'Name:\s*(.+)', confirm_text, re.MULTILINE)

            details = {
                'amount': confirmed_amount,
                'card': card_match.group(1) if card_match else None,
                'name': name_match.group(1).strip() if name_match else None,
                'full_text': confirm_text
            }

            self.logger.info(f"Purchase confirmed: ${confirmed_amount}")

            # Close confirmation
            self.close_purchase_confirmation()

            return (True, confirm_text, details)

        except TimeoutException:
            self.logger.error("Purchase confirmation did not appear")
            return (False, None, None)

    # ============================================================================
    # PURCHASE CONFIRMATION
    # ============================================================================

    def is_purchase_confirmed(self, timeout=10):
        """Check if purchase confirmation appeared"""
        try:
            WebDriverWait(self.driver, timeout).until(
                EC.visibility_of_element_located(self.PURCHASE_CONFIRM_MSG)
            )
            return True
        except TimeoutException:
            return False

    def get_purchase_confirmation_text(self):
        """Get full text of purchase confirmation"""
        try:
            confirm_modal = self.find_element(self.PURCHASE_CONFIRM_MODAL)
            return confirm_modal.text
        except:
            return None

    def get_confirmed_amount(self):
        """Extract confirmed amount from confirmation modal"""
        confirm_text = self.get_purchase_confirmation_text()
        if confirm_text:
            amount_match = re.search(r'Amount:\s*(\d+)\s*USD', confirm_text)
            if amount_match:
                return int(amount_match.group(1))
        return None

    def close_purchase_confirmation(self):
        """Click OK on purchase confirmation"""
        try:
            ok_btn = self.find_element(self.CONFIRM_OK_BUTTON)
            ok_btn.click()

            # Wait for modal to close
            WebDriverWait(self.driver, 10).until(
                EC.invisibility_of_element_located(self.PURCHASE_CONFIRM_MODAL)
            )

            self.logger.info("Purchase confirmation closed")
            return True
        except:
            return False

    # ============================================================================
    # VALIDATION HELPERS
    # ============================================================================

    def get_current_year(self):
        """Get current year for validation tests"""
        return datetime.date.today().year

    def get_expired_year(self):
        """Get an expired year for validation tests"""
        return str(datetime.date.today().year - 1)

    def create_validation_test_data(self):
        """Create standard test data for validation tests"""
        return {
            'valid': {
                'name': 'QA Tester',
                'country': 'Spain',
                'city': 'Barcelona',
                'card': '1234567890123456',
                'month': '12',
                'year': '2028'
            },
            'invalid_card_format': {
                'name': 'Test',
                'country': 'Spain',
                'city': 'Madrid',
                'card': 'ABCD-1234',
                'month': '12',
                'year': '2028'
            },
            'short_card': {
                'name': 'Test',
                'country': 'Spain',
                'city': 'Madrid',
                'card': '123',
                'month': '12',
                'year': '2028'
            },
            'expired_card': {
                'name': 'Test',
                'country': 'Spain',
                'city': 'Madrid',
                'card': '1234567890123456',
                'month': '12',
                'year': self.get_expired_year()
            },
            'invalid_month': {
                'name': 'Test',
                'country': 'Spain',
                'city': 'Madrid',
                'card': '1234567890123456',
                'month': '13',
                'year': '2028'
            },
            'sql_injection': {
                'name': "' OR '1'='1",
                'country': 'Spain',
                'city': 'Madrid',
                'card': '1234567890123456',
                'month': '12',
                'year': '2028'
            },
            'xss': {
                'name': 'Test',
                'country': 'Spain',
                'city': "<script>alert('XSS')</script>",
                'card': '1234567890123456',
                'month': '12',
                'year': '2028'
            }
        }

    # ============================================================================
    # ADDITIONAL MODALS (Contact, About Us)
    # ============================================================================

    CONTACT_NAV_LINK = (By.XPATH, "//a[text()='Contact']")
    CONTACT_EMAIL_FIELD = (By.ID, "recipient-email")
    CONTACT_NAME_FIELD = (By.ID, "recipient-name")
    CONTACT_MESSAGE_FIELD = (By.ID, "message-text")
    CONTACT_SEND_BUTTON = (By.XPATH, "//button[text()='Send message']")

    ABOUT_US_NAV_LINK = (By.XPATH, "//a[text()='About us']")
    ABOUT_US_MODAL = (By.ID, "videoModal")
    ABOUT_US_VIDEO = (By.ID, "example-video")
    ABOUT_US_CLOSE_BUTTON = (By.XPATH, "//div[@id='videoModal']//button[text()='Close']")

    def send_contact_message(self, email="test@example.com", name="Test User", message="Test message"):
        """Send a contact form message"""
        # Open contact modal
        self.click(self.CONTACT_NAV_LINK)
        self.wait_for_element_visible(self.CONTACT_EMAIL_FIELD)

        # Fill form
        self.type(self.CONTACT_EMAIL_FIELD, email)
        self.type(self.CONTACT_NAME_FIELD, name)
        self.type(self.CONTACT_MESSAGE_FIELD, message)

        # Send
        self.click(self.CONTACT_SEND_BUTTON)

        # Get alert
        alert_text = self.get_alert_text(timeout=5)
        self.logger.info(f"Contact form alert: {alert_text}")

        return alert_text

    def open_about_us(self):
        """Open About Us modal"""
        self.click(self.ABOUT_US_NAV_LINK)
        self.wait_for_element_visible(self.ABOUT_US_MODAL)
        return True

    def close_about_us(self):
        """Close About Us modal"""
        self.click(self.ABOUT_US_CLOSE_BUTTON)
        try:
            WebDriverWait(self.driver, 10).until(
                EC.invisibility_of_element_located(self.ABOUT_US_MODAL)
            )
            return True
        except TimeoutException:
            return False
