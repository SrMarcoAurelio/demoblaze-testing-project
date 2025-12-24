"""
Purchase/Checkout Page Object Model - TEMPLATE
Author: Marc Arevalo
Version: 6.0

IMPORTANT: This is a TEMPLATE/EXAMPLE for checkout/order page object.
The locators shown here are EXAMPLES and MUST be adapted to YOUR application's
actual element IDs, classes, and structure.

This template demonstrates:
- Checkout/order form functionality
- Form field interaction
- Form validation testing
- Payment processing patterns
- Keyboard navigation (Tab through fields)

ADAPTATION REQUIRED:
1. Update ALL locators to match your application's elements
2. Modify methods if your checkout flow differs (shipping, billing, payment gateways, etc.)
3. Consider loading locators from config/locators.json
4. Test thoroughly with YOUR application

For applications with different checkout patterns (multi-step, separate shipping/billing,
payment gateways like Stripe/PayPal, guest checkout, etc.), use this as inspiration but
create appropriate implementations.
"""

import datetime
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from .base_page import BasePage


class PurchasePage(BasePage):
    """
    TEMPLATE Page Object for Purchase/Checkout functionality.

    This template demonstrates a modal-based checkout pattern.
    Adapt all locators and logic to match YOUR application.

    Handles:
    - Order form display and interaction
    - Form field population
    - Purchase submission
    - Confirmation handling
    - Form validation testing
    - Accessibility testing (keyboard navigation)

    IMPORTANT: All locators below are EXAMPLES and must be replaced
    with your application's actual element locators.
    """

    # ========================================================================
    # ORDER MODAL LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    # If your app uses modal-based checkout:
    ORDER_MODAL = (By.ID, "order-modal")  # EXAMPLE - adapt to your app
    ORDER_MODAL_TITLE = (
        By.XPATH,
        "//div[@id='order-modal']//h5[@class='modal-title']",
    )  # EXAMPLE

    # ========================================================================
    # FORM FIELD LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    ORDER_NAME_FIELD = (By.ID, "customer-name")  # EXAMPLE
    ORDER_COUNTRY_FIELD = (By.ID, "country")  # EXAMPLE
    ORDER_CITY_FIELD = (By.ID, "city")  # EXAMPLE
    ORDER_CARD_FIELD = (By.ID, "card-number")  # EXAMPLE
    ORDER_MONTH_FIELD = (By.ID, "expiry-month")  # EXAMPLE
    ORDER_YEAR_FIELD = (By.ID, "expiry-year")  # EXAMPLE

    # Your app may have additional fields:
    # ORDER_ADDRESS_FIELD = (By.ID, "address")
    # ORDER_ZIP_FIELD = (By.ID, "zip-code")
    # ORDER_CVV_FIELD = (By.ID, "cvv")
    # ORDER_EMAIL_FIELD = (By.ID, "email")
    # ORDER_PHONE_FIELD = (By.ID, "phone")

    # ========================================================================
    # BUTTON LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    PURCHASE_BUTTON = (By.XPATH, "//button[text()='Purchase']")  # EXAMPLE
    CLOSE_ORDER_MODAL_BUTTON = (
        By.XPATH,
        "//div[@id='order-modal']//button[@class='close']",
    )  # EXAMPLE
    CLOSE_ORDER_MODAL_BUTTON_TEXT = (
        By.XPATH,
        "//div[@id='order-modal']//button[text()='Close']",
    )  # EXAMPLE

    # ========================================================================
    # CONFIRMATION LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    PURCHASE_CONFIRM_MODAL = (By.CLASS_NAME, "confirmation-modal")  # EXAMPLE
    PURCHASE_CONFIRM_MSG = (
        By.XPATH,
        "//h2[text()='Thank you for your purchase!']",
    )  # EXAMPLE
    PURCHASE_CONFIRM_TEXT = (By.CLASS_NAME, "confirmation-modal")  # EXAMPLE
    CONFIRM_OK_BUTTON = (
        By.XPATH,
        "//button[contains(@class, 'confirm')]",
    )  # EXAMPLE

    # ========================================================================
    # OTHER LOCATORS - ADAPT TO YOUR APPLICATION
    # ========================================================================
    CART_TOTAL_PRICE = (By.ID, "cart-total")  # EXAMPLE

    # ========================================================================
    # MODAL VISIBILITY METHODS - Adapt to your application
    # ========================================================================

    def is_order_modal_visible(self) -> bool:
        """
        Check if order modal is open.

        TEMPLATE METHOD - Adapt to your application's checkout display.
        If your app uses a separate checkout page instead of modal,
        check for page URL or main checkout element.

        Returns:
            True if modal/checkout is visible

        Example:
            >>> cart_page.click_place_order()
            >>> assert purchase_page.is_order_modal_visible()
        """
        try:
            modal = self.find_element(self.ORDER_MODAL)
            return modal.is_displayed()
        except Exception:
            return False

    def wait_for_order_modal(self, timeout: int = 10) -> bool:
        """
        Wait for order modal to appear.

        TEMPLATE METHOD - Adapt to your application.

        Args:
            timeout: Maximum time to wait

        Returns:
            True if modal appeared

        Example:
            >>> cart_page.click_place_order()
            >>> assert purchase_page.wait_for_order_modal()
        """
        try:
            self.wait_for_element_visible(
                self.ORDER_NAME_FIELD, timeout=timeout
            )
            self.logger.info("Order modal opened")
            return True
        except TimeoutException:
            self.logger.error("Order modal did not appear")
            return False

    # ========================================================================
    # MODAL CLOSING METHODS - Adapt to your application
    # ========================================================================

    def close_order_modal_with_x(self) -> bool:
        """
        Close order modal using X button.

        TEMPLATE METHOD - Adapt to your application.

        Returns:
            True if modal closed

        Example:
            >>> purchase_page.close_order_modal_with_x()
            >>> assert not purchase_page.is_order_modal_visible()
        """
        close_btn = self.find_element(self.CLOSE_ORDER_MODAL_BUTTON)
        close_btn.click()

        try:
            WebDriverWait(self.driver, 10).until(
                EC.invisibility_of_element_located(self.ORDER_MODAL)
            )
            self.logger.info("Order modal closed with X button")
            return True
        except TimeoutException:
            return False

    def close_order_modal_with_close_button(self) -> bool:
        """
        Close order modal using Close button.

        TEMPLATE METHOD - Adapt to your application.

        Returns:
            True if modal closed
        """
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

    def close_order_modal_with_escape(self) -> bool:
        """
        Close order modal using ESC key.

        TEMPLATE METHOD - Accessibility testing utility.
        Tests if ESC key closes the modal (good UX practice).

        Returns:
            True if modal closed with ESC

        Example:
            >>> purchase_page.wait_for_order_modal()
            >>> assert purchase_page.close_order_modal_with_escape()
        """
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

    # ========================================================================
    # FORM FILLING METHODS - Adapt to your application
    # ========================================================================

    def fill_order_form(
        self,
        name: str = "",
        country: str = "",
        city: str = "",
        card: str = "",
        month: str = "",
        year: str = "",
    ) -> bool:
        """
        Fill all order form fields.

        TEMPLATE METHOD - Adapt to YOUR application's form fields.
        Your app may have different fields (address, zip, email, phone, etc.).

        Args:
            name: Customer name
            country: Country
            city: City
            card: Credit card number
            month: Expiry month
            year: Expiry year

        Returns:
            True if form filled successfully

        Example:
            >>> purchase_page.fill_order_form(
            ...     name="Test User",
            ...     country="USA",
            ...     city="New York",
            ...     card="4532015112830366",
            ...     month="12",
            ...     year="2025"
            ... )
        """
        try:
            self.wait_for_element_visible(self.ORDER_NAME_FIELD)

            name_field = self.find_element(self.ORDER_NAME_FIELD)
            name_field.clear()
            if name:
                name_field.send_keys(name)

            country_field = self.find_element(self.ORDER_COUNTRY_FIELD)
            country_field.clear()
            if country:
                country_field.send_keys(country)

            city_field = self.find_element(self.ORDER_CITY_FIELD)
            city_field.clear()
            if city:
                city_field.send_keys(city)

            card_field = self.find_element(self.ORDER_CARD_FIELD)
            card_field.clear()
            if card:
                card_field.send_keys(card)

            month_field = self.find_element(self.ORDER_MONTH_FIELD)
            month_field.clear()
            if month:
                month_field.send_keys(month)

            year_field = self.find_element(self.ORDER_YEAR_FIELD)
            year_field.clear()
            if year:
                year_field.send_keys(year)

            self.logger.info(f"Filled order form: {name}, {country}, {city}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to fill order form: {str(e)}")
            return False

    def fill_valid_order_form(
        self,
        name: str = "Test User",
        country: str = "Test Country",
        city: str = "Test City",
    ) -> bool:
        """
        Fill form with valid test data.

        TEMPLATE METHOD - Convenience method for testing.
        Adapt the default values to valid test data for YOUR application.

        Args:
            name: Customer name (default: "Test User")
            country: Country (default: "Test Country")
            city: City (default: "Test City")

        Returns:
            True if form filled successfully

        Example:
            >>> purchase_page.fill_valid_order_form()
            >>> purchase_page.click_purchase()
            >>> assert purchase_page.is_purchase_confirmed()
        """
        # EXAMPLE test data - replace with YOUR valid test data
        return self.fill_order_form(
            name=name,
            country=country,
            city=city,
            card="4532015112830366",  # Test Visa card number
            month="12",
            year="2028",
        )

    def get_form_field_value(
        self, field_locator: Tuple[str, str]
    ) -> Optional[str]:
        """
        Get current value of a form field.

        TEMPLATE METHOD - Form field utility.

        Args:
            field_locator: Locator for the field

        Returns:
            Field value or None

        Example:
            >>> purchase_page.fill_order_form(name="John Doe", ...)
            >>> name = purchase_page.get_form_field_value(purchase_page.ORDER_NAME_FIELD)
            >>> assert name == "John Doe"
        """
        try:
            field = self.find_element(field_locator)
            return field.get_attribute("value")
        except Exception:
            return None

    # ========================================================================
    # KEYBOARD NAVIGATION METHODS - Accessibility testing
    # ========================================================================

    def navigate_form_with_tab(
        self, fill_data: Optional[List[str]] = None
    ) -> Dict[str, Optional[str]]:
        """
        Navigate through form fields using Tab key.

        TEMPLATE METHOD - Accessibility testing utility.
        Tests that users can Tab through form fields.

        Args:
            fill_data: Optional list of data to fill as you Tab

        Returns:
            Dict of field values after navigation

        Example:
            >>> values = purchase_page.navigate_form_with_tab(
            ...     ["Name", "USA", "NYC", "4532015112830366", "12", "2025"]
            ... )
            >>> assert values["name"] == "Name"
        """
        if fill_data is None:
            fill_data = ["Test1", "Test2", "Test3", "Test4", "Test5", "Test6"]

        name_field = self.find_element(self.ORDER_NAME_FIELD)
        name_field.click()

        actions = ActionChains(self.driver)

        for i, data in enumerate(fill_data):
            active_element = self.driver.switch_to.active_element
            active_element.send_keys(data)
            actions.send_keys(Keys.TAB).perform()
            self.logger.info(f"Tabbed to field {i+2}/{len(fill_data)+1}")

        filled_values = {
            "name": self.get_form_field_value(self.ORDER_NAME_FIELD),
            "country": self.get_form_field_value(self.ORDER_COUNTRY_FIELD),
            "city": self.get_form_field_value(self.ORDER_CITY_FIELD),
            "card": self.get_form_field_value(self.ORDER_CARD_FIELD),
            "month": self.get_form_field_value(self.ORDER_MONTH_FIELD),
            "year": self.get_form_field_value(self.ORDER_YEAR_FIELD),
        }

        return filled_values

    # ========================================================================
    # PURCHASE SUBMISSION METHODS - Adapt to your application
    # ========================================================================

    def click_purchase(self) -> bool:
        """
        Click Purchase button.

        TEMPLATE METHOD - Adapt to your application's submission button.

        Returns:
            True if button clicked

        Example:
            >>> purchase_page.fill_valid_order_form()
            >>> assert purchase_page.click_purchase()
        """
        purchase_btn = self.find_element(self.PURCHASE_BUTTON)
        purchase_btn.click()
        self.logger.info("Clicked Purchase button")
        return True

    def is_purchase_button_enabled(self) -> bool:
        """
        Check if Purchase button is enabled.

        TEMPLATE METHOD - Useful for testing form validation.

        Returns:
            True if button is enabled

        Example:
            >>> # Button should be disabled until form is valid
            >>> assert not purchase_page.is_purchase_button_enabled()
            >>> purchase_page.fill_valid_order_form()
            >>> assert purchase_page.is_purchase_button_enabled()
        """
        try:
            btn = self.find_element(self.PURCHASE_BUTTON)
            return btn.is_enabled()
        except Exception:
            return False

    def rapid_purchase_clicks(self, times: int = 3) -> bool:
        """
        Click Purchase button multiple times rapidly.

        TEMPLATE METHOD - Tests duplicate submission prevention.
        Good UX prevents duplicate orders from accidental double-clicks.

        Args:
            times: Number of times to click

        Returns:
            True if clicks completed

        Example:
            >>> purchase_page.fill_valid_order_form()
            >>> purchase_page.rapid_purchase_clicks(3)
            >>> # Should only create ONE order, not three
        """
        purchase_btn = self.find_element(self.PURCHASE_BUTTON)

        for i in range(times):
            purchase_btn.click()
            self.logger.info(f"Purchase click {i+1}")

        return True

    def complete_purchase(
        self,
        name: str = "Test User",
        country: str = "Test Country",
        city: str = "Test City",
        card: str = "4532015112830366",
        month: str = "12",
        year: str = "2028",
    ) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Complete entire purchase flow.

        TEMPLATE METHOD - Full checkout workflow.
        Steps: Fill form -> Click Purchase -> Get confirmation -> Close confirmation

        Args:
            name: Customer name
            country: Country
            city: City
            card: Credit card number
            month: Expiry month
            year: Expiry year

        Returns:
            Tuple of (success, confirmation_text, details_dict)

        Example:
            >>> success, msg, details = purchase_page.complete_purchase()
            >>> assert success
            >>> assert "Thank you" in msg
            >>> assert details["amount"] > 0
        """
        self.fill_order_form(name, country, city, card, month, year)

        time.sleep(0.5)  # Brief pause for form processing

        self.click_purchase()

        try:
            # Wait for confirmation message
            confirm_msg = WebDriverWait(self.driver, 10).until(
                EC.visibility_of_element_located(self.PURCHASE_CONFIRM_MSG)
            )

            confirm_modal = self.find_element(self.PURCHASE_CONFIRM_MODAL)
            confirm_text = confirm_modal.text

            # EXAMPLE: Parse confirmation details
            # Adapt to YOUR application's confirmation format
            amount_match = re.search(r"Amount:\s*(\d+)\s*USD", confirm_text)
            confirmed_amount = (
                int(amount_match.group(1)) if amount_match else 0
            )

            card_match = re.search(r"Card Number:\s*(\d+)", confirm_text)
            name_match = re.search(r"Name:\s*(.+)", confirm_text, re.MULTILINE)

            details = {
                "amount": confirmed_amount,
                "card": card_match.group(1) if card_match else None,
                "name": name_match.group(1).strip() if name_match else None,
                "full_text": confirm_text,
            }

            self.logger.info(f"Purchase confirmed: ${confirmed_amount}")

            self.close_purchase_confirmation()

            return (True, confirm_text, details)

        except TimeoutException:
            self.logger.error("Purchase confirmation did not appear")
            return (False, None, None)

    # ========================================================================
    # CONFIRMATION METHODS - Adapt to your application
    # ========================================================================

    def is_purchase_confirmed(self, timeout: int = 10) -> bool:
        """
        Check if purchase confirmation appeared.

        TEMPLATE METHOD - Adapt to your application's confirmation display.

        Args:
            timeout: Maximum time to wait

        Returns:
            True if confirmation appeared

        Example:
            >>> purchase_page.complete_purchase()
            >>> assert purchase_page.is_purchase_confirmed()
        """
        try:
            WebDriverWait(self.driver, timeout).until(
                EC.visibility_of_element_located(self.PURCHASE_CONFIRM_MSG)
            )
            return True
        except TimeoutException:
            return False

    def get_purchase_confirmation_text(self) -> Optional[str]:
        """
        Get full text of purchase confirmation.

        TEMPLATE METHOD - Adapt to your application.

        Returns:
            Confirmation text or None

        Example:
            >>> text = purchase_page.get_purchase_confirmation_text()
            >>> assert "Thank you" in text
        """
        try:
            confirm_modal = self.find_element(self.PURCHASE_CONFIRM_MODAL)
            return confirm_modal.text
        except Exception:
            return None

    def get_confirmed_amount(self) -> Optional[int]:
        """
        Extract confirmed amount from confirmation modal.

        TEMPLATE METHOD - Adapt to YOUR application's confirmation format.

        Returns:
            Amount as integer or None

        Example:
            >>> amount = purchase_page.get_confirmed_amount()
            >>> assert amount > 0
        """
        confirm_text = self.get_purchase_confirmation_text()
        if confirm_text:
            # EXAMPLE: Extract "Amount: 100 USD" -> 100
            # Adapt to YOUR application's format
            amount_match = re.search(r"Amount:\s*(\d+)\s*USD", confirm_text)
            if amount_match:
                return int(amount_match.group(1))
        return None

    def close_purchase_confirmation(self) -> bool:
        """
        Click OK on purchase confirmation.

        TEMPLATE METHOD - Adapt to your application.

        Returns:
            True if confirmation closed

        Example:
            >>> purchase_page.complete_purchase()
            >>> assert purchase_page.close_purchase_confirmation()
        """
        try:
            ok_btn = self.find_element(self.CONFIRM_OK_BUTTON)
            ok_btn.click()

            WebDriverWait(self.driver, 10).until(
                EC.invisibility_of_element_located(self.PURCHASE_CONFIRM_MODAL)
            )

            self.logger.info("Purchase confirmation closed")
            return True
        except Exception:
            return False

    # ========================================================================
    # TEST DATA GENERATION METHODS - Adapt to your application
    # ========================================================================

    def get_current_year(self) -> int:
        """
        Get current year for validation tests.

        TEMPLATE METHOD - Utility for generating test data.

        Returns:
            Current year

        Example:
            >>> year = purchase_page.get_current_year()
            >>> assert year >= 2025
        """
        return datetime.date.today().year

    def get_expired_year(self) -> str:
        """
        Get an expired year for validation tests.

        TEMPLATE METHOD - Utility for testing expired card validation.

        Returns:
            Last year as string

        Example:
            >>> expired = purchase_page.get_expired_year()
            >>> purchase_page.fill_order_form(..., year=expired)
            >>> # Should show validation error
        """
        return str(datetime.date.today().year - 1)

    def create_validation_test_data(self) -> Dict[str, Dict[str, str]]:
        """
        Create standard test data for validation tests.

        TEMPLATE METHOD - Provides various test cases.
        Adapt to YOUR application's validation rules.

        Returns:
            Dict of test case names to form data

        Example:
            >>> test_data = purchase_page.create_validation_test_data()
            >>> for case_name, data in test_data.items():
            ...     purchase_page.fill_order_form(**data)
            ...     # Test validation for this case
        """
        return {
            "valid": {
                "name": "Test User",
                "country": "Test Country",
                "city": "Test City",
                "card": "4532015112830366",  # Test Visa
                "month": "12",
                "year": "2028",
            },
            "invalid_card_format": {
                "name": "Test",
                "country": "USA",
                "city": "NYC",
                "card": "ABCD-1234",  # Letters in card
                "month": "12",
                "year": "2028",
            },
            "short_card": {
                "name": "Test",
                "country": "USA",
                "city": "NYC",
                "card": "123",  # Too short
                "month": "12",
                "year": "2028",
            },
            "expired_card": {
                "name": "Test",
                "country": "USA",
                "city": "NYC",
                "card": "4532015112830366",
                "month": "12",
                "year": self.get_expired_year(),  # Expired
            },
            "invalid_month": {
                "name": "Test",
                "country": "USA",
                "city": "NYC",
                "card": "4532015112830366",
                "month": "13",  # Month 13 doesn't exist
                "year": "2028",
            },
            "sql_injection": {
                "name": "' OR '1'='1",  # SQL injection attempt
                "country": "USA",
                "city": "NYC",
                "card": "4532015112830366",
                "month": "12",
                "year": "2028",
            },
            "xss": {
                "name": "Test",
                "country": "USA",
                "city": "<script>alert('XSS')</script>",  # XSS attempt
                "card": "4532015112830366",
                "month": "12",
                "year": "2028",
            },
        }

    # ========================================================================
    # ADDITIONAL FUNCTIONALITY - Contact form, About Us modal
    # These are EXAMPLES - remove if not applicable to your app
    # ========================================================================

    CONTACT_NAV_LINK = (By.XPATH, "//a[text()='Contact']")  # EXAMPLE
    CONTACT_EMAIL_FIELD = (By.ID, "contact-email")  # EXAMPLE
    CONTACT_NAME_FIELD = (By.ID, "contact-name")  # EXAMPLE
    CONTACT_MESSAGE_FIELD = (By.ID, "contact-message")  # EXAMPLE
    CONTACT_SEND_BUTTON = (
        By.XPATH,
        "//button[text()='Send message']",
    )  # EXAMPLE

    ABOUT_US_NAV_LINK = (By.XPATH, "//a[text()='About us']")  # EXAMPLE
    ABOUT_US_MODAL = (By.ID, "about-modal")  # EXAMPLE
    ABOUT_US_VIDEO = (By.ID, "about-video")  # EXAMPLE
    ABOUT_US_CLOSE_BUTTON = (
        By.XPATH,
        "//div[@id='about-modal']//button[text()='Close']",
    )  # EXAMPLE

    def send_contact_message(
        self,
        email: str = "test@example.com",
        name: str = "Test User",
        message: str = "Test message",
    ) -> Optional[str]:
        """
        Send a contact form message.

        TEMPLATE METHOD - EXAMPLE functionality.
        Remove if your app doesn't have contact form.

        Args:
            email: Email address
            name: Name
            message: Message text

        Returns:
            Alert text or None

        Example:
            >>> alert = purchase_page.send_contact_message()
            >>> assert "sent" in alert.lower()
        """
        self.click(self.CONTACT_NAV_LINK)
        self.wait_for_element_visible(self.CONTACT_EMAIL_FIELD)

        self.type(self.CONTACT_EMAIL_FIELD, email)
        self.type(self.CONTACT_NAME_FIELD, name)
        self.type(self.CONTACT_MESSAGE_FIELD, message)

        self.click(self.CONTACT_SEND_BUTTON)

        alert_text = self.get_alert_text(timeout=5)
        self.logger.info(f"Contact form alert: {alert_text}")

        return alert_text

    def open_about_us(self) -> bool:
        """
        Open About Us modal.

        TEMPLATE METHOD - EXAMPLE functionality.
        Remove if your app doesn't have about page.

        Returns:
            True if modal opened
        """
        self.click(self.ABOUT_US_NAV_LINK)
        self.wait_for_element_visible(self.ABOUT_US_MODAL)
        return True

    def close_about_us(self) -> bool:
        """
        Close About Us modal.

        TEMPLATE METHOD - EXAMPLE functionality.

        Returns:
            True if modal closed
        """
        self.click(self.ABOUT_US_CLOSE_BUTTON)
        try:
            WebDriverWait(self.driver, 10).until(
                EC.invisibility_of_element_located(self.ABOUT_US_MODAL)
            )
            return True
        except TimeoutException:
            return False


# ============================================================================
# USAGE EXAMPLE - How to adapt this template to your application
# ============================================================================
"""
EXAMPLE ADAPTATION:

1. Update locators to match your application:
   ORDER_NAME_FIELD = (By.ID, "your-name-field-id")
   ORDER_CARD_FIELD = (By.ID, "your-card-field-id")
   # ... etc

2. If your app has multi-step checkout (shipping, billing, payment):
   def fill_shipping_info(self, name: str, address: str, city: str, zip: str):
       self.type(self.SHIPPING_NAME, name)
       self.type(self.SHIPPING_ADDRESS, address)
       self.type(self.SHIPPING_CITY, city)
       self.type(self.SHIPPING_ZIP, zip)
       self.click(self.NEXT_BUTTON)

   def fill_billing_info(self, ...):
       # Similar to shipping
       self.click(self.NEXT_BUTTON)

   def fill_payment_info(self, card: str, cvv: str, ...):
       # Payment details
       self.click(self.COMPLETE_ORDER_BUTTON)

3. If your app uses payment gateways (Stripe, PayPal, etc.):
   STRIPE_IFRAME = (By.CSS_SELECTOR, "iframe[name*='stripe']")

   def fill_stripe_card(self, card_number: str, expiry: str, cvv: str):
       # Switch to Stripe iframe
       stripe_iframe = self.find_element(self.STRIPE_IFRAME)
       self.driver.switch_to.frame(stripe_iframe)

       # Fill Stripe fields
       self.type((By.NAME, "cardnumber"), card_number)
       self.type((By.NAME, "exp-date"), expiry)
       self.type((By.NAME, "cvc"), cvv)

       # Switch back
       self.driver.switch_to.default_content()

4. If your app has guest checkout vs logged-in checkout:
   GUEST_CHECKOUT_BUTTON = (By.ID, "guest-checkout")
   LOGIN_CHECKOUT_BUTTON = (By.ID, "login-checkout")

   def checkout_as_guest(self):
       self.click(self.GUEST_CHECKOUT_BUTTON)
       # Fill guest info

   def checkout_as_user(self, username: str, password: str):
       self.click(self.LOGIN_CHECKOUT_BUTTON)
       # Login then proceed

5. If your app sends order confirmation emails:
   def verify_confirmation_email_sent(self) -> bool:
       confirmation_text = self.get_purchase_confirmation_text()
       return confirmation_text and "email" in confirmation_text.lower()

6. Use discovery-based element finding:
   from framework.core import ElementFinder

   def fill_order_form(self, name: str, ...):
       name_field = self.finder.find_by_label("Full Name")
       if name_field:
           name_field.send_keys(name)
"""
