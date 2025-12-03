"""
Intelligent Locator Extractor
Extracts optimal locators from web pages automatically.

Author: Marc Arévalo
Version: 1.0
"""

import logging
import re
from typing import Dict, List, Optional, Tuple

from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.remote.webelement import WebElement

logger = logging.getLogger(__name__)


class LocatorExtractor:
    """
    Intelligently extracts optimal locators from web pages.

    Features:
    - Prefers stable locators (ID > name > CSS > XPath)
    - Generates meaningful element names
    - Identifies element purpose (login_button, username_field, etc.)
    - Handles modals, forms, navigation
    - Generates unique, descriptive locators
    """

    # Element type priorities (ID is most stable)
    LOCATOR_PRIORITY = ["id", "name", "css", "xpath"]

    def __init__(self, driver: WebDriver):
        """
        Initialize locator extractor.

        Args:
            driver: Selenium WebDriver instance
        """
        self.driver = driver

    def extract_page_locators(
        self, page_name: str, page_type: str
    ) -> Dict[str, dict]:
        """
        Extract all relevant locators from current page.

        Args:
            page_name: Name of page (e.g., "login", "catalog")
            page_type: Type of page (e.g., "login", "catalog", "form")

        Returns:
            Dict mapping element names to locator info
        """
        logger.info(f"Extracting locators for {page_name} ({page_type})")

        locators = {}

        # Extract different element types
        locators.update(self._extract_inputs(page_name))
        locators.update(self._extract_buttons(page_name))
        locators.update(self._extract_links(page_name))
        locators.update(self._extract_selects(page_name))
        locators.update(self._extract_textareas(page_name))

        # Extract modals if present
        if self._has_modals():
            locators.update(self._extract_modals(page_name))

        # Extract navigation
        locators.update(self._extract_navigation(page_name))

        logger.info(f"Extracted {len(locators)} locators for {page_name}")

        return locators

    def _extract_inputs(self, page_name: str) -> Dict[str, dict]:
        """Extract input field locators."""
        locators = {}

        try:
            inputs = self.driver.find_elements(By.TAG_NAME, "input")

            for idx, input_elem in enumerate(inputs):
                # Skip hidden inputs
                if not input_elem.is_displayed():
                    continue

                element_name = self._generate_input_name(
                    input_elem, page_name, idx
                )
                locator = self._get_best_locator(input_elem)

                if locator:
                    locators[element_name] = locator

        except Exception as e:
            logger.warning(f"Error extracting inputs: {e}")

        return locators

    def _extract_buttons(self, page_name: str) -> Dict[str, dict]:
        """Extract button locators."""
        locators = {}

        try:
            # Find <button> tags
            buttons = self.driver.find_elements(By.TAG_NAME, "button")

            # Also find input[type="submit"] and input[type="button"]
            submit_buttons = self.driver.find_elements(
                By.CSS_SELECTOR, "input[type='submit'], input[type='button']"
            )

            all_buttons = buttons + submit_buttons

            for idx, button in enumerate(all_buttons):
                if not button.is_displayed():
                    continue

                element_name = self._generate_button_name(
                    button, page_name, idx
                )
                locator = self._get_best_locator(button)

                if locator:
                    locators[element_name] = locator

        except Exception as e:
            logger.warning(f"Error extracting buttons: {e}")

        return locators

    def _extract_links(self, page_name: str) -> Dict[str, dict]:
        """Extract important link locators."""
        locators = {}

        try:
            # Focus on navigation and important links
            nav_links = self.driver.find_elements(
                By.CSS_SELECTOR, "nav a, header a, .navbar a, .nav a"
            )

            for idx, link in enumerate(nav_links):
                if not link.is_displayed():
                    continue

                element_name = self._generate_link_name(link, page_name, idx)
                locator = self._get_best_locator(link)

                if locator:
                    locators[element_name] = locator

        except Exception as e:
            logger.warning(f"Error extracting links: {e}")

        return locators

    def _extract_selects(self, page_name: str) -> Dict[str, dict]:
        """Extract select/dropdown locators."""
        locators = {}

        try:
            selects = self.driver.find_elements(By.TAG_NAME, "select")

            for idx, select in enumerate(selects):
                if not select.is_displayed():
                    continue

                element_name = self._generate_select_name(
                    select, page_name, idx
                )
                locator = self._get_best_locator(select)

                if locator:
                    locators[element_name] = locator

        except Exception as e:
            logger.warning(f"Error extracting selects: {e}")

        return locators

    def _extract_textareas(self, page_name: str) -> Dict[str, dict]:
        """Extract textarea locators."""
        locators = {}

        try:
            textareas = self.driver.find_elements(By.TAG_NAME, "textarea")

            for idx, textarea in enumerate(textareas):
                if not textarea.is_displayed():
                    continue

                element_name = self._generate_textarea_name(
                    textarea, page_name, idx
                )
                locator = self._get_best_locator(textarea)

                if locator:
                    locators[element_name] = locator

        except Exception as e:
            logger.warning(f"Error extracting textareas: {e}")

        return locators

    def _extract_modals(self, page_name: str) -> Dict[str, dict]:
        """Extract modal dialog locators."""
        locators = {}

        try:
            # Find modal containers
            modal_selectors = [
                ".modal",
                "[role='dialog']",
                ".dialog",
                ".popup",
            ]

            for selector in modal_selectors:
                modals = self.driver.find_elements(By.CSS_SELECTOR, selector)

                for idx, modal in enumerate(modals):
                    element_name = f"{page_name}_modal_container_{idx}"
                    locator = self._get_best_locator(modal)

                    if locator:
                        locators[element_name] = locator

                    # Extract close button
                    try:
                        close_btn = modal.find_element(
                            By.CSS_SELECTOR,
                            ".close, [data-dismiss], .modal-close",
                        )
                        close_name = f"{page_name}_modal_close_button_{idx}"
                        close_locator = self._get_best_locator(close_btn)

                        if close_locator:
                            locators[close_name] = close_locator
                    except:
                        pass

        except Exception as e:
            logger.warning(f"Error extracting modals: {e}")

        return locators

    def _extract_navigation(self, page_name: str) -> Dict[str, dict]:
        """Extract navigation menu locators."""
        locators = {}

        try:
            # Extract main navigation
            nav_selectors = [
                "nav",
                "header nav",
                ".navbar",
                "[role='navigation']",
            ]

            for selector in nav_selectors:
                try:
                    nav = self.driver.find_element(By.CSS_SELECTOR, selector)
                    element_name = f"{page_name}_navigation"
                    locator = self._get_best_locator(nav)

                    if locator:
                        locators[element_name] = locator
                        break  # Found main navigation
                except:
                    continue

        except Exception as e:
            logger.warning(f"Error extracting navigation: {e}")

        return locators

    def _get_best_locator(self, element: WebElement) -> Optional[dict]:
        """
        Get best locator for element (prefers ID > name > CSS > XPath).

        Args:
            element: WebElement to get locator for

        Returns:
            Dict with locator info or None
        """
        # Try ID first (most stable)
        element_id = element.get_attribute("id")
        if element_id:
            return {"by": "id", "value": element_id}

        # Try name attribute
        name = element.get_attribute("name")
        if name:
            return {"by": "name", "value": name}

        # Try class (if unique and meaningful)
        classes = element.get_attribute("class")
        if classes:
            # Check if class seems unique
            class_list = classes.split()
            for class_name in class_list:
                if self._is_meaningful_class(class_name):
                    # Verify uniqueness
                    try:
                        elements = self.driver.find_elements(
                            By.CLASS_NAME, class_name
                        )
                        if len(elements) == 1:
                            return {"by": "class", "value": class_name}
                    except:
                        pass

        # Generate CSS selector
        css_selector = self._generate_css_selector(element)
        if css_selector:
            return {"by": "css", "value": css_selector}

        # Fallback to XPath (least stable)
        xpath = self._generate_xpath(element)
        if xpath:
            return {"by": "xpath", "value": xpath}

        return None

    def _generate_css_selector(self, element: WebElement) -> Optional[str]:
        """Generate CSS selector for element."""
        try:
            # Try to build meaningful CSS selector
            tag = element.tag_name
            element_id = element.get_attribute("id")
            classes = element.get_attribute("class")

            if element_id:
                return f"{tag}#{element_id}"

            if classes:
                class_list = [
                    c for c in classes.split() if self._is_meaningful_class(c)
                ]
                if class_list:
                    return f"{tag}.{'.'.join(class_list)}"

            return None
        except:
            return None

    def _generate_xpath(self, element: WebElement) -> Optional[str]:
        """Generate XPath for element."""
        try:
            # Simple XPath generation (can be improved)
            tag = element.tag_name
            text = element.text.strip() if element.text else None

            if text and len(text) < 50:
                # Use text-based XPath if text is short
                return f"//{tag}[contains(text(), '{text}')]"

            # Fallback to position-based XPath
            return f"//{tag}"

        except:
            return None

    def _generate_input_name(
        self, element: WebElement, page_name: str, index: int
    ) -> str:
        """Generate meaningful name for input field."""
        # Check input type
        input_type = element.get_attribute("type") or "text"

        # Check placeholder, name, or label
        placeholder = element.get_attribute("placeholder") or ""
        name = element.get_attribute("name") or ""

        # Try to identify purpose from attributes
        purpose = None

        if any(
            keyword in placeholder.lower()
            for keyword in ["user", "email", "login"]
        ):
            purpose = "username"
        elif any(
            keyword in placeholder.lower() for keyword in ["pass", "pwd"]
        ):
            purpose = "password"
        elif any(keyword in name.lower() for keyword in ["user", "email"]):
            purpose = "username"
        elif any(keyword in name.lower() for keyword in ["pass", "pwd"]):
            purpose = "password"
        elif input_type == "email":
            purpose = "email"
        elif input_type == "password":
            purpose = "password"
        elif input_type == "search":
            purpose = "search"

        if purpose:
            return f"{page_name}_{purpose}_field"

        # Generic name
        return f"{page_name}_{input_type}_input_{index}"

    def _generate_button_name(
        self, element: WebElement, page_name: str, index: int
    ) -> str:
        """Generate meaningful name for button."""
        text = element.text.strip().lower() if element.text else ""
        value = element.get_attribute("value") or ""

        # Identify button purpose
        if any(keyword in text for keyword in ["login", "sign in", "log in"]):
            return f"{page_name}_login_button"
        elif any(
            keyword in text for keyword in ["signup", "sign up", "register"]
        ):
            return f"{page_name}_signup_button"
        elif any(keyword in text for keyword in ["submit", "send"]):
            return f"{page_name}_submit_button"
        elif any(keyword in text for keyword in ["cancel", "close"]):
            return f"{page_name}_cancel_button"
        elif any(keyword in text for keyword in ["save"]):
            return f"{page_name}_save_button"
        elif any(keyword in text for keyword in ["delete", "remove"]):
            return f"{page_name}_delete_button"
        elif any(keyword in text for keyword in ["add", "cart"]):
            return f"{page_name}_add_button"
        elif text:
            # Use button text as name
            clean_text = re.sub(r"[^a-z0-9_]", "_", text)
            return f"{page_name}_{clean_text}_button"

        # Generic name
        return f"{page_name}_button_{index}"

    def _generate_link_name(
        self, element: WebElement, page_name: str, index: int
    ) -> str:
        """Generate meaningful name for link."""
        text = element.text.strip().lower() if element.text else ""

        if text:
            # Clean text for variable name
            clean_text = re.sub(r"[^a-z0-9_]", "_", text)
            return f"{page_name}_{clean_text}_link"

        # Generic name
        return f"{page_name}_link_{index}"

    def _generate_select_name(
        self, element: WebElement, page_name: str, index: int
    ) -> str:
        """Generate meaningful name for select/dropdown."""
        name = element.get_attribute("name") or ""

        if name:
            clean_name = re.sub(r"[^a-z0-9_]", "_", name.lower())
            return f"{page_name}_{clean_name}_select"

        return f"{page_name}_select_{index}"

    def _generate_textarea_name(
        self, element: WebElement, page_name: str, index: int
    ) -> str:
        """Generate meaningful name for textarea."""
        placeholder = element.get_attribute("placeholder") or ""
        name = element.get_attribute("name") or ""

        if placeholder:
            clean_text = re.sub(r"[^a-z0-9_]", "_", placeholder.lower())
            return f"{page_name}_{clean_text}_textarea"
        elif name:
            clean_name = re.sub(r"[^a-z0-9_]", "_", name.lower())
            return f"{page_name}_{clean_name}_textarea"

        return f"{page_name}_textarea_{index}"

    def _is_meaningful_class(self, class_name: str) -> bool:
        """Check if class name is meaningful (not generic CSS framework class)."""
        # Skip common CSS framework classes
        generic_classes = [
            "btn",
            "button",
            "form",
            "input",
            "container",
            "row",
            "col",
            "flex",
            "grid",
            "d-flex",
            "text",
            "bg",
            "p-",
            "m-",
            "w-",
            "h-",
        ]

        for generic in generic_classes:
            if generic in class_name.lower():
                return False

        return len(class_name) > 2

    def _has_modals(self) -> bool:
        """Check if page has modal dialogs."""
        try:
            modal_selectors = [
                ".modal",
                "[role='dialog']",
                ".dialog",
                ".popup",
            ]

            for selector in modal_selectors:
                modals = self.driver.find_elements(By.CSS_SELECTOR, selector)
                if modals:
                    return True

            return False
        except:
            return False
