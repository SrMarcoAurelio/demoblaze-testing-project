"""
Discovery Engine - Universal Test Automation Framework
Author: Marc Arévalo
Version: 1.0

Automatically discovers page structure, forms, navigation, and interactive elements.
This is the KEY to universal testing: DISCOVER instead of ASSUME.

This engine makes the framework truly universal by eliminating assumptions
about page structure, form fields, or navigation patterns.
"""

import logging
from typing import Any, Dict, List, Optional, Set

from selenium.common.exceptions import (
    NoSuchElementException,
    StaleElementReferenceException,
)
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.remote.webelement import WebElement

from .element_finder import ElementFinder


class DiscoveryEngine:
    """
    Universal page structure discovery engine.

    Automatically discovers:
    - Forms and their fields
    - Input elements and types
    - Buttons and interactive elements
    - Navigation structure
    - Links and their destinations
    - Page metadata

    PHILOSOPHY: Tests should DISCOVER functionality, not ASSUME it.

    Example:
        discovery = DiscoveryEngine(driver)
        forms = discovery.discover_forms()
        print(f"Found {len(forms)} forms")

        for form in forms:
            print(f"Form has {len(form['inputs'])} inputs")
    """

    def __init__(self, driver: WebDriver):
        """
        Initialize discovery engine.

        Args:
            driver: Selenium WebDriver instance
        """
        self.driver = driver
        self.finder = ElementFinder(driver)
        self.logger = logging.getLogger(__name__)

    def discover_forms(self) -> List[Dict[str, Any]]:
        """
        Discover all forms on the current page.

        DISCOVERY METHOD: Automatically finds all forms and their structure.

        Returns:
            List of form dictionaries with structure:
            {
                "element": WebElement,
                "id": str,
                "name": str,
                "action": str,
                "method": str,
                "inputs": List[Dict],
                "buttons": List[Dict],
                "selects": List[Dict]
            }

        Example:
            forms = discovery.discover_forms()
            for form in forms:
                print(f"Form: {form['id']}")
                print(f"  Inputs: {len(form['inputs'])}")
                print(f"  Buttons: {len(form['buttons'])}")
        """
        forms = []
        form_elements = self.finder.find_elements(By.TAG_NAME, "form")

        for form_elem in form_elements:
            try:
                form_data = {
                    "element": form_elem,
                    "id": form_elem.get_attribute("id") or "",
                    "name": form_elem.get_attribute("name") or "",
                    "action": form_elem.get_attribute("action") or "",
                    "method": form_elem.get_attribute("method") or "get",
                    "inputs": self._discover_inputs(form_elem),
                    "buttons": self._discover_buttons(form_elem),
                    "selects": self._discover_selects(form_elem),
                    "textareas": self._discover_textareas(form_elem),
                }
                forms.append(form_data)
                self.logger.debug(
                    f"✓ Discovered form: id='{form_data['id']}', "
                    f"{len(form_data['inputs'])} inputs"
                )
            except StaleElementReferenceException:
                self.logger.debug("⚠ Skipped stale form element")
                continue

        self.logger.info(f"✓ Discovered {len(forms)} forms")
        return forms

    def _discover_inputs(
        self, context: Optional[WebElement] = None
    ) -> List[Dict[str, Any]]:
        """
        Discover all input elements within context.

        Args:
            context: Parent element (None = entire page)

        Returns:
            List of input dictionaries
        """
        inputs = []
        input_elements = self.finder.find_elements(
            By.TAG_NAME, "input", context
        )

        for input_elem in input_elements:
            try:
                input_type = input_elem.get_attribute("type") or "text"

                # Skip button-type inputs (handled separately)
                if input_type in ["submit", "button", "reset"]:
                    continue

                input_data = {
                    "element": input_elem,
                    "type": input_type,
                    "id": input_elem.get_attribute("id") or "",
                    "name": input_elem.get_attribute("name") or "",
                    "placeholder": input_elem.get_attribute("placeholder")
                    or "",
                    "value": input_elem.get_attribute("value") or "",
                    "required": input_elem.get_attribute("required")
                    is not None,
                    "disabled": not input_elem.is_enabled(),
                    "visible": input_elem.is_displayed(),
                }
                inputs.append(input_data)
            except StaleElementReferenceException:
                continue

        return inputs

    def _discover_buttons(
        self, context: Optional[WebElement] = None
    ) -> List[Dict[str, Any]]:
        """
        Discover all buttons within context.

        Args:
            context: Parent element (None = entire page)

        Returns:
            List of button dictionaries
        """
        buttons = []

        # Find <button> elements
        button_elements = self.finder.find_elements(
            By.TAG_NAME, "button", context
        )

        # Find <input type="submit|button|reset">
        submit_inputs = self.finder.find_elements(
            By.CSS_SELECTOR,
            "input[type='submit'], input[type='button'], input[type='reset']",
            context,
        )

        all_buttons = button_elements + submit_inputs

        for btn_elem in all_buttons:
            try:
                button_data = {
                    "element": btn_elem,
                    "type": btn_elem.get_attribute("type") or "button",
                    "text": btn_elem.text
                    or btn_elem.get_attribute("value")
                    or "",
                    "id": btn_elem.get_attribute("id") or "",
                    "name": btn_elem.get_attribute("name") or "",
                    "disabled": not btn_elem.is_enabled(),
                    "visible": btn_elem.is_displayed(),
                }
                buttons.append(button_data)
            except StaleElementReferenceException:
                continue

        return buttons

    def _discover_selects(
        self, context: Optional[WebElement] = None
    ) -> List[Dict[str, Any]]:
        """
        Discover all select/dropdown elements within context.

        Args:
            context: Parent element (None = entire page)

        Returns:
            List of select dictionaries
        """
        selects = []
        select_elements = self.finder.find_elements(
            By.TAG_NAME, "select", context
        )

        for select_elem in select_elements:
            try:
                from selenium.webdriver.support.ui import Select

                select_obj = Select(select_elem)

                select_data = {
                    "element": select_elem,
                    "id": select_elem.get_attribute("id") or "",
                    "name": select_elem.get_attribute("name") or "",
                    "options": [opt.text for opt in select_obj.options],
                    "selected": (
                        select_obj.first_selected_option.text
                        if select_obj.all_selected_options
                        else ""
                    ),
                    "multiple": select_elem.get_attribute("multiple")
                    is not None,
                    "disabled": not select_elem.is_enabled(),
                    "visible": select_elem.is_displayed(),
                }
                selects.append(select_data)
            except (StaleElementReferenceException, Exception):
                continue

        return selects

    def _discover_textareas(
        self, context: Optional[WebElement] = None
    ) -> List[Dict[str, Any]]:
        """
        Discover all textarea elements within context.

        Args:
            context: Parent element (None = entire page)

        Returns:
            List of textarea dictionaries
        """
        textareas = []
        textarea_elements = self.finder.find_elements(
            By.TAG_NAME, "textarea", context
        )

        for textarea_elem in textarea_elements:
            try:
                textarea_data = {
                    "element": textarea_elem,
                    "id": textarea_elem.get_attribute("id") or "",
                    "name": textarea_elem.get_attribute("name") or "",
                    "placeholder": textarea_elem.get_attribute("placeholder")
                    or "",
                    "value": textarea_elem.get_attribute("value")
                    or textarea_elem.text,
                    "required": textarea_elem.get_attribute("required")
                    is not None,
                    "disabled": not textarea_elem.is_enabled(),
                    "visible": textarea_elem.is_displayed(),
                }
                textareas.append(textarea_data)
            except StaleElementReferenceException:
                continue

        return textareas

    def discover_navigation(self) -> Dict[str, Any]:
        """
        Discover navigation structure.

        DISCOVERY METHOD: Identifies navigation elements automatically.

        Returns:
            Dict with navigation structure:
            {
                "header": List[Dict],
                "footer": List[Dict],
                "sidebar": List[Dict],
                "breadcrumbs": List[Dict],
                "all_links": List[Dict]
            }

        Example:
            nav = discovery.discover_navigation()
            print(f"Header links: {len(nav['header'])}")
            for link in nav['header']:
                print(f"  {link['text']} -> {link['href']}")
        """
        navigation = {
            "header": self._discover_header_navigation(),
            "footer": self._discover_footer_navigation(),
            "sidebar": self._discover_sidebar_navigation(),
            "breadcrumbs": self._discover_breadcrumbs(),
            "all_links": self._discover_all_links(),
        }

        total_nav_items = (
            len(navigation["header"])
            + len(navigation["footer"])
            + len(navigation["sidebar"])
            + len(navigation["breadcrumbs"])
        )

        self.logger.info(f"✓ Discovered {total_nav_items} navigation items")
        return navigation

    def _discover_header_navigation(self) -> List[Dict[str, Any]]:
        """Discover navigation in header/nav elements."""
        nav_items = []

        # Try common header selectors
        header_selectors = [
            (By.TAG_NAME, "header"),
            (By.TAG_NAME, "nav"),
            (By.CSS_SELECTOR, "[role='navigation']"),
            (By.CLASS_NAME, "navbar"),
            (By.CLASS_NAME, "nav"),
            (By.ID, "navigation"),
        ]

        for by, value in header_selectors:
            header = self.finder.find_element(by, value)
            if header:
                links = self.finder.find_elements(By.TAG_NAME, "a", header)
                for link in links:
                    try:
                        link_data = {
                            "element": link,
                            "text": link.text.strip(),
                            "href": link.get_attribute("href") or "",
                            "id": link.get_attribute("id") or "",
                            "visible": link.is_displayed(),
                        }
                        if link_data["text"] or link_data["href"]:
                            nav_items.append(link_data)
                    except StaleElementReferenceException:
                        continue
                break  # Found header, stop trying other selectors

        return nav_items

    def _discover_footer_navigation(self) -> List[Dict[str, Any]]:
        """Discover navigation in footer elements."""
        nav_items = []

        footer = self.finder.find_element(By.TAG_NAME, "footer")
        if footer:
            links = self.finder.find_elements(By.TAG_NAME, "a", footer)
            for link in links:
                try:
                    link_data = {
                        "element": link,
                        "text": link.text.strip(),
                        "href": link.get_attribute("href") or "",
                        "visible": link.is_displayed(),
                    }
                    if link_data["text"] or link_data["href"]:
                        nav_items.append(link_data)
                except StaleElementReferenceException:
                    continue

        return nav_items

    def _discover_sidebar_navigation(self) -> List[Dict[str, Any]]:
        """Discover navigation in sidebar elements."""
        nav_items = []

        # Try common sidebar selectors
        sidebar_selectors = [
            (By.CLASS_NAME, "sidebar"),
            (By.ID, "sidebar"),
            (By.CSS_SELECTOR, "aside"),
            (By.CSS_SELECTOR, "[role='complementary']"),
        ]

        for by, value in sidebar_selectors:
            sidebar = self.finder.find_element(by, value)
            if sidebar:
                links = self.finder.find_elements(By.TAG_NAME, "a", sidebar)
                for link in links:
                    try:
                        link_data = {
                            "element": link,
                            "text": link.text.strip(),
                            "href": link.get_attribute("href") or "",
                            "visible": link.is_displayed(),
                        }
                        if link_data["text"] or link_data["href"]:
                            nav_items.append(link_data)
                    except StaleElementReferenceException:
                        continue
                break

        return nav_items

    def _discover_breadcrumbs(self) -> List[Dict[str, Any]]:
        """Discover breadcrumb navigation."""
        breadcrumbs = []

        # Try common breadcrumb selectors
        breadcrumb_selectors = [
            (By.CSS_SELECTOR, "[aria-label='breadcrumb']"),
            (By.CLASS_NAME, "breadcrumb"),
            (By.CLASS_NAME, "breadcrumbs"),
        ]

        for by, value in breadcrumb_selectors:
            breadcrumb_container = self.finder.find_element(by, value)
            if breadcrumb_container:
                links = self.finder.find_elements(
                    By.TAG_NAME, "a", breadcrumb_container
                )
                for link in links:
                    try:
                        breadcrumbs.append(
                            {
                                "element": link,
                                "text": link.text.strip(),
                                "href": link.get_attribute("href") or "",
                            }
                        )
                    except StaleElementReferenceException:
                        continue
                break

        return breadcrumbs

    def _discover_all_links(self) -> List[Dict[str, Any]]:
        """Discover ALL links on page."""
        links = []
        link_elements = self.finder.find_elements(By.TAG_NAME, "a")

        for link_elem in link_elements:
            try:
                href = link_elem.get_attribute("href") or ""
                text = link_elem.text.strip()

                if href or text:  # Only add if has href or text
                    links.append(
                        {
                            "element": link_elem,
                            "text": text,
                            "href": href,
                            "visible": link_elem.is_displayed(),
                        }
                    )
            except StaleElementReferenceException:
                continue

        return links

    def discover_page_metadata(self) -> Dict[str, Any]:
        """
        Discover page metadata.

        Returns:
            Dict with page information:
            {
                "title": str,
                "url": str,
                "meta_description": str,
                "meta_keywords": str,
                "lang": str
            }

        Example:
            metadata = discovery.discover_page_metadata()
            print(f"Page: {metadata['title']}")
        """
        metadata = {
            "title": self.driver.title,
            "url": self.driver.current_url,
            "meta_description": "",
            "meta_keywords": "",
            "lang": "",
        }

        # Try to find meta description
        meta_desc = self.finder.find_element(
            By.CSS_SELECTOR, "meta[name='description']"
        )
        if meta_desc:
            metadata["meta_description"] = (
                meta_desc.get_attribute("content") or ""
            )

        # Try to find meta keywords
        meta_keywords = self.finder.find_element(
            By.CSS_SELECTOR, "meta[name='keywords']"
        )
        if meta_keywords:
            metadata["meta_keywords"] = (
                meta_keywords.get_attribute("content") or ""
            )

        # Try to find language
        html = self.finder.find_element(By.TAG_NAME, "html")
        if html:
            metadata["lang"] = html.get_attribute("lang") or ""

        self.logger.debug(f"✓ Discovered page metadata: {metadata['title']}")
        return metadata

    def discover_interactive_elements(self) -> Dict[str, Any]:
        """
        Discover all interactive elements on page.

        DISCOVERY METHOD: Finds ALL elements users can interact with.

        Returns:
            Dict with categorized interactive elements:
            {
                "buttons": List[Dict],
                "links": List[Dict],
                "inputs": List[Dict],
                "selects": List[Dict],
                "checkboxes": List[Dict],
                "radios": List[Dict]
            }

        Example:
            interactive = discovery.discover_interactive_elements()
            print(f"Total interactive elements: {
                sum(len(v) for v in interactive.values())
            }")
        """
        return {
            "buttons": self._discover_buttons(),
            "links": self._discover_all_links(),
            "inputs": [
                inp
                for inp in self._discover_inputs()
                if inp["type"] not in ["checkbox", "radio"]
            ],
            "selects": self._discover_selects(),
            "checkboxes": [
                inp
                for inp in self._discover_inputs()
                if inp["type"] == "checkbox"
            ],
            "radios": [
                inp
                for inp in self._discover_inputs()
                if inp["type"] == "radio"
            ],
            "textareas": self._discover_textareas(),
        }

    def generate_page_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive page structure report.

        DISCOVERY METHOD: Complete analysis of page structure.

        Returns:
            Complete page structure report

        Example:
            report = discovery.generate_page_report()
            print(f"Page: {report['metadata']['title']}")
            print(f"Forms: {len(report['forms'])}")
            print(f"Navigation items: {len(report['navigation']['header'])}")
            print(f"Interactive elements: {report['summary']['total_interactive']}")
        """
        forms = self.discover_forms()
        navigation = self.discover_navigation()
        metadata = self.discover_page_metadata()
        interactive = self.discover_interactive_elements()

        total_interactive = sum(len(v) for v in interactive.values())

        report = {
            "metadata": metadata,
            "forms": forms,
            "navigation": navigation,
            "interactive_elements": interactive,
            "summary": {
                "total_forms": len(forms),
                "total_inputs": sum(len(f["inputs"]) for f in forms),
                "total_buttons": len(interactive["buttons"]),
                "total_links": len(interactive["links"]),
                "total_interactive": total_interactive,
                "total_navigation": len(navigation["header"])
                + len(navigation["footer"]),
            },
        }

        self.logger.info(
            f"✓ Generated page report: "
            f"{report['summary']['total_forms']} forms, "
            f"{report['summary']['total_interactive']} interactive elements"
        )

        return report

    def __str__(self) -> str:
        """String representation."""
        return "DiscoveryEngine"

    def __repr__(self) -> str:
        """Detailed representation."""
        return f"DiscoveryEngine(driver={self.driver})"
