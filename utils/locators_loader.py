"""
Locators Loader - Universal Test Automation Framework
Author: Marc Arévalo
Version: 1.0

Utility for loading locators from external JSON configuration.
Makes framework adaptable to any web application by externalizing locators.
"""

import json
import os
from typing import Dict, Optional, Tuple

from selenium.webdriver.common.by import By


class LocatorsLoader:
    """
    Load and manage locators from external JSON configuration.

    Benefits:
    - Easy adaptation to new applications (just update JSON)
    - Centralized locator management
    - No need to modify page object code
    - Support for multiple environments (dev, staging, prod)

    Usage:
        >>> loader = LocatorsLoader()
        >>> LOGIN_BUTTON = loader.get_locator("login", "login_button_nav")
        >>> # Returns: (By.ID, "login2")

        >>> # Or load all locators for a page
        >>> login_locators = loader.get_page_locators("login")
        >>> LOGIN_BUTTON = login_locators["login_button_nav"]
    """

    BY_MAPPING = {
        "id": By.ID,
        "name": By.NAME,
        "xpath": By.XPATH,
        "css": By.CSS_SELECTOR,
        "class": By.CLASS_NAME,
        "tag": By.TAG_NAME,
        "link_text": By.LINK_TEXT,
        "partial_link_text": By.PARTIAL_LINK_TEXT,
    }

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the locators loader.

        Args:
            config_path: Path to locators JSON file (optional)
                        Defaults to config/locators.json
        """
        if config_path is None:
            # Default to config/locators.json relative to project root
            project_root = os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))
            )
            config_path = os.path.join(project_root, "config", "locators.json")

        self.config_path: str = config_path
        self.locators: Dict = self._load_locators()

    def _load_locators(self) -> Dict:
        """
        Load locators from JSON file.

        Returns:
            Dictionary containing all locators

        Raises:
            FileNotFoundError: If config file doesn't exist
            json.JSONDecodeError: If JSON is invalid
        """
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(
                f"Locators config file not found: {self.config_path}\n"
                f"Create config/locators.json to externalize locators."
            )
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError(
                f"Invalid JSON in locators config: {self.config_path}",
                e.doc,
                e.pos,
            )

    def get_locator(self, page: str, element: str) -> Tuple[str, str]:
        """
        Get a specific locator for a page element.

        Args:
            page: Page name (e.g., "login", "cart", "product")
            element: Element name (e.g., "login_button_nav", "username_field")

        Returns:
            Tuple (By.TYPE, "value") for Selenium

        Raises:
            KeyError: If page or element not found
            ValueError: If locator format is invalid

        Example:
            >>> loader = LocatorsLoader()
            >>> LOGIN_BUTTON = loader.get_locator("login", "login_button_nav")
            >>> driver.find_element(*LOGIN_BUTTON).click()
        """
        try:
            locator_config = self.locators[page][element]
        except KeyError as e:
            raise KeyError(
                f"Locator not found: page='{page}', element='{element}'\n"
                f"Check config/locators.json"
            ) from e

        by_type = locator_config.get("by")
        value = locator_config.get("value")

        if not by_type or not value:
            raise ValueError(
                f"Invalid locator format for {page}.{element}: {locator_config}\n"
                f"Expected: {'by': 'type', 'value': 'locator_value'}"
            )

        # Convert string "by" to Selenium By constant
        selenium_by = self.BY_MAPPING.get(by_type.lower())
        if not selenium_by:
            raise ValueError(
                f"Unknown locator type '{by_type}' for {page}.{element}\n"
                f"Valid types: {list(self.BY_MAPPING.keys())}"
            )

        return (selenium_by, value)

    def get_page_locators(self, page: str) -> Dict[str, Tuple[str, str]]:
        """
        Get all locators for a specific page.

        Args:
            page: Page name (e.g., "login", "cart")

        Returns:
            Dictionary mapping element names to Selenium locator tuples

        Example:
            >>> loader = LocatorsLoader()
            >>> login_locators = loader.get_page_locators("login")
            >>> LOGIN_BUTTON = login_locators["login_button_nav"]
            >>> USERNAME_FIELD = login_locators["login_username_field"]
        """
        if page not in self.locators:
            raise KeyError(
                f"Page '{page}' not found in locators config\n"
                f"Available pages: {list(self.locators.keys())}"
            )

        page_locators = {}
        for element_name, locator_config in self.locators[page].items():
            # Skip metadata fields (those starting with _)
            if element_name.startswith("_"):
                continue

            try:
                page_locators[element_name] = self.get_locator(
                    page, element_name
                )
            except (ValueError, KeyError) as e:
                # Log warning but continue loading other locators
                print(f"Warning: Could not load {page}.{element_name}: {e}")
                continue

        return page_locators

    def get_all_pages(self) -> list:
        """
        Get list of all available pages.

        Returns:
            List of page names

        Example:
            >>> loader = LocatorsLoader()
            >>> pages = loader.get_all_pages()
            >>> print(pages)
            ['login', 'signup', 'cart', 'catalog', 'product', 'purchase']
        """
        return [key for key in self.locators.keys() if not key.startswith("_")]

    def reload(self) -> None:
        """
        Reload locators from JSON file.

        Useful during development or when config changes at runtime.
        """
        self.locators = self._load_locators()


# Singleton instance for easy import
_loader = None


def get_loader() -> LocatorsLoader:
    """
    Get singleton instance of LocatorsLoader.

    Returns:
        LocatorsLoader instance

    Example:
        >>> from utils.locators_loader import get_loader
        >>> loader = get_loader()
        >>> LOGIN_BUTTON = loader.get_locator("login", "login_button_nav")
    """
    global _loader
    if _loader is None:
        _loader = LocatorsLoader()
    return _loader


# Convenience function for quick access
def load_locator(page: str, element: str) -> Tuple[str, str]:
    """
    Quick access function to load a single locator.

    Args:
        page: Page name
        element: Element name

    Returns:
        Selenium locator tuple

    Example:
        >>> from utils.locators_loader import load_locator
        >>> LOGIN_BUTTON = load_locator("login", "login_button_nav")
        >>> driver.find_element(*LOGIN_BUTTON).click()
    """
    return get_loader().get_locator(page, element)
