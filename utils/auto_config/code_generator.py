"""
Intelligent Code Generator
Generates locators config, page objects, and basic tests automatically.

Author: Marc Arévalo
Version: 1.0
"""

import json
import logging
import os
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger(__name__)


class CodeGenerator:
    """
    Generates framework code automatically from discovered pages and locators.

    Generates:
    - config/locators.json
    - Page object classes
    - Basic test files
    - Fixture definitions
    """

    def __init__(self, project_root: str):
        """
        Initialize code generator.

        Args:
            project_root: Path to project root directory
        """
        self.project_root = Path(project_root)
        self.config_dir = self.project_root / "config"
        self.pages_dir = self.project_root / "pages"
        self.tests_dir = self.project_root / "tests"

    def generate_all(
        self,
        discovered_pages: Dict[str, dict],
        page_locators: Dict[str, Dict[str, dict]],
    ) -> None:
        """
        Generate all code artifacts.

        Args:
            discovered_pages: Pages discovered by crawler
            page_locators: Locators extracted for each page
        """
        logger.info("Starting code generation...")

        # Generate locators.json
        self.generate_locators_json(page_locators)

        # Generate page objects
        for page_name, locators in page_locators.items():
            page_info = self._find_page_info(page_name, discovered_pages)
            self.generate_page_object(page_name, locators, page_info)

        # Generate basic tests
        for page_name in page_locators.keys():
            page_info = self._find_page_info(page_name, discovered_pages)
            self.generate_test_file(page_name, page_info)

        # Generate fixtures
        self.generate_fixtures(list(page_locators.keys()))

        logger.info("Code generation complete!")

    def generate_locators_json(
        self, page_locators: Dict[str, Dict[str, dict]]
    ) -> None:
        """
        Generate config/locators.json file.

        Args:
            page_locators: Locators for all pages
        """
        logger.info("Generating config/locators.json...")

        # Ensure config directory exists
        self.config_dir.mkdir(parents=True, exist_ok=True)

        locators_file = self.config_dir / "locators.json"

        # Write locators to JSON
        with open(locators_file, "w", encoding="utf-8") as f:
            json.dump(page_locators, f, indent=2, ensure_ascii=False)

        logger.info(f"Generated: {locators_file}")
        logger.info(f"  Pages: {len(page_locators)}")
        logger.info(
            f"  Total locators: {sum(len(locs) for locs in page_locators.values())}"
        )

    def generate_page_object(
        self, page_name: str, locators: Dict[str, dict], page_info: dict
    ) -> None:
        """
        Generate page object class file.

        Args:
            page_name: Name of page
            locators: Locators for this page
            page_info: Page information from crawler
        """
        logger.info(f"Generating page object for {page_name}...")

        # Ensure pages directory exists
        self.pages_dir.mkdir(parents=True, exist_ok=True)

        # Generate class name
        class_name = self._to_class_name(page_name)
        file_name = f"{page_name}_page.py"
        file_path = self.pages_dir / file_name

        # Generate page object code
        code = self._generate_page_object_code(
            class_name, page_name, locators, page_info
        )

        # Write file
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(code)

        logger.info(f"Generated: {file_path}")

    def generate_test_file(self, page_name: str, page_info: dict) -> None:
        """
        Generate basic test file for page.

        Args:
            page_name: Name of page
            page_info: Page information from crawler
        """
        logger.info(f"Generating tests for {page_name}...")

        # Create test directory for this page
        page_test_dir = self.tests_dir / page_name
        page_test_dir.mkdir(parents=True, exist_ok=True)

        # Generate test file
        file_name = f"test_{page_name}_functional.py"
        file_path = page_test_dir / file_name

        # Generate test code
        code = self._generate_test_code(page_name, page_info)

        # Write file
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(code)

        logger.info(f"Generated: {file_path}")

    def generate_fixtures(self, page_names: List[str]) -> None:
        """
        Generate or update conftest.py with page fixtures.

        Args:
            page_names: List of page names
        """
        logger.info("Generating fixtures...")

        conftest_path = self.project_root / "conftest.py"

        # Generate fixture code
        fixture_code = self._generate_fixture_code(page_names)

        # Append to existing conftest.py or create new section
        if conftest_path.exists():
            with open(conftest_path, "a", encoding="utf-8") as f:
                f.write("\n\n# Auto-generated page fixtures\n")
                f.write(fixture_code)
        else:
            # Create basic conftest.py
            with open(conftest_path, "w", encoding="utf-8") as f:
                f.write('"""Auto-generated fixtures"""\n\n')
                f.write("import pytest\n\n")
                f.write(fixture_code)

        logger.info(f"Updated: {conftest_path}")

    def _generate_page_object_code(
        self,
        class_name: str,
        page_name: str,
        locators: Dict[str, dict],
        page_info: dict,
    ) -> str:
        """Generate page object class code."""
        page_type = page_info.get("page_type", "page")

        # Header
        code = f'''"""
{class_name} - Auto-generated Page Object
Page Type: {page_type}
"""

from pages.base_page import BasePage
from utils.locators_loader import load_locator
from typing import Optional


class {class_name}(BasePage):
    """Page object for {page_name} page."""

    # Locators (auto-generated)
'''

        # Add locator attributes
        for locator_name in locators.keys():
            code += f'    {locator_name} = load_locator("{page_name}", "{locator_name}")\n'

        # Add methods based on page type
        code += "\n    # Methods (customize as needed)\n\n"

        if page_type == "login":
            code += '''    def login(self, username: str, password: str) -> None:
        """Perform login."""
        # TODO: Customize this method based on actual login flow
        pass

    def is_user_logged_in(self) -> bool:
        """Check if user is logged in."""
        # TODO: Implement login verification
        return False
'''
        elif page_type == "form":
            code += '''    def fill_form(self, **kwargs) -> None:
        """Fill form with provided data."""
        # TODO: Implement form filling logic
        pass

    def submit_form(self) -> None:
        """Submit form."""
        # TODO: Implement form submission
        pass
'''
        elif page_type == "catalog":
            code += '''    def select_item(self, item_name: str) -> None:
        """Select item from catalog."""
        # TODO: Implement item selection
        pass

    def get_items(self) -> list:
        """Get list of items in catalog."""
        # TODO: Implement item retrieval
        return []
'''
        else:
            code += '''    def navigate_to(self) -> None:
        """Navigate to this page."""
        # TODO: Implement navigation
        pass
'''

        return code

    def _generate_test_code(self, page_name: str, page_info: dict) -> str:
        """Generate basic test code."""
        class_name = self._to_class_name(page_name)
        page_type = page_info.get("page_type", "page")

        code = f'''"""
Auto-generated Functional Tests for {class_name}
"""

import pytest


@pytest.mark.functional
def test_{page_name}_page_loads({page_name}_page, base_url):
    """Test that {page_name} page loads successfully."""
    assert {page_name}_page.driver.title is not None


@pytest.mark.functional
def test_{page_name}_elements_present({page_name}_page):
    """Test that key elements are present on {page_name} page."""
    # TODO: Add assertions for key elements
    pass
'''

        # Add page-type-specific tests
        if page_type == "login":
            code += f'''

@pytest.mark.functional
def test_login_with_valid_credentials({page_name}_page, valid_user):
    """Test login with valid credentials."""
    # TODO: Implement login test
    pass


@pytest.mark.functional
def test_login_with_invalid_credentials({page_name}_page):
    """Test login with invalid credentials."""
    # TODO: Implement negative login test
    pass
'''

        return code

    def _generate_fixture_code(self, page_names: List[str]) -> str:
        """Generate fixture definitions for all pages."""
        code = ""

        for page_name in page_names:
            class_name = self._to_class_name(page_name)

            code += f'''
@pytest.fixture(scope="function")
def {page_name}_page(browser, base_url):
    """Provide initialized {class_name} instance."""
    from pages.{page_name}_page import {class_name}

    browser.get(base_url)
    return {class_name}(browser)
'''

        return code

    def _to_class_name(self, page_name: str) -> str:
        """Convert page name to class name (e.g., 'login' -> 'LoginPage')."""
        return (
            "".join(word.capitalize() for word in page_name.split("_"))
            + "Page"
        )

    def _find_page_info(
        self, page_name: str, discovered_pages: Dict[str, dict]
    ) -> dict:
        """Find page info for a given page name."""
        # Try to find matching page in discovered pages
        for url, info in discovered_pages.items():
            if (
                page_name in url.lower()
                or page_name in info.get("title", "").lower()
            ):
                return info

        # Return default if not found
        return {"page_type": "page", "title": page_name}
