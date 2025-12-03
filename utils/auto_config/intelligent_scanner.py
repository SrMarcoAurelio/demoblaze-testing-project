"""
Intelligent Scanner - Main Orchestrator
Coordinates crawling, extraction, and code generation.

Author: Marc Arévalo
Version: 1.0
"""

import logging
import time
from typing import Dict, Optional

from selenium.webdriver.remote.webdriver import WebDriver

from .code_generator import CodeGenerator
from .locator_extractor import LocatorExtractor
from .page_crawler import PageCrawler

logger = logging.getLogger(__name__)


class IntelligentScanner:
    """
    Main orchestrator for intelligent web scanning and framework configuration.

    Workflow:
    1. Crawls website recursively to discover all pages
    2. Identifies page types (login, catalog, etc.)
    3. Extracts optimal locators from each page
    4. Generates locators.json configuration
    5. Generates page object classes
    6. Generates basic test files
    7. Updates fixtures

    Usage:
        scanner = IntelligentScanner(driver, base_url, project_root)
        scanner.scan_and_configure()
    """

    def __init__(
        self,
        driver: WebDriver,
        base_url: str,
        project_root: str,
        max_depth: int = 3,
    ):
        """
        Initialize intelligent scanner.

        Args:
            driver: Selenium WebDriver instance
            base_url: Base URL to scan
            project_root: Path to project root directory
            max_depth: Maximum crawl depth (default: 3)
        """
        self.driver = driver
        self.base_url = base_url
        self.project_root = project_root
        self.max_depth = max_depth

        # Initialize components
        self.crawler = PageCrawler(driver, base_url, max_depth)
        self.extractor = LocatorExtractor(driver)
        self.generator = CodeGenerator(project_root)

        # Results
        self.discovered_pages: Dict[str, dict] = {}
        self.page_locators: Dict[str, Dict[str, dict]] = {}

    def scan_and_configure(self) -> dict:
        """
        Execute complete scan and configuration process.

        Returns:
            Summary dict with statistics
        """
        logger.info("=" * 70)
        logger.info("INTELLIGENT SCANNER - STARTING")
        logger.info(f"Target: {self.base_url}")
        logger.info(f"Max Depth: {self.max_depth}")
        logger.info("=" * 70)

        start_time = time.time()

        try:
            # Phase 1: Crawl website
            logger.info("\n[PHASE 1] Crawling website...")
            self.discovered_pages = self.crawler.crawl()

            logger.info(f"✓ Discovered {len(self.discovered_pages)} pages")
            logger.info(
                f"✓ Found {len(self.crawler.navigation_sections)} sections"
            )

            # Phase 2: Extract locators from each page
            logger.info("\n[PHASE 2] Extracting locators...")
            self.page_locators = self._extract_all_locators()

            total_locators = sum(
                len(locs) for locs in self.page_locators.values()
            )
            logger.info(
                f"✓ Extracted {total_locators} locators from {len(self.page_locators)} pages"
            )

            # Phase 3: Generate code
            logger.info("\n[PHASE 3] Generating code...")
            self.generator.generate_all(
                self.discovered_pages, self.page_locators
            )

            logger.info("✓ Code generation complete")

            # Calculate statistics
            duration = time.time() - start_time
            summary = self._generate_summary(duration)

            # Print summary
            self._print_summary(summary)

            logger.info("\n" + "=" * 70)
            logger.info("INTELLIGENT SCANNER - COMPLETE")
            logger.info(f"Total Time: {duration:.2f}s")
            logger.info("=" * 70)

            return summary

        except Exception as e:
            logger.error(f"Scanner failed: {e}", exc_info=True)
            raise

    def _extract_all_locators(self) -> Dict[str, Dict[str, dict]]:
        """
        Extract locators from all discovered pages.

        Returns:
            Dict mapping page names to their locators
        """
        all_locators = {}

        for url, page_info in self.discovered_pages.items():
            try:
                # Navigate to page
                self.driver.get(url)
                time.sleep(1)  # Allow page to load

                # Determine page name
                page_name = self._determine_page_name(url, page_info)
                page_type = page_info["page_type"]

                # Extract locators
                locators = self.extractor.extract_page_locators(
                    page_name, page_type
                )

                if locators:
                    all_locators[page_name] = locators
                    logger.info(f"  ✓ {page_name}: {len(locators)} locators")

            except Exception as e:
                logger.warning(f"Failed to extract locators from {url}: {e}")

        return all_locators

    def _determine_page_name(self, url: str, page_info: dict) -> str:
        """
        Determine page name from URL and page info.

        Args:
            url: Page URL
            page_info: Page information

        Returns:
            Page name (e.g., "login", "catalog", "home")
        """
        from urllib.parse import urlparse

        # Use page type if meaningful
        page_type = page_info.get("page_type", "page")
        if page_type != "page":
            return page_type

        # Extract from path
        path = urlparse(url).path.strip("/")

        if not path:
            return "home"

        # Use first path segment
        parts = path.split("/")
        page_name = parts[0] if parts[0] else "home"

        # Clean page name
        page_name = (
            page_name.replace("-", "_")
            .replace(".html", "")
            .replace(".php", "")
        )

        return page_name

    def _generate_summary(self, duration: float) -> dict:
        """
        Generate summary statistics.

        Args:
            duration: Scan duration in seconds

        Returns:
            Summary dict
        """
        total_locators = sum(len(locs) for locs in self.page_locators.values())

        return {
            "duration": duration,
            "pages_discovered": len(self.discovered_pages),
            "pages_with_locators": len(self.page_locators),
            "total_locators": total_locators,
            "navigation_sections": len(self.crawler.navigation_sections),
            "page_types": self.crawler._count_page_types(),
            "locators_by_page": {
                name: len(locs) for name, locs in self.page_locators.items()
            },
            "crawler_summary": self.crawler.get_summary(),
        }

    def _print_summary(self, summary: dict) -> None:
        """
        Print formatted summary.

        Args:
            summary: Summary dict
        """
        logger.info("\n" + "=" * 70)
        logger.info("SCAN SUMMARY")
        logger.info("=" * 70)

        logger.info(f"\nPages Discovered: {summary['pages_discovered']}")
        logger.info(f"Pages Configured: {summary['pages_with_locators']}")
        logger.info(f"Total Locators: {summary['total_locators']}")
        logger.info(f"Navigation Sections: {summary['navigation_sections']}")

        logger.info("\nPage Types:")
        for page_type, count in summary["page_types"].items():
            logger.info(f"  - {page_type}: {count}")

        logger.info("\nLocators per Page:")
        for page_name, count in summary["locators_by_page"].items():
            logger.info(f"  - {page_name}: {count} locators")

        logger.info("\nSections Found:")
        for section in summary["crawler_summary"]["sections"]:
            logger.info(
                f"  - {section['name']}: {section['page_count']} pages"
            )

        logger.info(f"\nGenerated Files:")
        logger.info(f"  - config/locators.json")
        logger.info(f"  - {summary['pages_with_locators']} page objects")
        logger.info(f"  - {summary['pages_with_locators']} test files")
        logger.info(f"  - Updated conftest.py")

    def get_discovered_pages(self) -> Dict[str, dict]:
        """Get discovered pages."""
        return self.discovered_pages

    def get_page_locators(self) -> Dict[str, Dict[str, dict]]:
        """Get extracted locators."""
        return self.page_locators
