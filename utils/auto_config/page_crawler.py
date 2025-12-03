"""
Intelligent Page Crawler
Recursively discovers all pages, sections, and navigation paths in a web application.

Author: Marc Arévalo
Version: 1.0
"""

import logging
import time
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webdriver import WebDriver

logger = logging.getLogger(__name__)


class PageCrawler:
    """
    Intelligent crawler that discovers all pages and sections in a web application.

    Features:
    - Recursive page discovery
    - Detects navigation menus, sections, directories
    - Identifies page types (login, form, catalog, etc.)
    - Respects same-domain policy
    - Avoids infinite loops
    - Handles dynamic content
    """

    def __init__(self, driver: WebDriver, base_url: str, max_depth: int = 3):
        """
        Initialize crawler.

        Args:
            driver: Selenium WebDriver instance
            base_url: Base URL to crawl (e.g., "https://www.demoblaze.com")
            max_depth: Maximum crawl depth (default: 3)
        """
        self.driver = driver
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.domain = urlparse(base_url).netloc

        # Track discovered pages
        self.visited_urls: Set[str] = set()
        self.discovered_pages: Dict[str, dict] = {}

        # Track sections/navigation
        self.navigation_sections: List[dict] = []
        self.page_types: Dict[str, str] = {}

    def crawl(self) -> Dict[str, dict]:
        """
        Start intelligent crawl of website.

        Returns:
            Dict mapping URLs to page information
        """
        logger.info(f"Starting intelligent crawl of {self.base_url}")
        logger.info(f"Max depth: {self.max_depth}")

        # Start crawling from base URL
        self._crawl_page(self.base_url, depth=0)

        # Detect navigation sections
        self._detect_navigation_sections()

        # Classify page types
        self._classify_pages()

        logger.info(
            f"Crawl complete! Discovered {len(self.discovered_pages)} pages"
        )
        logger.info(
            f"Navigation sections found: {len(self.navigation_sections)}"
        )

        return self.discovered_pages

    def _crawl_page(self, url: str, depth: int) -> None:
        """
        Recursively crawl a page.

        Args:
            url: URL to crawl
            depth: Current crawl depth
        """
        # Check depth limit
        if depth > self.max_depth:
            logger.debug(f"Max depth reached for {url}")
            return

        # Normalize URL
        url = url.rstrip("/")

        # Skip if already visited
        if url in self.visited_urls:
            return

        # Skip if different domain
        if urlparse(url).netloc != self.domain:
            logger.debug(f"Skipping external URL: {url}")
            return

        # Mark as visited
        self.visited_urls.add(url)

        logger.info(f"[Depth {depth}] Crawling: {url}")

        try:
            # Navigate to page
            self.driver.get(url)
            time.sleep(1)  # Allow page to load

            # Extract page information
            page_info = self._extract_page_info(url, depth)
            self.discovered_pages[url] = page_info

            # Find all links on page
            links = self._find_all_links()

            # Recursively crawl links
            for link in links:
                self._crawl_page(link, depth + 1)

        except TimeoutException:
            logger.warning(f"Timeout loading {url}")
        except WebDriverException as e:
            logger.error(f"Error crawling {url}: {e}")

    def _extract_page_info(self, url: str, depth: int) -> dict:
        """
        Extract comprehensive information about a page.

        Args:
            url: Page URL
            depth: Crawl depth

        Returns:
            Dict with page information
        """
        info = {
            "url": url,
            "depth": depth,
            "title": self.driver.title,
            "path": urlparse(url).path,
            "has_forms": self._has_forms(),
            "has_tables": self._has_tables(),
            "has_modals": self._has_modals(),
            "navigation_links": self._find_navigation_links(),
            "interactive_elements": self._count_interactive_elements(),
            "page_type": None,  # Will be set later
        }

        logger.debug(
            f"Page info: {info['title']} - {info['interactive_elements']} interactive elements"
        )

        return info

    def _find_all_links(self) -> List[str]:
        """
        Find all valid links on current page.

        Returns:
            List of absolute URLs
        """
        links = set()

        try:
            # Find all <a> tags
            link_elements = self.driver.find_elements(By.TAG_NAME, "a")

            for element in link_elements:
                href = element.get_attribute("href")

                if not href:
                    continue

                # Convert to absolute URL
                absolute_url = urljoin(self.base_url, href)

                # Clean URL (remove anchors, query params for deduplication)
                clean_url = absolute_url.split("#")[0].split("?")[0]

                # Only include same-domain links
                if urlparse(clean_url).netloc == self.domain:
                    links.add(clean_url)

        except Exception as e:
            logger.warning(f"Error finding links: {e}")

        return list(links)

    def _find_navigation_links(self) -> List[dict]:
        """
        Find navigation menu links (header, footer, sidebar).

        Returns:
            List of navigation link information
        """
        nav_links = []

        try:
            # Common navigation selectors
            nav_selectors = [
                "nav a",
                "header a",
                ".navbar a",
                ".nav a",
                ".menu a",
                "[role='navigation'] a",
            ]

            for selector in nav_selectors:
                try:
                    elements = self.driver.find_elements(
                        By.CSS_SELECTOR, selector
                    )

                    for element in elements:
                        href = element.get_attribute("href")
                        text = element.text.strip()

                        if href and text:
                            nav_links.append(
                                {
                                    "text": text,
                                    "href": href,
                                    "selector": selector,
                                }
                            )
                except:
                    continue

        except Exception as e:
            logger.warning(f"Error finding navigation: {e}")

        return nav_links

    def _has_forms(self) -> bool:
        """Check if page has forms."""
        try:
            forms = self.driver.find_elements(By.TAG_NAME, "form")
            return len(forms) > 0
        except:
            return False

    def _has_tables(self) -> bool:
        """Check if page has tables."""
        try:
            tables = self.driver.find_elements(By.TAG_NAME, "table")
            return len(tables) > 0
        except:
            return False

    def _has_modals(self) -> bool:
        """Check if page has modal dialogs."""
        try:
            # Common modal selectors
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

    def _count_interactive_elements(self) -> dict:
        """
        Count interactive elements on page.

        Returns:
            Dict with counts of different element types
        """
        counts = {
            "inputs": 0,
            "buttons": 0,
            "links": 0,
            "selects": 0,
            "textareas": 0,
        }

        try:
            counts["inputs"] = len(
                self.driver.find_elements(By.TAG_NAME, "input")
            )
            counts["buttons"] = len(
                self.driver.find_elements(By.TAG_NAME, "button")
            )
            counts["links"] = len(self.driver.find_elements(By.TAG_NAME, "a"))
            counts["selects"] = len(
                self.driver.find_elements(By.TAG_NAME, "select")
            )
            counts["textareas"] = len(
                self.driver.find_elements(By.TAG_NAME, "textarea")
            )
        except:
            pass

        return counts

    def _detect_navigation_sections(self) -> None:
        """
        Detect navigation sections (menus, categories, etc.).
        """
        logger.info("Detecting navigation sections...")

        # Group pages by common patterns
        sections = {}

        for url, info in self.discovered_pages.items():
            path = info["path"]

            # Extract section from path (e.g., /products/item1 → products)
            parts = path.strip("/").split("/")
            if parts and parts[0]:
                section = parts[0]

                if section not in sections:
                    sections[section] = []

                sections[section].append(url)

        # Create section information
        for section, urls in sections.items():
            self.navigation_sections.append(
                {"name": section, "page_count": len(urls), "urls": urls}
            )

        logger.info(
            f"Detected {len(self.navigation_sections)} navigation sections"
        )

    def _classify_pages(self) -> None:
        """
        Classify pages by type (login, catalog, product, cart, etc.).
        """
        logger.info("Classifying page types...")

        for url, info in self.discovered_pages.items():
            page_type = self._identify_page_type(info)
            info["page_type"] = page_type
            self.page_types[url] = page_type

        logger.info(f"Page type distribution: {self._count_page_types()}")

    def _identify_page_type(self, page_info: dict) -> str:
        """
        Identify page type based on content and structure.

        Args:
            page_info: Page information dict

        Returns:
            Page type string
        """
        path = page_info["path"].lower()
        title = page_info["title"].lower()
        interactive = page_info["interactive_elements"]

        # Login page detection
        if any(keyword in path for keyword in ["login", "signin", "auth"]):
            return "login"
        if any(keyword in title for keyword in ["login", "sign in"]):
            return "login"
        if interactive["inputs"] >= 2 and interactive["buttons"] >= 1:
            # Could be login (username + password + button)
            if "login" in title or "sign" in title:
                return "login"

        # Signup page detection
        if any(keyword in path for keyword in ["signup", "register"]):
            return "signup"
        if any(keyword in title for keyword in ["sign up", "register"]):
            return "signup"

        # Product catalog detection
        if any(
            keyword in path
            for keyword in ["products", "catalog", "shop", "store"]
        ):
            return "catalog"
        if page_info["has_tables"] or interactive["links"] > 10:
            return "catalog"

        # Product detail page detection
        if any(
            keyword in path for keyword in ["product/", "item/", "detail/"]
        ):
            return "product"

        # Cart page detection
        if any(keyword in path for keyword in ["cart", "basket", "bag"]):
            return "cart"
        if "cart" in title or "basket" in title:
            return "cart"

        # Checkout page detection
        if any(
            keyword in path for keyword in ["checkout", "purchase", "order"]
        ):
            return "checkout"

        # Home page detection
        if path == "/" or path == "":
            return "home"

        # Form page detection
        if page_info["has_forms"] and interactive["inputs"] > 3:
            return "form"

        # Default
        return "page"

    def _count_page_types(self) -> dict:
        """Count pages by type."""
        type_counts = {}

        for page_type in self.page_types.values():
            type_counts[page_type] = type_counts.get(page_type, 0) + 1

        return type_counts

    def get_summary(self) -> dict:
        """
        Get crawl summary.

        Returns:
            Summary dict with statistics
        """
        return {
            "total_pages": len(self.discovered_pages),
            "navigation_sections": len(self.navigation_sections),
            "page_types": self._count_page_types(),
            "max_depth_reached": max(
                (info["depth"] for info in self.discovered_pages.values()),
                default=0,
            ),
            "sections": [
                {"name": section["name"], "page_count": section["page_count"]}
                for section in self.navigation_sections
            ],
        }
