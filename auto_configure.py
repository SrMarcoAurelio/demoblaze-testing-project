#!/usr/bin/env python
"""
Intelligent Auto-Configurator
Automatically scans a web application and configures the test framework.

Usage:
    python auto_configure.py --url https://your-website.com
    python auto_configure.py --url https://your-website.com --depth 4
    python auto_configure.py --url https://your-website.com --headless

Author: Marc Arévalo
Version: 1.0
"""

import argparse
import logging
import os
import sys
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

from utils.auto_config.intelligent_scanner import IntelligentScanner


def setup_logging(verbose: bool = False) -> None:
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%H:%M:%S",
    )


def create_driver(headless: bool = False) -> webdriver.Chrome:
    """
    Create and configure WebDriver.

    Args:
        headless: Run in headless mode

    Returns:
        WebDriver instance
    """
    print("Initializing browser...")

    service = Service(ChromeDriverManager().install())
    options = webdriver.ChromeOptions()

    if headless:
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")

    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)
    options.add_argument("--window-size=1920,1080")

    driver = webdriver.Chrome(service=service, options=options)
    driver.maximize_window()

    print("✓ Browser initialized")

    return driver


def main():
    """Main execution function."""
    # Parse arguments
    parser = argparse.ArgumentParser(
        description="Intelligent Auto-Configurator for Test Framework"
    )

    parser.add_argument(
        "--url",
        required=True,
        help="Base URL of website to scan (e.g., https://www.example.com)",
    )

    parser.add_argument(
        "--depth", type=int, default=3, help="Maximum crawl depth (default: 3)"
    )

    parser.add_argument(
        "--headless", action="store_true", help="Run in headless mode (no GUI)"
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    parser.add_argument(
        "--backup",
        action="store_true",
        help="Backup existing configuration before overwriting",
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    # Get project root
    project_root = Path(__file__).parent.absolute()

    # Print header
    print("\n" + "=" * 70)
    print("INTELLIGENT AUTO-CONFIGURATOR")
    print("=" * 70)
    print(f"Target URL: {args.url}")
    print(f"Max Depth: {args.depth}")
    print(f"Headless: {args.headless}")
    print(f"Project Root: {project_root}")
    print("=" * 70 + "\n")

    # Backup existing configuration if requested
    if args.backup:
        backup_configuration(project_root)

    driver = None

    try:
        # Create WebDriver
        driver = create_driver(headless=args.headless)

        # Create scanner
        scanner = IntelligentScanner(
            driver=driver,
            base_url=args.url,
            project_root=str(project_root),
            max_depth=args.depth,
        )

        # Execute scan and configuration
        summary = scanner.scan_and_configure()

        # Print success message
        print("\n" + "=" * 70)
        print("AUTO-CONFIGURATION COMPLETE!")
        print("=" * 70)
        print(f"\n✓ Configured {summary['pages_with_locators']} pages")
        print(f"✓ Extracted {summary['total_locators']} locators")
        print(f"✓ Generated {summary['pages_with_locators']} page objects")
        print(f"✓ Generated {summary['pages_with_locators']} test files")

        print("\nGenerated Files:")
        print("  - config/locators.json")
        print(f"  - pages/*_page.py ({summary['pages_with_locators']} files)")
        print(
            f"  - tests/*/test_*_functional.py ({summary['pages_with_locators']} files)"
        )
        print("  - conftest.py (updated)")

        print("\nNext Steps:")
        print("  1. Review generated config/locators.json")
        print("  2. Customize page objects in pages/")
        print("  3. Enhance generated tests in tests/")
        print("  4. Run tests: pytest tests/ -v")

        print("\n" + "=" * 70 + "\n")

        return 0

    except KeyboardInterrupt:
        logger.warning("\nScan interrupted by user")
        return 1

    except Exception as e:
        logger.error(f"Auto-configuration failed: {e}", exc_info=True)
        return 1

    finally:
        if driver:
            try:
                driver.quit()
                print("✓ Browser closed")
            except:
                pass


def backup_configuration(project_root: Path) -> None:
    """
    Backup existing configuration files.

    Args:
        project_root: Project root directory
    """
    import shutil
    from datetime import datetime

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = project_root / "backups" / f"config_backup_{timestamp}"

    print(f"\nCreating backup in: {backup_dir}")

    # Backup locators.json
    locators_file = project_root / "config" / "locators.json"
    if locators_file.exists():
        backup_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(locators_file, backup_dir / "locators.json")
        print(f"✓ Backed up: config/locators.json")

    # Backup page objects
    pages_dir = project_root / "pages"
    if pages_dir.exists():
        backup_pages_dir = backup_dir / "pages"
        backup_pages_dir.mkdir(parents=True, exist_ok=True)

        for page_file in pages_dir.glob("*_page.py"):
            shutil.copy2(page_file, backup_pages_dir / page_file.name)

        print(f"✓ Backed up page objects")

    print()


if __name__ == "__main__":
    sys.exit(main())
