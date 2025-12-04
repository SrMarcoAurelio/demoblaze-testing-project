"""
Screenshot Manager
Manages screenshot capture and organization for visual testing.

Author: Marc Arévalo
Version: 1.0
"""

import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.remote.webelement import WebElement

logger = logging.getLogger(__name__)


class ScreenshotManager:
    """
    Manages screenshot capture and organization.

    Features:
    - Full page screenshots
    - Element screenshots
    - Baseline/actual organization
    - Automatic directory structure
    - Screenshot naming conventions
    - Viewport control
    """

    def __init__(
        self,
        screenshots_dir: Path = Path("screenshots"),
        baseline_dir: str = "baseline",
        actual_dir: str = "actual",
        diff_dir: str = "diff",
    ):
        """
        Initialize screenshot manager.

        Args:
            screenshots_dir: Root directory for screenshots
            baseline_dir: Subdirectory for baseline images
            actual_dir: Subdirectory for actual images
            diff_dir: Subdirectory for diff images
        """
        self.screenshots_dir = Path(screenshots_dir)
        self.baseline_dir = self.screenshots_dir / baseline_dir
        self.actual_dir = self.screenshots_dir / actual_dir
        self.diff_dir = self.screenshots_dir / diff_dir

        # Create directories
        self._create_directories()

    def _create_directories(self) -> None:
        """Create screenshot directory structure."""
        for directory in [self.baseline_dir, self.actual_dir, self.diff_dir]:
            directory.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Created directory: {directory}")

    def capture_screenshot(
        self,
        driver: WebDriver,
        name: str,
        as_baseline: bool = False,
        wait_before_capture: float = 0.5,
    ) -> Path:
        """
        Capture full page screenshot.

        Args:
            driver: Selenium WebDriver
            name: Screenshot name (without extension)
            as_baseline: Save as baseline (default: actual)
            wait_before_capture: Wait time before capture (for rendering)

        Returns:
            Path to saved screenshot
        """
        # Wait for rendering to complete
        if wait_before_capture > 0:
            time.sleep(wait_before_capture)

        # Determine target directory
        target_dir = self.baseline_dir if as_baseline else self.actual_dir

        # Generate filename
        filename = self._generate_filename(name)
        screenshot_path = target_dir / filename

        # Capture screenshot
        driver.save_screenshot(str(screenshot_path))

        logger.info(
            f"Screenshot captured: {screenshot_path} "
            f"({'baseline' if as_baseline else 'actual'})"
        )

        return screenshot_path

    def capture_element_screenshot(
        self,
        driver: WebDriver,
        element: WebElement,
        name: str,
        as_baseline: bool = False,
        wait_before_capture: float = 0.5,
    ) -> Path:
        """
        Capture screenshot of specific element.

        Args:
            driver: Selenium WebDriver
            element: WebElement to capture
            name: Screenshot name
            as_baseline: Save as baseline
            wait_before_capture: Wait time before capture

        Returns:
            Path to saved screenshot
        """
        # Wait for rendering
        if wait_before_capture > 0:
            time.sleep(wait_before_capture)

        # Determine target directory
        target_dir = self.baseline_dir if as_baseline else self.actual_dir

        # Generate filename
        filename = self._generate_filename(name)
        screenshot_path = target_dir / filename

        # Capture element screenshot
        element.screenshot(str(screenshot_path))

        logger.info(
            f"Element screenshot captured: {screenshot_path} "
            f"({'baseline' if as_baseline else 'actual'})"
        )

        return screenshot_path

    def capture_full_page_screenshot(
        self,
        driver: WebDriver,
        name: str,
        as_baseline: bool = False,
        wait_before_capture: float = 0.5,
    ) -> Path:
        """
        Capture full page screenshot (scroll to capture entire page).

        Args:
            driver: Selenium WebDriver
            name: Screenshot name
            as_baseline: Save as baseline
            wait_before_capture: Wait time before capture

        Returns:
            Path to saved screenshot

        Note:
            This uses Selenium's built-in full page capture.
            For more advanced stitching, consider using external tools.
        """
        # Get current window size
        original_size = driver.get_window_size()

        # Get full page dimensions
        total_width = driver.execute_script("return document.body.scrollWidth")
        total_height = driver.execute_script(
            "return document.body.scrollHeight"
        )

        # Set window to full page size
        driver.set_window_size(total_width, total_height)

        # Wait for resize
        time.sleep(wait_before_capture)

        # Capture
        screenshot_path = self.capture_screenshot(
            driver, name, as_baseline, wait_before_capture=0
        )

        # Restore original size
        driver.set_window_size(original_size["width"], original_size["height"])

        return screenshot_path

    def get_baseline_path(self, name: str) -> Path:
        """
        Get path to baseline screenshot.

        Args:
            name: Screenshot name

        Returns:
            Path to baseline screenshot
        """
        filename = self._generate_filename(name)
        return self.baseline_dir / filename

    def get_actual_path(self, name: str) -> Path:
        """
        Get path to actual screenshot.

        Args:
            name: Screenshot name

        Returns:
            Path to actual screenshot
        """
        filename = self._generate_filename(name)
        return self.actual_dir / filename

    def get_diff_path(self, name: str) -> Path:
        """
        Get path to diff screenshot.

        Args:
            name: Screenshot name

        Returns:
            Path to diff screenshot
        """
        filename = self._generate_filename(name, suffix="_diff")
        return self.diff_dir / filename

    def baseline_exists(self, name: str) -> bool:
        """
        Check if baseline exists.

        Args:
            name: Screenshot name

        Returns:
            True if baseline exists
        """
        return self.get_baseline_path(name).exists()

    def create_baseline(
        self,
        driver: WebDriver,
        name: str,
        wait_before_capture: float = 0.5,
    ) -> Path:
        """
        Create baseline screenshot.

        Args:
            driver: Selenium WebDriver
            name: Screenshot name
            wait_before_capture: Wait time before capture

        Returns:
            Path to baseline screenshot
        """
        return self.capture_screenshot(
            driver,
            name,
            as_baseline=True,
            wait_before_capture=wait_before_capture,
        )

    def capture_for_comparison(
        self,
        driver: WebDriver,
        name: str,
        wait_before_capture: float = 0.5,
    ) -> Path:
        """
        Capture actual screenshot for comparison.

        Args:
            driver: Selenium WebDriver
            name: Screenshot name
            wait_before_capture: Wait time before capture

        Returns:
            Path to actual screenshot
        """
        return self.capture_screenshot(
            driver,
            name,
            as_baseline=False,
            wait_before_capture=wait_before_capture,
        )

    def clean_actual_screenshots(self) -> None:
        """Remove all actual screenshots."""
        self._clean_directory(self.actual_dir)
        logger.info("Cleaned actual screenshots")

    def clean_diff_screenshots(self) -> None:
        """Remove all diff screenshots."""
        self._clean_directory(self.diff_dir)
        logger.info("Cleaned diff screenshots")

    def clean_all_screenshots(self) -> None:
        """Remove all screenshots (baseline, actual, diff)."""
        self._clean_directory(self.baseline_dir)
        self._clean_directory(self.actual_dir)
        self._clean_directory(self.diff_dir)
        logger.info("Cleaned all screenshots")

    def _clean_directory(self, directory: Path) -> None:
        """
        Remove all files in directory.

        Args:
            directory: Directory to clean
        """
        if directory.exists():
            for file in directory.glob("*"):
                if file.is_file():
                    file.unlink()

    def _generate_filename(
        self, name: str, suffix: str = "", extension: str = ".png"
    ) -> str:
        """
        Generate screenshot filename.

        Args:
            name: Base name
            suffix: Optional suffix
            extension: File extension

        Returns:
            Filename with extension
        """
        # Sanitize name
        sanitized_name = name.replace(" ", "_").replace("/", "_")

        return f"{sanitized_name}{suffix}{extension}"

    def capture_with_timestamp(
        self, driver: WebDriver, name: str, as_baseline: bool = False
    ) -> Path:
        """
        Capture screenshot with timestamp in filename.

        Args:
            driver: Selenium WebDriver
            name: Base name
            as_baseline: Save as baseline

        Returns:
            Path to screenshot
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        timestamped_name = f"{name}_{timestamp}"

        return self.capture_screenshot(driver, timestamped_name, as_baseline)
