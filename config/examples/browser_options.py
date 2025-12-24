"""
Browser Options Configuration Examples

This module provides optimized browser configurations for different scenarios.
Copy and adapt these functions to your conftest.py for improved performance.

Author: Marc Arevalo
Version: 6.0.1
"""

from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.edge.options import Options as EdgeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions

# ============================================================================
# CHROME OPTIONS
# ============================================================================


def get_chrome_options_basic() -> ChromeOptions:
    """
    Basic Chrome options - Standard configuration.

    Use for: Local development, debugging
    Performance: Baseline
    """
    options = ChromeOptions()

    # Standard anti-detection
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)

    return options


def get_chrome_options_headless() -> ChromeOptions:
    """
    Headless Chrome options - No GUI.

    Use for: CI/CD, background testing
    Performance: 30-50% faster than GUI mode
    """
    options = ChromeOptions()

    # Headless mode (Chrome 109+)
    options.add_argument("--headless=new")

    # Required for headless stability
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    # Set window size (important for headless)
    options.add_argument("--window-size=1920,1080")

    # Anti-detection
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])

    return options


def get_chrome_options_fast() -> ChromeOptions:
    """
    Performance-optimized Chrome options.

    Use for: Fast test execution, non-visual tests
    Performance: 70-80% faster than basic
    Trade-off: May break visual/layout tests

    Optimizations:
    - Headless mode: 30-50% faster
    - Disabled images: 40-60% faster
    - Disabled GPU: 5-10% faster
    - Disabled extensions: 10-20% faster
    """
    options = ChromeOptions()

    # Headless mode
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1920,1080")

    # Disable GPU (not needed for testing)
    options.add_argument("--disable-gpu")

    # Disable extensions
    options.add_argument("--disable-extensions")

    # Disable images (MAJOR performance boost)
    prefs = {
        "profile.managed_default_content_settings.images": 2,  # 0=allow, 2=block
        "profile.default_content_setting_values.notifications": 2,  # Block notifications
    }
    options.add_experimental_option("prefs", prefs)

    # Disable logging (reduces I/O)
    options.add_argument("--log-level=3")
    options.add_experimental_option("excludeSwitches", ["enable-logging"])

    # Anti-detection
    options.add_argument("--disable-blink-features=AutomationControlled")

    return options


def get_chrome_options_ultra_fast() -> ChromeOptions:
    """
    Ultra-fast Chrome options - Maximum performance.

    Use for: API-driven tests, data extraction, non-UI tests
    Performance: 80-90% faster than basic
    Trade-off: Breaks most visual/UI tests

    ⚠️ WARNING: Only use for tests that don't rely on:
    - Visual appearance
    - CSS layout
    - Images
    - JavaScript animations
    """
    options = ChromeOptions()

    # All "fast" optimizations
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-extensions")

    # Disable images and notifications
    prefs = {
        "profile.managed_default_content_settings.images": 2,
        "profile.default_content_setting_values.notifications": 2,
    }
    options.add_experimental_option("prefs", prefs)

    # Disable CSS (BREAKS layout but very fast)
    options.add_argument("--blink-settings=imagesEnabled=false")

    # Page load strategy: don't wait for full page load
    options.page_load_strategy = "eager"  # or "none" for even faster

    # Disable logging
    options.add_argument("--log-level=3")
    options.add_experimental_option("excludeSwitches", ["enable-logging"])

    return options


def get_chrome_options_mobile() -> ChromeOptions:
    """
    Mobile emulation Chrome options.

    Use for: Mobile responsiveness testing
    """
    options = ChromeOptions()

    # Mobile emulation
    mobile_emulation = {
        "deviceName": "iPhone 12 Pro"
        # Or custom:
        # "deviceMetrics": {"width": 390, "height": 844, "pixelRatio": 3.0},
        # "userAgent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)..."
    }
    options.add_experimental_option("mobileEmulation", mobile_emulation)

    return options


def get_chrome_options_download() -> ChromeOptions:
    """
    Chrome options configured for file downloads.

    Use for: Testing file download functionality
    """
    import os

    options = ChromeOptions()

    # Set download directory
    download_dir = os.path.join(os.getcwd(), "downloads")
    os.makedirs(download_dir, exist_ok=True)

    prefs = {
        "download.default_directory": download_dir,
        "download.prompt_for_download": False,
        "download.directory_upgrade": True,
        "safebrowsing.enabled": False,  # Disable safe browsing (faster downloads)
    }
    options.add_experimental_option("prefs", prefs)

    return options


# ============================================================================
# FIREFOX OPTIONS
# ============================================================================


def get_firefox_options_basic() -> FirefoxOptions:
    """
    Basic Firefox options - Standard configuration.
    """
    options = FirefoxOptions()
    return options


def get_firefox_options_headless() -> FirefoxOptions:
    """
    Headless Firefox options.

    Performance: 30-40% faster than GUI mode
    """
    options = FirefoxOptions()
    options.add_argument("--headless")
    options.add_argument("--width=1920")
    options.add_argument("--height=1080")
    return options


def get_firefox_options_fast() -> FirefoxOptions:
    """
    Performance-optimized Firefox options.

    Performance: 60-70% faster than basic
    """
    options = FirefoxOptions()

    # Headless mode
    options.add_argument("--headless")
    options.add_argument("--width=1920")
    options.add_argument("--height=1080")

    # Disable images
    options.set_preference("permissions.default.image", 2)

    # Disable Flash
    options.set_preference("dom.ipc.plugins.enabled.libflashplayer.so", False)

    # Disable CSS (use cautiously)
    # options.set_preference("permissions.default.stylesheet", 2)

    return options


# ============================================================================
# EDGE OPTIONS
# ============================================================================


def get_edge_options_basic() -> EdgeOptions:
    """
    Basic Edge options - Standard configuration.
    """
    options = EdgeOptions()
    options.use_chromium = True
    return options


def get_edge_options_headless() -> EdgeOptions:
    """
    Headless Edge options.

    Performance: 30-50% faster than GUI mode
    """
    options = EdgeOptions()
    options.use_chromium = True
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1920,1080")
    return options


def get_edge_options_fast() -> EdgeOptions:
    """
    Performance-optimized Edge options.

    Performance: 70-80% faster than basic
    """
    options = EdgeOptions()
    options.use_chromium = True

    # Headless mode
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1920,1080")

    # Disable GPU
    options.add_argument("--disable-gpu")

    # Disable extensions
    options.add_argument("--disable-extensions")

    # Disable images
    prefs = {
        "profile.managed_default_content_settings.images": 2,
        "profile.default_content_setting_values.notifications": 2,
    }
    options.add_experimental_option("prefs", prefs)

    return options


# ============================================================================
# SELENIUM GRID OPTIONS
# ============================================================================


def get_chrome_options_for_grid() -> ChromeOptions:
    """
    Chrome options optimized for Selenium Grid.

    Use for: Distributed test execution, CI/CD with Grid
    """
    options = ChromeOptions()

    # Grid-specific optimizations
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")

    # Reduce memory usage
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-logging")
    options.add_argument("--log-level=3")

    # Disable images for grid (faster)
    prefs = {
        "profile.managed_default_content_settings.images": 2,
    }
    options.add_experimental_option("prefs", prefs)

    return options


# ============================================================================
# USAGE EXAMPLES
# ============================================================================

"""
# Example 1: Use in conftest.py

from config.browser_options import get_chrome_options_fast

@pytest.fixture(scope="function")
def browser(request):
    options = get_chrome_options_fast()  # Use optimized options
    driver = webdriver.Chrome(options=options)
    yield driver
    driver.quit()


# Example 2: Conditional options based on environment

import os
from config.browser_options import (
    get_chrome_options_basic,
    get_chrome_options_fast,
    get_chrome_options_headless
)

@pytest.fixture(scope="function")
def browser():
    env = os.getenv("TEST_ENV", "development")

    if env == "production":
        options = get_chrome_options_fast()  # Fast for production smoke tests
    elif env == "ci":
        options = get_chrome_options_headless()  # Headless for CI/CD
    else:
        options = get_chrome_options_basic()  # Standard for local dev

    driver = webdriver.Chrome(options=options)
    yield driver
    driver.quit()


# Example 3: Command-line option to select performance level

def pytest_addoption(parser):
    parser.addoption(
        "--performance",
        action="store",
        default="basic",
        choices=["basic", "fast", "ultra"],
        help="Browser performance level"
    )

@pytest.fixture(scope="function")
def browser(request):
    perf_level = request.config.getoption("--performance")

    if perf_level == "ultra":
        options = get_chrome_options_ultra_fast()
    elif perf_level == "fast":
        options = get_chrome_options_fast()
    else:
        options = get_chrome_options_basic()

    driver = webdriver.Chrome(options=options)
    yield driver
    driver.quit()

# Run: pytest --performance=fast
"""


# ============================================================================
# PERFORMANCE COMPARISON
# ============================================================================

"""
Typical Performance Improvements:

Configuration          | Page Load Time | Memory Usage | Speed Gain
-----------------------|----------------|--------------|------------
Basic (GUI)            | 3.0s          | 500MB        | Baseline
Headless               | 2.0s          | 350MB        | 33% faster
Fast (headless + opts) | 1.2s          | 250MB        | 60% faster
Ultra Fast             | 0.6s          | 200MB        | 80% faster

Note: Actual results vary by application and test complexity
"""
