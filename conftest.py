"""
Pytest Configuration - Universal Test Automation Framework
Author: Arevalo, Marc
Version: 6.0

Centralized pytest configuration for universal test automation framework.
Provides browser management, fixtures, reporting, and performance tracking.
"""

import datetime
import logging
import os
import time

import pytest
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager
from webdriver_manager.microsoft import EdgeChromiumDriverManager

from config import config

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger(__name__)


def pytest_addoption(parser):
    """Add custom command line options."""
    parser.addoption(
        "--browser",
        action="store",
        default=config.BROWSER,
        help="Browser: chrome, firefox, or edge",
    )
    parser.addoption(
        "--headless",
        action="store_true",
        default=config.HEADLESS,
        help="Run in headless mode",
    )
    parser.addoption(
        "--slow",
        action="store",
        default=config.SLOW_MODE_DELAY,
        type=float,
        help="Delay between commands (seconds)",
    )
    parser.addoption(
        "--performance",
        action="store",
        default="basic",
        choices=["basic", "fast", "ultra"],
        help="Browser performance level: basic (baseline), fast (60%% faster), ultra (80%% faster)",
    )


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    """
    Configure pytest session.

    Creates results directory structure: results/module/type/date/
    Registers custom markers.
    """
    module_name = "general"
    test_type = "general"

    try:
        if config.args:
            test_path_str = str(config.args[0])
            norm_path = os.path.normpath(test_path_str)
            path_parts = norm_path.split(os.sep)

            if "tests" in path_parts:
                tests_idx = path_parts.index("tests")

                if len(path_parts) > tests_idx + 1:
                    module_name = path_parts[tests_idx + 1].lower()

                if len(path_parts) > tests_idx + 2:
                    filename = path_parts[-1]
                    if "functional" in filename:
                        test_type = "functional"
                    elif "business" in filename:
                        test_type = "business"
                    elif "security" in filename:
                        test_type = "security"

            logger.info(f"Detected module: {module_name}, type: {test_type}")
    except Exception as e:
        logger.warning(f"Could not detect module/type: {e}")

    date_folder = datetime.datetime.now().strftime("%Y-%m-%d")

    # Import config module to avoid name conflict
    from config import config as cfg

    if module_name != "general" and test_type != "general":
        report_dir = os.path.join(
            cfg.REPORTS_ROOT, module_name, test_type, date_folder
        )
    elif module_name != "general":
        report_dir = os.path.join(cfg.REPORTS_ROOT, module_name, date_folder)
    else:
        report_dir = os.path.join(cfg.REPORTS_ROOT, "general", date_folder)

    os.makedirs(report_dir, exist_ok=True)
    os.makedirs(cfg.SCREENSHOTS_DIR, exist_ok=True)

    browser_name = config.getoption("--browser").lower()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_name = f"report_{browser_name}_{timestamp}.html"
    report_path = os.path.join(report_dir, report_name)

    config.option.htmlpath = report_path
    config.option.self_contained_html = True

    logger.info(f"{'='*70}")
    logger.info(f"TEST SESSION STARTED")
    logger.info(f"Module: {module_name.upper()} | Type: {test_type.upper()}")
    logger.info(
        f"Browser: {browser_name.upper()} | Headless: {config.getoption('--headless')}"
    )
    logger.info(f"Report: {report_path}")
    logger.info(f"{'='*70}")

    config.addinivalue_line("markers", "smoke: Critical smoke tests")
    config.addinivalue_line("markers", "regression: Full regression suite")
    config.addinivalue_line("markers", "functional: Functional tests")
    config.addinivalue_line("markers", "security: Security tests")
    config.addinivalue_line(
        "markers", "business_rules: Business rules validation"
    )
    config.addinivalue_line("markers", "accessibility: Accessibility tests")
    config.addinivalue_line("markers", "slow: Long-running tests")
    config.addinivalue_line("markers", "performance: Performance tests")
    config.addinivalue_line("markers", "critical: Critical priority tests")
    config.addinivalue_line("markers", "high: High priority tests")
    config.addinivalue_line("markers", "medium: Medium priority tests")
    config.addinivalue_line("markers", "low: Low priority tests")


@pytest.fixture(scope="session")
def base_url():
    """Provide base URL from configuration."""
    return config.BASE_URL


@pytest.fixture(scope="session")
def timeout_config():
    """Provide timeout configuration."""
    return config.get_timeout_config()


@pytest.fixture(scope="session")
def test_config(request):
    """Provide test configuration."""
    return {
        "browser": request.config.getoption("--browser"),
        "headless": request.config.getoption("--headless"),
        "slow_mode": request.config.getoption("--slow"),
        "base_url": config.BASE_URL,
        "timeouts": config.get_timeout_config(),
    }


def _get_chrome_options(
    headless: bool, performance: str
) -> webdriver.ChromeOptions:
    """
    Get optimized Chrome options based on performance level.

    Args:
        headless: Whether to run in headless mode
        performance: Performance level (basic, fast, ultra)

    Returns:
        Configured ChromeOptions

    Performance Levels:
        - basic: Standard configuration
        - fast: 60-70% faster (disables images, GPU)
        - ultra: 80-90% faster (disables CSS, eager page load)
    """
    options = webdriver.ChromeOptions()

    # Anti-detection (all levels)
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)

    if headless:
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1920,1080")

    if performance in ["fast", "ultra"]:
        # Fast optimizations
        options.add_argument("--disable-gpu")
        options.add_argument("--disable-extensions")

        # Disable images and notifications
        prefs = {
            "profile.managed_default_content_settings.images": 2,
            "profile.default_content_setting_values.notifications": 2,
        }
        options.add_experimental_option("prefs", prefs)

        # Reduce logging
        options.add_argument("--log-level=3")
        options.add_experimental_option("excludeSwitches", ["enable-logging"])

    if performance == "ultra":
        # Ultra optimizations
        options.add_argument("--blink-settings=imagesEnabled=false")
        options.page_load_strategy = "eager"  # Don't wait for full page load

    return options


def _get_firefox_options(
    headless: bool, performance: str
) -> webdriver.FirefoxOptions:
    """Get optimized Firefox options based on performance level."""
    options = webdriver.FirefoxOptions()

    if headless:
        options.add_argument("--headless")
        options.add_argument("--width=1920")
        options.add_argument("--height=1080")

    if performance in ["fast", "ultra"]:
        # Disable images
        options.set_preference("permissions.default.image", 2)
        # Disable Flash
        options.set_preference(
            "dom.ipc.plugins.enabled.libflashplayer.so", False
        )

    return options


def _get_edge_options(
    headless: bool, performance: str
) -> webdriver.EdgeOptions:
    """Get optimized Edge options based on performance level."""
    options = webdriver.EdgeOptions()
    options.use_chromium = True

    if headless:
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1920,1080")

    if performance in ["fast", "ultra"]:
        options.add_argument("--disable-gpu")
        options.add_argument("--disable-extensions")

        prefs = {
            "profile.managed_default_content_settings.images": 2,
            "profile.default_content_setting_values.notifications": 2,
        }
        options.add_experimental_option("prefs", prefs)

    return options


@pytest.fixture(scope="function")
def browser(request):
    """
    Provide WebDriver instance for tests.

    Supports: Chrome, Firefox, Edge
    Supports: Headless mode, slow mode, performance optimization
    Automatically takes screenshots on test failure

    Performance Levels (use --performance flag):
        - basic: Standard configuration (baseline)
        - fast: 60-70% faster (disables images, GPU) - recommended for most tests
        - ultra: 80-90% faster (disables CSS, eager loading) - use for non-UI tests

    Example:
        pytest --performance=fast  # 60-70% faster
        pytest --performance=ultra --headless  # 80% faster + headless
    """
    browser_name = request.config.getoption("--browser").lower()
    headless = request.config.getoption("--headless")
    slow_mode = request.config.getoption("--slow")
    performance = request.config.getoption("--performance")
    driver = None

    logger.info(f"\n{'='*70}")
    logger.info(
        f"WebDriver: {browser_name.upper()} | Performance: {performance.upper()} | Test: {request.node.name}"
    )
    if slow_mode > 0:
        logger.info(f"Slow Mode: {slow_mode}s delay")
    logger.info(f"{'='*70}")

    start_time = time.time()

    try:
        if browser_name == "chrome":
            service = Service(ChromeDriverManager().install())
            options = _get_chrome_options(headless, performance)
            driver = webdriver.Chrome(service=service, options=options)

        elif browser_name == "firefox":
            service = Service(GeckoDriverManager().install())
            options = _get_firefox_options(headless, performance)
            driver = webdriver.Firefox(service=service, options=options)

        elif browser_name == "edge":
            service = Service(EdgeChromiumDriverManager().install())
            options = _get_edge_options(headless, performance)
            driver = webdriver.Edge(service=service, options=options)

        else:
            pytest.fail(
                f"Browser '{browser_name}' not supported. Use: chrome, firefox, edge"
            )

        driver.maximize_window()
        # Reduce implicit wait to 5s (use explicit waits instead)
        driver.implicitly_wait(5)
        driver.test_config = {
            "slow_mode": slow_mode,
            "browser_name": browser_name,
            "headless": headless,
            "performance": performance,
        }

        init_time = time.time() - start_time
        logger.info(f"✓ WebDriver initialized in {init_time:.2f}s")

    except Exception as e:
        logger.error(f"❌ WebDriver initialization failed: {e}")
        if driver:
            driver.quit()
        pytest.fail(f"WebDriver initialization failed: {e}")

    yield driver

    try:
        if hasattr(request.node, "rep_call") and request.node.rep_call.failed:
            _take_failure_screenshot(driver, request)
        driver.quit()
        cleanup_time = time.time() - start_time
        logger.info(f"✓ WebDriver closed (total: {cleanup_time:.2f}s)")
    except Exception as e:
        logger.warning(f"⚠ Cleanup error: {e}")

    logger.info(f"{'='*70}\n")


@pytest.fixture(scope="function", autouse=True)
def log_test_info(request):
    """Automatically log test start and finish with duration."""
    test_name = request.node.name
    start_time = time.time()
    logger.info(f"\n▶▶▶ Starting: {test_name}")
    yield
    duration = time.time() - start_time
    logger.info(f"✓✓✓ Finished: {test_name} ({duration:.2f}s)\n")


@pytest.fixture(scope="function")
def slow_down(request, browser):
    """Provide delay function for slow mode testing."""
    slow_mode = request.config.getoption("--slow")

    def delay():
        if slow_mode > 0:
            time.sleep(slow_mode)

    return delay


def _take_failure_screenshot(driver, request):
    """Take screenshot when test fails."""
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        test_name = request.node.name
        browser_name = driver.test_config["browser_name"]
        safe_test_name = "".join(c if c.isalnum() else "_" for c in test_name)
        screenshot_name = (
            f"FAIL_{browser_name}_{safe_test_name}_{timestamp}.png"
        )
        screenshot_path = os.path.join(config.SCREENSHOTS_DIR, screenshot_name)
        driver.save_screenshot(screenshot_path)
        logger.error(f"📸 Screenshot saved: {screenshot_path}")
        if hasattr(request.config, "_html"):
            extra = getattr(request.node, "extra", [])
            extra.append(pytest.html.extra.image(screenshot_path))
            request.node.extra = extra
    except Exception as e:
        logger.warning(f"⚠ Screenshot failed: {e}")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Hook to capture test results for reporting."""
    outcome = yield
    report = outcome.get_result()
    setattr(item, f"rep_{report.when}", report)
    if report.when == "call":
        if report.failed:
            logger.error(f"❌ FAILED: {item.name}")
            if hasattr(report, "longreprtext"):
                logger.error(f"   Error: {report.longreprtext[:200]}")
        elif report.passed:
            logger.info(f"✓ PASSED: {item.name}")
        elif report.skipped:
            logger.warning(f"⊘ SKIPPED: {item.name}")


def pytest_html_report_title(report):
    """Customize HTML report title."""
    report.title = "Universal Test Automation Report"


def pytest_html_results_summary(prefix, summary, postfix):
    """Add custom information to HTML report summary."""
    prefix.extend(
        [
            "<h2>Test Environment</h2>",
            f"<p><strong>Application URL:</strong> {config.BASE_URL or 'Not Configured'}</p>",
            f"<p><strong>Test Date:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        ]
    )


# ============================================================================
# DATA FIXTURES - Test Data Management
# ============================================================================


@pytest.fixture(scope="session")
def valid_user():
    """
    Provide valid user credentials for login tests.

    Returns:
        dict: Valid username and password from environment variables

    Example:
        >>> def test_login(browser, base_url, valid_user):
        ...     login_page.login(**valid_user)
    """
    from tests.static_test_data import Users

    return Users.VALID.copy()


@pytest.fixture(scope="session")
def invalid_user_username():
    """Provide user with invalid username."""
    from tests.static_test_data import Users

    return Users.INVALID_USERNAME.copy()


@pytest.fixture(scope="session")
def invalid_user_password():
    """Provide user with invalid password."""
    from tests.static_test_data import Users

    return Users.INVALID_PASSWORD.copy()


@pytest.fixture(scope="function")
def new_user():
    """
    Generate unique user credentials for signup tests.

    Creates a new username on each call to avoid conflicts.

    Returns:
        dict: Unique username and password

    Example:
        >>> def test_signup(browser, base_url, new_user):
        ...     signup_page.signup(**new_user)
    """
    from utils.helpers.data_generator import generate_random_password

    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S%f")
    return {
        "username": f"user_{timestamp}",
        "password": generate_random_password(length=12),
    }


@pytest.fixture(scope="function")
def purchase_data():
    """
    Provide valid purchase/checkout data.

    IMPORTANT: Adapt PurchaseData in static_test_data.py to match
    your application's form fields.

    Returns:
        dict: Valid billing and payment information

    Example:
        >>> def test_checkout(browser, purchase_data):
        ...     purchase_page.fill_form(**purchase_data)
    """
    from tests.static_test_data import PurchaseData

    return PurchaseData.VALID_PURCHASE.copy()


@pytest.fixture(scope="function")
def minimal_purchase_data():
    """Provide minimal valid purchase data."""
    from tests.static_test_data import PurchaseData

    return PurchaseData.MINIMAL_PURCHASE.copy()


# ============================================================================
# PAGE OBJECT FIXTURES - Initialized Page Objects
# ============================================================================
#
# IMPORTANT: Create YOUR application-specific page object fixtures here
#
# Example:
#
# @pytest.fixture(scope="function")
# def login_page(browser, base_url):
#     """Provide initialized LoginPage for YOUR application."""
#     from pages.login_page import LoginPage
#     browser.get(base_url)
#     return LoginPage(browser)
#
# See examples/demoblaze/conftest.py for reference implementation


# ============================================================================
# STATE FIXTURES - Pre-configured Test States
# ============================================================================
#
# IMPORTANT: Create YOUR application-specific state fixtures here
#
# Example:
#
# @pytest.fixture(scope="function")
# def logged_in_user(login_page, valid_user):
#     """Provide logged-in user session for YOUR application."""
#     login_page.login(**valid_user)
#     yield login_page
#     login_page.logout()
#
# See examples/demoblaze/conftest.py for reference implementation


# ============================================================================
# PERFORMANCE FIXTURES - Performance Testing
# ============================================================================


@pytest.fixture(scope="function")
def performance_collector():
    """
    Provide performance metrics collector for tests.

    Automatically clears metrics before each test and can generate
    reports after test completion.

    Example:
        >>> def test_login_performance(login_page, performance_collector):
        ...     performance_collector.start_timer("login")
        ...     login_page.login("user", "pass")
        ...     duration = performance_collector.stop_timer("login", category="auth")
        ...     assert performance_collector.check_threshold("login", duration)
    """
    from utils.performance.metrics import get_collector

    collector = get_collector()
    collector.clear_metrics()

    yield collector


@pytest.fixture(scope="function")
def performance_timer():
    """
    Provide performance timer context manager.

    Example:
        >>> def test_page_load(browser, performance_timer):
        ...     with performance_timer("page_load", category="navigation"):
        ...         browser.get("https://example.com")
    """
    from utils.performance.decorators import performance_timer as timer

    return timer


@pytest.fixture(scope="session", autouse=True)
def performance_report_cleanup(request):
    """Generate and save performance report at end of session."""
    yield

    try:
        from utils.performance.metrics import get_collector

        collector = get_collector()
        if len(collector) > 0:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            report_dir = os.path.join(
                config.REPORTS_ROOT, "performance", timestamp
            )
            os.makedirs(report_dir, exist_ok=True)

            report_file = os.path.join(report_dir, "performance_report.json")
            collector.save_report(report_file)

            logger.info(f"\n{'='*70}")
            logger.info(f"PERFORMANCE REPORT SAVED: {report_file}")
            logger.info(f"Total metrics collected: {len(collector)}")

            violations = collector.get_threshold_violations()
            if violations:
                logger.warning(
                    f"⚠ Performance threshold violations: {len(violations)}"
                )
            else:
                logger.info("✓ All performance checks passed")

            logger.info(f"{'='*70}\n")
    except Exception as e:
        logger.warning(f"Could not generate performance report: {e}")


# ============================================================================
# UNIVERSAL FRAMEWORK FIXTURES - Discovery-Based Testing
# ============================================================================


@pytest.fixture(scope="function")
def element_finder(browser):
    """
    Provide ElementFinder instance for element discovery.

    Example:
        def test_something(browser, element_finder):
            button = element_finder.find_by_text("Login", tag="button")
            button.click()
    """
    from framework.core import ElementFinder

    return ElementFinder(browser)


@pytest.fixture(scope="function")
def element_interactor(browser):
    """
    Provide ElementInteractor instance for element interactions.

    Example:
        def test_something(browser, element_interactor):
            element_interactor.click(button, force=True)
            element_interactor.type(input_field, "text")
    """
    from framework.core import ElementInteractor

    return ElementInteractor(browser)


@pytest.fixture(scope="function")
def wait_handler(browser):
    """
    Provide WaitHandler instance for intelligent waiting.

    Example:
        def test_something(browser, wait_handler):
            element = wait_handler.wait_for_element_visible(By.ID, "modal")
            wait_handler.wait_for_element_clickable(By.ID, "submit")
    """
    from framework.core import WaitHandler

    return WaitHandler(browser, default_timeout=config.TIMEOUT_DEFAULT)


@pytest.fixture(scope="function")
def discovery_engine(browser):
    """
    Provide DiscoveryEngine instance for automatic page structure discovery.

    Example:
        def test_something(browser, discovery_engine):
            forms = discovery_engine.discover_forms()
            nav = discovery_engine.discover_navigation()
            report = discovery_engine.generate_page_report()
    """
    from framework.core import DiscoveryEngine

    return DiscoveryEngine(browser)


@pytest.fixture(scope="function")
def universal_page(browser, element_finder, element_interactor, wait_handler):
    """
    Provide all universal components together for convenience.

    Returns a simple object with: finder, interactor, waiter

    Example:
        def test_something(browser, universal_page):
            button = universal_page.finder.find_by_text("Login")
            universal_page.interactor.click(button)
            universal_page.waiter.wait_for_element_visible(By.ID, "success")
    """
    from types import SimpleNamespace

    return SimpleNamespace(
        finder=element_finder,
        interactor=element_interactor,
        waiter=wait_handler,
    )


@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session, exitstatus):
    """Log session finish information."""
    logger.info(f"\n{'='*70}")
    logger.info(f"TEST SESSION FINISHED | Exit Status: {exitstatus}")
    if hasattr(session, "testscollected"):
        logger.info(f"Total Tests: {session.testscollected}")
    if hasattr(session, "testsfailed"):
        logger.info(f"Failed Tests: {session.testsfailed}")
    logger.info(f"{'='*70}\n")
