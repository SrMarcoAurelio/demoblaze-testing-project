"""
Pytest Configuration - DemoBlaze Test Automation
Author: Arévalo, Marc
Version: 6.0

Centralized pytest configuration using config.py for all settings.
"""
import pytest
import os
import datetime
import logging
import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager
from webdriver_manager.microsoft import EdgeChromiumDriverManager

from config import config

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)


def pytest_addoption(parser):
    """Add custom command line options."""
    parser.addoption(
        "--browser",
        action="store",
        default=config.BROWSER,
        help="Browser: chrome, firefox, or edge"
    )
    parser.addoption(
        "--headless",
        action="store_true",
        default=config.HEADLESS,
        help="Run in headless mode"
    )
    parser.addoption(
        "--slow",
        action="store",
        default=config.SLOW_MODE_DELAY,
        type=float,
        help="Delay between commands (seconds)"
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

            if 'tests' in path_parts:
                tests_idx = path_parts.index('tests')

                if len(path_parts) > tests_idx + 1:
                    module_name = path_parts[tests_idx + 1].lower()

                if len(path_parts) > tests_idx + 2:
                    filename = path_parts[-1]
                    if 'functional' in filename:
                        test_type = "functional"
                    elif 'business' in filename:
                        test_type = "business"
                    elif 'security' in filename:
                        test_type = "security"

            logger.info(f"Detected module: {module_name}, type: {test_type}")
    except Exception as e:
        logger.warning(f"Could not detect module/type: {e}")

    date_folder = datetime.datetime.now().strftime("%Y-%m-%d")

    # Import config module to avoid name conflict
    from config import config as cfg

    if module_name != "general" and test_type != "general":
        report_dir = os.path.join(cfg.REPORTS_ROOT, module_name, test_type, date_folder)
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
    logger.info(f"Browser: {browser_name.upper()} | Headless: {config.getoption('--headless')}")
    logger.info(f"Report: {report_path}")
    logger.info(f"{'='*70}")

    config.addinivalue_line("markers", "smoke: Critical smoke tests")
    config.addinivalue_line("markers", "regression: Full regression suite")
    config.addinivalue_line("markers", "functional: Functional tests")
    config.addinivalue_line("markers", "security: Security tests")
    config.addinivalue_line("markers", "business_rules: Business rules validation")
    config.addinivalue_line("markers", "accessibility: Accessibility tests")
    config.addinivalue_line("markers", "slow: Long-running tests")


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
        'browser': request.config.getoption("--browser"),
        'headless': request.config.getoption("--headless"),
        'slow_mode': request.config.getoption("--slow"),
        'base_url': config.BASE_URL,
        'timeouts': config.get_timeout_config()
    }


@pytest.fixture(scope="function")
def browser(request):
    """
    Provide WebDriver instance for tests.

    Supports: Chrome, Firefox, Edge
    Supports: Headless mode, slow mode
    Automatically takes screenshots on test failure
    """
    browser_name = request.config.getoption("--browser").lower()
    headless = request.config.getoption("--headless")
    slow_mode = request.config.getoption("--slow")
    driver = None

    logger.info(f"\n{'='*70}")
    logger.info(f"WebDriver: {browser_name.upper()} | Test: {request.node.name}")
    if slow_mode > 0:
        logger.info(f"Slow Mode: {slow_mode}s delay")
    logger.info(f"{'='*70}")

    start_time = time.time()

    try:
        if browser_name == "chrome":
            service = Service(ChromeDriverManager().install())
            options = webdriver.ChromeOptions()
            if headless:
                options.add_argument('--headless=new')
                options.add_argument('--no-sandbox')
                options.add_argument('--disable-dev-shm-usage')
                options.add_argument('--disable-gpu')
                options.add_argument('--window-size=1920,1080')
            options.add_argument('--disable-blink-features=AutomationControlled')
            options.add_experimental_option("excludeSwitches", ["enable-automation"])
            options.add_experimental_option('useAutomationExtension', False)
            driver = webdriver.Chrome(service=service, options=options)

        elif browser_name == "firefox":
            service = Service(GeckoDriverManager().install())
            options = webdriver.FirefoxOptions()
            if headless:
                options.add_argument('--headless')
                options.add_argument('--width=1920')
                options.add_argument('--height=1080')
            driver = webdriver.Firefox(service=service, options=options)

        elif browser_name == "edge":
            service = Service(EdgeChromiumDriverManager().install())
            options = webdriver.EdgeOptions()
            if headless:
                options.add_argument('--headless=new')
                options.add_argument('--no-sandbox')
                options.add_argument('--disable-dev-shm-usage')
                options.add_argument('--window-size=1920,1080')
            driver = webdriver.Edge(service=service, options=options)

        else:
            pytest.fail(f"Browser '{browser_name}' not supported. Use: chrome, firefox, edge")

        driver.maximize_window()
        driver.implicitly_wait(config.TIMEOUT_DEFAULT)
        driver.test_config = {
            'slow_mode': slow_mode,
            'browser_name': browser_name,
            'headless': headless
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
        if hasattr(request.node, 'rep_call') and request.node.rep_call.failed:
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
        browser_name = driver.test_config['browser_name']
        safe_test_name = "".join(c if c.isalnum() else "_" for c in test_name)
        screenshot_name = f"FAIL_{browser_name}_{safe_test_name}_{timestamp}.png"
        screenshot_path = os.path.join(config.SCREENSHOTS_DIR, screenshot_name)
        driver.save_screenshot(screenshot_path)
        logger.error(f"📸 Screenshot saved: {screenshot_path}")
        if hasattr(request.config, '_html'):
            extra = getattr(request.node, 'extra', [])
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
            if hasattr(report, 'longreprtext'):
                logger.error(f"   Error: {report.longreprtext[:200]}")
        elif report.passed:
            logger.info(f"✓ PASSED: {item.name}")
        elif report.skipped:
            logger.warning(f"⊘ SKIPPED: {item.name}")


def pytest_html_report_title(report):
    """Customize HTML report title."""
    report.title = "DemoBlaze Test Automation Report"


def pytest_html_results_summary(prefix, summary, postfix):
    """Add custom information to HTML report summary."""
    prefix.extend([
        "<h2>Test Environment</h2>",
        f"<p><strong>Application URL:</strong> {config.BASE_URL}</p>",
        f"<p><strong>Test Date:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
    ])


@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session, exitstatus):
    """Log session finish information."""
    logger.info(f"\n{'='*70}")
    logger.info(f"TEST SESSION FINISHED | Exit Status: {exitstatus}")
    if hasattr(session, 'testscollected'):
        logger.info(f"Total Tests: {session.testscollected}")
    if hasattr(session, 'testsfailed'):
        logger.info(f"Failed Tests: {session.testsfailed}")
    logger.info(f"{'='*70}\n")
