"""
Pytest Configuration - DemoBlaze Test Automation
Author: Arévalo, Marc
Version: 5.0
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

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Configuration
BASE_URL = "https://www.demoblaze.com/"
TIMEOUT = 10
TIMEOUT_SHORT = 5
TIMEOUT_MEDIUM = 15
TIMEOUT_LONG = 30
REPORTS_ROOT = "results"
SCREENSHOTS_DIR = "results/screenshots"

# ============================================================================
# Command Line Options
# ============================================================================

def pytest_addoption(parser):
    parser.addoption("--browser", action="store", default="chrome", 
                     help="Browser: chrome, firefox, or edge")
    parser.addoption("--headless", action="store_true", default=False,
                     help="Run in headless mode")
    parser.addoption("--slow", action="store", default=0, type=float,
                     help="Delay between commands (seconds)")

# ============================================================================
# Configuration Hook
# ============================================================================

@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
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
                    test_dir = path_parts[tests_idx + 2].lower()
                    if 'functional' in test_dir:
                        test_type = "functional"
                    elif 'security' in test_dir:
                        test_type = "security"
            
            logging.info(f"Detected module: {module_name}, type: {test_type}")
    except Exception as e:
        logging.warning(f"Could not detect module/type: {e}")
    
    if module_name != "general" and test_type != "general":
        report_dir = os.path.join(REPORTS_ROOT, module_name, test_type)
    elif module_name != "general":
        report_dir = os.path.join(REPORTS_ROOT, module_name)
    else:
        report_dir = os.path.join(REPORTS_ROOT, "general")
    
    os.makedirs(report_dir, exist_ok=True)
    os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
    
    browser_name = config.getoption("--browser").lower()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_name = f"report_{browser_name}_{timestamp}.html"
    report_path = os.path.join(report_dir, report_name)
    
    config.option.htmlpath = report_path
    config.option.self_contained_html = True
    
    logging.info(f"{'='*70}")
    logging.info(f"TEST SESSION STARTED")
    logging.info(f"Module: {module_name.upper()} | Type: {test_type.upper()}")
    logging.info(f"Browser: {browser_name.upper()} | Headless: {config.getoption('--headless')}")
    logging.info(f"Report: {report_path}")
    logging.info(f"{'='*70}")

# ============================================================================
# Session Fixtures
# ============================================================================

@pytest.fixture(scope="session")
def base_url():
    return BASE_URL

@pytest.fixture(scope="session")
def timeout_config():
    return {
        'default': TIMEOUT,
        'short': TIMEOUT_SHORT,
        'medium': TIMEOUT_MEDIUM,
        'long': TIMEOUT_LONG
    }

@pytest.fixture(scope="session")
def test_config(request):
    return {
        'browser': request.config.getoption("--browser"),
        'headless': request.config.getoption("--headless"),
        'slow_mode': request.config.getoption("--slow")
    }

# ============================================================================
# Function Fixtures
# ============================================================================

@pytest.fixture(scope="function")
def browser(request):
    browser_name = request.config.getoption("--browser").lower()
    headless = request.config.getoption("--headless")
    slow_mode = request.config.getoption("--slow")
    driver = None
    
    logging.info(f"\n{'='*70}")
    logging.info(f"WebDriver: {browser_name.upper()} | Test: {request.node.name}")
    if slow_mode > 0:
        logging.info(f"Slow Mode: {slow_mode}s delay")
    logging.info(f"{'='*70}")
    
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
        driver.implicitly_wait(TIMEOUT)
        driver.test_config = {
            'slow_mode': slow_mode,
            'browser_name': browser_name,
            'headless': headless
        }
        
        init_time = time.time() - start_time
        logging.info(f"✓ WebDriver initialized in {init_time:.2f}s")
        
    except Exception as e:
        logging.error(f"❌ WebDriver initialization failed: {e}")
        if driver:
            driver.quit()
        pytest.fail(f"WebDriver initialization failed: {e}")
    
    yield driver
    
    try:
        if hasattr(request.node, 'rep_call') and request.node.rep_call.failed:
            _take_failure_screenshot(driver, request)
        driver.quit()
        cleanup_time = time.time() - start_time
        logging.info(f"✓ WebDriver closed (total: {cleanup_time:.2f}s)")
    except Exception as e:
        logging.warning(f"⚠ Cleanup error: {e}")
    
    logging.info(f"{'='*70}\n")

@pytest.fixture(scope="function", autouse=True)
def log_test_info(request):
    test_name = request.node.name
    start_time = time.time()
    logging.info(f"\n▶▶▶ Starting: {test_name}")
    yield
    duration = time.time() - start_time
    logging.info(f"✓✓✓ Finished: {test_name} ({duration:.2f}s)\n")

@pytest.fixture(scope="function")
def slow_down(request, browser):
    slow_mode = request.config.getoption("--slow")
    def delay():
        if slow_mode > 0:
            time.sleep(slow_mode)
    return delay

# ============================================================================
# Helper Functions
# ============================================================================

def _take_failure_screenshot(driver, request):
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        test_name = request.node.name
        browser_name = driver.test_config['browser_name']
        safe_test_name = "".join(c if c.isalnum() else "_" for c in test_name)
        screenshot_name = f"FAIL_{browser_name}_{safe_test_name}_{timestamp}.png"
        screenshot_path = os.path.join(SCREENSHOTS_DIR, screenshot_name)
        driver.save_screenshot(screenshot_path)
        logging.error(f"📸 Screenshot saved: {screenshot_path}")
        if hasattr(request.config, '_html'):
            extra = getattr(request.node, 'extra', [])
            extra.append(pytest.html.extra.image(screenshot_path))
            request.node.extra = extra
    except Exception as e:
        logging.warning(f"⚠ Screenshot failed: {e}")

# ============================================================================
# Pytest Hooks
# ============================================================================

@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    setattr(item, f"rep_{report.when}", report)
    if report.when == "call":
        if report.failed:
            logging.error(f"❌ FAILED: {item.name}")
            if hasattr(report, 'longreprtext'):
                logging.error(f"   Error: {report.longreprtext[:200]}")
        elif report.passed:
            logging.info(f"✓ PASSED: {item.name}")
        elif report.skipped:
            logging.warning(f"⊘ SKIPPED: {item.name}")

def pytest_html_report_title(report):
    report.title = "DemoBlaze Test Automation Report"

def pytest_html_results_summary(prefix, summary, postfix):
    prefix.extend([
        "<h2>Test Environment</h2>",
        f"<p><strong>Application URL:</strong> {BASE_URL}</p>",
        f"<p><strong>Test Date:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
    ])

@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session, exitstatus):
    logging.info(f"\n{'='*70}")
    logging.info(f"TEST SESSION FINISHED | Exit Status: {exitstatus}")
    if hasattr(session, 'testscollected'):
        logging.info(f"Total Tests: {session.testscollected}")
    if hasattr(session, 'testsfailed'):
        logging.info(f"Failed Tests: {session.testsfailed}")
    logging.info(f"{'='*70}\n")

# ============================================================================
# Custom Markers
# ============================================================================

def pytest_configure(config):
    config.addinivalue_line("markers", "smoke: Critical smoke tests")
    config.addinivalue_line("markers", "regression: Full regression suite")
    config.addinivalue_line("markers", "functional: Functional tests")
    config.addinivalue_line("markers", "security: Security tests")
    config.addinivalue_line("markers", "business_rules: Business rules validation")
    config.addinivalue_line("markers", "slow: Long-running tests")
