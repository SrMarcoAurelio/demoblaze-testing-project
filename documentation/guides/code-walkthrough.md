# Code Walkthrough Guide

Complete walkthrough of code execution from test start to finish.

## Overview

This guide explains how code flows through the framework, from pytest discovering tests to generating final reports. Understanding this flow helps debug issues and extend the framework.

## Table of Contents

1. [Test Execution Lifecycle](#test-execution-lifecycle)
2. [Fixture Initialization Flow](#fixture-initialization-flow)
3. [Test Execution Flow](#test-execution-flow)
4. [Locators Loader Mechanism](#locators-loader-mechanism)
5. [Performance Metrics Collection](#performance-metrics-collection)
6. [Report Generation](#report-generation)

---

## Test Execution Lifecycle

### Phase 1: Pytest Collection

**When:** Before any tests run
**Where:** pytest command line

```bash
pytest tests/login/test_login_functional.py -v
```

**What Happens:**
1. Pytest discovers test files matching pattern `test_*.py` or `*_test.py`
2. Collects test functions matching pattern `test_*`
3. Reads markers from decorators (`@pytest.mark.functional`)
4. Builds execution graph based on fixtures

**Code Location:** Pytest internal

---

### Phase 2: Session Setup

**When:** Once at start of session
**Where:** conftest.py:55-139

**Hook:** `pytest_configure(config)`

```python
@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
```

**Execution Flow:**

1. **Detect Test Module and Type** (lines 63-89):
```python
# Parse test path to extract module name and type
# Example: tests/login/test_login_functional.py
# → module: "login", type: "functional"

test_path_str = str(config.args[0])
path_parts = norm_path.split(os.sep)

if "tests" in path_parts:
    tests_idx = path_parts.index("tests")
    module_name = path_parts[tests_idx + 1]  # "login"

    filename = path_parts[-1]
    if "functional" in filename:
        test_type = "functional"
```

2. **Create Report Directory** (lines 91-106):
```python
# Create hierarchical directory structure
# results/module/type/date/

date_folder = datetime.now().strftime("%Y-%m-%d")
report_dir = os.path.join(
    cfg.REPORTS_ROOT, module_name, test_type, date_folder
)
os.makedirs(report_dir, exist_ok=True)

# Example: results/login/functional/2025-12-03/
```

3. **Configure HTML Report** (lines 108-114):
```python
browser_name = config.getoption("--browser")
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
report_name = f"report_{browser_name}_{timestamp}.html"
report_path = os.path.join(report_dir, report_name)

config.option.htmlpath = report_path
```

4. **Register Markers** (lines 125-138):
```python
config.addinivalue_line("markers", "smoke: Critical smoke tests")
config.addinivalue_line("markers", "functional: Functional tests")
# ... registers all custom markers
```

**Result:** Test environment configured, report paths set, markers registered

---

### Phase 3: Session Fixtures Initialization

**When:** Once at session start
**Where:** conftest.py (session-scoped fixtures)

**Fixtures Initialized (in dependency order):**

1. **base_url** (line 141):
```python
@pytest.fixture(scope="session")
def base_url():
    return config.BASE_URL  # Returns "https://your-application-url.com"
```

2. **timeout_config** (line 147):
```python
@pytest.fixture(scope="session")
def timeout_config():
    return config.get_timeout_config()
    # Returns: {'default': 10, 'short': 5, 'long': 30, ...}
```

3. **test_config** (line 153):
```python
@pytest.fixture(scope="session")
def test_config(request):
    return {
        "browser": request.config.getoption("--browser"),  # "chrome"
        "headless": request.config.getoption("--headless"), # False
        "slow_mode": request.config.getoption("--slow"),   # 0.0
        "base_url": config.BASE_URL,
        "timeouts": config.get_timeout_config(),
    }
```

4. **Data Fixtures** (session scope):
```python
# valid_user, invalid_user_username, invalid_user_password
# product_phone, product_laptop, product_monitor
# All loaded once from tests.test_data
```

**Result:** Shared data available to all tests, loaded once for efficiency

---

## Fixture Initialization Flow

Let's trace a complete test with fixtures:

```python
def test_login(login_page, valid_user):
    login_page.login(**valid_user)
    assert login_page.is_user_logged_in()
```

### Step-by-Step Fixture Resolution

**Pytest Dependency Graph:**
```
test_login
├── login_page
│   ├── browser
│   │   └── request (pytest built-in)
│   └── base_url (session fixture - already initialized)
└── valid_user (session fixture - already initialized)
```

### 1. Browser Fixture Initialization

**File:** conftest.py:165-261
**Scope:** function (new instance for each test)

```python
@pytest.fixture(scope="function")
def browser(request):
```

**Execution:**

1. **Read Configuration** (lines 174-176):
```python
browser_name = request.config.getoption("--browser")  # "chrome"
headless = request.config.getoption("--headless")     # False
slow_mode = request.config.getoption("--slow")        # 0.0
```

2. **Log Session Start** (lines 179-185):
```python
logger.info(f"\n{'='*70}")
logger.info(f"WebDriver: CHROME | Test: test_login")
logger.info(f"{'='*70}")
```

3. **Install and Configure Driver** (lines 190-206):
```python
if browser_name == "chrome":
    # webdriver-manager automatically downloads correct driver
    service = Service(ChromeDriverManager().install())

    # Configure browser options
    options = webdriver.ChromeOptions()
    if headless:
        options.add_argument("--headless=new")
        options.add_argument("--window-size=1920,1080")

    # Anti-detection measures
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])

    # Create driver
    driver = webdriver.Chrome(service=service, options=options)
```

4. **Configure Driver** (lines 232-238):
```python
driver.maximize_window()
driver.implicitly_wait(config.TIMEOUT_DEFAULT)  # 10 seconds

# Attach test config to driver
driver.test_config = {
    "slow_mode": slow_mode,
    "browser_name": browser_name,
    "headless": headless,
}
```

5. **Yield Driver** (line 249):
```python
yield driver  # Test receives driver here
```

**At this point:** WebDriver is running, ready to control browser

### 2. Login Page Fixture Initialization

**File:** conftest.py:431-447
**Depends on:** browser, base_url

```python
@pytest.fixture(scope="function")
def login_page(browser, base_url):
    from pages.login_page import LoginPage

    browser.get(base_url)  # Navigate to https://your-application-url.com
    return LoginPage(browser)
```

**Execution:**

1. **Import LoginPage class:**
```python
from pages.login_page import LoginPage
```

2. **Navigate to base URL:**
```python
browser.get(base_url)  # Opens https://your-application-url.com
```

3. **Instantiate LoginPage:**
```python
page = LoginPage(browser)
```

**Inside LoginPage.__init__:**

```python
class LoginPage(BasePage):
    # Load locators (happens at class definition time)
    login_button_nav = load_locator("login", "login_button_nav")
    username_field = load_locator("login", "login_username_field")
    # ...

    def __init__(self, driver):
        super().__init__(driver)  # Call BasePage.__init__
```

**Inside BasePage.__init__** (base_page.py:45-64):

```python
def __init__(self, driver, base_url=None, timeout=10):
    self.driver = driver                           # Store driver
    self.base_url = base_url or config.BASE_URL   # Store base URL
    self.timeout = timeout                         # Store timeout
    self.logger = logging.getLogger(self.__class__.__name__)  # Create logger
```

**Result:** LoginPage instance ready, locators loaded, logger configured

### 3. Valid User Fixture

**File:** conftest.py:345-360
**Scope:** session (already initialized)

```python
@pytest.fixture(scope="session")
def valid_user():
    from tests.test_data import Users
    return Users.VALID.copy()  # {'username': '...', 'password': '...'}
```

**Result:** Returns dictionary of credentials

---

## Test Execution Flow

Now all fixtures are initialized. The test executes:

```python
def test_login(login_page, valid_user):
    login_page.login(**valid_user)
    assert login_page.is_user_logged_in()
```

### Step 1: login_page.login(**valid_user)

**File:** pages/login_page.py

```python
def login(self, username: str, password: str) -> None:
    self.click(self.login_button_nav)         # Step 1.1
    time.sleep(self.SLEEP_MODAL)              # Step 1.2
    self.type(self.username_field, username)  # Step 1.3
    self.type(self.password_field, password)  # Step 1.4
    self.click(self.login_button_modal)       # Step 1.5
    time.sleep(self.SLEEP_SHORT)              # Step 1.6
```

#### Step 1.1: Click Login Button (Navigation)

**Method:** BasePage.click() (base_page.py:189-202)

```python
def click(self, locator: Tuple[str, str], timeout: Optional[int] = None) -> None:
    # Step 1: Wait for element to be clickable
    element = self.wait_for_element_clickable(locator, timeout)

    # Step 2: Click element
    element.click()

    # Step 3: Log action
    self.logger.info(f"Clicked: {locator}")
```

**Inside wait_for_element_clickable** (base_page.py:141-164):

```python
def wait_for_element_clickable(self, locator, timeout=None):
    wait_time = timeout if timeout else self.timeout  # Use 10s default

    try:
        # WebDriverWait with explicit condition
        element = WebDriverWait(self.driver, wait_time).until(
            EC.element_to_be_clickable(locator)
        )
        self.logger.debug(f"Element clickable: {locator}")
        return element
    except TimeoutException:
        self.logger.error(f"Element not clickable: {locator}")
        raise
```

**What happens:**
1. Selenium waits up to 10 seconds for element to be clickable
2. Checks element is visible AND enabled
3. Returns element when ready
4. Clicks element
5. Logs action

**Browser Action:** Clicks "Log in" button in navigation

#### Step 1.2: Wait for Modal Animation

```python
time.sleep(self.SLEEP_MODAL)  # 1.5 seconds
```

**Reason:** Allows modal to fully animate before interacting

#### Step 1.3 & 1.4: Type Username and Password

**Method:** BasePage.type() (base_page.py:203-224)

```python
def type(self, locator, text, clear_first=True, timeout=None):
    # Step 1: Wait for element to be visible
    element = self.wait_for_element_visible(locator, timeout)

    # Step 2: Clear field (if clear_first=True)
    if clear_first:
        element.clear()

    # Step 3: Send keys
    element.send_keys(text)

    # Step 4: Log action
    self.logger.info(f"Typed '{text}' into: {locator}")
```

**Browser Actions:**
- Clears username field
- Types username
- Clears password field
- Types password

#### Step 1.5: Click Login Button (Modal)

Same as Step 1.1, but clicks button inside modal

### Step 2: assert login_page.is_user_logged_in()

**File:** pages/login_page.py

```python
def is_user_logged_in(self) -> bool:
    return self.is_element_present(self.logout_button, timeout=3)
```

**Method:** BasePage.is_element_present() (base_page.py:267-285)

```python
def is_element_present(self, locator, timeout=2) -> bool:
    try:
        self.find_element(locator, timeout)
        return True
    except TimeoutException:
        return False
```

**What happens:**
1. Tries to find logout button (only visible when logged in)
2. Waits up to 3 seconds
3. Returns True if found, False if timeout

**Assert:** If True, test passes. If False, test fails.

---

## Locators Loader Mechanism

Understanding how locators load is crucial for adapting the framework.

### Loading Process

**When:** At class definition time (when Python imports the module)

**Example:**
```python
from utils.locators_loader import load_locator

class LoginPage(BasePage):
    # These load when class is defined, NOT when instance is created
    login_button_nav = load_locator("login", "login_button_nav")
    username_field = load_locator("login", "login_username_field")
```

### Step-by-Step Execution

**1. Call load_locator()** (locators_loader.py:225-242):

```python
def load_locator(page: str, element: str) -> Tuple[str, str]:
    return get_loader().get_locator(page, element)
```

**2. Get Singleton Loader** (locators_loader.py:206-222):

```python
_loader = None  # Global variable

def get_loader() -> LocatorsLoader:
    global _loader
    if _loader is None:
        _loader = LocatorsLoader()  # Create on first call
    return _loader
```

**3. LocatorsLoader.__init__()** (locators_loader.py:48-64):

```python
def __init__(self, config_path=None):
    if config_path is None:
        # Find project root
        project_root = os.path.dirname(os.path.dirname(__file__))
        # Build path: project_root/config/locators.json
        config_path = os.path.join(project_root, "config", "locators.json")

    self.config_path = config_path
    self.locators = self._load_locators()  # Load JSON
```

**4. Load JSON File** (locators_loader.py:66-91):

```python
def _load_locators(self) -> Dict:
    with open(self.config_path, "r", encoding="utf-8") as f:
        return json.load(f)  # Parse JSON
```

**Loaded Structure:**
```python
{
    "login": {
        "login_button_nav": {"by": "id", "value": "login2"},
        "login_username_field": {"by": "id", "value": "loginusername"},
        ...
    },
    ...
}
```

**5. Get Specific Locator** (locators_loader.py:92-138):

```python
def get_locator(self, page: str, element: str) -> Tuple[str, str]:
    # Get config: {"by": "id", "value": "login2"}
    locator_config = self.locators[page][element]

    by_type = locator_config["by"]      # "id"
    value = locator_config["value"]     # "login2"

    # Convert "id" → By.ID
    selenium_by = self.BY_MAPPING[by_type]  # By.ID

    return (selenium_by, value)  # (By.ID, "login2")
```

**Result:** Returns `(By.ID, "login2")` - ready for Selenium

---

## Performance Metrics Collection

### Collection Flow

**When:** During test execution (if using performance_collector fixture)

**Example Test:**
```python
def test_login_performance(login_page, valid_user, performance_collector):
    performance_collector.start_timer("login")
    login_page.login(**valid_user)
    duration = performance_collector.stop_timer("login", category="auth")
```

### Step-by-Step Execution

**1. Get Collector Singleton** (metrics.py:324-330):

```python
_global_collector = None

def get_collector() -> PerformanceMetricsCollector:
    global _global_collector
    if _global_collector is None:
        _global_collector = PerformanceMetricsCollector()
    return _global_collector
```

**2. Start Timer** (metrics.py:110-114):

```python
def start_timer(self, name: str) -> None:
    self._start_times[name] = time.time()  # Store current time
    logger.debug(f"⏱️  Started timer: {name}")

# Example: self._start_times = {"login": 1733234567.123}
```

**3. Perform Operation:**

```python
login_page.login(**valid_user)  # Operation being measured
```

**4. Stop Timer** (metrics.py:115-144):

```python
def stop_timer(self, name: str, category="general", metadata=None) -> float:
    # Get elapsed time
    duration = time.time() - self._start_times[name]  # e.g., 2.35 seconds
    del self._start_times[name]  # Clean up

    # Create metric object
    metric = PerformanceMetric(
        name="login",
        duration=2.35,
        timestamp="2025-12-03T14:30:15.123456",
        category="auth",
        metadata={}
    )

    # Store metric
    self.metrics.append(metric)

    logger.debug(f"⏱️  Stopped timer: login - 2.350s")
    return duration  # Return 2.35
```

**5. Check Threshold** (metrics.py:207-228):

```python
def check_threshold(self, name: str, duration: float) -> bool:
    threshold = self.thresholds[name]  # Get threshold (e.g., 3.0s for login)

    is_ok = duration <= threshold.max_duration  # 2.35 <= 3.0 → True

    status = threshold.get_threshold_status(duration)
    # "✓ PASS (2.350s <= 3.0s)"

    logger.info(f"Performance check: login - {status}")
    return is_ok  # True
```

---

## Report Generation

### Test Completion Hooks

**After Each Test:** conftest.py:307-322

```python
@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()

    if report.when == "call":
        if report.failed:
            logger.error(f"❌ FAILED: {item.name}")
        elif report.passed:
            logger.info(f"✓ PASSED: {item.name}")
```

**Screenshot on Failure:** conftest.py:251-259 (browser fixture teardown)

```python
if hasattr(request.node, "rep_call") and request.node.rep_call.failed:
    _take_failure_screenshot(driver, request)
```

### Session End Report Generation

**Performance Report:** conftest.py:688-722

```python
@pytest.fixture(scope="session", autouse=True)
def performance_report_cleanup(request):
    yield  # Wait for all tests to complete

    # Generate report
    collector = get_collector()
    if len(collector) > 0:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = os.path.join(config.REPORTS_ROOT, "performance", timestamp)
        os.makedirs(report_dir, exist_ok=True)

        report_file = os.path.join(report_dir, "performance_report.json")
        collector.save_report(report_file)

        logger.info(f"PERFORMANCE REPORT SAVED: {report_file}")
```

**HTML Report:** Configured in pytest_configure, generated automatically by pytest-html

**Final Log:** conftest.py:724-733

```python
@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session, exitstatus):
    logger.info(f"\n{'='*70}")
    logger.info(f"TEST SESSION FINISHED | Exit Status: {exitstatus}")
    logger.info(f"Total Tests: {session.testscollected}")
    logger.info(f"{'='*70}\n")
```

---

## Complete Flow Diagram

```
[Pytest Discovery]
        ↓
[pytest_configure Hook]
   - Create report directories
   - Configure HTML report
   - Register markers
        ↓
[Session Fixtures Initialize]
   - base_url, test_config, valid_user, etc.
        ↓
[For Each Test:]
        ↓
[log_test_info (autouse)]
   - Log test start
        ↓
[Function Fixtures Initialize]
   - browser → LoginPage → valid_user
        ↓
[Test Executes]
   - login_page.login(**valid_user)
   - Selenium commands via BasePage methods
   - WebDriverWait for elements
   - Explicit waits, clicks, typing
        ↓
[Assertions Execute]
   - assert login_page.is_user_logged_in()
        ↓
[Fixture Teardown (reverse order)]
   - login_page: no cleanup
   - browser: screenshot if failed, driver.quit()
        ↓
[log_test_info (autouse)]
   - Log test finish and duration
        ↓
[Next Test or Session End]
        ↓
[Session Fixtures Teardown]
   - performance_report_cleanup: save report
        ↓
[pytest_sessionfinish Hook]
   - Final logging
        ↓
[Exit]
```

---

## Key Takeaways

1. **Fixtures execute in dependency order** - browser before login_page
2. **Session fixtures initialize once** - shared data for efficiency
3. **Locators load at class definition** - not instance creation
4. **BasePage methods use WebDriverWait** - explicit waits for reliability
5. **Logging happens at every layer** - helps debugging
6. **Reports generate automatically** - via hooks and autouse fixtures
7. **Cleanup happens in reverse** - teardown opposite of setup

---

## Related Documentation

- [API Reference](../api-reference/README.md) - Detailed method documentation
- [Fixtures Guide](test-fixtures.md) - Complete fixture reference
- [Troubleshooting Guide](troubleshooting.md) - Common issues and solutions
