# Performance Optimization Guide

**Master the art of fast, efficient test execution**

---

## 📊 Overview

This guide provides comprehensive strategies for optimizing test execution performance, reducing test suite runtime, and improving resource utilization.

**Performance Goals**:
- ⚡ Individual tests: < 30 seconds
- 🚀 Full suite: < 15 minutes (with parallelization)
- 💾 Memory usage: < 2GB per worker
- 🔄 CI/CD pipeline: < 10 minutes

---

## Table of Contents

1. [Understanding Test Performance](#understanding-test-performance)
2. [Identifying Slow Tests](#identifying-slow-tests)
3. [Parallel Execution](#parallel-execution)
4. [Browser Optimization](#browser-optimization)
5. [Wait Strategy Optimization](#wait-strategy-optimization)
6. [Fixture Scope Optimization](#fixture-scope-optimization)
7. [Network Optimization](#network-optimization)
8. [Resource Cleanup](#resource-cleanup)
9. [CI/CD Optimization](#cicd-optimization)
10. [Profiling and Monitoring](#profiling-and-monitoring)

---

## Understanding Test Performance

### Performance Metrics

**Test Duration Components**:
```
Total Test Time = Browser Startup + Page Load + Element Interactions + Waits + Teardown
```

**Typical Breakdown**:
- Browser startup: 2-5 seconds
- Page load: 1-5 seconds
- Element interactions: 0.1-0.5 seconds each
- Waits: 0-10 seconds (can be optimized)
- Teardown: 0.5-2 seconds

### Performance Anti-Patterns

❌ **DON'T DO THIS**:
```python
import time

def test_slow_example(browser):
    # 1. Hard-coded sleeps
    time.sleep(5)  # ❌ Always waits 5s, even if ready in 1s

    # 2. Finding same element multiple times
    browser.find_element(By.ID, "button").text
    browser.find_element(By.ID, "button").click()  # ❌ Finds again
    browser.find_element(By.ID, "button").is_displayed()  # ❌ Finds again

    # 3. Unnecessary page loads
    browser.get("https://example.com")
    do_something()
    browser.get("https://example.com")  # ❌ Reloads same page

    # 4. Function-scoped fixtures for expensive resources
    # ❌ Creates new browser for each test
```

✅ **DO THIS INSTEAD**:
```python
from selenium.webdriver.support import expected_conditions as EC

def test_fast_example(browser, wait_handler):
    # 1. Explicit waits with conditions
    wait_handler.wait_for_element_visible((By.ID, "button"), timeout=5)

    # 2. Store element reference
    button = browser.find_element(By.ID, "button")
    text = button.text
    button.click()
    is_displayed = button.is_displayed()

    # 3. Navigate only when necessary
    current_url = browser.current_url
    if "example.com" not in current_url:
        browser.get("https://example.com")

    # 4. Use appropriate fixture scopes
    # ✅ Reuses browser across tests when possible
```

---

## Identifying Slow Tests

### 1. Built-in Pytest Duration Report

```bash
# Show slowest 10 tests
pytest --durations=10

# Show all test durations
pytest --durations=0

# Only show tests slower than 1 second
pytest --durations-min=1.0
```

**Example Output**:
```
============================= slowest 10 durations =============================
15.23s call     tests/login/test_login_functional.py::test_successful_login
12.45s call     tests/cart/test_cart_functional.py::test_add_multiple_products
8.91s call      tests/purchase/test_purchase_functional.py::test_complete_checkout
```

### 2. pytest-profiling

```bash
# Install
pip install pytest-profiling

# Profile tests
pytest --profile

# Generate SVG graph
pytest --profile-svg
```

### 3. Custom Performance Tracking

```python
# conftest.py
import time
import pytest

@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()

    if report.when == "call":
        duration = call.stop - call.start
        if duration > 10.0:
            print(f"\n⚠️ SLOW TEST: {item.nodeid} took {duration:.2f}s")
```

---

## Parallel Execution

### Setup pytest-xdist

```bash
# Install
pip install pytest-xdist

# Run with all CPU cores
pytest -n auto

# Run with specific number of workers
pytest -n 4

# Run with load balancing
pytest -n auto --dist loadscope
```

### Test Isolation for Parallel Execution

**Requirements for Parallel Tests**:
1. ✅ No shared state between tests
2. ✅ Each test gets fresh browser
3. ✅ Unique test data per test
4. ✅ No file system conflicts
5. ✅ No port conflicts

**Example - Parallel-Safe Test**:
```python
import pytest
from utils.helpers.data_generator import generate_unique_username

@pytest.mark.parametrize("test_case", [
    {"username": None, "password": "test123"},  # Will generate unique username
    {"username": None, "password": "test456"},
])
def test_parallel_safe_login(browser, base_url, test_case):
    # Generate unique username for this test
    username = test_case["username"] or generate_unique_username()

    # No shared state - completely isolated
    login_page = LoginPage(browser)
    login_page.login(username, test_case["password"])

    # Each worker gets its own browser, no conflicts
```

**Example - NOT Parallel-Safe** ❌:
```python
# Global state - BREAKS parallel execution
logged_in_user = None

def test_login(browser):
    global logged_in_user  # ❌ Shared across workers!
    logged_in_user = do_login()

def test_profile(browser):
    # ❌ May get None from different worker!
    assert logged_in_user is not None
```

### Fixture Scopes for Parallel Execution

```python
# conftest.py

# ❌ BAD - Session scope browser shared across workers (not supported)
@pytest.fixture(scope="session")
def browser_session():
    driver = webdriver.Chrome()
    yield driver
    driver.quit()

# ✅ GOOD - Function scope, each test gets fresh browser
@pytest.fixture(scope="function")
def browser():
    driver = webdriver.Chrome()
    yield driver
    driver.quit()

# ✅ GOOD - Class scope for test classes
@pytest.fixture(scope="class")
def browser_class():
    driver = webdriver.Chrome()
    yield driver
    driver.quit()
```

### Distribution Strategies

```bash
# Load distribution - balance tests across workers
pytest -n auto --dist load

# Load scope - tests from same module go to same worker
pytest -n auto --dist loadscope  # Better for module-scoped fixtures

# Load group - tests from same file go to same worker
pytest -n auto --dist loadgroup

# No distribution - run tests in order
pytest -n auto --dist no
```

### Performance Comparison

**Sequential vs Parallel** (100 tests, 5 seconds each):

```
Sequential: 100 tests × 5s = 500 seconds (8.3 minutes)

Parallel (4 workers):
100 tests ÷ 4 workers × 5s = 125 seconds (2.1 minutes)
Speedup: 4x faster! ⚡
```

---

## Browser Optimization

### Headless Mode

**Benefits**: 30-50% faster, lower memory usage

```python
# conftest.py
from selenium.webdriver.chrome.options import Options

@pytest.fixture
def browser():
    options = Options()

    # Enable headless mode
    options.add_argument("--headless=new")  # New headless mode (Chrome 109+)

    driver = webdriver.Chrome(options=options)
    yield driver
    driver.quit()
```

```bash
# Run tests in headless mode
pytest --headless
```

### Disable Unnecessary Browser Features

```python
# conftest.py
def get_optimized_chrome_options():
    options = Options()

    # Core optimizations
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    # Disable GPU (not needed for testing)
    options.add_argument("--disable-gpu")

    # Disable extensions
    options.add_argument("--disable-extensions")

    # Disable images (50% faster page loads!)
    prefs = {
        "profile.managed_default_content_settings.images": 2,
        "profile.default_content_setting_values.notifications": 2,
    }
    options.add_experimental_option("prefs", prefs)

    # Disable CSS (use cautiously - may break tests)
    # options.add_argument("--disable-css")

    # Set window size (faster than maximize)
    options.add_argument("--window-size=1920,1080")

    # Disable logging (reduces I/O)
    options.add_argument("--log-level=3")
    options.add_experimental_option("excludeSwitches", ["enable-logging"])

    return options

@pytest.fixture
def browser():
    options = get_optimized_chrome_options()
    driver = webdriver.Chrome(options=options)
    yield driver
    driver.quit()
```

### Browser-Specific Optimizations

**Firefox**:
```python
from selenium.webdriver.firefox.options import Options

options = Options()
options.headless = True
options.set_preference("permissions.default.image", 2)  # Disable images
options.set_preference("dom.ipc.plugins.enabled.libflashplayer.so", False)  # Disable Flash
```

**Edge**:
```python
from selenium.webdriver.edge.options import Options

options = Options()
options.use_chromium = True
options.add_argument("--headless")
options.add_argument("--disable-gpu")
```

### Performance Impact

| Optimization | Speed Gain | Risk |
|--------------|------------|------|
| Headless mode | 30-50% | Low |
| Disable images | 40-60% | Medium (visual tests may fail) |
| Disable CSS | 20-30% | High (layout tests will fail) |
| Disable extensions | 10-20% | Low |
| No GPU | 5-10% | Low |
| Window size (vs maximize) | 5-10% | Low |

---

## Wait Strategy Optimization

### The Cost of Poor Waits

```python
# ❌ SLOW - Hard-coded sleep (always waits 10 seconds)
time.sleep(10)  # Wastes time if element ready in 1s
# Cost: 9 wasted seconds

# ✅ FAST - Explicit wait (waits only as long as needed)
wait.until(EC.presence_of_element_located((By.ID, "element")))
# Cost: 0-10 seconds (only what's necessary)
```

**Impact**: In 100 tests with 5 waits each:
- Hard sleeps: 500 × 10s = 5,000 seconds (83 minutes) ❌
- Explicit waits: 500 × 2s avg = 1,000 seconds (16 minutes) ✅
- **Time saved: 67 minutes!**

### Best Wait Practices

```python
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# ✅ 1. Use explicit waits
wait = WebDriverWait(driver, 10)
element = wait.until(EC.element_to_be_clickable((By.ID, "submit")))

# ✅ 2. Wait for specific condition
wait.until(EC.text_to_be_present_in_element((By.ID, "status"), "Complete"))

# ✅ 3. Use custom conditions for complex scenarios
def element_has_css_class(locator, css_class):
    def check(driver):
        element = driver.find_element(*locator)
        return css_class in element.get_attribute("class")
    return check

wait.until(element_has_css_class((By.ID, "button"), "enabled"))

# ✅ 4. Reduce default timeout for fast operations
short_wait = WebDriverWait(driver, 2)  # Instead of 10s
short_wait.until(EC.presence_of_element_located((By.ID, "fast-element")))
```

### Implicit vs Explicit Waits

```python
# ❌ Implicit wait - applies to ALL find_element calls
driver.implicitly_wait(10)  # Every find_element waits up to 10s

# Problem: Even fast elements wait unnecessarily
driver.find_element(By.ID, "instant-element")  # May still wait 10s!

# ✅ Explicit wait - wait only when needed
# No implicit wait (or set to 0)
driver.implicitly_wait(0)

# Wait explicitly only when necessary
if element_is_slow_to_load:
    wait.until(EC.presence_of_element_located((By.ID, "slow-element")))
else:
    driver.find_element(By.ID, "fast-element")  # Returns immediately
```

**Recommendation**: Use explicit waits only, set implicit wait to 0.

---

## Fixture Scope Optimization

### Understanding Fixture Scopes

| Scope | Setup Frequency | Best For | Performance |
|-------|----------------|----------|-------------|
| `function` | Every test | Unique state per test | Slowest |
| `class` | Once per test class | Shared class state | Medium |
| `module` | Once per module | Module-level setup | Fast |
| `session` | Once per test session | Expensive setup | Fastest |

### Optimization Strategy

```python
# ❌ SLOW - Function scope for expensive resource
@pytest.fixture(scope="function")
def database_connection():
    conn = create_expensive_db_connection()  # 2 seconds
    yield conn
    conn.close()  # 0.5 seconds
# Cost: 2.5 seconds × 100 tests = 250 seconds!

# ✅ FAST - Session scope with cleanup
@pytest.fixture(scope="session")
def database_connection():
    conn = create_expensive_db_connection()  # 2 seconds (once!)
    yield conn
    conn.close()  # 0.5 seconds (once!)
# Cost: 2.5 seconds total for 100 tests!
# Time saved: 247.5 seconds (4+ minutes)
```

### Browser Fixture Scope Strategy

```python
# Strategy 1: Function scope (safest, slowest)
@pytest.fixture(scope="function")
def browser():
    driver = webdriver.Chrome()  # New browser per test
    yield driver
    driver.quit()
# Cost: 3s × 100 tests = 300s
# Safety: ✅ Complete isolation

# Strategy 2: Class scope (medium)
@pytest.fixture(scope="class")
def browser():
    driver = webdriver.Chrome()  # New browser per class
    yield driver
    driver.quit()
# Cost: 3s × 10 classes = 30s
# Safety: ⚠️ Tests in class must not conflict

# Strategy 3: Hybrid approach (recommended)
@pytest.fixture(scope="function")
def browser(browser_session):
    # Get session browser
    driver = browser_session

    # Reset to clean state
    driver.delete_all_cookies()
    driver.execute_script("window.localStorage.clear()")
    driver.execute_script("window.sessionStorage.clear()")

    yield driver
    # Don't quit - reuse for next test!

@pytest.fixture(scope="session")
def browser_session():
    driver = webdriver.Chrome()
    yield driver
    driver.quit()
# Cost: 3s (once) + 0.2s × 100 tests = 23s
# Safety: ✅ Clean state per test
# Speedup: 92% faster!
```

---

## Network Optimization

### Disable Image Loading

```python
chrome_prefs = {
    "profile.managed_default_content_settings.images": 2  # 0=allow, 2=block
}
options.add_experimental_option("prefs", chrome_prefs)
```

**Impact**: 40-60% faster page loads

### Disable CSS (Use Cautiously)

```python
options.add_argument("--blink-settings=imagesEnabled=false")
```

**Warning**: May break layout-dependent tests

### Page Load Strategy

```python
# Wait for full page load (default)
options.page_load_strategy = 'normal'  # Slowest, safest

# Wait for DOMContentLoaded event
options.page_load_strategy = 'eager'  # Faster, usually safe

# Don't wait for page load
options.page_load_strategy = 'none'  # Fastest, risky
```

**Example**:
```python
from selenium.webdriver.chrome.options import Options

options = Options()
options.page_load_strategy = 'eager'  # 30-50% faster page loads
driver = webdriver.Chrome(options=options)
```

---

## Resource Cleanup

### Browser Memory Leaks

```python
# ❌ Memory leak - browser not quit
def test_leaky(browser):
    # Test runs, but browser keeps running!
    pass  # Forgot driver.quit()

# ✅ Proper cleanup with fixture
@pytest.fixture
def browser():
    driver = webdriver.Chrome()
    yield driver
    driver.quit()  # Always cleaned up

# ✅ Extra safety with try/finally
@pytest.fixture
def browser():
    driver = webdriver.Chrome()
    try:
        yield driver
    finally:
        driver.quit()  # Cleaned up even on errors
```

### Screenshot Cleanup

```python
# conftest.py
import pytest
import os
from pathlib import Path

@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()

    if report.when == "call" and report.failed:
        driver = item.funcargs.get("browser")
        if driver:
            # Save screenshot
            screenshot_dir = Path("results/screenshots")
            screenshot_dir.mkdir(parents=True, exist_ok=True)
            driver.save_screenshot(f"{screenshot_dir}/{item.name}.png")

# Clean up old screenshots
def pytest_sessionstart(session):
    screenshot_dir = Path("results/screenshots")
    if screenshot_dir.exists():
        # Delete screenshots older than 7 days
        import time
        now = time.time()
        for f in screenshot_dir.glob("*.png"):
            if os.stat(f).st_mtime < now - 7 * 86400:
                f.unlink()
```

### Log File Rotation

```python
# config.py
import logging
from logging.handlers import RotatingFileHandler

# Rotate logs at 10MB, keep 3 backups
handler = RotatingFileHandler(
    "pytest.log",
    maxBytes=10*1024*1024,  # 10MB
    backupCount=3
)
logging.basicConfig(handlers=[handler])
```

---

## CI/CD Optimization

### Caching Dependencies

**GitHub Actions**:
```yaml
# .github/workflows/tests.yml
- name: Cache pip packages
  uses: actions/cache@v3
  with:
    path: ~/.cache/pip
    key: ${{ runner.os }}-pip-${{ hashFiles('requirements.txt') }}

- name: Cache browser drivers
  uses: actions/cache@v3
  with:
    path: ~/.wdm
    key: ${{ runner.os }}-wdm-${{ hashFiles('requirements.txt') }}
```

### Parallel Matrix Builds

```yaml
jobs:
  test:
    strategy:
      matrix:
        browser: [chrome, firefox]
        python: ["3.11", "3.12"]
    runs-on: ubuntu-latest
    steps:
      - name: Run tests
        run: pytest -n auto --browser=${{ matrix.browser }}
```

### Selective Test Execution

```yaml
# Only run tests for changed files
- name: Get changed files
  id: changed-files
  uses: tj-actions/changed-files@v40

- name: Run relevant tests
  run: |
    if [[ "${{ steps.changed-files.outputs.all_changed_files }}" == *"login"* ]]; then
      pytest tests/login/
    fi
```

### Artifact Optimization

```yaml
# Only upload artifacts on failure
- name: Upload screenshots
  if: failure()
  uses: actions/upload-artifact@v3
  with:
    name: screenshots
    path: results/screenshots/
    retention-days: 7  # Auto-delete after 7 days
```

---

## Profiling and Monitoring

### pytest-benchmark

```bash
pip install pytest-benchmark

# Run benchmarks
pytest --benchmark-only
```

```python
def test_login_performance(benchmark, login_page, valid_user):
    benchmark(login_page.login, **valid_user)
```

### Memory Profiling

```bash
pip install pytest-memray

# Profile memory usage
pytest --memray
```

### Continuous Monitoring

```python
# conftest.py - Track performance trends
import json
from pathlib import Path
from datetime import datetime

def pytest_sessionfinish(session):
    stats = {
        "timestamp": datetime.now().isoformat(),
        "total_tests": session.testscollected,
        "duration": session.duration,
        "passed": session.passed,
        "failed": session.failed,
    }

    # Append to metrics file
    metrics_file = Path("results/performance_metrics.jsonl")
    metrics_file.parent.mkdir(parents=True, exist_ok=True)

    with metrics_file.open("a") as f:
        f.write(json.dumps(stats) + "\n")
```

---

## Performance Checklist

### Before Every Test Run

- [ ] Are you using parallel execution? (`pytest -n auto`)
- [ ] Is headless mode enabled? (`--headless`)
- [ ] Are images disabled for non-visual tests?
- [ ] Are you using explicit waits instead of `time.sleep()`?
- [ ] Are expensive fixtures using appropriate scopes?

### Code Review Checklist

- [ ] No `time.sleep()` calls (use explicit waits)
- [ ] No unnecessary `driver.get()` calls
- [ ] Elements not found multiple times unnecessarily
- [ ] Fixtures use appropriate scopes
- [ ] Browser cleanup happens (driver.quit())
- [ ] No global state that prevents parallel execution

### CI/CD Checklist

- [ ] Dependency caching enabled
- [ ] Test parallelization configured
- [ ] Selective test execution (only changed modules)
- [ ] Artifact retention policies set
- [ ] Performance metrics tracked over time

---

## Quick Wins Summary

**Implementation Time: 30 minutes, Speedup: 70-80%**

1. **Enable parallel execution** (2 minutes)
   ```bash
   pip install pytest-xdist
   pytest -n auto
   ```
   Speedup: 3-4x

2. **Use headless mode** (5 minutes)
   ```python
   options.add_argument("--headless=new")
   ```
   Speedup: 1.3-1.5x

3. **Disable images** (5 minutes)
   ```python
   prefs = {"profile.managed_default_content_settings.images": 2}
   ```
   Speedup: 1.4-1.6x

4. **Remove time.sleep()** (15 minutes)
   Replace all `time.sleep()` with explicit waits
   Speedup: 1.5-2x

5. **Optimize fixture scopes** (10 minutes)
   Use session/module scope for expensive fixtures
   Speedup: 1.2-1.5x

**Total combined speedup: 70-80% faster tests!**

---

## Related Documentation

- [Parallel Execution Guide](parallel-execution.md)
- [Performance Testing Guide](performance-testing.md)
- [CI/CD Advanced Guide](ci-cd-advanced.md)
- [Docker Advanced Guide](docker-advanced.md)

---

**Last Updated**: December 24, 2025
**Framework Version**: 6.0
