# Troubleshooting Guide

Common errors, their causes, and solutions.

## Table of Contents

1. [Element Not Found Errors](#element-not-found-errors)
2. [Timeout Errors](#timeout-errors)
3. [Stale Element Errors](#stale-element-errors)
4. [Import Errors](#import-errors)
5. [Fixture Errors](#fixture-errors)
6. [Browser Driver Errors](#browser-driver-errors)
7. [Configuration Errors](#configuration-errors)
8. [Coverage Errors](#coverage-errors)
9. [Performance Issues](#performance-issues)
10. [Docker Errors](#docker-errors)

---

## Element Not Found Errors

### Error 1: NoSuchElementException

**Error Message:**
```
selenium.common.exceptions.NoSuchElementException: Message: no such element:
Unable to locate element: {"method":"css selector","selector":"#loginBtn"}
```

**Cause:**
- Element locator is incorrect
- Element hasn't loaded yet
- Element is in iframe
- Element is dynamically generated

**Solutions:**

**1. Verify Locator:**
```python
# Check locator in config/locators.json
{
  "login": {
    "login_button": {"by": "id", "value": "login2"}  # Correct?
  }
}

# Test locator in browser DevTools:
# - Press F12
# - Console tab
# - Type: document.querySelector("#login2")
# - Should return element
```

**2. Add Wait:**
```python
# Instead of:
element = driver.find_element(By.ID, "loginBtn")

# Use BasePage methods with waits:
page.wait_for_element_visible((By.ID, "loginBtn"), timeout=10)
page.click((By.ID, "loginBtn"))
```

**3. Check for iframes:**
```python
# If element is in iframe, switch to it first
driver.switch_to.frame("iframe_name")
element = driver.find_element(By.ID, "loginBtn")

# Don't forget to switch back
driver.switch_to.default_content()
```

**4. Wait for dynamic content:**
```python
# For AJAX-loaded elements
from selenium.webdriver.support import expected_conditions as EC

WebDriverWait(driver, 10).until(
    EC.presence_of_element_located((By.ID, "dynamic_element"))
)
```

---

### Error 2: Element Not Visible

**Error Message:**
```
selenium.common.exceptions.ElementNotInteractableException:
Message: element not interactable
```

**Cause:**
- Element exists in DOM but is hidden (display: none, visibility: hidden)
- Element is covered by another element
- Element is outside viewport

**Solutions:**

**1. Wait for Visibility:**
```python
# Use wait_for_element_visible instead of find_element
page.wait_for_element_visible((By.ID, "hiddenElement"), timeout=10)
```

**2. Scroll to Element:**
```python
page.scroll_to_element((By.ID, "element"))
page.click((By.ID, "element"))
```

**3. Wait for Overlays to Disappear:**
```python
# Wait for loading spinner to disappear
page.wait_for_element_invisible((By.CLASS_NAME, "spinner"), timeout=5)

# Then interact with element
page.click((By.ID, "submitBtn"))
```

**4. JavaScript Click (Last Resort):**
```python
element = page.find_element((By.ID, "element"))
page.execute_script("arguments[0].click();", element)
```

---

## Timeout Errors

### Error 3: TimeoutException

**Error Message:**
```
selenium.common.exceptions.TimeoutException:
Message: Timeout waiting for element to be clickable
```

**Cause:**
- Element takes longer to load than timeout allows
- Network is slow
- Application is slow
- Wrong locator (element never appears)

**Solutions:**

**1. Increase Timeout:**
```python
# Increase global timeout in BasePage
page = LoginPage(driver, timeout=30)  # 30 seconds instead of 10

# Or increase for specific operation
page.wait_for_element_clickable((By.ID, "slowElement"), timeout=30)
```

**2. Check Network Tab:**
- Open browser DevTools (F12)
- Network tab
- Check if requests are completing
- Look for failed requests (red)

**3. Verify Element Exists:**
```python
# Check if element ever appears
if page.is_element_present((By.ID, "element"), timeout=30):
    print("Element found eventually")
else:
    print("Element never appears - check locator")
```

**4. Check for JavaScript Errors:**
- Open browser DevTools
- Console tab
- Look for errors (red text)
- JavaScript errors can prevent elements from appearing

---

## Stale Element Errors

### Error 4: StaleElementReferenceException

**Error Message:**
```
selenium.common.exceptions.StaleElementReferenceException:
Message: stale element reference: element is not attached to the page document
```

**Cause:**
- Element was found, but DOM was refreshed before interaction
- Page navigation occurred
- AJAX request replaced element
- React/Vue re-rendered component

**Solutions:**

**1. Re-find Element:**
```python
# Bad - stores element reference
element = page.find_element((By.ID, "button"))
time.sleep(5)  # DOM changes during this time
element.click()  # Stale!

# Good - find element right before use
page.click((By.ID, "button"))  # Finds fresh element each time
```

**2. Use Explicit Waits:**
```python
# Wait for element to be stable
WebDriverWait(driver, 10).until(
    EC.staleness_of(old_element)
)
# Then find fresh element
new_element = page.find_element((By.ID, "element"))
```

**3. Retry on Stale:**
```python
from selenium.common.exceptions import StaleElementReferenceException

def click_with_retry(page, locator, retries=3):
    for attempt in range(retries):
        try:
            page.click(locator)
            return
        except StaleElementReferenceException:
            if attempt == retries - 1:
                raise
            time.sleep(0.5)
```

---

## Import Errors

### Error 5: ModuleNotFoundError

**Error Message:**
```
ModuleNotFoundError: No module named 'pages'
```

**Cause:**
- Running tests from wrong directory
- Python path not configured
- Missing __init__.py files

**Solutions:**

**1. Run from Project Root:**
```bash
# Bad - running from subdirectory
cd tests/login
pytest test_login_functional.py  # Error!

# Good - run from project root
cd /path/to/demoblaze-testing-project
pytest tests/login/test_login_functional.py
```

**2. Check PYTHONPATH:**
```bash
# Add project root to PYTHONPATH
export PYTHONPATH=/path/to/demoblaze-testing-project:$PYTHONPATH

# Or in PyCharm/VSCode:
# - Mark project root as "Sources Root"
```

**3. Verify __init__.py Files:**
```bash
# Ensure __init__.py exists in all package directories
ls pages/__init__.py
ls tests/__init__.py
ls utils/__init__.py
```

---

### Error 6: ImportError for Dependencies

**Error Message:**
```
ImportError: No module named 'selenium'
```

**Cause:**
- Virtual environment not activated
- Dependencies not installed

**Solutions:**

**1. Activate Virtual Environment:**
```bash
# Unix/Mac
source venv/bin/activate

# Windows
venv\Scripts\activate

# Verify
which python  # Should show venv path
```

**2. Install Dependencies:**
```bash
pip install -r requirements.txt

# Verify installation
pip list | grep selenium
```

**3. Recreate Virtual Environment:**
```bash
# If corrupted
rm -rf venv
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Fixture Errors

### Error 7: Fixture Not Found

**Error Message:**
```
E       fixture 'invalid_user' not found
>       available fixtures: base_url, browser, cache, ...
```

**Cause:**
- Fixture name typo
- Fixture not defined
- conftest.py not loaded

**Solutions:**

**1. Check Fixture Name:**
```python
# Wrong
def test_login(invalid_user):  # Typo

# Correct
def test_login(invalid_user_password):
```

**2. List Available Fixtures:**
```bash
pytest --fixtures | grep user
# Shows all fixtures with "user" in name
```

**3. Verify conftest.py Location:**
```bash
# conftest.py should be in tests/ or project root
ls tests/conftest.py  # ✓
ls conftest.py        # ✓ (in project root)
```

---

### Error 8: Fixture Scope Error

**Error Message:**
```
ScopeMismatch: You tried to access the 'function' scoped fixture 'browser'
with a 'session' scoped request object
```

**Cause:**
- Session-scoped fixture trying to use function-scoped fixture

**Solution:**
```python
# Bad - session fixture using function fixture
@pytest.fixture(scope="session")
def session_page(browser):  # browser is function-scoped!
    return LoginPage(browser)

# Good - match scopes
@pytest.fixture(scope="function")
def function_page(browser):  # Both function-scoped
    return LoginPage(browser)

# Or use session-scoped browser (not recommended)
```

---

## Browser Driver Errors

### Error 9: WebDriver Not Found

**Error Message:**
```
selenium.common.exceptions.WebDriverException:
Message: 'chromedriver' executable needs to be in PATH
```

**Cause:**
- webdriver-manager failed to download driver
- Driver not in PATH
- Network issues

**Solutions:**

**1. Let webdriver-manager Handle It:**
```python
# Framework uses webdriver-manager (should auto-download)
from webdriver_manager.chrome import ChromeDriverManager

service = Service(ChromeDriverManager().install())
driver = webdriver.Chrome(service=service)
```

**2. Manual Driver Installation:**
```bash
# Download driver manually:
# https://chromedriver.chromium.org/

# Place in PATH or specify path:
from selenium.webdriver.chrome.service import Service

service = Service("/path/to/chromedriver")
driver = webdriver.Chrome(service=service)
```

**3. Clear webdriver-manager Cache:**
```bash
# Remove cached drivers
rm -rf ~/.wdm

# Next run will re-download
pytest tests/
```

---

### Error 10: Browser Version Mismatch

**Error Message:**
```
selenium.common.exceptions.SessionNotCreatedException:
Message: session not created: This version of ChromeDriver only supports Chrome version 120
```

**Cause:**
- Chrome browser updated but driver didn't
- webdriver-manager cache is stale

**Solutions:**

**1. Update Browser:**
```bash
# Ubuntu
sudo apt update && sudo apt upgrade google-chrome-stable

# Mac
# Chrome updates automatically
```

**2. Clear Driver Cache:**
```bash
rm -rf ~/.wdm
pytest tests/  # Will download correct driver
```

**3. Force Driver Update:**
```python
from webdriver_manager.chrome import ChromeDriverManager

# Force latest version
ChromeDriverManager(version="latest").install()
```

---

## Configuration Errors

### Error 11: Locator Configuration Error

**Error Message:**
```
KeyError: "Locator not found: page='login', element='submit_button'
Check config/locators.json"
```

**Cause:**
- Locator not defined in config/locators.json
- Typo in element name
- JSON syntax error

**Solutions:**

**1. Check locators.json:**
```json
{
  "login": {
    "submit_button": {  // This element exists?
      "by": "id",
      "value": "submitBtn"
    }
  }
}
```

**2. Validate JSON Syntax:**
```bash
# Use JSON validator
python -m json.tool config/locators.json

# Should print formatted JSON if valid
```

**3. Check Element Name:**
```python
# In page object
login_button = load_locator("login", "submit_button")
                                     ^^^^^^^^^^^^^^^^
# Matches JSON key exactly?
```

---

### Error 12: Configuration File Not Found

**Error Message:**
```
FileNotFoundError: Locators config file not found: config/locators.json
```

**Cause:**
- Running tests from wrong directory
- locators.json deleted or moved

**Solutions:**

**1. Verify File Exists:**
```bash
ls config/locators.json  # Should exist
```

**2. Run from Project Root:**
```bash
# Current directory should be project root
pwd
# /path/to/demoblaze-testing-project

pytest tests/
```

**3. Check File Permissions:**
```bash
chmod 644 config/locators.json
```

---

## Coverage Errors

### Error 13: Coverage Threshold Not Met

**Error Message:**
```
FAIL Required test coverage of 70% not reached. Total coverage: 45.32%
```

**Cause:**
- Not all code paths executed
- Running subset of tests
- Coverage threshold too high

**Solutions:**

**1. Run All Tests:**
```bash
# Run complete test suite
pytest tests/

# Check coverage
pytest --cov=pages --cov=utils --cov-report=html
```

**2. Adjust Threshold (if appropriate):**
```ini
# pytest.ini
[pytest]
# Reduce threshold for unit tests
--cov-fail-under=30  # Instead of 70

# Or disable entirely
# --cov-fail-under=70  # Commented out
```

**3. Identify Uncovered Code:**
```bash
# Generate HTML coverage report
pytest --cov=pages --cov=utils --cov-report=html

# Open htmlcov/index.html
# Red lines = uncovered code
```

---

## Performance Issues

### Error 14: Tests Running Slowly

**Symptoms:**
- Tests take minutes instead of seconds
- Excessive waiting
- Browser feels sluggish

**Causes & Solutions:**

**1. Unnecessary time.sleep():**
```python
# Bad - hard-coded sleep
time.sleep(10)  # Why 10 seconds?

# Good - explicit wait
page.wait_for_element_visible((By.ID, "element"), timeout=10)
```

**2. Implicit Waits Too High:**
```python
# conftest.py
driver.implicitly_wait(config.TIMEOUT_DEFAULT)  # Check this value

# config.py - reduce if too high
TIMEOUT_DEFAULT = 5  # Instead of 30
```

**3. Run in Headless Mode:**
```bash
# Faster without GUI
pytest --headless
```

**4. Parallel Execution:**
```bash
# Run tests in parallel
pip install pytest-xdist
pytest -n auto  # Use all CPU cores
```

**5. Disable Logging:**
```python
# conftest.py - reduce log level
logging.basicConfig(level=logging.WARNING)  # Instead of DEBUG
```

---

## Docker Errors

### Error 15: Docker Selenium Grid Connection Failed

**Error Message:**
```
selenium.common.exceptions.WebDriverException:
Message: Reached error page: about:neterror?e=connectionFailure
```

**Cause:**
- Selenium Grid not running
- Wrong URL
- Network issues

**Solutions:**

**1. Verify Grid is Running:**
```bash
docker-compose ps

# Should show:
# selenium-hub    running
# chrome          running
```

**2. Check Grid URL:**
```bash
# Should be accessible
curl http://localhost:4444/wd/hub/status
```

**3. Restart Containers:**
```bash
docker-compose down
docker-compose up -d
```

**4. Check Logs:**
```bash
docker-compose logs selenium-hub
docker-compose logs chrome
```

---

### Error 16: Docker Permission Denied

**Error Message:**
```
docker: Got permission denied while trying to connect to the Docker daemon socket
```

**Cause:**
- User not in docker group
- Docker daemon not running

**Solutions:**

**1. Add User to Docker Group:**
```bash
sudo usermod -aG docker $USER

# Log out and log back in
```

**2. Start Docker Daemon:**
```bash
# Ubuntu/Debian
sudo systemctl start docker

# Mac
# Start Docker Desktop application
```

---

## Quick Diagnosis Checklist

When a test fails, check these in order:

**1. Is the error consistent?**
```bash
# Run test 3 times
pytest tests/test_file.py::test_name -v
# Same error every time = real issue
# Random failures = timing/flaky test
```

**2. Is it a locator issue?**
```python
# Print locator value
print(page.login_button)  # (By.ID, "login2")

# Test in browser console
# document.querySelector("#login2")
```

**3. Is it a timing issue?**
```python
# Add longer waits
page.wait_for_element_visible(locator, timeout=30)

# If this fixes it, timing is the issue
```

**4. Is it environment-specific?**
```bash
# Works locally but fails in CI?
# → Probably timing or environment differences

# Works in Chrome but not Firefox?
# → Browser compatibility issue
```

**5. Check logs:**
```bash
# Enable verbose logging
pytest -v -s --log-cli-level=DEBUG

# Check log file
tail -f pytest.log
```

---

## Getting Help

**1. Check Documentation:**
- [API Reference](../api-reference/README.md)
- [Code Walkthrough](code-walkthrough.md)
- [Test Fixtures Guide](test-fixtures.md)

**2. Enable Debug Logging:**
```python
# In test
import logging
logging.basicConfig(level=logging.DEBUG)
```

**3. Use Pytest Verbosity:**
```bash
pytest -vv --tb=long --showlocals
```

**4. Create Minimal Reproduction:**
```python
# Simplify test to minimal failing example
def test_minimal():
    driver.get("https://example.com")
    element = driver.find_element(By.ID, "problematic_element")
    element.click()
```

**5. Search for Similar Issues:**
- Selenium documentation: https://www.selenium.dev/documentation/
- Stack Overflow: tag `[selenium]` `[python]`
- pytest documentation: https://docs.pytest.org/

---

## Related Documentation

- [Code Walkthrough](code-walkthrough.md) - Understand code flow
- [API Reference](../api-reference/README.md) - Method documentation
- [Implementation Guide](implementation-guide.md) - Setup and configuration
