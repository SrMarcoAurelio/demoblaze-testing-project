# Migration Guide: Selenium + unittest → Universal Test Framework

**Comprehensive guide for migrating from Selenium + unittest to this pytest-based framework**

---

## 📋 Overview

This guide helps you migrate existing Selenium + unittest test suites to this modern pytest-based framework with Page Object Model, fixtures, and advanced features.

**Migration Time**: 4-8 hours for typical test suite (20-50 tests)

**Benefits of Migration**:
- ✅ Modern fixtures instead of setUp/tearDown
- ✅ Parametrized tests (reduce code duplication)
- ✅ Better assertions and error messages
- ✅ Built-in parallel execution
- ✅ Page Object Model templates
- ✅ Performance optimization options
- ✅ Professional reporting (HTML, Allure)
- ✅ Type hints and IDE autocomplete

---

## Table of Contents

1. [Quick Comparison](#quick-comparison)
2. [Concept Mapping](#concept-mapping)
3. [Step-by-Step Migration](#step-by-step-migration)
4. [Code Examples](#code-examples)
5. [Common Patterns](#common-patterns)
6. [Migration Checklist](#migration-checklist)
7. [Troubleshooting](#troubleshooting)

---

## Quick Comparison

| Feature | unittest | This Framework (pytest) |
|---------|----------|------------------------|
| **Test Discovery** | `test_*.py` or `*_test.py` | `test_*.py` (configurable) |
| **Test Class** | Inherit from `unittest.TestCase` | Optional, use plain functions |
| **Setup/Teardown** | `setUp()`, `tearDown()` | `@pytest.fixture` with yield |
| **Assertions** | `self.assertEqual(a, b)` | `assert a == b` |
| **Test Data** | Class attributes | Fixtures, parametrize |
| **Browser Setup** | `setUp()` creates driver | Fixture provides driver |
| **Parametrization** | Manual loops or subTest | `@pytest.mark.parametrize` |
| **Parallel Execution** | Manual (unittest-parallel) | Built-in (`pytest -n auto`) |
| **Reports** | Basic text | HTML, Allure, custom |
| **Fixtures** | No native support | Rich fixture system |
| **Markers** | No native support | `@pytest.mark.*` |

---

## Concept Mapping

### Test Classes

**unittest:**
```python
import unittest

class TestLogin(unittest.TestCase):
    def test_valid_login(self):
        self.assertEqual(result, expected)
```

**This Framework:**
```python
import pytest

class TestLogin:  # No inheritance needed!
    def test_valid_login(self):
        assert result == expected
```

Or even simpler:
```python
def test_valid_login():  # No class needed!
    assert result == expected
```

### Setup and Teardown

**unittest:**
```python
class TestLogin(unittest.TestCase):
    def setUp(self):
        self.driver = webdriver.Chrome()
        self.driver.get("https://example.com")

    def tearDown(self):
        self.driver.quit()

    def test_login(self):
        # Test code using self.driver
        pass
```

**This Framework:**
```python
# In conftest.py (automatic setup/teardown)
@pytest.fixture
def browser():
    driver = webdriver.Chrome()
    driver.get("https://example.com")
    yield driver  # Test runs here
    driver.quit()  # Automatic cleanup

# In test file
def test_login(browser):  # Fixture injected automatically!
    # Test code using browser
    pass
```

### Assertions

**unittest:**
```python
self.assertEqual(actual, expected)
self.assertTrue(condition)
self.assertIn(item, collection)
self.assertIsNone(value)
self.assertRaises(Exception, func)
```

**This Framework:**
```python
assert actual == expected
assert condition
assert item in collection
assert value is None
with pytest.raises(Exception):
    func()
```

### Class-Level Setup

**unittest:**
```python
class TestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shared_resource = expensive_setup()

    @classmethod
    def tearDownClass(cls):
        cls.shared_resource.cleanup()
```

**This Framework:**
```python
@pytest.fixture(scope="class")
def shared_resource():
    resource = expensive_setup()
    yield resource
    resource.cleanup()

class TestSuite:
    def test_one(self, shared_resource):
        # Uses shared resource
        pass
```

---

## Step-by-Step Migration

### Step 1: Setup Framework (30 minutes)

```bash
# Clone framework
git clone <framework-url>
cd test-automation-framework

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure
cp config/examples/.env.development .env
# Edit .env with your application URL and credentials
```

### Step 2: Analyze Existing Tests (1 hour)

Create inventory of your unittest tests:

```bash
# Count test files
find . -name "test_*.py" | wc -l

# Count test methods
grep -r "def test_" . | wc -l

# Identify patterns
grep -r "def setUp" .
grep -r "def tearDown" .
grep -r "self.assert" .
```

**Document:**
- Number of test files
- Number of test classes
- Number of test methods
- Common setUp/tearDown patterns
- Shared resources
- Test data sources

### Step 3: Create Page Objects (2-3 hours)

**Before (unittest with no Page Objects):**
```python
class TestLogin(unittest.TestCase):
    def test_login(self):
        self.driver.find_element(By.ID, "username").send_keys("user")
        self.driver.find_element(By.ID, "password").send_keys("pass")
        self.driver.find_element(By.ID, "login-btn").click()
        # Locators scattered everywhere!
```

**After (with Page Objects):**
```python
# pages/login_page.py
from framework.core import ElementFinder, WaitHandler, ElementInteractor

class LoginPage:
    USERNAME_FIELD = (By.ID, "username")
    PASSWORD_FIELD = (By.ID, "password")
    LOGIN_BUTTON = (By.ID, "login-btn")

    def __init__(self, driver):
        self.driver = driver
        self.finder = ElementFinder(driver)
        self.interactor = ElementInteractor(driver)
        self.waiter = WaitHandler(driver)

    def login(self, username, password):
        self.interactor.type_text(self.USERNAME_FIELD, username)
        self.interactor.type_text(self.PASSWORD_FIELD, password)
        self.interactor.click(self.LOGIN_BUTTON)

# tests/test_login.py
def test_login(browser, login_page):
    login_page.login("user", "pass")
    assert login_page.is_logged_in()
```

**Use templates:**
```bash
cp templates/page_objects/__template_login_page.py pages/login_page.py
# Adapt to your application
```

### Step 4: Convert Tests One Module at a Time (2-3 hours)

Start with login tests (usually simplest):

**Before (unittest):**
```python
import unittest
from selenium import webdriver

class TestLogin(unittest.TestCase):
    def setUp(self):
        self.driver = webdriver.Chrome()
        self.driver.get("https://example.com")

    def tearDown(self):
        self.driver.quit()

    def test_valid_login(self):
        self.driver.find_element(By.ID, "username").send_keys("testuser")
        self.driver.find_element(By.ID, "password").send_keys("password")
        self.driver.find_element(By.ID, "login-btn").click()

        welcome = self.driver.find_element(By.ID, "welcome-message")
        self.assertIn("Welcome", welcome.text)

    def test_invalid_login(self):
        self.driver.find_element(By.ID, "username").send_keys("wrong")
        self.driver.find_element(By.ID, "password").send_keys("wrong")
        self.driver.find_element(By.ID, "login-btn").click()

        error = self.driver.find_element(By.CLASS_NAME, "error")
        self.assertTrue(error.is_displayed())
```

**After (pytest + Page Objects):**
```python
import pytest
from pages.login_page import LoginPage

@pytest.mark.functional
def test_valid_login(browser, base_url):
    """Test successful login with valid credentials"""
    login_page = LoginPage(browser)
    browser.get(base_url)

    login_page.login("testuser", "password")

    assert login_page.is_logged_in()
    assert "Welcome" in login_page.get_welcome_message()

@pytest.mark.functional
def test_invalid_login(browser, base_url):
    """Test failed login with invalid credentials"""
    login_page = LoginPage(browser)
    browser.get(base_url)

    login_page.login("wrong", "wrong")

    assert login_page.is_error_displayed()
```

**Even better with fixtures:**
```python
# conftest.py
@pytest.fixture
def login_page(browser, base_url):
    browser.get(base_url)
    return LoginPage(browser)

# test_login.py
def test_valid_login(login_page):
    login_page.login("testuser", "password")
    assert login_page.is_logged_in()

def test_invalid_login(login_page):
    login_page.login("wrong", "wrong")
    assert login_page.is_error_displayed()
```

### Step 5: Migrate Parametrized Tests (1 hour)

**Before (unittest with manual loops):**
```python
class TestLogin(unittest.TestCase):
    def test_invalid_credentials(self):
        test_cases = [
            ("", "password", "Username required"),
            ("user", "", "Password required"),
            ("a"*51, "password", "Username too long"),
        ]

        for username, password, expected_error in test_cases:
            with self.subTest(username=username):
                self.driver.find_element(By.ID, "username").send_keys(username)
                self.driver.find_element(By.ID, "password").send_keys(password)
                self.driver.find_element(By.ID, "login-btn").click()

                error = self.driver.find_element(By.CLASS_NAME, "error")
                self.assertIn(expected_error, error.text)
```

**After (pytest.mark.parametrize):**
```python
@pytest.mark.parametrize("username,password,expected_error", [
    ("", "password", "Username required"),
    ("user", "", "Password required"),
    ("a"*51, "password", "Username too long"),
])
def test_invalid_credentials(login_page, username, password, expected_error):
    """Test login validation with invalid credentials"""
    login_page.login(username, password)

    error_message = login_page.get_error_message()
    assert expected_error in error_message
```

Benefits:
- Each parameter combo runs as separate test
- Better failure reporting
- Can run specific parameter: `pytest -k "a*51"`

### Step 6: Add Fixtures for Test Data (30 minutes)

**Before (unittest with hardcoded data):**
```python
def test_login(self):
    self.driver.find_element(By.ID, "username").send_keys("testuser")
    self.driver.find_element(By.ID, "password").send_keys("testpass123")
```

**After (pytest with fixtures):**
```python
# conftest.py
@pytest.fixture
def valid_user():
    return {
        "username": os.getenv("TEST_USERNAME", "testuser"),
        "password": os.getenv("TEST_PASSWORD", "testpass123")
    }

# test_login.py
def test_login(login_page, valid_user):
    login_page.login(**valid_user)  # Cleaner!
    assert login_page.is_logged_in()
```

### Step 7: Update Test Running (15 minutes)

**Before (unittest):**
```bash
# Run all tests
python -m unittest discover

# Run specific test file
python -m unittest tests.test_login

# Run specific test
python -m unittest tests.test_login.TestLogin.test_valid_login
```

**After (pytest):**
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_login.py

# Run specific test
pytest tests/test_login.py::test_valid_login

# Run with markers
pytest -m functional

# Run in parallel (NEW!)
pytest -n auto

# Run with HTML report (NEW!)
pytest --html=report.html
```

---

## Code Examples

### Example 1: Basic Test Migration

**Before (unittest):**
```python
import unittest
from selenium import webdriver
from selenium.webdriver.common.by import By

class TestHomepage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = webdriver.Chrome()

    @classmethod
    def tearDownClass(cls):
        cls.driver.quit()

    def test_title(self):
        self.driver.get("https://example.com")
        self.assertEqual(self.driver.title, "Example Domain")

    def test_heading(self):
        self.driver.get("https://example.com")
        heading = self.driver.find_element(By.TAG_NAME, "h1")
        self.assertEqual(heading.text, "Example Domain")
```

**After (pytest):**
```python
import pytest
from selenium.webdriver.common.by import By

@pytest.fixture(scope="class")
def browser():
    from selenium import webdriver
    driver = webdriver.Chrome()
    yield driver
    driver.quit()

class TestHomepage:
    def test_title(self, browser, base_url):
        browser.get(base_url)
        assert browser.title == "Example Domain"

    def test_heading(self, browser, base_url):
        browser.get(base_url)
        heading = browser.find_element(By.TAG_NAME, "h1")
        assert heading.text == "Example Domain"
```

### Example 2: Data-Driven Test Migration

**Before (unittest with CSV):**
```python
import csv
import unittest

class TestLogin(unittest.TestCase):
    def test_multiple_users(self):
        with open('users.csv') as f:
            reader = csv.DictReader(f)
            for row in reader:
                with self.subTest(user=row['username']):
                    self.driver.get("https://example.com/login")
                    # ... login logic
                    self.assertTrue(logged_in)
```

**After (pytest with parametrize):**
```python
import pytest
import csv

def load_users():
    with open('users.csv') as f:
        return list(csv.DictReader(f))

@pytest.mark.parametrize("user", load_users())
def test_user_login(login_page, user):
    login_page.login(user['username'], user['password'])
    assert login_page.is_logged_in()
```

### Example 3: Page Object Refactor

**Before (no Page Objects):**
```python
class TestCart(unittest.TestCase):
    def test_add_to_cart(self):
        # Navigate
        self.driver.get("https://example.com")

        # Find and click product
        product = self.driver.find_element(By.CSS_SELECTOR, ".product:first-child")
        product.click()

        # Add to cart
        add_btn = self.driver.find_element(By.ID, "add-to-cart")
        add_btn.click()

        # Verify
        cart_count = self.driver.find_element(By.ID, "cart-count")
        self.assertEqual(cart_count.text, "1")
```

**After (with Page Objects):**
```python
# pages/product_page.py
class ProductPage:
    ADD_TO_CART_BUTTON = (By.ID, "add-to-cart")

    def add_to_cart(self):
        self.interactor.click(self.ADD_TO_CART_BUTTON)
        return CartPage(self.driver)

# pages/catalog_page.py
class CatalogPage:
    FIRST_PRODUCT = (By.CSS_SELECTOR, ".product:first-child")

    def select_first_product(self):
        self.interactor.click(self.FIRST_PRODUCT)
        return ProductPage(self.driver)

# tests/test_cart.py
def test_add_to_cart(browser, base_url):
    catalog = CatalogPage(browser)
    browser.get(base_url)

    product = catalog.select_first_product()
    cart = product.add_to_cart()

    assert cart.get_item_count() == 1
```

---

## Common Patterns

### Pattern 1: Browser Setup

**unittest:**
```python
class BaseTest(unittest.TestCase):
    def setUp(self):
        self.driver = webdriver.Chrome()
        self.driver.implicitly_wait(10)
        self.driver.maximize_window()

    def tearDown(self):
        self.driver.quit()

class TestLogin(BaseTest):
    def test_something(self):
        self.driver.get("...")
```

**pytest:**
```python
# conftest.py (framework already has this!)
@pytest.fixture(scope="function")
def browser():
    driver = webdriver.Chrome()
    driver.implicitly_wait(10)
    driver.maximize_window()
    yield driver
    driver.quit()

# All tests get browser automatically
def test_something(browser):
    browser.get("...")
```

### Pattern 2: Wait Utilities

**unittest:**
```python
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

class TestPage(unittest.TestCase):
    def wait_for_element(self, by, value, timeout=10):
        return WebDriverWait(self.driver, timeout).until(
            EC.presence_of_element_located((by, value))
        )
```

**pytest (framework provides WaitHandler):**
```python
# Use WaitHandler from framework
def test_something(browser, wait_handler):
    element = wait_handler.wait_for_element_visible((By.ID, "element"))
    # or
    wait_handler.wait_for_element_clickable((By.ID, "button"))
```

### Pattern 3: Test Data

**unittest:**
```python
class TestData:
    VALID_USER = {"username": "test", "password": "pass"}
    INVALID_USER = {"username": "wrong", "password": "wrong"}

class TestLogin(unittest.TestCase):
    def test_valid(self):
        data = TestData.VALID_USER
        # ...
```

**pytest:**
```python
# tests/test_data.py (framework has this!)
from dataclasses import dataclass

@dataclass
class User:
    username: str
    password: str

class Users:
    VALID = User("test", "pass")
    INVALID = User("wrong", "wrong")

# conftest.py
@pytest.fixture
def valid_user():
    from tests.test_data import Users
    return Users.VALID

# test
def test_login(login_page, valid_user):
    login_page.login(valid_user.username, valid_user.password)
```

---

## Migration Checklist

### Before Migration

- [ ] Document all test files and test count
- [ ] Identify shared setUp/tearDown code
- [ ] List all test data sources
- [ ] Note any custom utilities
- [ ] Backup original test suite
- [ ] Create git branch for migration

### During Migration

- [ ] Setup framework and dependencies
- [ ] Configure BASE_URL and credentials
- [ ] Create page objects for main pages
- [ ] Migrate one test module completely
- [ ] Verify migrated tests pass
- [ ] Migrate remaining modules
- [ ] Add pytest markers
- [ ] Create fixtures for common data
- [ ] Update CI/CD scripts

### After Migration

- [ ] Run full test suite
- [ ] Compare coverage with original suite
- [ ] Update documentation
- [ ] Train team on pytest
- [ ] Remove unittest code (or keep in separate branch)
- [ ] Celebrate! 🎉

---

## Troubleshooting

### Issue 1: Tests can't find fixtures

**Error:**
```
fixture 'browser' not found
```

**Solution:**
Ensure `conftest.py` is in project root or test directory:
```bash
test-automation-framework/
├── conftest.py  # ✅ Here
└── tests/
    └── test_login.py
```

### Issue 2: Assertions failing with no message

**unittest (better errors):**
```python
self.assertEqual(actual, expected, "Expected X but got Y")
```

**pytest (add messages):**
```python
assert actual == expected, f"Expected {expected} but got {actual}"
```

### Issue 3: Class-level setup not working

**unittest:**
```python
@classmethod
def setUpClass(cls):
    cls.resource = setup()
```

**pytest:**
```python
@pytest.fixture(scope="class")
def resource():
    return setup()

class TestSuite:
    def test_one(self, resource):  # Don't forget parameter!
        pass
```

### Issue 4: SubTest equivalent

**unittest:**
```python
for item in items:
    with self.subTest(item=item):
        test(item)
```

**pytest:**
```python
@pytest.mark.parametrize("item", items)
def test_item(item):
    test(item)
```

---

## Performance Comparison

### Test Execution Time

**unittest** (100 tests):
- Sequential: ~300 seconds
- With unittest-parallel: ~150 seconds (manual setup)

**pytest** (100 tests):
- Sequential: ~300 seconds
- With pytest-xdist: `pytest -n auto` → ~75 seconds (built-in!)
- With --performance=fast: → ~120 seconds
- Combined: `pytest -n auto --performance=fast` → **~30 seconds!**

### Developer Experience

| Aspect | unittest | pytest |
|--------|----------|--------|
| Boilerplate | High (inheritance, setUp) | Low (fixtures) |
| Readability | Medium (self.assert*) | High (assert) |
| Test Discovery | Strict naming | Flexible |
| Parametrization | Manual/subTest | Built-in decorator |
| Fixtures | Manual (setUp) | Automatic injection |
| Parallel | Manual setup | `pytest -n auto` |

---

## Additional Resources

- [pytest Documentation](https://docs.pytest.org/)
- [Migration from unittest](https://docs.pytest.org/en/latest/how-to/unittest.html)
- [Fixture Documentation](../guides/test-fixtures.md)
- [Best Practices](../guides/best-practices.md)
- [Performance Optimization](../guides/performance-optimization.md)

---

## Need Help?

Common questions:

**Q: Can I run unittest and pytest tests together?**
A: Yes! pytest can run unittest tests. Migrate gradually.

**Q: Do I need to migrate all tests at once?**
A: No. Migrate module by module, verify each works.

**Q: What about my custom unittest utilities?**
A: Convert to pytest fixtures or helper functions.

**Q: Can I keep using unittest assertions?**
A: Yes, but native pytest assertions are better.

---

**Last Updated**: December 24, 2025
**Framework Version**: 6.0
