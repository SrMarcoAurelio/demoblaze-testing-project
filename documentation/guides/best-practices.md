# Test Automation Best Practices

**Write maintainable, reliable, and efficient tests**

---

## 📋 Overview

This guide covers proven best practices for test automation, helping you write tests that are reliable, maintainable, and provide real value.

**Core Principles**:
1. ✅ Tests should be independent
2. ✅ Tests should be deterministic
3. ✅ Tests should be fast
4. ✅ Tests should be readable
5. ✅ Tests should test one thing

---

## Table of Contents

1. [Test Independence](#test-independence)
2. [Page Object Model Best Practices](#page-object-model-best-practices)
3. [Locator Strategies](#locator-strategies)
4. [Wait Strategies](#wait-strategies)
5. [Test Data Management](#test-data-management)
6. [Assertion Strategies](#assertion-strategies)
7. [Test Organization](#test-organization)
8. [Fixture Best Practices](#fixture-best-practices)
9. [Error Handling](#error-handling)
10. [Code Review Checklist](#code-review-checklist)
11. [Common Anti-Patterns](#common-anti-patterns)

---

## Test Independence

### The Golden Rule

> **Every test should be able to run alone, in any order, and produce the same result.**

### ✅ Good Example

```python
@pytest.mark.functional
def test_login_with_valid_credentials(browser, base_url):
    """Test login with valid credentials - INDEPENDENT"""
    # Setup: Create fresh state
    browser.get(base_url)
    browser.delete_all_cookies()

    # Arrange: Get test data
    from tests.test_data import Users
    user = Users.VALID

    # Act: Perform login
    login_page = LoginPage(browser)
    login_page.open_login_modal()
    login_page.login(user.username, user.password)

    # Assert: Verify success
    assert login_page.is_user_logged_in()

    # Cleanup: Logout (or let fixture handle it)
    login_page.logout()
```

### ❌ Bad Example

```python
# ❌ Test depends on previous test running first
logged_in_user = None  # Global state!

def test_login():
    """Login test - sets global state"""
    global logged_in_user
    logged_in_user = do_login()  # ❌ Sets global state

def test_view_profile():
    """View profile - DEPENDS on test_login running first!"""
    assert logged_in_user is not None  # ❌ Breaks if run alone!
    view_profile(logged_in_user)
```

### Ensuring Independence

**1. No Shared State**:
```python
# ❌ Shared mutable state
cart_items = []

def test_add_to_cart():
    cart_items.append("item1")  # ❌ Modifies shared list

# ✅ Local state
def test_add_to_cart(browser):
    cart_page = CartPage(browser)
    cart_page.add_item("item1")  # ✅ Isolated to this browser instance
```

**2. Use Fixtures for Setup**:
```python
# ✅ Fixture provides fresh state
@pytest.fixture
def logged_in_user(browser, base_url, valid_user):
    """Provide logged-in browser session"""
    login_page = LoginPage(browser, base_url)
    login_page.login(**valid_user)
    yield browser
    login_page.logout()

def test_view_profile(logged_in_user):
    """Test runs with fresh logged-in session"""
    profile_page = ProfilePage(logged_in_user)
    assert profile_page.is_loaded()
```

**3. Clean Up After Tests**:
```python
# ✅ Proper cleanup
def test_create_user(browser, base_url):
    signup_page = SignupPage(browser, base_url)
    username = generate_unique_username()

    try:
        signup_page.signup(username, "password123")
        assert signup_page.is_signup_successful()
    finally:
        # Clean up: Delete created user
        delete_user(username)
```

---

## Page Object Model Best Practices

### Structure

✅ **DO**:
```python
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webdriver import WebDriver
from framework.core import ElementFinder, WaitHandler, ElementInteractor

class LoginPage:
    """Page Object for Login page

    Encapsulates all login page interactions and elements.
    """

    # 1. Locators at top (class constants)
    USERNAME_FIELD = (By.ID, "loginusername")
    PASSWORD_FIELD = (By.ID, "loginpassword")
    LOGIN_BUTTON = (By.XPATH, "//button[text()='Log in']")
    ERROR_MESSAGE = (By.CSS_SELECTOR, ".alert-danger")

    def __init__(self, driver: WebDriver):
        self.driver = driver
        self.finder = ElementFinder(driver)
        self.waiter = WaitHandler(driver)
        self.interactor = ElementInteractor(driver)

    # 2. Public methods (actions a user can take)
    def login(self, username: str, password: str) -> None:
        """Perform login with given credentials"""
        self._enter_username(username)
        self._enter_password(password)
        self._click_login_button()
        self._wait_for_login_complete()

    def is_error_displayed(self) -> bool:
        """Check if error message is displayed"""
        return self.finder.is_element_present(self.ERROR_MESSAGE)

    # 3. Private methods (internal implementation)
    def _enter_username(self, username: str) -> None:
        """Enter username (private helper)"""
        self.waiter.wait_for_element_visible(self.USERNAME_FIELD)
        self.interactor.type_text(self.USERNAME_FIELD, username)

    def _enter_password(self, password: str) -> None:
        """Enter password (private helper)"""
        self.interactor.type_text(self.PASSWORD_FIELD, password)

    def _click_login_button(self) -> None:
        """Click login button (private helper)"""
        self.waiter.wait_for_element_clickable(self.LOGIN_BUTTON)
        self.interactor.click(self.LOGIN_BUTTON)

    def _wait_for_login_complete(self) -> None:
        """Wait for login to complete (private helper)"""
        # Wait for page to load after login
        self.waiter.wait_for_url_change(timeout=5)
```

### Page Object Principles

1. **One Page Object per Page**
   - ✅ `LoginPage`, `ProfilePage`, `CartPage`
   - ❌ `AllPagesInOne`

2. **Locators as Constants**
   ```python
   # ✅ Class constant
   LOGIN_BUTTON = (By.ID, "login-btn")

   # ❌ Hardcoded in method
   def click_login(self):
       self.driver.find_element(By.ID, "login-btn").click()
   ```

3. **Methods Represent User Actions**
   ```python
   # ✅ User action
   def add_to_cart(self, product_name: str) -> None:
       """Add product to cart"""

   # ❌ Implementation detail
   def click_add_button(self) -> None:
       """Click add button"""  # Too low-level
   ```

4. **No Assertions in Page Objects**
   ```python
   # ❌ Assertion in page object
   class LoginPage:
       def login(self, username, password):
           self.type_username(username)
           self.type_password(password)
           self.click_login()
           assert "Welcome" in self.driver.page_source  # ❌ Don't assert here!

   # ✅ Return values, assert in tests
   class LoginPage:
       def login(self, username, password):
           self.type_username(username)
           self.type_password(password)
           self.click_login()

       def is_logged_in(self) -> bool:
           return self.finder.is_element_present(self.USER_MENU)

   # In test:
   def test_login(login_page):
       login_page.login("user", "pass")
       assert login_page.is_logged_in()  # ✅ Assert in test
   ```

5. **Return Page Objects for Navigation**
   ```python
   class HomePage:
       def navigate_to_login(self) -> LoginPage:
           """Navigate to login page, return LoginPage object"""
           self.interactor.click(self.LOGIN_LINK)
           return LoginPage(self.driver)

   # Usage in test:
   def test_login_flow(browser):
       home_page = HomePage(browser)
       login_page = home_page.navigate_to_login()  # Returns LoginPage
       login_page.login("user", "pass")  # Now we have correct page object
   ```

---

## Locator Strategies

### Locator Precedence

**Best to Worst** (use higher priority when possible):

1. 🥇 **ID** - Most reliable, fastest
   ```python
   (By.ID, "username")
   ```

2. 🥈 **data-testid** - Designed for testing
   ```python
   (By.CSS_SELECTOR, "[data-testid='login-button']")
   ```

3. 🥉 **Name attribute**
   ```python
   (By.NAME, "username")
   ```

4. **CSS Selector** - Flexible, readable
   ```python
   (By.CSS_SELECTOR, "#login-form > button.submit")
   ```

5. **XPath (relative)** - When CSS can't do it
   ```python
   (By.XPATH, "//button[contains(@class, 'submit')]")
   ```

6. 🚫 **Link Text / Partial Link Text** - Fragile (changes with copy)
   ```python
   (By.LINK_TEXT, "Click Here")  # Breaks if text changes
   ```

7. ⛔ **XPath (absolute)** - AVOID! Extremely fragile
   ```python
   # ❌ AVOID - breaks with any HTML structure change
   (By.XPATH, "/html/body/div[1]/div[2]/form/input[1]")
   ```

### Locator Best Practices

**✅ DO**:
```python
# Specific, unique identifier
USERNAME_FIELD = (By.ID, "email-input")

# data-testid attribute (add to HTML)
LOGIN_BUTTON = (By.CSS_SELECTOR, "[data-testid='submit-login']")

# Semantic, stable CSS
PRODUCT_CARDS = (By.CSS_SELECTOR, ".product-card")

# Relative XPath with attributes
ERROR_MESSAGE = (By.XPATH, "//div[@role='alert'][@class='error']")
```

**❌ DON'T**:
```python
# Text-based (breaks with copy changes)
LOGIN_BUTTON = (By.LINK_TEXT, "Log In")  # ❌ "Login" vs "Log In"

# Index-based
FIRST_PRODUCT = (By.CSS_SELECTOR, "div:nth-child(1)")  # ❌ Breaks if order changes

# Absolute XPath
BUTTON = (By.XPATH, "/html/body/div/div/button")  # ❌ Extremely fragile

# Class only (too generic)
BUTTON = (By.CLASS_NAME, "btn")  # ❌ Too many matches
```

### Dynamic Locators

```python
class ProductPage:
    # Template for dynamic locator
    PRODUCT_BY_NAME = "//div[@class='product'][.//h2[text()='{}']]"

    def select_product(self, product_name: str) -> None:
        """Select product by name using dynamic locator"""
        locator = (By.XPATH, self.PRODUCT_BY_NAME.format(product_name))
        self.interactor.click(locator)
```

---

## Wait Strategies

### The Wait Hierarchy

1. 🥇 **Explicit Waits** - Wait for specific condition (BEST)
2. 🥈 **Fluent Waits** - Explicit waits with polling interval
3. 🥉 **Implicit Waits** - Global default wait (USE CAUTIOUSLY)
4. ⛔ **time.sleep()** - AVOID! Hard-coded delays (WORST)

### Explicit Waits (Recommended)

```python
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# ✅ Wait for element to be present
wait = WebDriverWait(driver, 10)
element = wait.until(EC.presence_of_element_located((By.ID, "element")))

# ✅ Wait for element to be visible
element = wait.until(EC.visibility_of_element_located((By.ID, "element")))

# ✅ Wait for element to be clickable
element = wait.until(EC.element_to_be_clickable((By.ID, "button")))

# ✅ Wait for text in element
wait.until(EC.text_to_be_present_in_element((By.ID, "status"), "Complete"))

# ✅ Wait for URL change
wait.until(EC.url_contains("dashboard"))
```

### Custom Wait Conditions

```python
def element_has_css_class(locator, css_class):
    """Custom wait condition for CSS class"""
    def check(driver):
        element = driver.find_element(*locator)
        return css_class in element.get_attribute("class")
    return check

# Usage
wait.until(element_has_css_class((By.ID, "button"), "enabled"))
```

### Wait Anti-Patterns

```python
# ❌ ANTI-PATTERN 1: Hard-coded sleep
import time
time.sleep(5)  # Wastes time if ready earlier, fails if needs more

# ✅ CORRECT: Explicit wait
wait.until(EC.presence_of_element_located((By.ID, "element")))

# ❌ ANTI-PATTERN 2: Excessive implicit wait
driver.implicitly_wait(30)  # Every find_element waits up to 30s!

# ✅ CORRECT: Short or zero implicit wait
driver.implicitly_wait(0)  # Use explicit waits instead

# ❌ ANTI-PATTERN 3: Mixing implicit and explicit waits
driver.implicitly_wait(10)  # Global
wait.until(EC.presence_of_element_located(...))  # Can cause unexpected delays

# ✅ CORRECT: Use one or the other (prefer explicit)
driver.implicitly_wait(0)  # Disable implicit
wait.until(EC.presence_of_element_located(...))  # Use explicit only
```

---

## Test Data Management

### Test Data Strategies

1. **Static Test Data** (in code)
2. **Generated Test Data** (Faker)
3. **Fixtures**
4. **External Files** (JSON, CSV)

### Static Test Data

```python
# tests/test_data.py
from dataclasses import dataclass

@dataclass
class User:
    username: str
    password: str

class TestUsers:
    VALID = User("test_user", "Test123!")
    INVALID_PASSWORD = User("test_user", "wrong_password")
    ADMIN = User("admin", "Admin123!")
```

### Generated Test Data

```python
from faker import Faker

fake = Faker()

@pytest.fixture
def random_user():
    """Generate random user data"""
    return User(
        username=fake.user_name(),
        password=fake.password(length=12),
        email=fake.email(),
    )

def test_signup(browser, random_user):
    """Test signup with generated data"""
    signup_page = SignupPage(browser)
    signup_page.signup(**random_user.__dict__)
    assert signup_page.is_signup_successful()
```

### Data Files

```python
import json
import pytest

@pytest.fixture
def test_users():
    """Load test users from JSON"""
    with open("test_data/users.json") as f:
        return json.load(f)

# test_data/users.json
{
    "valid_user": {
        "username": "testuser",
        "password": "Test123!"
    },
    "admin_user": {
        "username": "admin",
        "password": "Admin123!"
    }
}
```

### Parametrized Tests with Data

```python
@pytest.mark.parametrize("username,password,expected_error", [
    ("", "password", "Username is required"),
    ("user", "", "Password is required"),
    ("user", "123", "Password too short"),
    ("a" * 51, "password", "Username too long"),
])
def test_login_validation(browser, login_page, username, password, expected_error):
    """Test login validation with various invalid inputs"""
    login_page.login(username, password)
    assert expected_error in login_page.get_error_message()
```

---

## Assertion Strategies

### Good Assertions

**✅ DO**:
```python
# Specific, descriptive assertions
assert login_page.is_logged_in(), "User should be logged in after valid credentials"

# Multiple related assertions (grouped)
user_info = profile_page.get_user_info()
assert user_info["name"] == "John Doe", "Name should match"
assert user_info["email"] == "john@example.com", "Email should match"

# Soft assertions (when appropriate)
from pytest_check import check

check.equal(actual_name, expected_name)
check.equal(actual_email, expected_email)
# Both assertions run even if first fails
```

**❌ DON'T**:
```python
# Vague assertion
assert element is not None  # ❌ What element? Why?

# No assertion message
assert result == expected  # ❌ Unclear why test failed

# Too many unrelated assertions in one test
assert login_works()
assert profile_loads()
assert settings_save()
assert logout_works()  # ❌ Testing too much in one test
```

### Assertion Patterns

```python
# Pattern 1: Boolean checks
assert page.is_visible(), "Page should be visible"
assert not page.has_errors(), "Page should not have errors"

# Pattern 2: Equality
assert actual_title == expected_title, f"Expected '{expected_title}', got '{actual_title}'"

# Pattern 3: Membership
assert "Success" in page.get_message(), "Message should contain 'Success'"

# Pattern 4: Collection assertions
products = page.get_products()
assert len(products) > 0, "Should have at least one product"
assert all(p.price > 0 for p in products), "All products should have positive prices"

# Pattern 5: Exception testing
with pytest.raises(ValueError, match="Invalid username"):
    page.login("", "password")
```

---

## Test Organization

### Test File Structure

```
tests/
├── login/
│   ├── __init__.py
│   ├── test_login_functional.py      # Happy path tests
│   ├── test_login_validation.py      # Input validation tests
│   ├── test_login_security.py        # Security tests
│   └── test_login_accessibility.py   # A11y tests
│
├── cart/
│   ├── test_cart_functional.py
│   └── test_cart_edge_cases.py
│
└── conftest.py  # Shared fixtures for all tests
```

### Test Class Organization

```python
class TestLoginFunctionality:
    """Tests for login functionality"""

    def test_successful_login_with_valid_credentials(self, login_page, valid_user):
        """Test successful login with valid credentials"""
        pass

    def test_failed_login_with_invalid_password(self, login_page):
        """Test failed login with incorrect password"""
        pass

    def test_failed_login_with_nonexistent_user(self, login_page):
        """Test failed login with non-existent user"""
        pass
```

### Test Naming Convention

**Pattern**: `test_<action>_<condition>_<expected_result>`

```python
# ✅ Good names (clear and descriptive)
def test_login_with_valid_credentials_succeeds()
def test_login_with_invalid_password_shows_error()
def test_add_product_to_empty_cart_updates_counter()
def test_checkout_with_invalid_card_number_rejects()

# ❌ Bad names (vague)
def test_login()  # Which scenario?
def test_1()  # What does it test?
def test_it_works()  # What works?
```

---

## Fixture Best Practices

### Fixture Scope

```python
# Function scope (default) - fresh for each test
@pytest.fixture(scope="function")
def browser():
    driver = webdriver.Chrome()
    yield driver
    driver.quit()

# Class scope - shared across test class
@pytest.fixture(scope="class")
def database_connection():
    conn = create_connection()
    yield conn
    conn.close()

# Module scope - shared across test module
@pytest.fixture(scope="module")
def test_data():
    return load_test_data()

# Session scope - once per test session
@pytest.fixture(scope="session")
def config():
    return load_config()
```

### Fixture Composition

```python
# Build complex fixtures from simple ones
@pytest.fixture
def browser():
    driver = webdriver.Chrome()
    yield driver
    driver.quit()

@pytest.fixture
def login_page(browser, base_url):
    browser.get(base_url)
    return LoginPage(browser)

@pytest.fixture
def logged_in_user(login_page, valid_user):
    login_page.login(**valid_user)
    yield login_page
    login_page.logout()
```

### Fixture Cleanup

```python
# ✅ Proper cleanup with yield
@pytest.fixture
def resource():
    r = create_resource()
    yield r
    r.cleanup()  # Always runs

# ✅ Extra safety with try/finally
@pytest.fixture
def resource():
    r = create_resource()
    try:
        yield r
    finally:
        r.cleanup()  # Runs even if test fails
```

---

## Error Handling

### Page Object Error Handling

```python
class LoginPage:
    def login(self, username: str, password: str) -> None:
        """Login with error handling"""
        try:
            self.waiter.wait_for_element_visible(self.USERNAME_FIELD, timeout=10)
            self.interactor.type_text(self.USERNAME_FIELD, username)
            self.interactor.type_text(self.PASSWORD_FIELD, password)
            self.interactor.click(self.LOGIN_BUTTON)
        except TimeoutException as e:
            raise RuntimeError(f"Login failed: Element not found - {e}")
        except Exception as e:
            raise RuntimeError(f"Login failed: Unexpected error - {e}")
```

### Test Error Handling

```python
def test_login_with_retry(browser, login_page, valid_user):
    """Test login with retry mechanism"""
    max_retries = 3

    for attempt in range(max_retries):
        try:
            login_page.login(**valid_user)
            assert login_page.is_logged_in()
            break  # Success
        except AssertionError:
            if attempt == max_retries - 1:
                raise  # Last attempt failed
            browser.refresh()  # Retry
```

---

## Code Review Checklist

**Before submitting code for review**:

### Test Quality
- [ ] Tests are independent (can run in any order)
- [ ] Tests are deterministic (same input → same output)
- [ ] Tests have descriptive names
- [ ] Tests have docstrings explaining what they test
- [ ] Each test tests one thing
- [ ] Assertions have failure messages

### Page Objects
- [ ] Locators are class constants at top
- [ ] Methods represent user actions (not implementation details)
- [ ] No assertions in page objects (return values instead)
- [ ] Proper use of waits (explicit, not sleep())
- [ ] Type hints on all methods

### Performance
- [ ] No `time.sleep()` (use explicit waits)
- [ ] No unnecessary `driver.get()` calls
- [ ] Elements not found multiple times
- [ ] Appropriate fixture scopes

### Maintainability
- [ ] No hardcoded values (use test data)
- [ ] No duplicate code (use fixtures/helpers)
- [ ] Clear variable names
- [ ] Comments for complex logic
- [ ] Follows project conventions

---

## Common Anti-Patterns

### Anti-Pattern 1: Sleep Instead of Wait

❌ **BAD**:
```python
import time
driver.find_element(By.ID, "button").click()
time.sleep(3)  # Hope element appears
driver.find_element(By.ID, "result")
```

✅ **GOOD**:
```python
driver.find_element(By.ID, "button").click()
wait.until(EC.presence_of_element_located((By.ID, "result")))
```

### Anti-Pattern 2: Testing Multiple Things

❌ **BAD**:
```python
def test_entire_user_flow():
    """Test everything in one test"""
    # 50 lines of test code
    test_login()
    test_navigation()
    test_form_submission()
    test_validation()
    test_logout()
    # If one fails, all remaining checks are skipped!
```

✅ **GOOD**:
```python
def test_login():
    """Test login only"""
    # 5 lines

def test_navigation():
    """Test navigation only"""
    # 5 lines

def test_form_submission():
    """Test form submission only"""
    # 5 lines
```

### Anti-Pattern 3: Hardcoded Test Data

❌ **BAD**:
```python
def test_login():
    login_page.login("test@example.com", "password123")  # ❌ Hardcoded
```

✅ **GOOD**:
```python
def test_login(valid_user):
    login_page.login(**valid_user)  # ✅ From fixture
```

### Anti-Pattern 4: No Cleanup

❌ **BAD**:
```python
def test_create_user():
    user = create_user("testuser")
    assert user exists
    # ❌ User left in database!
```

✅ **GOOD**:
```python
def test_create_user():
    user = create_user("testuser")
    try:
        assert user_exists(user)
    finally:
        delete_user(user)  # ✅ Always cleaned up
```

### Anti-Pattern 5: Absolute XPath

❌ **BAD**:
```python
LOGIN_BUTTON = (By.XPATH, "/html/body/div[1]/div[2]/form/button")
# ❌ Breaks with any HTML change!
```

✅ **GOOD**:
```python
LOGIN_BUTTON = (By.ID, "login-btn")
# or
LOGIN_BUTTON = (By.XPATH, "//button[@type='submit'][@form='login']")
```

---

## Quick Reference

### Test Checklist
- ✅ Independent (can run alone)
- ✅ Deterministic (repeatable)
- ✅ Fast (< 30 seconds)
- ✅ Readable (clear purpose)
- ✅ Focused (tests one thing)

### Page Object Checklist
- ✅ Locators as class constants
- ✅ Methods = user actions
- ✅ No assertions (return values)
- ✅ Explicit waits
- ✅ Type hints

### Locator Priority
1. 🥇 ID
2. 🥈 data-testid
3. 🥉 Name
4. CSS Selector
5. Relative XPath
6. ⛔ Avoid: Link text, absolute XPath

### Wait Priority
1. 🥇 Explicit waits
2. 🥈 Fluent waits
3. 🥉 Implicit waits (cautiously)
4. ⛔ Never: time.sleep()

---

## Related Documentation

- [Implementation Guide](implementation-guide.md)
- [Performance Optimization](performance-optimization.md)
- [Troubleshooting Guide](troubleshooting.md)
- [Test Fixtures Guide](test-fixtures.md)

---

**Last Updated**: December 24, 2025
**Framework Version**: 6.0
