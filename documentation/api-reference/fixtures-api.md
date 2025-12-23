# Fixtures API Reference

Complete reference for all 18 pytest fixtures in the framework.

**File:** `conftest.py`
**Version:** 6.0

## Overview

Pytest fixtures provide dependency injection for tests. The framework provides 18 fixtures organized into 6 categories:

1. **Configuration Fixtures** (3) - Test configuration and settings
2. **Browser Fixtures** (3) - WebDriver management
3. **Data Fixtures** (6) - Test data provisioning
4. **Page Object Fixtures** (6) - Initialized page objects
5. **Product Fixtures** (4) - Product test data
6. **State Fixtures** (3) - Pre-configured test states
7. **Performance Fixtures** (3) - Performance testing tools

**Total:** 18 fixtures

---

## Configuration Fixtures

### `base_url`

Provides base URL from configuration.

**Scope:** session
**File:** conftest.py:141-144

**Signature:**
```python
@pytest.fixture(scope="session")
def base_url():
```

**Returns:**
- `str`: Base URL from config.BASE_URL

**Usage:**
```python
def test_homepage(browser, base_url):
    browser.get(base_url)
    assert "PRODUCT STORE" in browser.title
```

**Internal Behavior:**
- Reads `config.BASE_URL` once per test session
- Shared across all tests in session

---

### `timeout_config`

Provides timeout configuration dictionary.

**Scope:** session
**File:** conftest.py:147-150

**Signature:**
```python
@pytest.fixture(scope="session")
def timeout_config():
```

**Returns:**
- `dict`: Timeout configuration from `config.get_timeout_config()`

**Example Return Value:**
```python
{
    "default": 10,
    "short": 5,
    "long": 30,
    "page_load": 60
}
```

**Usage:**
```python
def test_with_custom_timeout(browser, base_url, timeout_config):
    wait = WebDriverWait(browser, timeout_config["long"])
    # Use long timeout for slow operations
```

---

### `test_config`

Provides complete test configuration including browser settings and timeouts.

**Scope:** session
**File:** conftest.py:153-163

**Signature:**
```python
@pytest.fixture(scope="session")
def test_config(request):
```

**Returns:**
- `dict`: Complete test configuration

**Example Return Value:**
```python
{
    "browser": "chrome",
    "headless": False,
    "slow_mode": 0.0,
    "base_url": "https://your-application-url.com",
    "timeouts": {...}
}
```

**Usage:**
```python
def test_browser_config(test_config):
    print(f"Running on: {test_config['browser']}")
    if test_config['headless']:
        print("Headless mode enabled")
```

---

## Browser Fixtures

### `browser`

Provides WebDriver instance with automatic setup and teardown.

**Scope:** function
**File:** conftest.py:165-261

**Signature:**
```python
@pytest.fixture(scope="function")
def browser(request):
```

**Returns:**
- `WebDriver`: Selenium WebDriver instance (Chrome/Firefox/Edge)

**Raises:**
- `pytest.fail`: If browser initialization fails

**Features:**
- Automatic driver installation via webdriver-manager
- Supports Chrome, Firefox, Edge
- Headless mode support
- Slow mode for debugging
- Automatic screenshot on test failure
- Automatic cleanup (driver.quit())

**Command Line Options:**
```bash
pytest --browser=chrome          # Chrome (default)
pytest --browser=firefox         # Firefox
pytest --browser=edge            # Edge
pytest --headless               # Headless mode
pytest --slow=1.0               # 1 second delay between actions
```

**Usage:**
```python
def test_example(browser, base_url):
    browser.get(base_url)
    # WebDriver is automatically closed after test
```

**Internal Behavior:**
1. **Setup:**
   - Reads browser name from `--browser` option
   - Installs appropriate driver via webdriver-manager
   - Configures browser options (headless, automation flags)
   - Maximizes window
   - Sets implicit wait from config

2. **Teardown:**
   - Takes screenshot if test failed
   - Calls `driver.quit()`
   - Logs total execution time

**Attributes Added:**
- `browser.test_config`: Dict with browser_name, headless, slow_mode

---

### `log_test_info`

Automatically logs test start and finish with duration.

**Scope:** function
**Autouse:** True (runs for every test automatically)
**File:** conftest.py:263-272

**Signature:**
```python
@pytest.fixture(scope="function", autouse=True)
def log_test_info(request):
```

**Usage:**
- Automatically applied - no need to request in test parameters

**Log Output Example:**
```
▶▶▶ Starting: test_login_with_valid_credentials
✓✓✓ Finished: test_login_with_valid_credentials (2.35s)
```

---

### `slow_down`

Provides delay function for slow mode testing.

**Scope:** function
**File:** conftest.py:274-284

**Signature:**
```python
@pytest.fixture(scope="function")
def slow_down(request, browser):
```

**Returns:**
- `Callable`: Function that delays based on `--slow` option

**Usage:**
```python
def test_with_delays(browser, base_url, slow_down):
    browser.get(base_url)
    slow_down()  # Delays if --slow option provided

    browser.find_element(By.ID, "username").send_keys("user")
    slow_down()
```

**Command:**
```bash
pytest --slow=1.5  # 1.5 second delay after each slow_down() call
```

---

## Data Fixtures

### `valid_user`

Provides valid user credentials for login tests.

**Scope:** session
**File:** conftest.py:345-360

**Signature:**
```python
@pytest.fixture(scope="session")
def valid_user():
```

**Returns:**
- `dict`: Valid username and password

**Example Return Value:**
```python
{
    "username": "testuser123",
    "password": "ValidPass123"
}
```

**Usage:**
```python
def test_login(login_page, valid_user):
    login_page.login(**valid_user)
    assert login_page.is_user_logged_in()
```

**Source:**
- Data from `tests.test_data.Users.VALID`

---

### `invalid_user_username`

Provides user with invalid username.

**Scope:** session
**File:** conftest.py:362-368

**Signature:**
```python
@pytest.fixture(scope="session")
def invalid_user_username():
```

**Returns:**
- `dict`: Invalid username, valid password

**Usage:**
```python
def test_login_invalid_username(login_page, invalid_user_username):
    login_page.login(**invalid_user_username)
    assert not login_page.is_user_logged_in()
```

---

### `invalid_user_password`

Provides user with invalid password.

**Scope:** session
**File:** conftest.py:370-376

**Signature:**
```python
@pytest.fixture(scope="session")
def invalid_user_password():
```

**Returns:**
- `dict`: Valid username, invalid password

**Usage:**
```python
def test_login_invalid_password(login_page, invalid_user_password):
    login_page.login(**invalid_user_password)
    assert not login_page.is_user_logged_in()
```

---

### `new_user`

Generates unique user credentials for signup tests.

**Scope:** function
**File:** conftest.py:378-399

**Signature:**
```python
@pytest.fixture(scope="function")
def new_user():
```

**Returns:**
- `dict`: Unique username and password (generated per test)

**Example Return Value:**
```python
{
    "username": "user_20251203142530123456",
    "password": "aB3!xY9@pQ1#"
}
```

**Usage:**
```python
def test_signup(signup_page, new_user):
    signup_page.signup(**new_user)
    # Each test gets unique credentials
```

**Internal Behavior:**
- Generates timestamp-based username
- Creates random 12-character password
- Prevents username conflicts

---

### `purchase_data`

Provides valid purchase/checkout data.

**Scope:** function
**File:** conftest.py:401-416

**Signature:**
```python
@pytest.fixture(scope="function")
def purchase_data():
```

**Returns:**
- `dict`: Valid credit card and billing information

**Example Return Value:**
```python
{
    "name": "John Doe",
    "country": "United States",
    "city": "New York",
    "card": "4532015112830366",  # Valid Luhn
    "month": "12",
    "year": "2025"
}
```

**Usage:**
```python
def test_checkout(prepared_checkout, purchase_data):
    prepared_checkout.fill_form(**purchase_data)
    prepared_checkout.confirm_purchase()
```

**Source:**
- Data from `tests.test_data.PurchaseData.VALID_PURCHASE`

---

### `minimal_purchase_data`

Provides minimal valid purchase data.

**Scope:** function
**File:** conftest.py:418-424

**Signature:**
```python
@pytest.fixture(scope="function")
def minimal_purchase_data():
```

**Returns:**
- `dict`: Minimal required fields only

**Usage:**
```python
def test_minimal_checkout(prepared_checkout, minimal_purchase_data):
    # Test with only required fields
    prepared_checkout.fill_form(**minimal_purchase_data)
```

---

## Page Object Fixtures

All page object fixtures follow the same pattern:
1. Navigate to base_url
2. Create page object instance
3. Return initialized page object

### `login_page`

Provides initialized LoginPage instance.

**Scope:** function
**File:** conftest.py:431-447

**Signature:**
```python
@pytest.fixture(scope="function")
def login_page(browser, base_url):
```

**Returns:**
- `LoginPage`: Initialized page object

**Usage:**
```python
def test_login(login_page, valid_user):
    login_page.login(**valid_user)
    assert login_page.is_user_logged_in()
```

**Internal Behavior:**
1. Navigates to `base_url`
2. Creates `LoginPage(browser)` instance
3. Returns page object

---

### `signup_page`

Provides initialized SignupPage instance.

**Scope:** function
**File:** conftest.py:449-456

**Usage:**
```python
def test_signup(signup_page, new_user):
    signup_page.signup(**new_user)
```

---

### `catalog_page`

Provides initialized CatalogPage instance.

**Scope:** function
**File:** conftest.py:458-465

**Usage:**
```python
def test_browse_products(catalog_page):
    products = catalog_page.get_all_products()
    assert len(products) > 0
```

---

### `product_page`

Provides initialized ProductPage instance.

**Scope:** function
**File:** conftest.py:467-474

**Usage:**
```python
def test_add_to_cart(catalog_page, product_page):
    catalog_page.select_product("Samsung galaxy s6")
    product_page.add_to_cart()
```

---

### `cart_page`

Provides initialized CartPage instance.

**Scope:** function
**File:** conftest.py:476-483

**Usage:**
```python
def test_view_cart(cart_with_product):
    cart_page, product = cart_with_product
    items = cart_page.get_cart_items()
    assert product in items
```

---

### `purchase_page`

Provides initialized PurchasePage instance.

**Scope:** function
**File:** conftest.py:485-492

**Usage:**
```python
def test_purchase_form(purchase_page, purchase_data):
    purchase_page.open_modal()
    purchase_page.fill_form(**purchase_data)
```

---

## Product Fixtures

### `product_phone`

Provides phone product name.

**Scope:** session
**File:** conftest.py:499-505

**Returns:**
- `str`: "Samsung galaxy s6"

**Usage:**
```python
def test_phone_product(catalog_page, product_phone):
    catalog_page.select_product(product_phone)
```

---

### `product_laptop`

Provides laptop product name.

**Scope:** session
**File:** conftest.py:507-513

**Returns:**
- `str`: "Sony vaio i5"

**Usage:**
```python
def test_laptop_product(catalog_page, product_laptop):
    catalog_page.select_product(product_laptop)
```

---

### `product_monitor`

Provides monitor product name.

**Scope:** session
**File:** conftest.py:515-521

**Returns:**
- `str`: "Apple monitor 24"

---

### `random_product`

Provides random product from available products.

**Scope:** function
**File:** conftest.py:523-537

**Returns:**
- `str`: Random product name (different each test execution)

**Usage:**
```python
def test_random_product(catalog_page, random_product):
    # Tests run with different products each time
    catalog_page.select_product(random_product)
```

---

## State Fixtures

State fixtures provide pre-configured application states to reduce test setup code.

### `logged_in_user`

Provides logged-in user session with automatic logout cleanup.

**Scope:** function
**File:** conftest.py:544-575

**Signature:**
```python
@pytest.fixture(scope="function")
def logged_in_user(login_page, valid_user):
```

**Returns:**
- `LoginPage`: Page object with user already logged in

**Raises:**
- `pytest.fail`: If login fails

**Usage:**
```python
def test_add_to_cart(logged_in_user, catalog_page):
    # User is already logged in
    catalog_page.select_product("Samsung galaxy s6")
    # User is automatically logged out after test
```

**Internal Behavior:**
1. **Setup:**
   - Performs login with valid_user
   - Verifies login success
   - Fails test if login unsuccessful

2. **Teardown:**
   - Logs out user if still logged in
   - Handles logout errors gracefully

---

### `cart_with_product`

Provides cart with one product already added.

**Scope:** function
**File:** conftest.py:577-610

**Signature:**
```python
@pytest.fixture(scope="function")
def cart_with_product(logged_in_user, catalog_page, product_phone):
```

**Returns:**
- `tuple`: (CartPage instance, product_name)

**Usage:**
```python
def test_remove_from_cart(cart_with_product):
    cart_page, product = cart_with_product
    cart_page.remove_product(product)
    assert cart_page.is_cart_empty()
```

**Internal Behavior:**
1. User is logged in (via logged_in_user)
2. Navigates to catalog
3. Selects product
4. Adds to cart
5. Handles "Product added" alert
6. Navigates to cart page
7. Returns (cart_page, product_name)

---

### `prepared_checkout`

Provides checkout state ready for purchase.

**Scope:** function
**File:** conftest.py:612-640

**Signature:**
```python
@pytest.fixture(scope="function")
def prepared_checkout(cart_with_product):
```

**Returns:**
- `PurchasePage`: Purchase page with modal already open

**Raises:**
- `pytest.fail`: If modal doesn't open

**Usage:**
```python
def test_purchase(prepared_checkout, purchase_data):
    # Purchase modal is already open
    prepared_checkout.fill_form(**purchase_data)
    prepared_checkout.confirm_purchase()
```

**Internal Behavior:**
1. Cart has product (via cart_with_product)
2. Clicks "Place Order" button
3. Verifies modal opened
4. Returns PurchasePage instance

---

## Performance Fixtures

### `performance_collector`

Provides performance metrics collector for tests.

**Scope:** function
**File:** conftest.py:647-672

**Signature:**
```python
@pytest.fixture(scope="function")
def performance_collector():
```

**Returns:**
- `PerformanceMetricsCollector`: Metrics collector instance

**Usage:**
```python
def test_login_performance(login_page, performance_collector, valid_user):
    performance_collector.start_timer("login")
    login_page.login(**valid_user)
    duration = performance_collector.stop_timer("login", category="auth")

    assert performance_collector.check_threshold("login", duration)
```

**Internal Behavior:**
- Clears metrics before each test
- Returns global collector instance
- Metrics are automatically saved at session end

**Available Methods:**
- `start_timer(name)`
- `stop_timer(name, category, metadata)`
- `record_metric(name, duration, category, metadata)`
- `check_threshold(name, duration)`
- `get_statistics(name)`

---

### `performance_timer`

Provides performance timer context manager.

**Scope:** function
**File:** conftest.py:674-686

**Signature:**
```python
@pytest.fixture(scope="function")
def performance_timer():
```

**Returns:**
- `ContextManager`: Performance timer context manager

**Usage:**
```python
def test_page_load(browser, base_url, performance_timer):
    with performance_timer("page_load", category="navigation"):
        browser.get(base_url)
    # Duration is automatically recorded
```

---

### `performance_report_cleanup`

Generates and saves performance report at end of session.

**Scope:** session
**Autouse:** True
**File:** conftest.py:688-722

**Signature:**
```python
@pytest.fixture(scope="session", autouse=True)
def performance_report_cleanup(request):
```

**Internal Behavior:**
1. Runs after all tests complete
2. Checks if any metrics were collected
3. Generates timestamp-based report directory
4. Saves JSON report to `results/performance/{timestamp}/performance_report.json`
5. Logs summary:
   - Total metrics collected
   - Threshold violations
   - Report file path

**Report Contents:**
- Summary statistics
- Metrics by category
- Statistics by metric name
- Threshold violations
- All individual metrics

---

## Fixture Dependencies

Visual representation of fixture dependencies:

```
browser
├── login_page
│   └── logged_in_user
│       └── cart_with_product
│           └── prepared_checkout
├── signup_page
├── catalog_page
├── product_page
├── cart_page
└── purchase_page

base_url (used by all page fixtures)

valid_user
└── logged_in_user

product_phone
└── cart_with_product
```

---

## Fixture Scopes

**Session Scope** (created once per test session):
- base_url
- timeout_config
- test_config
- valid_user
- invalid_user_username
- invalid_user_password
- product_phone
- product_laptop
- product_monitor

**Function Scope** (created for each test):
- browser
- slow_down
- new_user
- purchase_data
- minimal_purchase_data
- login_page
- signup_page
- catalog_page
- product_page
- cart_page
- purchase_page
- random_product
- logged_in_user
- cart_with_product
- prepared_checkout
- performance_collector
- performance_timer

**Autouse** (automatically used by all tests):
- log_test_info
- performance_report_cleanup

---

## Best Practices

1. **Use state fixtures to reduce setup code:**
```python
# Instead of:
def test_checkout(login_page, catalog_page, valid_user):
    login_page.login(**valid_user)
    catalog_page.select_product("Phone")
    # ...

# Do this:
def test_checkout(cart_with_product):
    cart_page, product = cart_with_product
    # Already logged in, product in cart
```

2. **Combine fixtures for complex scenarios:**
```python
def test_full_purchase(prepared_checkout, purchase_data, performance_collector):
    # User logged in, product in cart, modal open, performance tracked
    performance_collector.start_timer("purchase")
    prepared_checkout.fill_form(**purchase_data)
    prepared_checkout.confirm_purchase()
    duration = performance_collector.stop_timer("purchase")
```

3. **Request only needed fixtures:**
```python
# Don't request browser if you have page object
def test_login(login_page, valid_user):  # Good
    login_page.login(**valid_user)

def test_login(browser, login_page, valid_user):  # Unnecessary
    # login_page already has browser internally
```

4. **Use session scope for static data:**
```python
# Product names don't change - session scope is efficient
product_phone  # Session scope

# User credentials are unique - function scope prevents conflicts
new_user  # Function scope
```

## Related Documentation

- [BasePage API](base-page-api.md) - Page object methods
- [Test Data Guide](../guides/test-fixtures.md) - Managing test data
- [Code Walkthrough](../guides/code-walkthrough.md) - Fixture initialization flow
