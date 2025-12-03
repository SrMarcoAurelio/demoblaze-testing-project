# Test Fixtures Guide - Phase 6

## 🎯 Overview

This guide explains the test data fixtures system implemented in Phase 6. Fixtures provide reusable, consistent test data and pre-configured test states that make tests cleaner, more maintainable, and easier to write.

## 📦 What are Fixtures?

Fixtures are functions that provide test data or set up test states. They:
- **Reduce code duplication** - Write setup logic once, use everywhere
- **Improve readability** - Tests focus on what they're testing, not setup
- **Ensure consistency** - Same data used across tests
- **Automatic cleanup** - Fixtures can tear down after tests
- **Support dependency injection** - Fixtures can depend on other fixtures

## 📋 Available Fixtures

### 1. **Data Fixtures** (Test Data)

#### User Credentials

| Fixture | Scope | Description | Example |
|---------|-------|-------------|---------|
| `valid_user` | session | Valid username/password | `login_page.login(**valid_user)` |
| `invalid_user_username` | session | Invalid username | Testing login failures |
| `invalid_user_password` | session | Invalid password | Testing login failures |
| `new_user` | function | Unique user (timestamp-based) | Signup tests |

**Example:**
```python
def test_login(login_page, valid_user):
    login_page.login(**valid_user)
    assert login_page.is_user_logged_in()
```

#### Purchase Data

| Fixture | Scope | Description |
|---------|-------|-------------|
| `purchase_data` | function | Valid credit card & billing info |
| `minimal_purchase_data` | function | Minimal valid purchase data |

**Example:**
```python
def test_checkout(purchase_page, purchase_data):
    purchase_page.fill_form(**purchase_data)
    purchase_page.confirm_purchase()
```

#### Product Data

| Fixture | Scope | Description |
|---------|-------|-------------|
| `product_phone` | session | Phone product name (Samsung Galaxy S6) |
| `product_laptop` | session | Laptop product name (Sony Vaio i5) |
| `product_monitor` | session | Monitor product name (Apple Monitor 24) |
| `random_product` | function | Random product from phones list |

**Example:**
```python
def test_add_to_cart(catalog_page, product_phone):
    catalog_page.select_product(product_phone)
    # product_phone = "Samsung galaxy s6"
```

### 2. **Page Object Fixtures** (Initialized Pages)

All page fixtures automatically navigate to `base_url` before returning the page object.

| Fixture | Returns | Auto-navigates |
|---------|---------|----------------|
| `login_page` | LoginPage instance | ✅ Yes |
| `signup_page` | SignupPage instance | ✅ Yes |
| `catalog_page` | CatalogPage instance | ✅ Yes |
| `product_page` | ProductPage instance | ✅ Yes |
| `cart_page` | CartPage instance | ✅ Yes |
| `purchase_page` | PurchasePage instance | ✅ Yes |

**Example:**
```python
def test_catalog_filters(catalog_page):
    # Page is already initialized and navigated
    catalog_page.click_category("Phones")
    assert catalog_page.get_product_count() > 0
```

### 3. **State Fixtures** (Pre-configured States)

These fixtures set up complex test states automatically.

#### `logged_in_user`

- **Scope:** function
- **Setup:** User logged in
- **Cleanup:** Automatic logout after test
- **Returns:** LoginPage instance

**Example:**
```python
def test_user_can_access_cart(logged_in_user, catalog_page):
    # User is already logged in
    catalog_page.go_to_cart()
    # User will be logged out automatically after test
```

#### `cart_with_product`

- **Scope:** function
- **Setup:**
  - User logged in
  - Product added to cart
  - Navigated to cart page
- **Returns:** `(CartPage, product_name)` tuple

**Example:**
```python
def test_remove_from_cart(cart_with_product):
    cart_page, product = cart_with_product
    # Cart already has product
    cart_page.delete_product(product)
    assert cart_page.is_cart_empty()
```

#### `prepared_checkout`

- **Scope:** function
- **Setup:**
  - User logged in
  - Product in cart
  - Purchase modal opened
- **Returns:** PurchasePage instance

**Example:**
```python
def test_purchase_form_validation(prepared_checkout, purchase_data):
    # Ready to fill purchase form
    prepared_checkout.fill_form(**purchase_data)
    prepared_checkout.confirm_purchase()
```

## 🔧 Usage Patterns

### Pattern 1: Basic Data Injection

**Before (without fixtures):**
```python
def test_login(browser, base_url):
    browser.get(base_url)
    login_page = LoginPage(browser)
    login_page.login("Apolo2025", "apolo2025")
    assert login_page.is_user_logged_in()
```

**After (with fixtures):**
```python
def test_login(login_page, valid_user):
    login_page.login(**valid_user)
    assert login_page.is_user_logged_in()
```

**Benefits:** Less boilerplate, centralized data, automatic navigation

### Pattern 2: State Setup

**Before (without fixtures):**
```python
def test_checkout(browser, base_url):
    # Login
    browser.get(base_url)
    login_page = LoginPage(browser)
    login_page.login("Apolo2025", "apolo2025")

    # Add product
    catalog_page = CatalogPage(browser)
    catalog_page.select_product("Samsung galaxy s6")

    product_page = ProductPage(browser)
    product_page.add_to_cart()

    # Go to cart
    cart_page = CartPage(browser)
    cart_page.go_to_cart()
    cart_page.click_place_order()

    # Finally test checkout
    purchase_page = PurchasePage(browser)
    purchase_page.fill_form(...)
```

**After (with fixtures):**
```python
def test_checkout(prepared_checkout, purchase_data):
    # Setup done automatically by fixture
    prepared_checkout.fill_form(**purchase_data)
    prepared_checkout.confirm_purchase()
```

**Benefits:** 90% less setup code, focus on test logic

### Pattern 3: Parametrized Tests

```python
@pytest.mark.parametrize("user_fixture", [
    "invalid_user_username",
    "invalid_user_password",
])
def test_login_failures(login_page, user_fixture, request):
    user_data = request.getfixturevalue(user_fixture)
    login_page.login(**user_data)
    assert not login_page.is_user_logged_in()
```

**Benefits:** Test multiple scenarios with one test function

## 📊 Fixture Scope

Understanding scope is important for performance and test isolation:

| Scope | Lifecycle | Use Case |
|-------|-----------|----------|
| **session** | Once per test run | Expensive setup, immutable data |
| **module** | Once per test file | Shared state within file |
| **function** | Once per test | Unique state for each test (default) |

**Examples:**
- `valid_user` (session) - Data doesn't change, safe to reuse
- `new_user` (function) - Needs unique value each time
- `logged_in_user` (function) - State shouldn't leak between tests

## 🎨 Best Practices

### 1. ✅ **DO: Use fixtures for repetitive setup**

```python
# Good - Clean and focused
def test_add_to_cart(logged_in_user, catalog_page, product_phone):
    catalog_page.select_product(product_phone)
    # Test logic here
```

### 2. ✅ **DO: Combine multiple fixtures**

```python
def test_purchase(prepared_checkout, purchase_data, valid_user):
    # Multiple fixtures work together
    prepared_checkout.fill_form(**purchase_data)
    assert "Thank you" in prepared_checkout.get_confirmation()
```

### 3. ✅ **DO: Use descriptive fixture names**

```python
# Good
def test_checkout(cart_with_product, purchase_data):
    ...

# Bad
def test_checkout(cp, pd):
    ...
```

### 4. ❌ **DON'T: Modify session-scoped fixture data**

```python
# BAD - Don't modify session fixtures
def test_login(valid_user):
    valid_user["username"] = "different_user"  # ❌ Affects other tests!

# GOOD - Copy if you need to modify
def test_login(valid_user):
    modified_user = valid_user.copy()  # ✅ Safe
    modified_user["username"] = "different_user"
```

### 5. ❌ **DON'T: Create fixtures for one-time use**

```python
# BAD - Unnecessary fixture
@pytest.fixture
def single_use_string():
    return "only used once"

# GOOD - Just use the value directly
def test_something():
    value = "only used once"
```

## 🔍 Fixture Discovery

Pytest automatically discovers fixtures from:
1. **conftest.py** in current directory
2. **conftest.py** in parent directories
3. **Built-in pytest fixtures**

To see all available fixtures:
```bash
pytest --fixtures
pytest --fixtures -v  # More verbose
```

## 📈 Migration Guide

### Migrating Existing Tests

**Step 1:** Identify repetitive setup code
```python
# Look for patterns like:
browser.get(base_url)
login_page = LoginPage(browser)
login_page.login("user", "pass")
```

**Step 2:** Replace with appropriate fixtures
```python
# Before
def test_something(browser, base_url):
    browser.get(base_url)
    login_page = LoginPage(browser)
    login_page.login("Apolo2025", "apolo2025")

# After
def test_something(logged_in_user):
    # Setup done by fixture
```

**Step 3:** Verify test still passes
```bash
pytest tests/your_test.py::test_something -v
```

## 📚 Examples

See `tests/examples/test_fixtures_demo.py` for comprehensive examples of:
- Basic fixture usage
- Parametrized tests with fixtures
- Before/after comparisons
- Complex state fixtures

## 🔗 Related Documentation

- **Pytest Fixtures**: https://docs.pytest.org/en/stable/fixture.html
- **Test Data** (`tests/test_data.py`): Centralized test data classes
- **Page Objects** (`pages/`): Page object implementations
- **Configuration** (`conftest.py`): All fixture definitions

## 🎓 Summary

**Key Takeaways:**
1. Fixtures reduce boilerplate and improve test readability
2. Use appropriate scope (session vs function) for performance
3. State fixtures (`logged_in_user`, `cart_with_product`) eliminate complex setup
4. Page fixtures auto-initialize and navigate
5. Data fixtures centralize test data management

**Fixture Categories:**
- 📝 **Data:** `valid_user`, `purchase_data`, `product_phone`
- 📄 **Pages:** `login_page`, `catalog_page`, `cart_page`
- 🎭 **State:** `logged_in_user`, `cart_with_product`, `prepared_checkout`

---

**Phase 6 Complete** - Test Data Fixtures System
**Framework Universality: 9.0/10** (Highly reusable patterns)
