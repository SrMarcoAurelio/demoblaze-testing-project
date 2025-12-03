# Your First Test

Learn how to create a test from scratch.

## Project Structure Overview

```
demoblaze-testing-project/
├── config/              # Configuration files
├── pages/               # Page Object Model classes
├── tests/               # Test files
├── utils/               # Helper utilities
└── conftest.py          # Pytest fixtures
```

## Understanding Page Objects

Page objects encapsulate page interactions:

```python
# pages/login_page.py
class LoginPage(BasePage):
    username_field = load_locator("login", "username_field")
    password_field = load_locator("login", "password_field")

    def login(self, username: str, password: str) -> None:
        self.type(self.username_field, username)
        self.type(self.password_field, password)
        self.click(self.login_button)
```

## Creating a Simple Test

### 1. Create Test File

```python
# tests/login/test_my_first.py
import pytest

def test_login_page_loads(browser, base_url):
    """Test that login page loads successfully"""
    browser.get(base_url)
    assert "PRODUCT STORE" in browser.title
```

### 2. Using Page Objects

```python
def test_login_with_valid_credentials(login_page, valid_user):
    """Test successful login with valid credentials"""
    login_page.open_login_modal()
    login_page.login(**valid_user)
    assert login_page.is_user_logged_in()
```

### 3. Using Test Data

```python
@pytest.mark.parametrize("username,password", [
    ("user1", "pass1"),
    ("user2", "pass2"),
])
def test_login_variations(login_page, username, password):
    """Test login with multiple user combinations"""
    login_page.open_login_modal()
    login_page.login(username, password)
    # Assert expected behavior
```

## Test Markers

Organize tests with markers:

```python
@pytest.mark.functional
def test_basic_functionality():
    """Test core functionality"""
    pass

@pytest.mark.security
def test_sql_injection_prevention():
    """Test security against SQL injection"""
    pass

@pytest.mark.accessibility
def test_wcag_compliance():
    """Test WCAG 2.1 compliance"""
    pass
```

## Running Your Test

```bash
# Run your specific test
pytest tests/login/test_my_first.py -v

# Run with specific marker
pytest -m functional -v

# Run with detailed output
pytest tests/login/test_my_first.py -v -s
```

## Test Structure Best Practices

### 1. Arrange-Act-Assert Pattern

```python
def test_add_product_to_cart(catalog_page, product_page):
    # Arrange - Set up test data and state
    catalog_page.navigate_to_catalog()

    # Act - Perform the action being tested
    catalog_page.click_first_product()
    product_page.add_to_cart()

    # Assert - Verify expected outcome
    assert product_page.is_product_added_to_cart()
```

### 2. Clear Test Names

```python
# Good
def test_login_fails_with_invalid_password():
    pass

# Avoid
def test_login():
    pass
```

### 3. Docstrings

```python
def test_password_strength_validation():
    """
    Test password strength requirements according to NIST 800-63B.

    Validates that passwords must meet minimum strength criteria:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    """
    pass
```

## Using Fixtures

Framework provides 18 fixtures. Common ones:

```python
def test_with_fixtures(
    browser,           # WebDriver instance
    base_url,          # Application URL
    login_page,        # LoginPage object
    valid_user,        # Valid user credentials
    logged_in_user     # Pre-authenticated user
):
    # Test implementation
    pass
```

See [Test Fixtures Guide](../guides/test-fixtures.md) for complete fixture documentation.

## Next Steps

1. Review existing tests in `/tests` directory
2. Read [Test Templates](../templates/) for structured test creation
3. Explore [Implementation Guide](../guides/implementation-guide.md)
4. Learn about [Test Fixtures](../guides/test-fixtures.md)

## Common Patterns

### Waiting for Elements

```python
# Wait for element to be visible
element = self.wait_for_element_visible(locator, timeout=10)

# Wait for element to be clickable
element = self.wait_for_element_clickable(locator, timeout=10)
```

### Handling Alerts

```python
# Accept alert
self.accept_alert()

# Dismiss alert
self.dismiss_alert()
```

### Taking Screenshots

```python
# Screenshot on failure (automatic in conftest.py)
# Or manual screenshot
self.driver.save_screenshot("screenshot.png")
```

## Debugging Tests

```bash
# Run with live output
pytest tests/login/test_my_first.py -v -s

# Stop on first failure
pytest tests/login/test_my_first.py -x

# Run last failed tests
pytest --lf

# Show local variables on failure
pytest --showlocals
```
