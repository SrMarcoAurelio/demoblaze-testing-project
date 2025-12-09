# Page Objects Directory

## Overview

This directory contains all Page Object Model (POM) classes for the test automation framework. Each page object encapsulates the UI elements and interactions for a specific page or component of the application, following the Page Object design pattern.

## Design Pattern

The Page Object Model provides:
- **Separation of concerns**: UI logic separated from test logic
- **Reusability**: Page methods used across multiple tests
- **Maintainability**: UI changes require updates in one place only
- **Readability**: Tests read like user stories

## File Structure

```
pages/
├── __init__.py              # Package initialization
├── base_page.py            # Base class for all page objects (598 lines, 35 tests)
├── login_page.py           # Login page interactions
├── signup_page.py          # Signup/registration page interactions
├── cart_page.py            # Shopping cart page interactions (281 lines)
├── catalog_page.py         # Product catalog/listing page interactions
├── product_page.py         # Individual product page interactions
└── purchase_page.py        # Checkout/purchase flow interactions
```

## Page Objects

### base_page.py

**Purpose:** Base class providing common functionality for all page objects

**Key Features:**
- Element interaction methods (click, type, select)
- Wait strategies (explicit waits, element visibility)
- Navigation helpers
- Screenshot capture
- JavaScript execution
- Error handling

**Lines of Code:** 598 lines
**Test Coverage:** 35 integration tests (tests/test_base_page.py)

**Core Methods:**
```python
class BasePage:
    def __init__(self, driver, timeout=10):
        """Initialize base page with WebDriver"""

    def find_element(self, by, value, timeout=None) -> WebElement:
        """Find single element with explicit wait"""

    def find_elements(self, by, value, timeout=None) -> List[WebElement]:
        """Find multiple elements"""

    def click(self, by, value, timeout=None):
        """Click element with wait"""

    def type_text(self, by, value, text, timeout=None):
        """Type text into input field"""

    def is_visible(self, by, value, timeout=None) -> bool:
        """Check if element is visible"""

    def wait_for_page_load(self, timeout=None):
        """Wait for page to fully load"""

    def take_screenshot(self, filename):
        """Capture screenshot"""

    def execute_script(self, script, *args):
        """Execute JavaScript"""
```

**Usage:**
```python
from pages.base_page import BasePage

class LoginPage(BasePage):
    def __init__(self, driver):
        super().__init__(driver)
```

---

### login_page.py

**Purpose:** Login page interactions and validations

**Locators:**
- Username input: `#loginusername`
- Password input: `#loginpassword`
- Login button: `//button[text()='Log in']`
- Login modal: `#logInModal`
- Close button: `.close` (modal)

**Key Methods:**
```python
class LoginPage(BasePage):
    def open_login_modal(self):
        """Click login link to open modal"""

    def enter_credentials(self, username, password):
        """Enter username and password"""

    def click_login_button(self):
        """Submit login form"""

    def login(self, username, password):
        """Complete login workflow"""

    def is_logged_in(self) -> bool:
        """Verify successful login"""

    def get_welcome_message(self) -> str:
        """Get welcome username text"""
```

**Test Coverage:** tests/login/ (40 tests)

---

### signup_page.py

**Purpose:** User registration page interactions

**Locators:**
- Username input: `#sign-username`
- Password input: `#sign-password`
- Signup button: `//button[text()='Sign up']`
- Signup modal: `#signInModal`

**Key Methods:**
```python
class SignupPage(BasePage):
    def open_signup_modal(self):
        """Open registration modal"""

    def enter_signup_credentials(self, username, password):
        """Enter registration details"""

    def click_signup_button(self):
        """Submit registration form"""

    def signup(self, username, password):
        """Complete signup workflow"""

    def get_alert_text(self) -> str:
        """Get alert message (success/error)"""
```

**Test Coverage:** tests/signup/ (32 tests)

---

### cart_page.py

**Purpose:** Shopping cart management and operations

**Lines of Code:** 281 lines

**Key Methods:**
```python
class CartPage(BasePage):
    def get_cart_items(self) -> List[Dict]:
        """Get list of cart items with details"""

    def get_total_price(self) -> float:
        """Calculate total cart price"""

    def remove_item(self, product_name):
        """Remove product from cart"""

    def place_order(self):
        """Click Place Order button"""

    def is_cart_empty(self) -> bool:
        """Check if cart has no items"""
```

**Test Coverage:** tests/cart/ (55 tests)

---

### catalog_page.py

**Purpose:** Product catalog browsing and filtering

**Key Methods:**
```python
class CatalogPage(BasePage):
    def get_all_products(self) -> List[Dict]:
        """Get list of all products with details"""

    def filter_by_category(self, category):
        """Filter products by category (Phones, Laptops, Monitors)"""

    def select_product(self, product_name):
        """Click on product to view details"""

    def is_product_displayed(self, product_name) -> bool:
        """Check if product is visible"""

    def navigate_to_next_page(self):
        """Click Next button for pagination"""
```

**Test Coverage:** tests/catalog/ (48 tests)

---

### product_page.py

**Purpose:** Individual product details and add to cart

**Key Methods:**
```python
class ProductPage(BasePage):
    def get_product_name(self) -> str:
        """Get product title"""

    def get_product_price(self) -> float:
        """Get product price"""

    def get_product_description(self) -> str:
        """Get product description text"""

    def add_to_cart(self):
        """Click Add to cart button"""

    def handle_cart_alert(self):
        """Handle 'Product added' alert"""
```

**Test Coverage:** tests/product/ (40 tests)

---

### purchase_page.py

**Purpose:** Checkout and purchase completion

**Key Methods:**
```python
class PurchasePage(BasePage):
    def enter_name(self, name):
        """Enter customer name"""

    def enter_country(self, country):
        """Enter shipping country"""

    def enter_city(self, city):
        """Enter shipping city"""

    def enter_credit_card(self, card_number):
        """Enter credit card number"""

    def enter_month(self, month):
        """Enter expiration month"""

    def enter_year(self, year):
        """Enter expiration year"""

    def click_purchase_button(self):
        """Complete purchase"""

    def get_confirmation_message(self) -> str:
        """Get purchase confirmation"""

    def complete_purchase(self, customer_data: Dict):
        """Complete entire purchase workflow"""
```

**Test Coverage:** tests/purchase/ (55 tests)

## Usage

### Basic Usage

```python
from pages.login_page import LoginPage

def test_login(browser):
    login_page = LoginPage(browser)
    login_page.login("testuser", "password123")
    assert login_page.is_logged_in()
```

### Chaining Page Objects

```python
def test_complete_purchase_flow(browser):
    # Login
    login_page = LoginPage(browser)
    login_page.login("testuser", "password123")

    # Browse catalog
    catalog_page = CatalogPage(browser)
    catalog_page.filter_by_category("Phones")
    catalog_page.select_product("Samsung galaxy s6")

    # Add to cart
    product_page = ProductPage(browser)
    product_page.add_to_cart()

    # Checkout
    cart_page = CartPage(browser)
    cart_page.place_order()

    # Complete purchase
    purchase_page = PurchasePage(browser)
    purchase_page.complete_purchase({
        "name": "John Doe",
        "country": "USA",
        "city": "New York",
        "card": "4111111111111111",
        "month": "12",
        "year": "2025"
    })

    assert "Thank you" in purchase_page.get_confirmation_message()
```

### Using Locators from JSON

```python
from utils.locators_loader import LocatorsLoader

class LoginPage(BasePage):
    def __init__(self, driver):
        super().__init__(driver)
        self.locators = LocatorsLoader().load()["login"]

    def enter_username(self, username):
        locator = self.locators["username_input"]
        self.type_text(locator["by"], locator["value"], username)
```

## Best Practices

### 1. Inherit from BasePage

All page objects should extend BasePage:

```python
from pages.base_page import BasePage

class NewPage(BasePage):
    def __init__(self, driver):
        super().__init__(driver)
```

### 2. Use Descriptive Method Names

Method names should describe user actions:

```python
# Good
def login(self, username, password):
    pass

# Bad
def do_stuff(self, u, p):
    pass
```

### 3. Return Page Objects or Data

Methods should return:
- New page object (for navigation)
- Data (for verification)
- Self (for method chaining)

```python
def click_login_button(self) -> 'HomePage':
    """Click login button, return home page"""
    self.click(By.ID, "login-btn")
    return HomePage(self.driver)

def get_username(self) -> str:
    """Get displayed username"""
    return self.find_element(By.ID, "username").text

def enter_text(self, text) -> 'SearchPage':
    """Enter search text, return self for chaining"""
    self.type_text(By.ID, "search", text)
    return self
```

### 4. Separate Locators

Define locators as class variables or load from JSON:

```python
class LoginPage(BasePage):
    # Class variable locators
    USERNAME_INPUT = (By.ID, "loginusername")
    PASSWORD_INPUT = (By.ID, "loginpassword")
    LOGIN_BUTTON = (By.XPATH, "//button[text()='Log in']")

    def enter_username(self, username):
        self.type_text(*self.USERNAME_INPUT, username)
```

### 5. Handle Waits in Page Objects

Don't make tests wait explicitly:

```python
# Good - Wait in page object
def is_logged_in(self) -> bool:
    try:
        self.find_element(By.ID, "welcome-message", timeout=10)
        return True
    except TimeoutException:
        return False

# Bad - Wait in test
def test_login(browser):
    login_page.login("user", "pass")
    time.sleep(5)  # Don't do this
    assert login_page.is_logged_in()
```

### 6. Keep Tests Clean

Tests should be readable and use page objects only:

```python
# Good
def test_login_success(browser):
    login_page = LoginPage(browser)
    login_page.login("testuser", "password123")
    assert login_page.is_logged_in()

# Bad - Selenium calls in test
def test_login_success(browser):
    browser.find_element(By.ID, "login").click()
    browser.find_element(By.ID, "username").send_keys("testuser")
    # ...
```

## Adding New Page Objects

1. **Create new file** in `pages/`:

```python
# pages/new_page.py

from pages.base_page import BasePage
from selenium.webdriver.common.by import By

class NewPage(BasePage):
    """Page object for New Page"""

    # Locators
    ELEMENT_LOCATOR = (By.ID, "element-id")

    def __init__(self, driver):
        super().__init__(driver)

    def interact_with_element(self):
        """Method description"""
        self.click(*self.ELEMENT_LOCATOR)
```

2. **Add locators** to `config/locators.json`:

```json
{
  "new_page": {
    "element": {
      "by": "id",
      "value": "element-id",
      "description": "Element description"
    }
  }
}
```

3. **Create tests** in `tests/new_page/`:

```python
# tests/new_page/test_new_page.py

from pages.new_page import NewPage

def test_new_page_functionality(browser):
    new_page = NewPage(browser)
    new_page.interact_with_element()
    assert new_page.is_interaction_successful()
```

4. **Document page object** in this README

## Maintenance

### When UI Changes

1. Identify affected page object
2. Update locators in page object or `locators.json`
3. Run tests to verify:
   ```bash
   pytest tests/login/ -v
   ```
4. Update page object methods if needed
5. Re-run full test suite

### Refactoring Page Objects

When page objects become too large:

1. **Extract components**: Create separate classes for reusable components
2. **Create base pages**: Group common functionality in intermediate base classes
3. **Use composition**: Inject components into page objects

Example:

```python
# pages/components/navigation.py
class NavigationComponent(BasePage):
    def navigate_to(self, menu_item):
        pass

# pages/home_page.py
class HomePage(BasePage):
    def __init__(self, driver):
        super().__init__(driver)
        self.navigation = NavigationComponent(driver)
```

## Testing Page Objects

Page objects themselves should have unit/integration tests:

**Location:** `tests/test_base_page.py` (35 tests for BasePage)

**Example:**
```python
def test_base_page_find_element(browser):
    """Test BasePage.find_element method"""
    base_page = BasePage(browser)
    element = base_page.find_element(By.ID, "element-id")
    assert element is not None
```

## Common Issues

### Issue: Element Not Interactable

**Cause:** Element not visible or covered by another element

**Solution:**
```python
def click_element(self):
    """Click with wait for element to be clickable"""
    element = WebDriverWait(self.driver, 10).until(
        EC.element_to_be_clickable((By.ID, "element-id"))
    )
    element.click()
```

### Issue: Stale Element Reference

**Cause:** DOM changed after element was found

**Solution:**
```python
def get_text_with_retry(self):
    """Get text with stale element retry"""
    for attempt in range(3):
        try:
            element = self.find_element(By.ID, "element-id")
            return element.text
        except StaleElementReferenceException:
            if attempt == 2:
                raise
            time.sleep(1)
```

### Issue: Test Flakiness

**Cause:** Insufficient waits or timing issues

**Solution:**
- Use explicit waits in page objects
- Wait for page load before interaction
- Add retry logic for flaky elements

## Performance Considerations

- **Minimize element searches**: Cache frequently used elements
- **Use efficient locators**: ID > CSS > XPath
- **Avoid implicit waits**: Use explicit waits only
- **Lazy loading**: Find elements only when needed

## References

- [Page Object Model Pattern](https://www.selenium.dev/documentation/test_practices/encouraged/page_object_models/)
- [Selenium Python Documentation](https://selenium-python.readthedocs.io/)
- [BasePage Documentation](../documentation/architecture/page-object-model.md)

## Statistics

- **Total Page Objects:** 7 classes
- **Total Lines of Code:** ~111,000 lines
- **Test Coverage:** 270+ tests across all pages
- **BasePage Tests:** 35 dedicated tests

## Support

For page object issues:
- Review this README
- Check BasePage implementation
- Verify locators in browser DevTools
- Consult framework architecture documentation

## License

Internal page objects - follows project license.
