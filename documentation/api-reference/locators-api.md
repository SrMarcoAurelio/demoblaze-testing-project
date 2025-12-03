# Locators API Reference

External locators management system for UI element selectors.

**File:** `utils/locators_loader.py`
**Version:** 1.0
**Author:** Marc Arévalo

## Overview

The Locators Loader system externalizes UI element selectors to JSON configuration, making the framework adaptable to any web application without modifying page object code.

**Benefits:**
- Easy adaptation to new applications (just update JSON)
- Centralized locator management
- No code changes needed when UI selectors change
- Support for multiple environments (dev, staging, prod)

---

## LocatorsLoader Class

### Constructor

```python
def __init__(self, config_path: Optional[str] = None):
```

**Parameters:**
- `config_path` (Optional[str]): Path to locators JSON file. Defaults to `config/locators.json`

**Raises:**
- `FileNotFoundError`: If config file doesn't exist
- `json.JSONDecodeError`: If JSON is invalid

**Example:**
```python
from utils.locators_loader import LocatorsLoader

# Use default config/locators.json
loader = LocatorsLoader()

# Custom path
loader = LocatorsLoader("config/locators_staging.json")
```

---

### get_locator(page, element)

Get a specific locator for a page element.

**Signature:**
```python
def get_locator(self, page: str, element: str) -> Tuple[str, str]:
```

**Parameters:**
- `page` (str): Page name (e.g., "login", "cart", "product")
- `element` (str): Element name (e.g., "login_button_nav", "username_field")

**Returns:**
- `Tuple[str, str]`: Selenium locator tuple (By.TYPE, "value")

**Raises:**
- `KeyError`: If page or element not found in configuration
- `ValueError`: If locator format is invalid or "by" type unknown

**Example:**
```python
loader = LocatorsLoader()

# Get login button locator
LOGIN_BUTTON = loader.get_locator("login", "login_button_nav")
# Returns: (By.ID, "login2")

# Use with driver
driver.find_element(*LOGIN_BUTTON).click()
```

**Location:** locators_loader.py:92-138

---

### get_page_locators(page)

Get all locators for a specific page.

**Signature:**
```python
def get_page_locators(self, page: str) -> Dict[str, Tuple[str, str]]:
```

**Parameters:**
- `page` (str): Page name (e.g., "login", "cart")

**Returns:**
- `Dict[str, Tuple[str, str]]`: Dictionary mapping element names to Selenium locator tuples

**Raises:**
- `KeyError`: If page not found in configuration

**Example:**
```python
loader = LocatorsLoader()

# Load all login page locators
login_locators = loader.get_page_locators("login")

# Access locators
LOGIN_BUTTON = login_locators["login_button_nav"]
USERNAME_FIELD = login_locators["login_username_field"]
PASSWORD_FIELD = login_locators["login_password_field"]

# Use in page object
class LoginPage(BasePage):
    def __init__(self, driver):
        super().__init__(driver)
        locators = get_loader().get_page_locators("login")
        self.username_field = locators["login_username_field"]
        self.password_field = locators["login_password_field"]
```

**Internal Behavior:**
- Skips fields starting with "_" (metadata fields)
- Continues loading other locators if one fails (logs warning)

**Location:** locators_loader.py:139-177

---

### get_all_pages()

Get list of all available pages.

**Signature:**
```python
def get_all_pages(self) -> list:
```

**Returns:**
- `list`: List of page names

**Example:**
```python
loader = LocatorsLoader()
pages = loader.get_all_pages()
print(pages)
# Output: ['login', 'signup', 'cart', 'catalog', 'product', 'purchase']
```

**Location:** locators_loader.py:178-192

---

### reload()

Reload locators from JSON file.

**Signature:**
```python
def reload(self) -> None:
```

**Returns:**
- None

**When to Use:**
- During development when config changes
- Switching between environments at runtime
- Hot-reloading configurations

**Example:**
```python
loader = LocatorsLoader()

# ... modify config/locators.json ...

loader.reload()  # Load updated configuration
```

**Location:** locators_loader.py:193-200

---

## Helper Functions

### get_loader()

Get singleton instance of LocatorsLoader.

**Signature:**
```python
def get_loader() -> LocatorsLoader:
```

**Returns:**
- `LocatorsLoader`: Singleton instance

**Example:**
```python
from utils.locators_loader import get_loader

loader = get_loader()
LOGIN_BUTTON = loader.get_locator("login", "login_button_nav")
```

**Location:** locators_loader.py:206-222

---

### load_locator(page, element)

Quick access function to load a single locator.

**Signature:**
```python
def load_locator(page: str, element: str) -> Tuple[str, str]:
```

**Parameters:**
- `page` (str): Page name
- `element` (str): Element name

**Returns:**
- `Tuple[str, str]`: Selenium locator tuple

**Example:**
```python
from utils.locators_loader import load_locator

# Quick one-liner
LOGIN_BUTTON = load_locator("login", "login_button_nav")

# Use in page object
class LoginPage(BasePage):
    username_field = load_locator("login", "login_username_field")
    password_field = load_locator("login", "login_password_field")
    login_button = load_locator("login", "login_button_modal")
```

**Location:** locators_loader.py:225-242

---

## JSON Configuration Format

### File Structure

**Location:** `config/locators.json`

```json
{
  "page_name": {
    "element_name": {
      "by": "id|xpath|css|name|class|tag|link_text|partial_link_text",
      "value": "selector_value"
    }
  }
}
```

### Example Configuration

```json
{
  "login": {
    "login_button_nav": {
      "by": "id",
      "value": "login2"
    },
    "login_username_field": {
      "by": "id",
      "value": "loginusername"
    },
    "login_password_field": {
      "by": "id",
      "value": "loginpassword"
    },
    "login_button_modal": {
      "by": "xpath",
      "value": "//button[contains(text(),'Log in')]"
    },
    "close_button": {
      "by": "css",
      "value": ".close"
    }
  },
  "cart": {
    "place_order_button": {
      "by": "xpath",
      "value": "//button[contains(text(),'Place Order')]"
    },
    "cart_items": {
      "by": "css",
      "value": ".success"
    }
  }
}
```

### Supported Locator Types

Mapping of JSON "by" values to Selenium By constants:

| JSON Value | Selenium By | Example |
|------------|-------------|---------|
| `"id"` | `By.ID` | `"loginBtn"` |
| `"name"` | `By.NAME` | `"username"` |
| `"xpath"` | `By.XPATH` | `"//button[@id='submit']"` |
| `"css"` | `By.CSS_SELECTOR` | `".btn-primary"` |
| `"class"` | `By.CLASS_NAME` | `"error-message"` |
| `"tag"` | `By.TAG_NAME` | `"button"` |
| `"link_text"` | `By.LINK_TEXT` | `"Sign Up"` |
| `"partial_link_text"` | `By.PARTIAL_LINK_TEXT` | `"Sign"` |

---

## Usage Patterns

### Pattern 1: Load Locators in Page Object Constructor

```python
from pages.base_page import BasePage
from utils.locators_loader import load_locator

class LoginPage(BasePage):
    # Load locators as class variables
    username_field = load_locator("login", "login_username_field")
    password_field = load_locator("login", "login_password_field")
    login_button = load_locator("login", "login_button_modal")

    def login(self, username: str, password: str) -> None:
        self.type(self.username_field, username)
        self.type(self.password_field, password)
        self.click(self.login_button)
```

### Pattern 2: Load All Page Locators

```python
from pages.base_page import BasePage
from utils.locators_loader import get_loader

class CatalogPage(BasePage):
    def __init__(self, driver):
        super().__init__(driver)
        # Load all locators for this page
        self.locators = get_loader().get_page_locators("catalog")

    def select_category(self, category: str) -> None:
        # Use locators from dictionary
        self.click(self.locators[f"{category.lower()}_category"])
```

### Pattern 3: Direct Usage in Tests

```python
from utils.locators_loader import load_locator

def test_login(browser, base_url):
    browser.get(base_url)

    username_loc = load_locator("login", "login_username_field")
    password_loc = load_locator("login", "login_password_field")
    button_loc = load_locator("login", "login_button_modal")

    browser.find_element(*username_loc).send_keys("user")
    browser.find_element(*password_loc).send_keys("pass")
    browser.find_element(*button_loc).click()
```

---

## Adapting to New Applications

To adapt framework to a new application:

1. **Identify all pages and elements**
2. **Find selectors** using browser DevTools
3. **Update config/locators.json** with new selectors
4. **No code changes needed** in page objects

### Example: Adapting Login Page

**Old Application (DemoBlaze):**
```json
{
  "login": {
    "login_button_nav": {"by": "id", "value": "login2"},
    "username_field": {"by": "id", "value": "loginusername"}
  }
}
```

**New Application (Your App):**
```json
{
  "login": {
    "login_button_nav": {"by": "id", "value": "nav-login"},
    "username_field": {"by": "name", "value": "email"}
  }
}
```

**Page object code remains unchanged:**
```python
class LoginPage(BasePage):
    # These still work - just point to different selectors
    login_button = load_locator("login", "login_button_nav")
    username_field = load_locator("login", "username_field")
```

---

## Error Handling

### Locator Not Found

```python
try:
    locator = loader.get_locator("login", "nonexistent")
except KeyError as e:
    print(f"Error: {e}")
    # Output: Locator not found: page='login', element='nonexistent'
    #         Check config/locators.json
```

### Invalid Locator Format

```json
{
  "login": {
    "bad_locator": {
      "by": "id"
      // Missing "value" field
    }
  }
}
```

```python
try:
    locator = loader.get_locator("login", "bad_locator")
except ValueError as e:
    print(f"Error: {e}")
    # Output: Invalid locator format for login.bad_locator: {'by': 'id'}
    #         Expected: {'by': 'type', 'value': 'locator_value'}
```

### Unknown Locator Type

```json
{
  "login": {
    "bad_type": {
      "by": "selector",  // Invalid type
      "value": "something"
    }
  }
}
```

```python
try:
    locator = loader.get_locator("login", "bad_type")
except ValueError as e:
    print(f"Error: {e}")
    # Output: Unknown locator type 'selector' for login.bad_type
    #         Valid types: ['id', 'name', 'xpath', 'css', 'class', 'tag', 'link_text', 'partial_link_text']
```

---

## Best Practices

1. **Use descriptive element names:**
```json
// Good
"login_username_field": {"by": "id", "value": "username"}

// Avoid
"field1": {"by": "id", "value": "username"}
```

2. **Prefer stable selectors (ID > CSS > XPath):**
```json
// Best - ID rarely changes
"submit_button": {"by": "id", "value": "submitBtn"}

// Good - CSS is stable
"submit_button": {"by": "css", "value": ".btn-submit"}

// Last resort - XPath can break easily
"submit_button": {"by": "xpath", "value": "//div[3]/button[2]"}
```

3. **Use consistent naming convention:**
```json
{
  "login": {
    "login_username_field": {...},
    "login_password_field": {...},
    "login_button_modal": {...},
    "login_button_nav": {...}
  }
}
```

4. **Add metadata fields (optional):**
```json
{
  "_metadata": {
    "page": "login",
    "last_updated": "2025-12-03",
    "owner": "QA Team"
  },
  "login_button_nav": {...}
}
```

---

## Related Documentation

- [BasePage API](base-page-api.md) - Using locators in page objects
- [Implementation Guide](../guides/implementation-guide.md) - Adapting to new applications
- [Extending Framework](../guides/extending-framework.md) - Custom locator management
