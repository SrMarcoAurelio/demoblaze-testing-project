# BasePage API Reference

Complete API reference for the BasePage class - the foundation of all page objects.

**File:** `pages/base_page.py`
**Version:** 2.0
**Author:** Marc Arévalo

## Overview

BasePage provides universal methods for interacting with web elements. All page objects inherit from this class.

**Key Features:**
- Automatic explicit waits for all element interactions
- Comprehensive error handling with logging
- Type hints for IDE support
- Universal and reusable across any web application

## Class Definition

```python
class BasePage:
    """
    Base class for all Page Objects.

    Provides common methods for interacting with web elements:
    - Finding elements with waits
    - Clicking elements
    - Typing text
    - Handling alerts
    - Taking screenshots
    """
```

## Constructor

### `__init__(driver, base_url=None, timeout=10)`

Initialize the BasePage instance.

**Signature:**
```python
def __init__(
    self,
    driver: WebDriver,
    base_url: Optional[str] = None,
    timeout: int = 10,
) -> None:
```

**Parameters:**
- `driver` (WebDriver): Selenium WebDriver instance
- `base_url` (Optional[str]): Base URL of the application. Defaults to `config.BASE_URL`
- `timeout` (int): Default timeout for waits in seconds. Default: 10

**Internal Behavior:**
- Stores driver reference
- Initializes base_url from parameter or config
- Sets default timeout
- Creates logger instance using class name

**Example:**
```python
from pages.login_page import LoginPage

# Using default config
login_page = LoginPage(driver)

# Custom base_url and timeout
login_page = LoginPage(driver, base_url="https://custom.url", timeout=15)
```

---

## Element Finding Methods

### `find_element(locator, timeout=None)`

Find a single element with explicit wait.

**Signature:**
```python
def find_element(
    self, locator: Tuple[str, str], timeout: Optional[int] = None
) -> WebElement:
```

**Parameters:**
- `locator` (Tuple[str, str]): Tuple of (By.TYPE, "value")
- `timeout` (Optional[int]): Custom timeout. Uses instance timeout if None

**Returns:**
- `WebElement`: Found element

**Raises:**
- `TimeoutException`: If element not found within timeout

**Internal Behavior:**
1. Uses `WebDriverWait` with `EC.presence_of_element_located`
2. Logs debug message on success
3. Logs error message on timeout

**Example:**
```python
from selenium.webdriver.common.by import By

locator = (By.ID, "username")
element = page.find_element(locator)

# With custom timeout
element = page.find_element(locator, timeout=20)
```

**Location:** pages/base_page.py:66-92

---

### `find_elements(locator, timeout=None)`

Find multiple elements with explicit wait.

**Signature:**
```python
def find_elements(
    self, locator: Tuple[str, str], timeout: Optional[int] = None
) -> List[WebElement]:
```

**Parameters:**
- `locator` (Tuple[str, str]): Tuple of (By.TYPE, "value")
- `timeout` (Optional[int]): Custom timeout. Uses instance timeout if None

**Returns:**
- `List[WebElement]`: List of found elements (empty list if none found)

**Raises:**
- Does NOT raise exception - returns empty list if no elements found

**Internal Behavior:**
1. Uses `WebDriverWait` with `EC.presence_of_all_elements_located`
2. Returns empty list on timeout instead of raising exception
3. Logs count of elements found

**Example:**
```python
# Find all product items
products = page.find_elements((By.CLASS_NAME, "product-item"))

if products:
    print(f"Found {len(products)} products")
    for product in products:
        print(product.text)
```

**Location:** pages/base_page.py:93-116

---

## Wait Methods

### `wait_for_element_visible(locator, timeout=None)`

Wait for element to be visible (displayed and has height/width > 0).

**Signature:**
```python
def wait_for_element_visible(
    self, locator: Tuple[str, str], timeout: Optional[int] = None
) -> WebElement:
```

**Parameters:**
- `locator` (Tuple[str, str]): Tuple of (By.TYPE, "value")
- `timeout` (Optional[int]): Custom timeout

**Returns:**
- `WebElement`: Visible element

**Raises:**
- `TimeoutException`: If element not visible within timeout

**When to Use:**
- Element exists in DOM but may not be visible yet (e.g., modals, dropdowns)
- Need to verify element is actually displayed to user

**Example:**
```python
# Wait for modal to appear
modal = page.wait_for_element_visible((By.ID, "loginModal"), timeout=5)

# Element exists in DOM but hidden - will timeout
hidden_elem = page.wait_for_element_visible((By.ID, "hiddenDiv"))  # Raises TimeoutException
```

**Location:** pages/base_page.py:117-140

---

### `wait_for_element_clickable(locator, timeout=None)`

Wait for element to be clickable (visible and enabled).

**Signature:**
```python
def wait_for_element_clickable(
    self, locator: Tuple[str, str], timeout: Optional[int] = None
) -> WebElement:
```

**Parameters:**
- `locator` (Tuple[str, str]): Tuple of (By.TYPE, "value")
- `timeout` (Optional[int]): Custom timeout

**Returns:**
- `WebElement`: Clickable element

**Raises:**
- `TimeoutException`: If element not clickable within timeout

**When to Use:**
- Before clicking buttons/links
- Element may be visible but disabled
- Prevents "element not interactable" errors

**Example:**
```python
# Wait for button to be enabled
submit_btn = page.wait_for_element_clickable((By.ID, "submit"))
submit_btn.click()

# Button is visible but disabled - will timeout
disabled_btn = page.wait_for_element_clickable((By.ID, "disabledBtn"))  # Raises TimeoutException
```

**Location:** pages/base_page.py:141-164

---

### `wait_for_element_invisible(locator, timeout=None)`

Wait for element to become invisible or removed from DOM.

**Signature:**
```python
def wait_for_element_invisible(
    self, locator: Tuple[str, str], timeout: Optional[int] = None
) -> bool:
```

**Parameters:**
- `locator` (Tuple[str, str]): Tuple of (By.TYPE, "value")
- `timeout` (Optional[int]): Custom timeout

**Returns:**
- `bool`: True if element becomes invisible

**Raises:**
- `TimeoutException`: If element still visible after timeout

**When to Use:**
- Wait for loading spinners to disappear
- Verify modals close
- Ensure elements are removed after operations

**Example:**
```python
# Click close button and wait for modal to disappear
page.click((By.ID, "closeModal"))
page.wait_for_element_invisible((By.ID, "loginModal"), timeout=3)

# Wait for loading spinner
page.wait_for_element_invisible((By.CLASS_NAME, "spinner"))
```

**Location:** pages/base_page.py:165-188

---

## Interaction Methods

### `click(locator, timeout=None)`

Click an element with automatic wait for clickability.

**Signature:**
```python
def click(
    self, locator: Tuple[str, str], timeout: Optional[int] = None
) -> None:
```

**Parameters:**
- `locator` (Tuple[str, str]): Tuple of (By.TYPE, "value")
- `timeout` (Optional[int]): Custom timeout

**Returns:**
- None

**Raises:**
- `TimeoutException`: If element not clickable within timeout

**Internal Behavior:**
1. Waits for element to be clickable
2. Performs click action
3. Logs info message

**Example:**
```python
# Click button
page.click((By.ID, "loginBtn"))

# Click with custom timeout
page.click((By.LINK_TEXT, "Sign Up"), timeout=15)
```

**Location:** pages/base_page.py:189-202

---

### `type(locator, text, clear_first=True, timeout=None)`

Type text into an input field.

**Signature:**
```python
def type(
    self,
    locator: Tuple[str, str],
    text: str,
    clear_first: bool = True,
    timeout: Optional[int] = None,
) -> None:
```

**Parameters:**
- `locator` (Tuple[str, str]): Tuple of (By.TYPE, "value")
- `text` (str): Text to type
- `clear_first` (bool): Clear field before typing. Default: True
- `timeout` (Optional[int]): Custom timeout

**Returns:**
- None

**Raises:**
- `TimeoutException`: If element not visible within timeout

**Internal Behavior:**
1. Waits for element to be visible
2. Clears field if `clear_first=True`
3. Sends keys to element
4. Logs info message

**Example:**
```python
# Type username (clears first)
page.type((By.ID, "username"), "testuser")

# Append text without clearing
page.type((By.ID, "message"), " - appended text", clear_first=False)
```

**Location:** pages/base_page.py:203-224

---

### `get_text(locator, timeout=None)`

Get text content from an element.

**Signature:**
```python
def get_text(
    self, locator: Tuple[str, str], timeout: Optional[int] = None
) -> str:
```

**Parameters:**
- `locator` (Tuple[str, str]): Tuple of (By.TYPE, "value")
- `timeout` (Optional[int]): Custom timeout

**Returns:**
- `str`: Text content of element

**Raises:**
- `TimeoutException`: If element not visible within timeout

**Internal Behavior:**
1. Waits for element to be visible
2. Retrieves `element.text`
3. Logs debug message with retrieved text

**Example:**
```python
# Get welcome message
message = page.get_text((By.ID, "welcomeMsg"))
assert "Welcome" in message

# Get error message
error = page.get_text((By.CLASS_NAME, "error-message"))
```

**Location:** pages/base_page.py:225-242

---

### `get_attribute(locator, attribute, timeout=None)`

Get attribute value from an element.

**Signature:**
```python
def get_attribute(
    self,
    locator: Tuple[str, str],
    attribute: str,
    timeout: Optional[int] = None,
) -> Optional[str]:
```

**Parameters:**
- `locator` (Tuple[str, str]): Tuple of (By.TYPE, "value")
- `attribute` (str): Attribute name (e.g., "href", "class", "value")
- `timeout` (Optional[int]): Custom timeout

**Returns:**
- `Optional[str]`: Attribute value or None if attribute doesn't exist

**Raises:**
- `TimeoutException`: If element not found within timeout

**Internal Behavior:**
1. Finds element
2. Calls `element.get_attribute(attribute)`
3. Logs debug message with attribute and value

**Example:**
```python
# Get link URL
url = page.get_attribute((By.ID, "homeLink"), "href")

# Get input value
value = page.get_attribute((By.ID, "username"), "value")

# Check if element has class
classes = page.get_attribute((By.ID, "alert"), "class")
assert "danger" in classes
```

**Location:** pages/base_page.py:243-266

---

## Element State Checking

### `is_element_present(locator, timeout=2)`

Check if element is present in DOM (uses short timeout).

**Signature:**
```python
def is_element_present(
    self, locator: Tuple[str, str], timeout: int = 2
) -> bool:
```

**Parameters:**
- `locator` (Tuple[str, str]): Tuple of (By.TYPE, "value")
- `timeout` (int): Timeout in seconds. Default: 2

**Returns:**
- `bool`: True if element present, False otherwise

**Raises:**
- Does NOT raise exception

**When to Use:**
- Check optional elements
- Conditional test logic
- Verify element removal

**Example:**
```python
# Check if error message appears
if page.is_element_present((By.CLASS_NAME, "error")):
    error_msg = page.get_text((By.CLASS_NAME, "error"))
    print(f"Error: {error_msg}")

# Verify element removed
assert not page.is_element_present((By.ID, "deletedItem"))
```

**Location:** pages/base_page.py:267-285

---

### `is_element_visible(locator, timeout=2)`

Check if element is visible (uses short timeout).

**Signature:**
```python
def is_element_visible(
    self, locator: Tuple[str, str], timeout: int = 2
) -> bool:
```

**Parameters:**
- `locator` (Tuple[str, str]): Tuple of (By.TYPE, "value")
- `timeout` (int): Timeout in seconds. Default: 2

**Returns:**
- `bool`: True if element visible, False otherwise

**Raises:**
- Does NOT raise exception

**When to Use:**
- Conditional visibility checks
- Verify element shown/hidden
- Test validation messages

**Example:**
```python
# Check if success message is visible
if page.is_element_visible((By.CLASS_NAME, "success")):
    print("Operation successful!")

# Verify modal not visible
assert not page.is_element_visible((By.ID, "modal"))
```

**Location:** pages/base_page.py:286-304

---

## Alert Handling

### `wait_for_alert(timeout=5)`

Wait for JavaScript alert to be present.

**Signature:**
```python
def wait_for_alert(self, timeout: int = 5) -> Optional[Alert]:
```

**Parameters:**
- `timeout` (int): Timeout in seconds. Default: 5

**Returns:**
- `Optional[Alert]`: Alert object if present, None if no alert appears

**Raises:**
- Does NOT raise exception

**Internal Behavior:**
1. Uses `WebDriverWait` with `EC.alert_is_present()`
2. Switches to alert
3. Logs alert text
4. Returns None on timeout instead of raising exception

**Example:**
```python
# Wait for alert
alert = page.wait_for_alert()
if alert:
    print(f"Alert text: {alert.text}")
    alert.accept()
```

**Location:** pages/base_page.py:305-323

---

### `get_alert_text(timeout=5)`

Get alert text and accept the alert.

**Signature:**
```python
def get_alert_text(self, timeout: int = 5) -> Optional[str]:
```

**Parameters:**
- `timeout` (int): Timeout in seconds. Default: 5

**Returns:**
- `Optional[str]`: Alert text if alert present, None otherwise

**Raises:**
- Does NOT raise exception

**Internal Behavior:**
1. Waits for alert
2. Retrieves alert text
3. **Automatically accepts the alert**
4. Logs alert text
5. Returns None if no alert

**Example:**
```python
# Get alert text (alert is accepted automatically)
text = page.get_alert_text()
if text:
    assert "Success" in text
```

**Location:** pages/base_page.py:324-341

---

### `accept_alert(timeout=5)`

Accept alert if present.

**Signature:**
```python
def accept_alert(self, timeout: int = 5) -> None:
```

**Parameters:**
- `timeout` (int): Timeout in seconds. Default: 5

**Returns:**
- None

**Raises:**
- Does NOT raise exception if no alert

**Example:**
```python
# Click delete and accept confirmation
page.click((By.ID, "deleteBtn"))
page.accept_alert()
```

**Location:** pages/base_page.py:342-353

---

### `dismiss_alert(timeout=5)`

Dismiss (cancel) alert if present.

**Signature:**
```python
def dismiss_alert(self, timeout: int = 5) -> None:
```

**Parameters:**
- `timeout` (int): Timeout in seconds. Default: 5

**Returns:**
- None

**Raises:**
- Does NOT raise exception if no alert

**Example:**
```python
# Click delete but cancel
page.click((By.ID, "deleteBtn"))
page.dismiss_alert()
```

**Location:** pages/base_page.py:354-365

---

## Navigation Methods

### `navigate_to(url)`

Navigate to a URL.

**Signature:**
```python
def navigate_to(self, url: str) -> None:
```

**Parameters:**
- `url` (str): Full URL to navigate to

**Returns:**
- None

**Internal Behavior:**
- Calls `driver.get(url)`
- Logs navigation

**Example:**
```python
page.navigate_to("https://www.example.com/login")
page.navigate_to(page.base_url + "/products")
```

**Location:** pages/base_page.py:366-375

---

### `refresh_page()`

Refresh the current page.

**Signature:**
```python
def refresh_page(self) -> None:
```

**Returns:**
- None

**Example:**
```python
# Refresh to see updated data
page.refresh_page()
```

**Location:** pages/base_page.py:376-380

---

### `go_back()`

Navigate back in browser history.

**Signature:**
```python
def go_back(self) -> None:
```

**Returns:**
- None

**Example:**
```python
page.go_back()
```

**Location:** pages/base_page.py:381-385

---

### `get_current_url()`

Get current page URL.

**Signature:**
```python
def get_current_url(self) -> str:
```

**Returns:**
- `str`: Current URL

**Example:**
```python
url = page.get_current_url()
assert "/login" in url
```

**Location:** pages/base_page.py:386-396

---

### `get_page_title()`

Get current page title.

**Signature:**
```python
def get_page_title(self) -> str:
```

**Returns:**
- `str`: Page title

**Example:**
```python
title = page.get_page_title()
assert "Login" in title
```

**Location:** pages/base_page.py:397-407

---

## JavaScript Execution

### `execute_script(script, *args)`

Execute JavaScript code.

**Signature:**
```python
def execute_script(self, script: str, *args: Any) -> Any:
```

**Parameters:**
- `script` (str): JavaScript code to execute
- `*args` (Any): Arguments to pass to script

**Returns:**
- `Any`: Script return value

**Example:**
```python
# Get element text via JS
text = page.execute_script("return document.getElementById('username').value")

# Scroll to position
page.execute_script("window.scrollTo(0, 500)")

# Pass element as argument
element = page.find_element((By.ID, "myDiv"))
page.execute_script("arguments[0].style.border='2px solid red'", element)
```

**Location:** pages/base_page.py:408-422

---

### `scroll_to_element(locator)`

Scroll to make element visible.

**Signature:**
```python
def scroll_to_element(self, locator: Tuple[str, str]) -> None:
```

**Parameters:**
- `locator` (Tuple[str, str]): Tuple of (By.TYPE, "value")

**Returns:**
- None

**Internal Behavior:**
1. Finds element
2. Executes `scrollIntoView(true)` JavaScript
3. Logs scroll action

**Example:**
```python
# Scroll to footer
page.scroll_to_element((By.ID, "footer"))

# Scroll to element before interacting
page.scroll_to_element((By.ID, "submitBtn"))
page.click((By.ID, "submitBtn"))
```

**Location:** pages/base_page.py:423-435

---

### `scroll_to_bottom()`

Scroll to bottom of page.

**Signature:**
```python
def scroll_to_bottom(self) -> None:
```

**Returns:**
- None

**Example:**
```python
# Scroll to load more content
page.scroll_to_bottom()
time.sleep(2)  # Wait for content to load
```

**Location:** pages/base_page.py:436-442

---

## Advanced Interaction

### `send_keys(locator, keys, timeout=None)`

Send keyboard keys to element (for special keys like ENTER, TAB).

**Signature:**
```python
def send_keys(
    self,
    locator: Tuple[str, str],
    keys: str,
    timeout: Optional[int] = None,
) -> None:
```

**Parameters:**
- `locator` (Tuple[str, str]): Tuple of (By.TYPE, "value")
- `keys` (str): Keys to send (e.g., Keys.ENTER, Keys.TAB)
- `timeout` (Optional[int]): Custom timeout

**Returns:**
- None

**Example:**
```python
from selenium.webdriver.common.keys import Keys

# Type and press Enter
page.type((By.ID, "search"), "laptop")
page.send_keys((By.ID, "search"), Keys.ENTER)

# Press Tab to move focus
page.send_keys((By.ID, "username"), Keys.TAB)
```

**Location:** pages/base_page.py:443-460

---

### `press_key(key)`

Press a keyboard key globally (not targeting specific element).

**Signature:**
```python
def press_key(self, key: str) -> None:
```

**Parameters:**
- `key` (str): Key to press (e.g., Keys.ESCAPE)

**Returns:**
- None

**Example:**
```python
from selenium.webdriver.common.keys import Keys

# Close modal with Escape
page.press_key(Keys.ESCAPE)

# Press Ctrl+A
page.press_key(Keys.CONTROL + 'a')
```

**Location:** pages/base_page.py:461-470

---

### `hover(locator, timeout=None)`

Hover mouse over element.

**Signature:**
```python
def hover(
    self, locator: Tuple[str, str], timeout: Optional[int] = None
) -> None:
```

**Parameters:**
- `locator` (Tuple[str, str]): Tuple of (By.TYPE, "value")
- `timeout` (Optional[int]): Custom timeout

**Returns:**
- None

**Internal Behavior:**
1. Finds element
2. Uses ActionChains to move to element
3. Logs hover action

**Example:**
```python
# Hover to show dropdown menu
page.hover((By.ID, "userMenu"))
page.click((By.LINK_TEXT, "Logout"))
```

**Location:** pages/base_page.py:471-484

---

## Utility Methods

### `wait(seconds)`

Explicit hard wait (use sparingly, prefer explicit waits).

**Signature:**
```python
def wait(self, seconds: Union[int, float]) -> None:
```

**Parameters:**
- `seconds` (Union[int, float]): Seconds to wait

**Returns:**
- None

**When to Use:**
- Testing timing-dependent features
- Debugging
- Waiting for animations (prefer explicit waits when possible)

**Example:**
```python
# Wait for animation (prefer explicit waits)
page.click((By.ID, "animate"))
page.wait(2)

# Use predefined constants
page.wait(page.SLEEP_SHORT)  # 0.5s
page.wait(page.SLEEP_MEDIUM)  # 1.0s
page.wait(page.SLEEP_LONG)  # 2.0s
page.wait(page.SLEEP_MODAL)  # 1.5s
```

**Location:** pages/base_page.py:485-494

---

### `wait_for_page_load(timeout=30)`

Wait for page to finish loading (document.readyState == "complete").

**Signature:**
```python
def wait_for_page_load(self, timeout: int = 30) -> bool:
```

**Parameters:**
- `timeout` (int): Maximum wait time in seconds. Default: 30

**Returns:**
- `bool`: True if page loaded successfully

**Raises:**
- `TimeoutException`: If page doesn't load within timeout

**Internal Behavior:**
1. Uses JavaScript to check `document.readyState`
2. Waits until state is "complete"
3. Logs success or timeout

**Example:**
```python
page.navigate_to("https://example.com")
page.wait_for_page_load()

# With custom timeout
page.refresh_page()
page.wait_for_page_load(timeout=60)
```

**Location:** pages/base_page.py:495-520

---

### `take_screenshot(filename)`

Take screenshot and save to file.

**Signature:**
```python
def take_screenshot(self, filename: str) -> None:
```

**Parameters:**
- `filename` (str): Path to save screenshot (including extension)

**Returns:**
- None

**Example:**
```python
# Take screenshot on error
try:
    page.click((By.ID, "submitBtn"))
except TimeoutException:
    page.take_screenshot("screenshots/error.png")
    raise
```

**Note:** Automatic screenshots on test failure are handled by conftest.py

**Location:** pages/base_page.py:521-530

---

### `get_page_source()`

Get full HTML source of current page.

**Signature:**
```python
def get_page_source(self) -> str:
```

**Returns:**
- `str`: Complete page HTML source

**Example:**
```python
# Verify element in page source
source = page.get_page_source()
assert "Welcome" in source

# Debug - save page source
with open("debug.html", "w") as f:
    f.write(page.get_page_source())
```

**Location:** pages/base_page.py:531-539

---

## Class Constants

### Sleep Duration Constants

Predefined sleep durations for consistent timing:

```python
SLEEP_SHORT = 0.5    # 500ms - Quick waits
SLEEP_MEDIUM = 1.0   # 1 second - Standard wait
SLEEP_LONG = 2.0     # 2 seconds - Extended wait
SLEEP_MODAL = 1.5    # 1.5 seconds - Modal animations
```

**Example:**
```python
page.wait(page.SLEEP_MODAL)  # Wait for modal animation
```

---

## Complete Example

```python
from pages.base_page import BasePage
from selenium.webdriver.common.by import By

class LoginPage(BasePage):
    # Define locators
    USERNAME_FIELD = (By.ID, "username")
    PASSWORD_FIELD = (By.ID, "password")
    LOGIN_BUTTON = (By.ID, "loginBtn")
    ERROR_MESSAGE = (By.CLASS_NAME, "error")

    def login(self, username: str, password: str) -> None:
        """Perform login."""
        self.type(self.USERNAME_FIELD, username)
        self.type(self.PASSWORD_FIELD, password)
        self.click(self.LOGIN_BUTTON)

    def is_login_successful(self) -> bool:
        """Check if login succeeded."""
        return not self.is_element_visible(self.ERROR_MESSAGE, timeout=2)

    def get_error_message(self) -> str:
        """Get error message if present."""
        if self.is_element_visible(self.ERROR_MESSAGE):
            return self.get_text(self.ERROR_MESSAGE)
        return ""

# Usage in test
def test_login(browser, base_url):
    login_page = LoginPage(browser, base_url)
    login_page.navigate_to(base_url + "/login")
    login_page.login("testuser", "password123")

    assert login_page.is_login_successful()
```

---

## Best Practices

1. **Always use waits** - Never use hard waits except for debugging
2. **Use appropriate wait methods** - `wait_for_element_clickable` before clicking
3. **Handle alerts safely** - Use `wait_for_alert` with timeout
4. **Check element state** - Use `is_element_visible` for conditional logic
5. **Log actions** - BasePage automatically logs all actions
6. **Type hints** - All methods have complete type hints

## Related Documentation

- [Fixtures API](fixtures-api.md) - Page object fixtures
- [Locators API](locators-api.md) - Managing element locators
- [Code Walkthrough](../guides/code-walkthrough.md) - Understanding execution flow
