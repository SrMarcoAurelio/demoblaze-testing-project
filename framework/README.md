# Universal Test Automation Framework

**Version:** 1.0
**Author:** Marc Arévalo
**Philosophy:** DISCOVER, not ASSUME

## Overview

This is a **truly universal** test automation framework that can be adapted to **any web application** with minimal effort.

The framework separates universal testing logic from application-specific details through the **Adapter Pattern**, enabling:

- ✅ **True Universality** - Core framework works with ANY web application
- ✅ **Discovery-Based Testing** - Tests discover functionality instead of assuming it
- ✅ **Clean Architecture** - Separation of concerns, no God Classes
- ✅ **Easy Adaptation** - Add new applications via adapters
- ✅ **No Hardcoded Values** - All configuration via adapters and environment variables
- ✅ **Professional Quality** - Follows industry best practices

## Architecture

```
framework/
├── core/                     # Universal framework core (no app-specific code)
│   ├── element_finder.py     # Element discovery strategies
│   ├── element_interactor.py # Element interactions (click, type, etc.)
│   ├── wait_handler.py       # Wait strategies (NO sleep calls!)
│   └── discovery_engine.py   # Automatic page structure discovery
│
├── adapters/                 # Application-specific adapters
│   ├── base_adapter.py       # Abstract adapter interface
│   ├── demoblaze_adapter.py  # Demoblaze application adapter
│   └── your_app_adapter.py   # Your application adapter
│
├── generators/               # Code generators
│   ├── page_generator.py     # Generate page objects
│   ├── test_generator.py     # Generate test skeletons
│   └── locator_generator.py  # Generate locator files
│
└── cli/                      # Command-line tools
    └── setup_wizard.py       # Interactive setup for new applications
```

## Key Concepts

### 1. Adapter Pattern

**ALL application-specific details are isolated in adapters.**

```python
# framework/adapters/your_app_adapter.py
from framework.adapters.base_adapter import ApplicationAdapter, AuthenticationMethod

class YourAppAdapter(ApplicationAdapter):
    def get_base_url(self) -> str:
        return "https://your-app.com"

    def get_authentication_method(self) -> AuthenticationMethod:
        return AuthenticationMethod.PAGE  # or MODAL, OAUTH, etc.

    def get_url_patterns(self) -> Dict[str, str]:
        return {
            "product": "/products/{id}",
            "user": "/users/{username}",
            "search": "/search?q={query}"
        }

    # ... implement other methods
```

### 2. Discovery Engine

**Tests DISCOVER page structure instead of ASSUMING it.**

```python
from framework.core.discovery_engine import DiscoveryEngine

# Discover all forms on the page
discovery = DiscoveryEngine(driver)
forms = discovery.discover_forms()

for form in forms:
    print(f"Found form with {len(form['inputs'])} inputs")
    for input_field in form['inputs']:
        print(f"  - {input_field['name']}: {input_field['type']}")
```

### 3. Separation of Concerns

**No more God Classes! Each component has a single responsibility.**

```python
from framework.core.element_finder import ElementFinder
from framework.core.element_interactor import ElementInteractor
from framework.core.wait_handler import WaitHandler

# Each component does ONE thing well
finder = ElementFinder(driver)
interactor = ElementInteractor(driver)
waiter = WaitHandler(driver)

# Find element
element = finder.find_element(By.ID, "username")

# Wait for it to be clickable
waiter.wait_for_element_clickable(By.ID, "username")

# Interact with it
interactor.type(element, "testuser")
```

## Getting Started

### 1. For Existing Applications (Demoblaze Example)

```python
# Use the Demoblaze adapter
from framework.adapters.demoblaze_adapter import DemoblazeAdapter

adapter = DemoblazeAdapter()
print(adapter.get_base_url())  # https://www.demoblaze.com
print(adapter.get_authentication_method())  # MODAL
```

### 2. For New Applications

#### Option A: Use the Setup Wizard (Recommended)

```bash
python -m framework.cli.setup_wizard
```

The wizard will:
1. Ask about your application
2. Discover page structure automatically
3. Generate adapter code
4. Create page object templates
5. Generate test skeletons

#### Option B: Create Adapter Manually

```python
# framework/adapters/myapp_adapter.py
from framework.adapters.base_adapter import ApplicationAdapter, AuthenticationMethod
import os

class MyAppAdapter(ApplicationAdapter):
    def get_base_url(self) -> str:
        return os.getenv("BASE_URL", "https://myapp.com")

    def get_authentication_method(self) -> AuthenticationMethod:
        return AuthenticationMethod.PAGE

    def get_url_patterns(self) -> Dict[str, str]:
        return {
            "home": "/",
            "login": "/login",
            "dashboard": "/dashboard"
        }

    def discover_page_structure(self, page_type: str) -> Dict[str, Any]:
        # Use DiscoveryEngine to automatically discover structure
        from framework.core.discovery_engine import DiscoveryEngine
        # ... implement discovery logic

    def get_test_users(self) -> Dict[str, Dict[str, str]]:
        return {
            "valid": {
                "username": os.getenv("TEST_USERNAME", ""),
                "password": os.getenv("TEST_PASSWORD", "")
            }
        }
```

### 3. Configure Environment Variables

```bash
# Copy example file
cp .env.example .env

# Edit .env with your values
nano .env
```

Required variables:
```bash
TEST_USERNAME=your_test_user
TEST_PASSWORD=your_test_password
BASE_URL=https://your-app.com
```

## Core Components

### ElementFinder

Discovers elements using multiple strategies:

```python
finder = ElementFinder(driver)

# Basic finding
element = finder.find_element(By.ID, "login-button")

# Find with fallback strategies (KEY to discovery-based testing!)
element = finder.find_element_with_fallback([
    (By.ID, "submit-btn"),
    (By.NAME, "submit"),
    (By.XPATH, "//button[@type='submit']"),
    (By.CSS_SELECTOR, "button[type='submit']")
])

# Find by visible text (what users see!)
button = finder.find_by_text("Login", tag="button")

# Discover all clickable elements
clickable = finder.find_clickable_elements()
```

### ElementInteractor

Handles all interactions reliably:

```python
interactor = ElementInteractor(driver)

# Click with automatic retry
interactor.click(button, force=True)  # Falls back to JS click if needed

# Type with smart clearing
interactor.type(input_field, "text", clear_first=True)

# Type slowly for fields with JS validation
interactor.type_slowly(search_field, "query", delay=0.1)

# Get dropdown options (discovery!)
options = interactor.get_select_options(dropdown)
print(f"Available options: {options}")
```

### WaitHandler

Intelligent waits, NO SLEEP CALLS:

```python
waiter = WaitHandler(driver, default_timeout=10)

# Wait for element to be visible
element = waiter.wait_for_element_visible(By.ID, "modal")

# Wait for element to be clickable
button = waiter.wait_for_element_clickable(By.ID, "submit")

# Wait for element to disappear
waiter.wait_for_element_invisible(By.ID, "loading")

# Wait for text to appear
waiter.wait_for_text_present(By.ID, "status", "Success")

# Wait for custom condition
def cart_not_empty(driver):
    count = driver.find_element(By.ID, "cart-count")
    return int(count.text) > 0

waiter.wait_for_condition(cart_not_empty, timeout=15)
```

### DiscoveryEngine

Automatically discovers page structure:

```python
discovery = DiscoveryEngine(driver)

# Discover all forms
forms = discovery.discover_forms()
for form in forms:
    print(f"Form: {form['id']}")
    print(f"  Inputs: {len(form['inputs'])}")
    print(f"  Buttons: {len(form['buttons'])}")

# Discover navigation
nav = discovery.discover_navigation()
print(f"Header links: {len(nav['header'])}")
print(f"Footer links: {len(nav['footer'])}")

# Discover all interactive elements
interactive = discovery.discover_interactive_elements()
total = sum(len(v) for v in interactive.values())
print(f"Total interactive elements: {total}")

# Generate complete page report
report = discovery.generate_page_report()
print(f"Page: {report['metadata']['title']}")
print(f"Forms: {report['summary']['total_forms']}")
print(f"Interactive: {report['summary']['total_interactive']}")
```

## Writing Tests

### Discovery-Based Tests (Recommended)

Tests that DISCOVER instead of ASSUME:

```python
def test_login_form_exists_and_works(browser, adapter):
    """
    DISCOVERY-BASED: Discovers login form automatically.
    Works with ANY application that has a login form!
    """
    browser.get(adapter.get_base_url())

    discovery = DiscoveryEngine(browser)
    forms = discovery.discover_forms()

    # Find form with username and password fields
    login_form = None
    for form in forms:
        input_names = [inp['name'] for inp in form['inputs']]
        if any('user' in name.lower() for name in input_names) and \
           any('pass' in name.lower() for name in input_names):
            login_form = form
            break

    assert login_form is not None, "No login form found"

    # Fill discovered form
    username_input = next(
        inp for inp in login_form['inputs']
        if 'user' in inp['name'].lower()
    )
    password_input = next(
        inp for inp in login_form['inputs']
        if 'pass' in inp['name'].lower()
    )

    interactor = ElementInteractor(browser)
    interactor.type(username_input['element'], "testuser")
    interactor.type(password_input['element'], "testpass")

    # Find and click submit button
    submit_button = next(
        btn for btn in login_form['buttons']
        if 'submit' in btn['type'].lower()
    )
    interactor.click(submit_button['element'])
```

### Adapter-Based Tests (Application-Specific)

Tests that use adapter configuration:

```python
def test_login_with_adapter(browser, adapter):
    """
    ADAPTER-BASED: Uses adapter configuration.
    Application-specific but still clean and maintainable.
    """
    browser.get(adapter.get_base_url())

    # Get login page structure from adapter
    login_structure = adapter.discover_page_structure('login')

    # Get test credentials from adapter (reads from env vars)
    test_users = adapter.get_test_users()
    valid_user = test_users['valid']

    assert valid_user['username'], "TEST_USERNAME not configured"

    # Use adapter-provided structure
    username_field = browser.find_element(By.ID, login_structure['form_fields']['username']['id'])
    password_field = browser.find_element(By.ID, login_structure['form_fields']['password']['id'])

    interactor = ElementInteractor(browser)
    interactor.type(username_field, valid_user['username'])
    interactor.type(password_field, valid_user['password'])

    # Click submit
    submit_button = browser.find_element(By.CSS_SELECTOR, login_structure['buttons']['submit']['selector'])
    interactor.click(submit_button)
```

## Adapting to New Applications

### Time Estimates

- **Simple application** (e-commerce, blog): 2-4 hours
  - Create adapter: 1 hour
  - Configure credentials: 15 minutes
  - Create 2-3 page objects: 1-2 hours
  - Write initial tests: 30-60 minutes

- **Medium application** (SaaS, dashboard): 4-8 hours
  - Create adapter: 2 hours
  - Handle authentication: 1 hour
  - Create 5-10 page objects: 2-4 hours
  - Write test suite: 1-2 hours

- **Complex application** (enterprise): 8-16 hours
  - Create adapter: 3-4 hours
  - Complex auth (SSO, OAuth): 2-3 hours
  - Create 15+ page objects: 4-6 hours
  - Comprehensive tests: 3-5 hours

## Best Practices

### 1. Never Hardcode Values

❌ **BAD:**
```python
def test_login(browser):
    browser.get("https://myapp.com")
    username_field = browser.find_element(By.ID, "username")
    username_field.send_keys("testuser")  # HARDCODED!
```

✅ **GOOD:**
```python
def test_login(browser, adapter):
    browser.get(adapter.get_base_url())  # From adapter
    test_users = adapter.get_test_users()  # From env vars
    valid_user = test_users['valid']

    username_field = browser.find_element(By.ID, "username")
    username_field.send_keys(valid_user['username'])
```

### 2. Use Discovery When Possible

❌ **BAD (Assumes structure):**
```python
submit_button = browser.find_element(By.ID, "submit-button-123")
```

✅ **GOOD (Discovers structure):**
```python
finder = ElementFinder(browser)
submit_button = finder.find_element_with_fallback([
    (By.ID, "submit"),
    (By.NAME, "submit"),
    (By.XPATH, "//button[@type='submit']")
])
```

✅ **BEST (Discovers automatically):**
```python
discovery = DiscoveryEngine(browser)
forms = discovery.discover_forms()
submit_button = forms[0]['buttons'][0]['element']
```

### 3. No Sleep Calls

❌ **BAD:**
```python
import time
button.click()
time.sleep(2)  # NEVER DO THIS!
```

✅ **GOOD:**
```python
waiter = WaitHandler(browser)
waiter.wait_for_element_clickable(By.ID, "next-button")
```

### 4. Separate Concerns

❌ **BAD (God Class):**
```python
class BasePage:
    def find_element(self, ...): ...
    def click(self, ...): ...
    def wait(self, ...): ...
    def screenshot(self, ...): ...
    def execute_js(self, ...): ...
    # 50+ methods in one class
```

✅ **GOOD (Separation of Concerns):**
```python
finder = ElementFinder(driver)      # Finding
interactor = ElementInteractor(driver)  # Interacting
waiter = WaitHandler(driver)        # Waiting
discovery = DiscoveryEngine(driver)  # Discovering
```

## Migration Guide

### Migrating from Hardcoded Tests

1. **Create Adapter:**
   ```bash
   python -m framework.cli.setup_wizard
   ```

2. **Move Configuration:**
   - Hardcoded URLs → `adapter.get_base_url()`
   - Hardcoded credentials → `adapter.get_test_users()` + `.env`
   - Hardcoded locators → `adapter.discover_page_structure()`

3. **Refactor Tests:**
   - Add `adapter` fixture
   - Replace hardcoded values with adapter methods
   - Use discovery methods where possible

4. **Update Environment:**
   - Create `.env` file
   - Set TEST_USERNAME and TEST_PASSWORD
   - Remove hardcoded credentials from code

## Examples

See `/tests/examples/` for complete examples:
- `test_discovery_based.py` - Discovery-based tests
- `test_adapter_based.py` - Adapter-based tests
- `test_mixed_approach.py` - Combining both approaches

## Support

For questions or issues:
1. Check `/documentation/` for detailed guides
2. See examples in `/tests/examples/`
3. Review adapter implementations in `/framework/adapters/`

## License

MIT License - See LICENSE file for details

---

**Remember:** The goal is to DISCOVER, not ASSUME. Write tests that work with ANY application structure, not just one specific implementation.
