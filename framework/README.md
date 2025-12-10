# Universal Test Automation Framework

**Version:** 1.0
**Author:** Marc Arévalo
**Philosophy:** DISCOVER, not ASSUME

## Overview

Professional test automation framework designed to work with **ANY web application**.

This framework provides universal testing components that adapt to your application through the **Adapter Pattern**, enabling professional-quality test automation regardless of your technology stack.

### Key Features

- ✅ **True Universality** - Core framework works with ANY web application
- ✅ **Discovery-Based Testing** - Tests discover functionality instead of assuming it
- ✅ **Clean Architecture** - Separation of concerns, no God Classes
- ✅ **Easy Adaptation** - Adapt to your application via simple adapter
- ✅ **No Hardcoded Values** - All configuration via adapters and environment variables
- ✅ **Professional Quality** - Follows industry best practices (Django, Flask, Pytest style)

## Architecture

```
framework/
├── core/                     # Universal framework core
│   ├── element_finder.py     # Element discovery strategies
│   ├── element_interactor.py # Element interactions
│   ├── wait_handler.py       # Intelligent wait strategies
│   └── discovery_engine.py   # Automatic page structure discovery
│
├── adapters/                 # Application-specific adapters
│   ├── base_adapter.py       # Abstract adapter interface
│   └── adapter_template.py   # Template for your adapter
│
├── generators/               # Code generators (future)
│   ├── page_generator.py     # Generate page objects
│   ├── test_generator.py     # Generate test skeletons
│   └── locator_generator.py  # Generate locator files
│
└── cli/                      # Command-line tools (future)
    └── setup_wizard.py       # Interactive setup
```

## Philosophy

### Universal Framework Principles

1. **DISCOVER, not ASSUME**
   - Tests discover page structure automatically
   - No assumptions about implementation details
   - Find elements by what users see, not by internal IDs

2. **SEPARATE, not COMBINE**
   - Each class has one responsibility (SOLID principles)
   - No God Classes with 50+ methods
   - Clean interfaces between components

3. **CONFIGURE, not HARDCODE**
   - All app-specific details in adapters
   - Credentials in environment variables
   - URLs and patterns in configuration

4. **WAIT INTELLIGENTLY, not BLINDLY**
   - No `time.sleep()` calls anywhere
   - Wait for actual conditions
   - Poll for element states

5. **ADAPT, not REWRITE**
   - New applications via adapters
   - Core framework unchanged
   - Professional separation of concerns

## Core Components

### 1. ElementFinder

Discovers elements using multiple strategies:

```python
from framework.core.element_finder import ElementFinder

finder = ElementFinder(driver)

# Find with fallback strategies (discovery-based!)
element = finder.find_element_with_fallback([
    (By.ID, "submit-btn"),
    (By.NAME, "submit"),
    (By.XPATH, "//button[@type='submit']"),
    (By.CSS_SELECTOR, "button[type='submit']")
])

# Find by visible text (what users see)
button = finder.find_by_text("Login", tag="button")

# Discover all clickable elements
clickable = finder.find_clickable_elements()
```

### 2. ElementInteractor

Handles all interactions reliably:

```python
from framework.core.element_interactor import ElementInteractor

interactor = ElementInteractor(driver)

# Click with automatic retry and JS fallback
interactor.click(button, force=True)

# Type with smart clearing
interactor.type(input_field, "text", clear_first=True)

# Get dropdown options (discovery!)
options = interactor.get_select_options(dropdown)
```

### 3. WaitHandler

Intelligent waits, NO sleep calls:

```python
from framework.core.wait_handler import WaitHandler

waiter = WaitHandler(driver, default_timeout=10)

# Wait for element to be visible
element = waiter.wait_for_element_visible(By.ID, "modal")

# Wait for element to be clickable
button = waiter.wait_for_element_clickable(By.ID, "submit")

# Wait for custom condition
def custom_condition(driver):
    return some_check(driver)

waiter.wait_for_condition(custom_condition, timeout=15)
```

### 4. DiscoveryEngine

Automatically discovers page structure:

```python
from framework.core.discovery_engine import DiscoveryEngine

discovery = DiscoveryEngine(driver)

# Discover all forms
forms = discovery.discover_forms()
for form in forms:
    print(f"Form: {form['id']}, Inputs: {len(form['inputs'])}")

# Discover navigation
nav = discovery.discover_navigation()
print(f"Header links: {len(nav['header'])}")

# Discover all interactive elements
interactive = discovery.discover_interactive_elements()
total = sum(len(v) for v in interactive.values())
print(f"Total interactive elements: {total}")

# Generate complete page report
report = discovery.generate_page_report()
```

## Getting Started

### 1. Create Your Application Adapter

Copy the template and implement for YOUR application:

```bash
cp framework/adapters/adapter_template.py framework/adapters/my_app_adapter.py
```

Edit `my_app_adapter.py` and implement all methods for your application.

### 2. Configure Environment Variables

Create `.env` file:

```bash
cp .env.example .env
```

Set your values:
```bash
# Your application
BASE_URL=https://your-app.com

# Your credentials
TEST_USERNAME=your_test_user
TEST_PASSWORD=your_test_password

# Browser config
BROWSER=chrome
HEADLESS=false
```

### 3. Use in Tests

```python
import pytest
from framework.core import DiscoveryEngine, ElementInteractor, WaitHandler
from framework.adapters.my_app_adapter import MyAppAdapter

@pytest.fixture
def app_adapter():
    return MyAppAdapter()

def test_your_functionality(browser, app_adapter):
    # Get URL from adapter
    browser.get(app_adapter.get_base_url())

    # Use universal components
    discovery = DiscoveryEngine(browser)
    interactor = ElementInteractor(browser)
    waiter = WaitHandler(browser)

    # Discover page structure
    forms = discovery.discover_forms()

    # Interact with elements
    # ... your test logic here
```

## Adapter Pattern

The adapter pattern isolates ALL application-specific details:

**What Goes in Your Adapter:**
- Base URL
- URL patterns
- Authentication method
- Navigation structure
- Page structures
- Test credentials (from env vars)
- Special behaviors

**What Stays Universal:**
- ElementFinder
- ElementInteractor
- WaitHandler
- DiscoveryEngine
- All core components

## Best Practices

### 1. Never Hardcode Values

❌ **BAD:**
```python
browser.get("https://myapp.com")
username_field.send_keys("testuser")  # HARDCODED!
```

✅ **GOOD:**
```python
browser.get(adapter.get_base_url())  # From adapter
test_users = adapter.get_test_users()  # From env vars
username_field.send_keys(test_users['valid']['username'])
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
    # 50+ methods in one class
```

✅ **GOOD (Separation of Concerns):**
```python
finder = ElementFinder(driver)      # Finding
interactor = ElementInteractor(driver)  # Interacting
waiter = WaitHandler(driver)        # Waiting
discovery = DiscoveryEngine(driver)  # Discovering
```

## Professional Usage

This framework follows the same principles as professional frameworks:

- **Django** - Universal web framework, you adapt it to YOUR application
- **Flask** - Universal microframework, you add YOUR routes
- **Pytest** - Universal test framework, you write YOUR tests
- **This Framework** - Universal test automation, you create YOUR adapter

**No examples of specific applications included** - that's YOUR job as the developer.

## Time Estimates for Adaptation

Actual time to adapt this framework to your application:

- **Simple web app:** 2-4 hours
  - Create adapter: 1-2 hours
  - Configure environment: 30 mins
  - Write initial tests: 1-2 hours

- **Medium web app:** 4-8 hours
  - Create adapter: 2-3 hours
  - Handle auth complexity: 1-2 hours
  - Write test suite: 2-3 hours

- **Complex web app:** 8-16 hours
  - Create adapter: 3-4 hours
  - Complex auth (SSO, OAuth): 2-3 hours
  - Comprehensive testing: 4-6 hours

## Documentation

- **Core Components:** See docstrings in each module
- **Adapter Template:** `framework/adapters/adapter_template.py`
- **Environment Config:** `.env.example`
- **This README:** Complete usage guide

## Support

This is a professional framework template. Implementation details are YOUR responsibility as a developer.

Key files to understand:
1. `framework/core/` - Universal components
2. `framework/adapters/base_adapter.py` - Adapter interface
3. `framework/adapters/adapter_template.py` - Your starting point
4. `.env.example` - Configuration template

## License

MIT License

---

**Remember:** This is a UNIVERSAL framework. Like Django, Flask, or Pytest - it provides the tools, YOU provide the application-specific details through adapters.

No hand-holding, no specific examples - professional frameworks trust developers to do their job.
