# Auto-Configuration Guide

Automatic framework configuration using intelligent web scanning.

## Overview

The **Intelligent Auto-Configurator** automatically scans your target web application and configures the entire test framework in minutes instead of hours.

**What it does:**
1. Crawls your website recursively (discovers all pages and sections)
2. Identifies page types (login, catalog, forms, etc.)
3. Extracts optimal locators from every page
4. Generates `config/locators.json` automatically
5. Generates page object classes
6. Generates basic test files
7. Creates pytest fixtures

**Time saved:** Reduces setup from 4-8 hours to ~5 minutes!

---

## Quick Start

### Basic Usage

```bash
# Scan website and auto-configure framework
python auto_configure.py --url https://your-website.com
```

### With Options

```bash
# Deeper crawl (up to 4 levels deep)
python auto_configure.py --url https://your-website.com --depth 4

# Run in headless mode (no browser window)
python auto_configure.py --url https://your-website.com --headless

# Verbose output for debugging
python auto_configure.py --url https://your-website.com --verbose

# Backup existing configuration before overwriting
python auto_configure.py --url https://your-website.com --backup
```

---

## How It Works

### Phase 1: Intelligent Crawling

**PageCrawler** discovers all pages recursively:

```
Starting at: https://example.com

[Depth 0] https://example.com (Home)
  ├─ [Depth 1] https://example.com/login
  ├─ [Depth 1] https://example.com/products
  │   ├─ [Depth 2] https://example.com/products/phones
  │   ├─ [Depth 2] https://example.com/products/laptops
  │   └─ [Depth 2] https://example.com/products/monitors
  ├─ [Depth 1] https://example.com/cart
  └─ [Depth 1] https://example.com/checkout

✓ Discovered 8 pages
✓ Found 3 navigation sections
```

**Features:**
- Follows all links within same domain
- Respects depth limits (avoid infinite loops)
- Detects page types automatically
- Identifies navigation sections
- Finds forms, modals, tables

### Phase 2: Locator Extraction

**LocatorExtractor** finds optimal locators for each element:

```
Extracting locators from: login page

✓ login_username_field: (By.ID, "loginusername")
✓ login_password_field: (By.ID, "loginpassword")
✓ login_button: (By.XPATH, "//button[text()='Log in']")
✓ login_modal_container: (By.ID, "logInModal")
✓ login_modal_close_button: (By.CSS, ".close")

Total: 5 locators
```

**Locator Priority:**
1. **ID** - Most stable (preferred)
2. **Name** - Stable
3. **CSS Selector** - Good
4. **XPath** - Last resort (least stable)

**Smart Element Naming:**
- Identifies element purpose from attributes
- Generates meaningful names: `username_field`, `login_button`
- Avoids generic names: `input_1`, `button_2`

### Phase 3: Code Generation

**CodeGenerator** creates all necessary files:

**Generated `config/locators.json`:**
```json
{
  "login": {
    "login_username_field": {
      "by": "id",
      "value": "loginusername"
    },
    "login_password_field": {
      "by": "id",
      "value": "loginpassword"
    },
    "login_button": {
      "by": "xpath",
      "value": "//button[text()='Log in']"
    }
  },
  "catalog": {
    ...
  }
}
```

**Generated `pages/login_page.py`:**
```python
"""
LoginPage - Auto-generated Page Object
Page Type: login
"""

from pages.base_page import BasePage
from utils.locators_loader import load_locator


class LoginPage(BasePage):
    """Page object for login page."""

    # Locators (auto-generated)
    login_username_field = load_locator("login", "login_username_field")
    login_password_field = load_locator("login", "login_password_field")
    login_button = load_locator("login", "login_button")

    # Methods (customize as needed)

    def login(self, username: str, password: str) -> None:
        """Perform login."""
        # TODO: Customize this method based on actual login flow
        pass

    def is_user_logged_in(self) -> bool:
        """Check if user is logged in."""
        # TODO: Implement login verification
        return False
```

**Generated `tests/login/test_login_functional.py`:**
```python
"""
Auto-generated Functional Tests for LoginPage
"""

import pytest


@pytest.mark.functional
def test_login_page_loads(login_page, base_url):
    """Test that login page loads successfully."""
    assert login_page.driver.title is not None


@pytest.mark.functional
def test_login_elements_present(login_page):
    """Test that key elements are present on login page."""
    # TODO: Add assertions for key elements
    pass


@pytest.mark.functional
def test_login_with_valid_credentials(login_page, valid_user):
    """Test login with valid credentials."""
    # TODO: Implement login test
    pass
```

**Updated `conftest.py`:**
```python
# Auto-generated page fixtures

@pytest.fixture(scope="function")
def login_page(browser, base_url):
    """Provide initialized LoginPage instance."""
    from pages.login_page import LoginPage

    browser.get(base_url)
    return LoginPage(browser)
```

---

## Output Example

```
==================================================================
INTELLIGENT AUTO-CONFIGURATOR
==================================================================
Target URL: https://your-application-url.com
Max Depth: 3
Headless: False
Project Root: /home/user/test-automation-framework
==================================================================

Initializing browser...
✓ Browser initialized

==================================================================
INTELLIGENT SCANNER - STARTING
Target: https://your-application-url.com
Max Depth: 3
==================================================================

[PHASE 1] Crawling website...
[Depth 0] Crawling: https://your-application-url.com
[Depth 1] Crawling: https://your-application-url.com/index.html
[Depth 1] Crawling: https://your-application-url.com/cart.html
[Depth 1] Crawling: https://your-application-url.com/prod.html?idp_=1
...
✓ Discovered 12 pages
✓ Found 4 sections

[PHASE 2] Extracting locators...
  ✓ home: 15 locators
  ✓ login: 5 locators
  ✓ cart: 8 locators
  ✓ catalog: 12 locators
  ✓ product: 6 locators
✓ Extracted 46 locators from 5 pages

[PHASE 3] Generating code...
Generated: /home/user/test-automation-framework/config/locators.json
  Pages: 5
  Total locators: 46
Generated: /home/user/test-automation-framework/pages/home_page.py
Generated: /home/user/test-automation-framework/pages/login_page.py
Generated: /home/user/test-automation-framework/pages/cart_page.py
Generated: /home/user/test-automation-framework/pages/catalog_page.py
Generated: /home/user/test-automation-framework/pages/product_page.py
Generated: /home/user/test-automation-framework/tests/home/test_home_functional.py
Generated: /home/user/test-automation-framework/tests/login/test_login_functional.py
...
Updated: /home/user/test-automation-framework/conftest.py
✓ Code generation complete

==================================================================
SCAN SUMMARY
==================================================================

Pages Discovered: 12
Pages Configured: 5
Total Locators: 46
Navigation Sections: 4

Page Types:
  - home: 1
  - login: 1
  - catalog: 3
  - product: 4
  - cart: 1
  - checkout: 1
  - page: 1

Locators per Page:
  - home: 15 locators
  - login: 5 locators
  - cart: 8 locators
  - catalog: 12 locators
  - product: 6 locators

Sections Found:
  - index: 2 pages
  - cart: 1 pages
  - prod: 4 pages

Generated Files:
  - config/locators.json
  - 5 page objects
  - 5 test files
  - Updated conftest.py

==================================================================
INTELLIGENT SCANNER - COMPLETE
Total Time: 45.32s
==================================================================

==================================================================
AUTO-CONFIGURATION COMPLETE!
==================================================================

✓ Configured 5 pages
✓ Extracted 46 locators
✓ Generated 5 page objects
✓ Generated 5 test files

Generated Files:
  - config/locators.json
  - pages/*_page.py (5 files)
  - tests/*/test_*_functional.py (5 files)
  - conftest.py (updated)

Next Steps:
  1. Review generated config/locators.json
  2. Customize page objects in pages/
  3. Enhance generated tests in tests/
  4. Run tests: pytest tests/ -v

==================================================================

✓ Browser closed
```

---

## After Auto-Configuration

### Step 1: Review Generated Locators

```bash
# Check generated locators.json
cat config/locators.json
```

**Verify:**
- Locators are accurate
- IDs/names are correct
- No duplicate element names

### Step 2: Customize Page Objects

Generated page objects have TODO placeholders:

```python
def login(self, username: str, password: str) -> None:
    """Perform login."""
    # TODO: Customize this method based on actual login flow
    pass
```

**Customize based on actual application flow:**

```python
def login(self, username: str, password: str) -> None:
    """Perform login."""
    self.click(self.login_button_nav)  # Open modal
    time.sleep(self.SLEEP_MODAL)       # Wait for animation
    self.type(self.login_username_field, username)
    self.type(self.login_password_field, password)
    self.click(self.login_button_modal)
    time.sleep(self.SLEEP_SHORT)
```

### Step 3: Enhance Tests

Generated tests are basic templates:

```python
@pytest.mark.functional
def test_login_with_valid_credentials(login_page, valid_user):
    """Test login with valid credentials."""
    # TODO: Implement login test
    pass
```

**Enhance with actual test logic:**

```python
@pytest.mark.functional
def test_login_with_valid_credentials(login_page, valid_user):
    """Test login with valid credentials."""
    login_page.login(**valid_user)
    assert login_page.is_user_logged_in()
```

### Step 4: Add Test Data

Update `tests/test_data.py` with real test data:

```python
class Users:
    VALID = {
        "username": "your_test_user",
        "password": "your_test_password"
    }
```

### Step 5: Run Tests

```bash
# Run generated tests
pytest tests/ -v

# Run specific page tests
pytest tests/login/ -v
```

---

## Configuration Options

### Crawl Depth

Controls how deep the crawler goes:

```bash
# Shallow (fast, less coverage)
python auto_configure.py --url https://example.com --depth 1

# Default (balanced)
python auto_configure.py --url https://example.com --depth 3

# Deep (slow, more coverage)
python auto_configure.py --url https://example.com --depth 5
```

**Recommendations:**
- **Depth 1-2:** Small sites (< 10 pages)
- **Depth 3:** Medium sites (10-50 pages) - DEFAULT
- **Depth 4-5:** Large sites (50+ pages)

### Headless Mode

Run without opening browser window:

```bash
python auto_configure.py --url https://example.com --headless
```

**Use when:**
- Running on CI/CD server
- Running on remote server without display
- Want faster execution

### Backup Existing Configuration

Backup before overwriting:

```bash
python auto_configure.py --url https://example.com --backup
```

**Creates backup in:**
```
backups/config_backup_20251203_143025/
├── locators.json
└── pages/
    ├── login_page.py
    ├── catalog_page.py
    └── ...
```

---

## Troubleshooting

### Error: "Browser initialization failed"

**Cause:** ChromeDriver not installed or incompatible version

**Solution:**
```bash
# Clear webdriver-manager cache
rm -rf ~/.wdm

# Run again - will re-download correct driver
python auto_configure.py --url https://example.com
```

### Error: "No pages discovered"

**Cause:** Website blocks automation or requires authentication

**Solutions:**

1. **Check if site is accessible:**
```bash
curl https://your-website.com
```

2. **Try with authentication:**
```python
# Modify auto_configure.py to login first
driver.get("https://your-website.com/login")
# Perform login
# Then run scanner
```

3. **Check robots.txt:**
Some sites block crawlers via robots.txt

### Warning: "Failed to extract locators from page"

**Cause:** JavaScript-heavy page or timeout

**Solutions:**

1. **Increase wait time:**
```python
# In locator_extractor.py, increase sleep time
time.sleep(2)  # Instead of 1
```

2. **Run in non-headless mode:**
```bash
python auto_configure.py --url https://example.com  # No --headless
```

### Issue: Too many/too few pages discovered

**Too many pages:**
```bash
# Reduce depth
python auto_configure.py --url https://example.com --depth 1
```

**Too few pages:**
```bash
# Increase depth
python auto_configure.py --url https://example.com --depth 4
```

---

## Advanced Customization

### Modify Crawl Behavior

Edit `utils/auto_config/page_crawler.py`:

```python
class PageCrawler:
    def _should_crawl_url(self, url: str) -> bool:
        """Custom logic for which URLs to crawl."""
        # Skip admin pages
        if '/admin/' in url:
            return False

        # Skip API endpoints
        if '/api/' in url:
            return False

        return True
```

### Customize Locator Extraction

Edit `utils/auto_config/locator_extractor.py`:

```python
class LocatorExtractor:
    def _get_best_locator(self, element):
        """Customize locator preference."""
        # Always prefer data-testid if available
        test_id = element.get_attribute("data-testid")
        if test_id:
            return {"by": "css", "value": f"[data-testid='{test_id}']"}

        # Default behavior
        return super()._get_best_locator(element)
```

### Customize Code Generation

Edit `utils/auto_config/code_generator.py`:

```python
class CodeGenerator:
    def _generate_page_object_code(self, ...):
        """Customize generated page object template."""
        # Add custom imports, methods, etc.
        pass
```

---

## Best Practices

1. **Review generated code** - Always review before using
2. **Backup first** - Use `--backup` flag before re-running
3. **Start shallow** - Use depth 1-2 for initial scan
4. **Customize incrementally** - Enhance generated code gradually
5. **Re-run after UI changes** - Keep locators up to date

---

## Limitations

**What auto-configurator CANNOT do:**

1. **Understand business logic** - You must add test assertions
2. **Handle complex workflows** - Multi-step processes need manual implementation
3. **Deal with authentication walls** - May need manual login
4. **Extract from iframes** - Currently doesn't handle iframe content
5. **Handle SPA routing** - JavaScript-based routing may be missed
6. **Verify locator uniqueness** - May generate non-unique locators

**Manual review required for:**
- Test assertions
- Complex page interactions
- Authentication flows
- Business logic validation
- Error handling

---

## Related Documentation

- [Implementation Guide](implementation-guide.md) - Manual configuration
- [Locators API](../api-reference/locators-api.md) - Locators system
- [Extending Framework](extending-framework.md) - Customization
