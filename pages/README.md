# User Page Objects Directory

This directory is where **YOU** place your application-specific page objects.

## Purpose

The framework is universal and cannot know your application's structure. This directory exists for YOU to create page objects that model YOUR application's pages.

## Quick Start

### 1. Create Your First Page Object

```bash
# Copy a template
cp templates/page_objects/__template_login_page.py pages/login_page.py

# Edit with your application's locators
# Replace placeholder IDs with YOUR app's element IDs
```

### 2. Example Page Object

```python
# pages/login_page.py
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webdriver import WebDriver

class LoginPage:
    """Page object for YOUR application's login page."""

    def __init__(self, driver: WebDriver):
        self.driver = driver
        # TODO: Replace with YOUR application's actual locators
        self.username_input = (By.ID, "username")
        self.password_input = (By.ID, "password")
        self.login_button = (By.ID, "login-btn")

    def login(self, username: str, password: str):
        """Perform login with credentials."""
        self.driver.find_element(*self.username_input).send_keys(username)
        self.driver.find_element(*self.password_input).send_keys(password)
        self.driver.find_element(*self.login_button).click()
```

### 3. Use in Tests

```python
# tests/test_login.py
def test_login(browser, base_url):
    from pages.login_page import LoginPage

    browser.get(base_url)
    login_page = LoginPage(browser)
    login_page.login("testuser", "testpass")

    assert "dashboard" in browser.current_url
```

## Templates Available

The framework provides templates in `templates/page_objects/`:

- `__template_login_page.py` - Login page template
- `__template_base_page.py` - Base page class with common methods

## Best Practices

1. **One Page Object per Page** - Each page should have its own class
2. **Use Locators as Tuples** - `(By.ID, "element-id")`
3. **Methods for Actions** - Methods like `login()`, `search()`, `add_to_cart()`
4. **Properties for State** - Properties like `is_logged_in`, `error_message`
5. **Inherit from BasePage** - For common functionality (optional)

## What NOT to Put Here

- ❌ Framework code (use `framework/` for that)
- ❌ Test files (use `tests/` for that)
- ❌ Utilities (use `utils/` for that)
- ❌ Configuration (use `config/` for that)

## Need Help?

- See `templates/page_objects/` for examples
- See `documentation/guides/implementation-guide.md` for detailed guide
- See `documentation/api-reference/base-page-api.md` for base class reference

---

**Remember**: This framework is universal. Page objects are YOUR responsibility to create based on YOUR application structure.
