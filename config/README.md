# Configuration Directory

## Overview

This directory contains all configuration files for the test automation framework. Configuration is centralized here to enable easy maintenance and environment-specific customization.

## Files

### config.py

**Purpose:** Application-wide configuration settings

**Contains:**
- `BASE_URL`: Target application URL
- `TIMEOUT`: Default wait timeout (seconds)
- `HEADLESS`: Browser headless mode flag
- `BROWSER`: Browser selection (chrome, firefox, edge, safari)
- `IMPLICIT_WAIT`: Implicit wait timeout
- `SCREENSHOT_ON_FAILURE`: Automatic screenshot capture on test failure
- `LOG_LEVEL`: Logging verbosity level
- Environment-specific settings

**Usage:**
```python
from config.config import BASE_URL, TIMEOUT, BROWSER

driver.get(BASE_URL)
WebDriverWait(driver, TIMEOUT).until(...)
```

**Configuration:**
```python
# config.py
BASE_URL = "https://www.demoblaze.com"
TIMEOUT = 10
HEADLESS = False
BROWSER = "chrome"
IMPLICIT_WAIT = 5
SCREENSHOT_ON_FAILURE = True
LOG_LEVEL = "INFO"
```

### locators.json

**Purpose:** Centralized UI element locators

**Structure:**
```json
{
  "page_name": {
    "element_name": {
      "by": "locator_strategy",
      "value": "locator_value",
      "description": "Element description"
    }
  }
}
```

**Locator Strategies:**
- `id`: Element ID
- `name`: Element name attribute
- `css`: CSS selector
- `xpath`: XPath expression
- `link_text`: Link text (exact match)
- `partial_link_text`: Partial link text match
- `class_name`: CSS class name
- `tag_name`: HTML tag name

**Example:**
```json
{
  "login": {
    "username_input": {
      "by": "id",
      "value": "loginusername",
      "description": "Login username input field"
    },
    "password_input": {
      "by": "id",
      "value": "loginpassword",
      "description": "Login password input field"
    },
    "login_button": {
      "by": "xpath",
      "value": "//button[text()='Log in']",
      "description": "Login submit button"
    }
  }
}
```

**Usage:**
```python
from utils.locators_loader import LocatorsLoader

loader = LocatorsLoader()
locators = loader.load()

username_locator = locators["login"]["username_input"]
driver.find_element(By.ID, username_locator["value"])
```

## Configuration Management

### Environment Variables

Override configuration using environment variables:

```bash
export BASE_URL="https://staging.example.com"
export HEADLESS=true
export BROWSER=firefox
export TIMEOUT=20
```

### Environment-Specific Configs

For multiple environments, create environment-specific config files:

```
config/
├── config.py              # Base configuration
├── config_dev.py          # Development environment
├── config_staging.py      # Staging environment
└── config_production.py   # Production environment (read-only tests only)
```

Load environment-specific config:

```python
import os
env = os.getenv("TEST_ENV", "dev")

if env == "staging":
    from config.config_staging import *
elif env == "production":
    from config.config_production import *
else:
    from config.config import *
```

## Locators Management

### Best Practices

1. **Use ID when available**: IDs are unique and fastest
2. **Prefer CSS over XPath**: CSS selectors are faster
3. **Use data attributes**: Add `data-testid` attributes for stable locators
4. **Avoid brittle locators**: Don't rely on dynamic values or text
5. **Document locators**: Include descriptions for maintainability

### Updating Locators

When UI changes:

1. Open `locators.json`
2. Find affected page section
3. Update locator values
4. Test changes:
   ```bash
   pytest tests/login/ -v
   ```

### Adding New Locators

```json
{
  "new_page": {
    "new_element": {
      "by": "css",
      "value": "#element-id",
      "description": "Description of the element"
    }
  }
}
```

## Configuration Validation

Validate configuration before test runs:

```python
def validate_config():
    """Validate configuration settings"""
    assert BASE_URL.startswith("http"), "BASE_URL must be valid URL"
    assert TIMEOUT > 0, "TIMEOUT must be positive"
    assert BROWSER in ["chrome", "firefox", "edge", "safari"], "Invalid BROWSER"
    print("✓ Configuration valid")
```

## Security Considerations

1. **Never commit sensitive data**: Use environment variables
2. **Use .env files**: Store secrets in `.env` (gitignored)
3. **Rotate credentials**: Change test credentials regularly
4. **Read-only production**: Production tests should never modify data

## Troubleshooting

### Issue: Element Not Found

**Cause:** Locator outdated or incorrect

**Solution:**
1. Inspect element in browser DevTools
2. Verify locator strategy and value
3. Update `locators.json`
4. Re-run tests

### Issue: Timeout Errors

**Cause:** `TIMEOUT` too low for slow pages

**Solution:**
```python
# Increase timeout in config.py
TIMEOUT = 20  # Increase from 10 to 20 seconds
```

### Issue: Tests Fail in Different Environment

**Cause:** Hardcoded configuration values

**Solution:**
- Use environment variables
- Create environment-specific configs
- Never hardcode URLs or timeouts in test code

## Integration with Tests

Tests automatically load configuration from this directory:

```python
# conftest.py loads config automatically
@pytest.fixture
def browser():
    driver = webdriver.Chrome() if BROWSER == "chrome" else ...
    driver.get(BASE_URL)
    driver.implicitly_wait(IMPLICIT_WAIT)
    yield driver
    driver.quit()
```

## Maintenance

**When to update:**
- UI redesign or element changes
- New page or feature added
- Environment changes (URLs, credentials)
- Performance tuning (timeouts)

**How to update:**
1. Update configuration values
2. Validate changes with test run
3. Document changes in commit message
4. Review with team before merging

## References

- [Selenium Locator Strategies](https://www.selenium.dev/documentation/webdriver/elements/locators/)
- [CSS Selectors Reference](https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_Selectors)
- [XPath Tutorial](https://www.w3schools.com/xml/xpath_intro.asp)

## Support

For configuration issues:
- Review this README
- Check environment variables
- Validate locators with browser DevTools
- Consult framework documentation

## License

Internal configuration - follows project license.
