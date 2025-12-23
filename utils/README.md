# Utils Package - Universal Test Automation Framework

**Version:** 1.0
**Author:** Marc Arévalo

---

## 📋 Overview

This package contains utility modules that make the test automation framework **universal and reusable** across any web application. These utilities are completely decoupled from any specific application implementation.

---

## 🎯 Philosophy: Universal Design

This framework follows a **universal design philosophy**:

✅ **Application-Agnostic**: No hardcoded application-specific logic
✅ **Configurable**: All application-specific values externalized to config
✅ **Reusable**: Helpers can be used across different projects
✅ **Extensible**: Easy to add new helpers without modifying existing code
✅ **Well-Documented**: Clear examples and type hints for easy adoption

---

## 📦 Package Structure

```
utils/
├── __init__.py
├── README.md (this file)
└── helpers/
    ├── __init__.py
    ├── data_generator.py    # Generate test data (users, emails, passwords, etc.)
    ├── wait_helpers.py      # Waiting strategies and retry logic
    └── validators.py        # Data validation functions
```

---

## 🔧 Modules

### 1. `data_generator.py`

Generate test data for any application.

**Functions:**
- `generate_unique_username(prefix="testuser", length=4)` - Create unique usernames
- `generate_random_password(length=12, ...)` - Generate secure passwords
- `generate_random_email(domain="testmail.com")` - Create email addresses
- `generate_credit_card_number(card_type="visa")` - Test credit card numbers
- `generate_random_string(length=10)` - Random strings for any purpose

**Example:**
```python
from utils.helpers.data_generator import generate_unique_username, generate_random_password

username = generate_unique_username(prefix="qa_user")
# Returns: "qa_user_1701234567_a1b2"

password = generate_random_password(length=16, include_special=True)
# Returns: "aB3$xY9!zK2#mN7@"
```

---

### 2. `wait_helpers.py`

Universal waiting strategies for asynchronous operations.

**Functions:**
- `wait_for_condition(condition_func, timeout=10)` - Wait for any condition
- `retry_on_failure(max_attempts=3)` - Retry decorator for flaky operations
- `wait_for_page_ready(driver, timeout=30)` - Wait for page load
- `wait_for_ajax(driver, timeout=10)` - Wait for AJAX completion (jQuery)

**Example:**
```python
from utils.helpers.wait_helpers import wait_for_condition, retry_on_failure

# Wait for custom condition
def is_button_enabled():
    return driver.find_element(By.ID, "submit").is_enabled()

wait_for_condition(is_button_enabled, timeout=5)

# Retry flaky operations
@retry_on_failure(max_attempts=3, delay=2.0, exponential_backoff=True)
def click_element():
    driver.find_element(By.ID, "button").click()
```

---

### 3. `validators.py`

Universal data validation functions.

**Functions:**
- `validate_email(email)` - Email format validation
- `validate_url(url)` - URL format validation
- `validate_credit_card(card_number)` - Luhn algorithm validation
- `validate_phone_number(phone, country_code="US")` - Phone validation
- `validate_password_strength(password, min_length=8)` - Password strength check
- `validate_username(username, min_length=3, max_length=20)` - Username validation
- `validate_postal_code(postal_code, country_code="US")` - Postal code validation

**Example:**
```python
from utils.helpers.validators import validate_email, validate_password_strength

# Validate email
is_valid = validate_email("user@example.com")  # True
is_valid = validate_email("invalid.email")     # False

# Check password strength
result = validate_password_strength("MyP@ssw0rd123")
# Returns: {
#     'valid': True,
#     'score': 5,
#     'feedback': []
# }
```

---

## 🌍 How This Framework is Universal

### 1. **No Application-Specific Logic**

The helpers contain ZERO hardcoded values for any specific application:

❌ **BAD (Not Universal):**
```python
def login(username):
    # Hardcoded Universal Test Automation Framework-specific logic
    driver.get("https://www.your-application-url.com")
    driver.find_element(By.ID, "login2").click()  # Universal Test Automation Framework-specific ID
```

✅ **GOOD (Universal):**
```python
def generate_unique_username(prefix="testuser"):
    # Works for ANY application
    timestamp = int(time.time())
    random_suffix = ''.join(random.choices(string.ascii_lowercase, k=4))
    return f"{prefix}_{timestamp}_{random_suffix}"
```

---

### 2. **Configurable Behavior**

All application-specific values are externalized to `config.py`:

```python
# config.py - Application-specific configuration
BASE_URL = "https://www.your-application-url.com/"  # Change for your app
PRODUCT_URL_PATTERN = "prod.html?idp_={product_id}"  # Change for your URL structure

# utils/helpers - Universal code that uses config
from config import config

def navigate_to_product(driver, product_id):
    url = f"{config.BASE_URL}{config.PRODUCT_URL_PATTERN}".format(product_id=product_id)
    driver.get(url)
```

To adapt to a different application:
1. Update `config.py` with new URLs and patterns
2. Update page object locators
3. Utils remain unchanged ✨

---

### 3. **Type Hints and Documentation**

All functions have:
- **Type hints** for parameters and return values
- **Docstrings** with clear examples
- **No assumptions** about the application

```python
def generate_unique_username(prefix: str = "testuser", length: int = 4) -> str:
    """
    Generate a unique username for testing.

    Args:
        prefix: Prefix for the username (default: "testuser")
        length: Length of random suffix (default: 4)

    Returns:
        Unique username string (e.g., "testuser_1234567890_ab12")

    Example:
        >>> username = generate_unique_username(prefix="admin")
        >>> print(username)
        admin_1701234567_a1b2
    """
```

---

## 🚀 Quick Start: Adapting to Your Application

### Step 1: Update Configuration

```python
# config.py
BASE_URL = "https://your-application.com/"
PRODUCT_URL_PATTERN = "products/{product_id}"  # Your URL structure
CATEGORY_QUERY_PARAM = "category"  # Your query parameter
```

### Step 2: Update Page Object Locators

Create a locators configuration file (optional):

```json
// locators.json
{
  "login": {
    "username_field": {"by": "id", "value": "email"},
    "password_field": {"by": "id", "value": "pwd"},
    "submit_button": {"by": "css", "value": ".btn-login"}
  }
}
```

### Step 3: Use Utils (No Changes Needed!)

```python
from utils.helpers.data_generator import generate_unique_username, generate_random_password

# Works exactly the same on any application
username = generate_unique_username()
password = generate_random_password(length=12)
```

---

## 📝 Best Practices

1. **Keep Utils Generic**: Never add application-specific logic to utils
2. **Use Type Hints**: Makes adoption easier for other developers
3. **Document Well**: Include examples in docstrings
4. **Test Independently**: Utils should have their own unit tests
5. **Externalize Config**: All app-specific values go in config.py or locators files

---

## 🔍 Example: Before vs After

### Before (Not Universal)

```python
# signup_page.py - Universal Test Automation Framework-specific
def generate_unique_username():
    timestamp = int(time.time())
    return f"testuser_{timestamp}"  # Hardcoded in page object
```

### After (Universal)

```python
# utils/helpers/data_generator.py - Universal
def generate_unique_username(prefix: str = "testuser", length: int = 4) -> str:
    """Works for ANY application"""
    timestamp = int(time.time())
    random_suffix = ''.join(random.choices(string.ascii_lowercase, k=4))
    return f"{prefix}_{timestamp}_{random_suffix}"

# pages/signup_page.py - Uses universal helper
from utils.helpers.data_generator import generate_unique_username

# Can customize for different apps
username = generate_unique_username(prefix="qa_user")  # qa_user_1234567890_ab12
```

---

## 💡 Contributing

When adding new helpers:

1. Keep them **generic** and **reusable**
2. Add **type hints** to all parameters and returns
3. Include **docstrings** with examples
4. Write **unit tests** (in `tests/utils/` - to be created)
5. Update this README with the new function

---

## 📚 Related Documentation

- [config.py Documentation](../config.py) - Application configuration
- [BasePage Documentation](../pages/base_page.py) - Base page object
- [Test Data Management](../tests/test_data.py) - Centralized test data

---

**Remember**: The goal is to make this framework work on **ANY web application** with minimal changes. Keep utils universal! 🌍
