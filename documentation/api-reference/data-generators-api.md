# Data Generators API Reference

Test data generation utilities.

**File:** `utils/helpers/data_generator.py`
**Version:** 1.0
**Author:** Marc Arévalo

## Overview

Data generators provide functions for creating unique, random test data. All functions are universal and reusable across any web application.

**Total Functions:** 7

---

## Functions

### generate_unique_username(prefix="testuser", length=4)

Generate a unique username for testing with timestamp and random suffix.

**Signature:**
```python
def generate_unique_username(prefix: str = "testuser", length: int = 4) -> str:
```

**Parameters:**
- `prefix` (str): Username prefix. Default: "testuser"
- `length` (int): Length of random suffix. Default: 4

**Returns:**
- `str`: Unique username (e.g., "testuser_1701234567_a1b2")

**Format:**
- `{prefix}_{timestamp}_{random_suffix}`
- Timestamp: Unix timestamp (10 digits)
- Random suffix: Lowercase letters + digits

**Example:**
```python
from utils.helpers.data_generator import generate_unique_username

# Default
username = generate_unique_username()
# Returns: "testuser_1701234567_a1b2"

# Custom prefix
username = generate_unique_username(prefix="qa_user")
# Returns: "qa_user_1701234567_x9z3"

# Longer random suffix
username = generate_unique_username(length=8)
# Returns: "testuser_1701234567_abc12345"
```

**Location:** data_generator.py:16-37

---

### generate_random_password(length=12, include_uppercase=True, include_numbers=True, include_special=True)

Generate a random password for testing.

**Signature:**
```python
def generate_random_password(
    length: int = 12,
    include_uppercase: bool = True,
    include_numbers: bool = True,
    include_special: bool = True,
) -> str:
```

**Parameters:**
- `length` (int): Password length. Default: 12
- `include_uppercase` (bool): Include uppercase letters. Default: True
- `include_numbers` (bool): Include numbers. Default: True
- `include_special` (bool): Include special characters. Default: True

**Returns:**
- `str`: Random password string

**Character Sets:**
- Lowercase: always included
- Uppercase: A-Z (if enabled)
- Numbers: 0-9 (if enabled)
- Special: `!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~` (if enabled)

**Example:**
```python
from utils.helpers.data_generator import generate_random_password

# Default - all character types
password = generate_random_password()
# Returns: "aB3!xY9@pQ1#" (12 chars)

# Custom length
password = generate_random_password(length=16)
# Returns: "Ab3!xY9@pQ1#Zz4$" (16 chars)

# Lowercase + numbers only
password = generate_random_password(
    include_uppercase=False,
    include_special=False
)
# Returns: "a3xy9pq1z4" (12 chars)

# Simple password
password = generate_random_password(
    length=8,
    include_special=False
)
# Returns: "Abc12345" (8 chars)
```

**Location:** data_generator.py:39-71

---

### generate_random_email(domain="testmail.com")

Generate a random email address for testing.

**Signature:**
```python
def generate_random_email(domain: str = "testmail.com") -> str:
```

**Parameters:**
- `domain` (str): Email domain. Default: "testmail.com"

**Returns:**
- `str`: Random email address

**Format:**
- `{unique_username}@{domain}`
- Username generated using `generate_unique_username()`

**Example:**
```python
from utils.helpers.data_generator import generate_random_email

# Default domain
email = generate_random_email()
# Returns: "testuser_1701234567_a1b2@testmail.com"

# Custom domain
email = generate_random_email(domain="example.org")
# Returns: "testuser_1701234567_x9z3@example.org"

# Use in test
def test_signup(signup_page):
    email = generate_random_email()
    signup_page.register(email=email, password="Pass123!")
```

**Location:** data_generator.py:73-90

---

### generate_credit_card_number(card_type="visa")

Generate a test credit card number (Luhn algorithm valid).

**Signature:**
```python
def generate_credit_card_number(card_type: str = "visa") -> str:
```

**Parameters:**
- `card_type` (str): Card type - "visa", "mastercard", "amex". Default: "visa"

**Returns:**
- `str`: Test credit card number string

**Supported Cards:**
- **Visa:** "4532015112830366" (16 digits)
- **Mastercard:** "5425233430109903" (16 digits)
- **American Express:** "374245455400126" (15 digits)

**Note:**
- These are TEST ONLY numbers
- NEVER use for real transactions
- All numbers pass Luhn algorithm validation

**Example:**
```python
from utils.helpers.data_generator import generate_credit_card_number

# Visa (default)
card = generate_credit_card_number()
# Returns: "4532015112830366"

# Mastercard
card = generate_credit_card_number("mastercard")
# Returns: "5425233430109903"

# American Express
card = generate_credit_card_number("amex")
# Returns: "374245455400126"

# Use in test
def test_checkout(purchase_page):
    card = generate_credit_card_number("visa")
    purchase_page.fill_card_number(card)
```

**Location:** data_generator.py:92-116

---

### generate_random_string(length=10, charset=None)

Generate a random string of specified length.

**Signature:**
```python
def generate_random_string(
    length: int = 10, charset: Optional[str] = None
) -> str:
```

**Parameters:**
- `length` (int): Length of string. Default: 10
- `charset` (Optional[str]): Character set to use. Default: ascii letters + digits

**Returns:**
- `str`: Random string

**Default Charset:**
- `string.ascii_letters` + `string.digits`
- "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

**Example:**
```python
from utils.helpers.data_generator import generate_random_string
import string

# Default - letters + digits
random_str = generate_random_string()
# Returns: "aB3xY9pQ1z" (10 chars)

# Custom length
random_str = generate_random_string(length=20)
# Returns: "aB3xY9pQ1zKm4Lv7Nw2T" (20 chars)

# Lowercase only
random_str = generate_random_string(
    length=8,
    charset=string.ascii_lowercase
)
# Returns: "abcdefgh" (8 chars)

# Numbers only
random_str = generate_random_string(
    length=6,
    charset=string.digits
)
# Returns: "123456" (6 chars)

# Use in test
def test_comment(page):
    comment = generate_random_string(length=50)
    page.submit_comment(comment)
```

**Location:** data_generator.py:118-139

---

## Usage Patterns

### Pattern 1: User Registration Test Data

```python
from utils.helpers.data_generator import (
    generate_unique_username,
    generate_random_password,
    generate_random_email
)

def test_user_registration(signup_page):
    # Generate complete user data
    username = generate_unique_username(prefix="qa_user")
    email = generate_random_email(domain="test.qa")
    password = generate_random_password(length=16)

    # Register user
    signup_page.register(
        username=username,
        email=email,
        password=password
    )

    assert signup_page.is_registration_successful()
```

### Pattern 2: Purchase Test Data

```python
from utils.helpers.data_generator import (
    generate_credit_card_number,
    generate_random_string
)

def test_checkout(purchase_page):
    # Generate purchase data
    purchase_data = {
        "name": generate_random_string(length=15),
        "country": "United States",
        "city": generate_random_string(length=10),
        "card": generate_credit_card_number("visa"),
        "month": "12",
        "year": "2025"
    }

    purchase_page.fill_form(**purchase_data)
    purchase_page.confirm_purchase()
```

### Pattern 3: Combining with Fixtures

```python
import pytest
from utils.helpers.data_generator import generate_unique_username

@pytest.fixture
def unique_user():
    """Generate unique user for each test."""
    return {
        "username": generate_unique_username(),
        "password": generate_random_password(length=12)
    }

def test_signup(signup_page, unique_user):
    signup_page.signup(**unique_user)
    assert signup_page.is_signup_successful()

def test_login(login_page, unique_user):
    # Different unique user for this test
    login_page.login(**unique_user)
```

### Pattern 4: Data-Driven Testing

```python
import pytest
from utils.helpers.data_generator import generate_random_password

@pytest.mark.parametrize("length", [8, 12, 16, 20])
def test_password_lengths(signup_page, length):
    """Test signup with different password lengths."""
    password = generate_random_password(length=length)
    username = generate_unique_username()

    signup_page.signup(username=username, password=password)
    assert signup_page.is_signup_successful()
```

---

## Best Practices

1. **Use unique usernames to avoid conflicts:**
```python
# Good - prevents conflicts
username = generate_unique_username()

# Bad - same username in every test
username = "testuser123"
```

2. **Generate strong passwords for security tests:**
```python
# Strong password for security testing
password = generate_random_password(
    length=16,
    include_uppercase=True,
    include_numbers=True,
    include_special=True
)

# Weak password for negative testing
weak_password = generate_random_password(
    length=6,
    include_uppercase=False,
    include_special=False
)
```

3. **Use appropriate card types for payment tests:**
```python
@pytest.mark.parametrize("card_type", ["visa", "mastercard", "amex"])
def test_payment_card_types(purchase_page, card_type):
    card = generate_credit_card_number(card_type)
    purchase_page.enter_card_number(card)
    assert purchase_page.is_card_valid()
```

4. **Keep generated data in test scope:**
```python
def test_user_flow():
    # Generate data within test for clarity
    username = generate_unique_username()
    email = generate_random_email()

    # Use data
    signup_page.register(username, email)
```

---

## Security Notes

**Credit Card Numbers:**
- Only use generated credit cards for UI testing
- Never store or transmit to real payment processors
- Not valid for actual transactions

**Generated Passwords:**
- Use only for test accounts
- Not cryptographically secure for production
- Suitable for functional testing only

**Email Addresses:**
- Use test domains (e.g., "testmail.com")
- Avoid real email providers
- Consider using disposable email services

---

## Related Documentation

- [Validators API](validators-api.md) - Validate generated data
- [Fixtures API](fixtures-api.md) - Use generators in fixtures
- [Test Data Guide](../guides/test-fixtures.md) - Managing test data
