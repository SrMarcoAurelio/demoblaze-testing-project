# Validators API Reference

Data validation utilities for business logic testing.

**File:** `utils/helpers/validators.py`
**Version:** 1.0
**Author:** Marc Arévalo

## Overview

Validators provide functions for validating data formats and business rules. All validators are universal and reusable across any web application.

**Total Functions:** 9

---

## Email & URL Validation

### validate_email(email)

Validate email address format.

**Signature:**
```python
def validate_email(email: str) -> bool:
```

**Parameters:**
- `email` (str): Email address to validate

**Returns:**
- `bool`: True if valid email format, False otherwise

**Validation Rules:**
- Standard email pattern: `username@domain.tld`
- Username: letters, numbers, `._%+-`
- Domain: letters, numbers, `.`-`
- TLD: at least 2 letters

**Example:**
```python
from utils.helpers.validators import validate_email

# Valid emails
assert validate_email("user@example.com") == True
assert validate_email("test.user+tag@domain.co.uk") == True

# Invalid emails
assert validate_email("invalid.email") == False
assert validate_email("@example.com") == False
assert validate_email("user@") == False

# Use in test
def test_email_validation(signup_page):
    invalid_email = "not-an-email"
    signup_page.enter_email(invalid_email)
    assert not validate_email(invalid_email)
    assert signup_page.has_error_message()
```

**Location:** validators.py:14-35

---

### validate_url(url)

Validate URL format.

**Signature:**
```python
def validate_url(url: str) -> bool:
```

**Parameters:**
- `url` (str): URL to validate

**Returns:**
- `bool`: True if valid URL format, False otherwise

**Validation Rules:**
- Must have scheme (http, https, ftp, etc.)
- Must have netloc (domain/host)

**Example:**
```python
from utils.helpers.validators import validate_url

# Valid URLs
assert validate_url("https://www.example.com") == True
assert validate_url("http://localhost:8080") == True
assert validate_url("ftp://files.example.com/data") == True

# Invalid URLs
assert validate_url("not a url") == False
assert validate_url("example.com") == False  # Missing scheme
assert validate_url("https://") == False  # Missing netloc
```

**Location:** validators.py:37-61

---

## Financial Validation

### validate_credit_card(card_number)

Validate credit card number using Luhn algorithm.

**Signature:**
```python
def validate_credit_card(card_number: str) -> bool:
```

**Parameters:**
- `card_number` (str): Credit card number (can include spaces/dashes)

**Returns:**
- `bool`: True if valid by Luhn algorithm, False otherwise

**Validation Rules:**
1. Removes spaces and dashes
2. Checks all digits
3. Length between 13-19 digits
4. Passes Luhn algorithm checksum

**Example:**
```python
from utils.helpers.validators import validate_credit_card

# Valid credit cards
assert validate_credit_card("4532015112830366") == True  # Visa
assert validate_credit_card("5425 2334 3010 9903") == True  # Mastercard with spaces
assert validate_credit_card("3742-4545-5400-126") == True  # Amex with dashes

# Invalid cards
assert validate_credit_card("1234567890123456") == False  # Invalid Luhn
assert validate_credit_card("123") == False  # Too short
assert validate_credit_card("abc123") == False  # Not all digits

# Use in business logic test
def test_card_validation(purchase_page):
    invalid_card = "1234567890123456"
    purchase_page.enter_card_number(invalid_card)

    if not validate_credit_card(invalid_card):
        # Application SHOULD reject invalid card
        assert purchase_page.has_validation_error()
```

**Location:** validators.py:63-99

---

### validate_postal_code(postal_code, country_code="US")

Validate postal/zip code format for different countries.

**Signature:**
```python
def validate_postal_code(postal_code: str, country_code: str = "US") -> bool:
```

**Parameters:**
- `postal_code` (str): Postal code to validate
- `country_code` (str): Country code ("US", "UK", "CA"). Default: "US"

**Returns:**
- `bool`: True if valid format, False otherwise

**Supported Formats:**
- **US:** 12345 or 12345-6789
- **UK:** SW1A 1AA or SW1A1AA
- **CA:** A1A 1A1 or A1A1A1

**Example:**
```python
from utils.helpers.validators import validate_postal_code

# US zip codes
assert validate_postal_code("12345") == True
assert validate_postal_code("12345-6789") == True

# UK postal codes
assert validate_postal_code("SW1A 1AA", "UK") == True
assert validate_postal_code("SW1A1AA", "UK") == True

# Canadian postal codes
assert validate_postal_code("K1A 0B1", "CA") == True

# Invalid
assert validate_postal_code("INVALID", "US") == False
```

**Location:** validators.py:209-234

---

## Contact Information

### validate_phone_number(phone, country_code="US")

Validate phone number format.

**Signature:**
```python
def validate_phone_number(phone: str, country_code: str = "US") -> bool:
```

**Parameters:**
- `phone` (str): Phone number to validate
- `country_code` (str): Country code. Default: "US"

**Returns:**
- `bool`: True if valid format, False otherwise

**US Format:**
- 10 digits
- Optional +1 prefix
- Spaces, dashes, parentheses, dots ignored

**Example:**
```python
from utils.helpers.validators import validate_phone_number

# Valid US numbers
assert validate_phone_number("555-123-4567") == True
assert validate_phone_number("(555) 123-4567") == True
assert validate_phone_number("5551234567") == True
assert validate_phone_number("+1 555 123 4567") == True

# Invalid
assert validate_phone_number("123") == False
assert validate_phone_number("abc-def-ghij") == False
```

**Location:** validators.py:101-124

---

## Authentication Validation

### validate_password_strength(password, min_length=8)

Validate password strength and return detailed feedback.

**Signature:**
```python
def validate_password_strength(password: str, min_length: int = 8) -> dict:
```

**Parameters:**
- `password` (str): Password to validate
- `min_length` (int): Minimum required length. Default: 8

**Returns:**
- `dict`: Validation results dictionary

**Return Dictionary:**
```python
{
    'valid': bool,        # Overall validity
    'score': int,         # Score 0-5
    'feedback': list[str] # List of requirements not met
}
```

**Scoring:**
- +1: Meets minimum length
- +1: Contains lowercase letters
- +1: Contains uppercase letters
- +1: Contains numbers
- +1: Contains special characters
- Valid if: length >= min_length AND score >= 3

**Example:**
```python
from utils.helpers.validators import validate_password_strength

# Strong password
result = validate_password_strength("MyP@ssw0rd")
assert result['valid'] == True
assert result['score'] == 4
assert result['feedback'] == []

# Weak password
result = validate_password_strength("weak")
assert result['valid'] == False
assert result['score'] == 1
assert "at least 8 characters" in result['feedback']
assert "Include uppercase letters" in result['feedback']

# Use in security test
def test_password_requirements(signup_page):
    weak_password = "12345"
    result = validate_password_strength(weak_password)

    signup_page.enter_password(weak_password)

    if not result['valid']:
        # Application SHOULD reject weak password
        assert signup_page.has_password_error()
        print(f"Feedback: {result['feedback']}")
```

**Location:** validators.py:126-182

---

### validate_username(username, min_length=3, max_length=20)

Validate username format and provide feedback.

**Signature:**
```python
def validate_username(
    username: str, min_length: int = 3, max_length: int = 20
) -> dict:
```

**Parameters:**
- `username` (str): Username to validate
- `min_length` (int): Minimum length. Default: 3
- `max_length` (int): Maximum length. Default: 20

**Returns:**
- `dict`: Validation results dictionary

**Return Dictionary:**
```python
{
    'valid': bool,         # Overall validity
    'feedback': list[str]  # List of violations
}
```

**Validation Rules:**
- Length between min_length and max_length
- Only letters, numbers, underscores
- Cannot start with number

**Example:**
```python
from utils.helpers.validators import validate_username

# Valid usernames
result = validate_username("user123")
assert result['valid'] == True
assert result['feedback'] == []

result = validate_username("test_user")
assert result['valid'] == True

# Invalid usernames
result = validate_username("ab")  # Too short
assert result['valid'] == False
assert "at least 3 characters" in result['feedback']

result = validate_username("user@name")  # Invalid character
assert result['valid'] == False
assert "letters, numbers, and underscores" in result['feedback']

result = validate_username("1user")  # Starts with number
assert result['valid'] == False
assert "cannot start with a number" in result['feedback']
```

**Location:** validators.py:236-277

---

## Date Validation

### validate_date_format(date_string, format_pattern=r"^\d{4}-\d{2}-\d{2}$")

Validate date string format.

**Signature:**
```python
def validate_date_format(
    date_string: str, format_pattern: str = r"^\d{4}-\d{2}-\d{2}$"
) -> bool:
```

**Parameters:**
- `date_string` (str): Date string to validate
- `format_pattern` (str): Regex pattern for date format. Default: YYYY-MM-DD

**Returns:**
- `bool`: True if valid format, False otherwise

**Default Pattern:**
- YYYY-MM-DD (ISO 8601)
- Example: "2025-12-03"

**Example:**
```python
from utils.helpers.validators import validate_date_format

# Valid dates (format only, not actual date validity)
assert validate_date_format("2025-11-28") == True
assert validate_date_format("2025-01-01") == True

# Invalid format
assert validate_date_format("28/11/2025") == False
assert validate_date_format("2025-1-1") == False  # Not zero-padded

# Custom pattern - MM/DD/YYYY
us_pattern = r"^\d{2}/\d{2}/\d{4}$"
assert validate_date_format("11/28/2025", us_pattern) == True
assert validate_date_format("2025-11-28", us_pattern) == False
```

**Location:** validators.py:184-207

---

## Usage Patterns

### Pattern 1: Business Logic Testing

```python
from utils.helpers.validators import (
    validate_email,
    validate_credit_card,
    validate_password_strength
)

def test_signup_validation_rules(signup_page):
    """Test that application enforces validation rules."""

    # Test invalid email
    invalid_email = "not-an-email"
    signup_page.enter_email(invalid_email)

    if not validate_email(invalid_email):
        # Application SHOULD show error
        assert signup_page.has_email_error()

    # Test weak password
    weak_password = "123"
    result = validate_password_strength(weak_password)

    signup_page.enter_password(weak_password)

    if not result['valid']:
        # Application SHOULD reject weak password
        assert signup_page.has_password_error()
```

### Pattern 2: Payment Validation Test

```python
from utils.helpers.validators import validate_credit_card

def test_invalid_credit_card_rejected(purchase_page):
    """Test that invalid credit cards are rejected."""

    invalid_cards = [
        "1234567890123456",  # Invalid Luhn
        "123",               # Too short
        "abcd1234efgh5678",  # Non-numeric
    ]

    for card in invalid_cards:
        purchase_page.enter_card_number(card)

        if not validate_credit_card(card):
            # Application SHOULD reject invalid card
            assert purchase_page.has_card_error()
            purchase_page.clear_card_field()
```

### Pattern 3: Data-Driven Validation Testing

```python
import pytest
from utils.helpers.validators import validate_email

@pytest.mark.parametrize("email,expected", [
    ("valid@example.com", True),
    ("user+tag@domain.co", True),
    ("invalid.email", False),
    ("@example.com", False),
    ("user@", False),
])
def test_email_validation_comprehensive(signup_page, email, expected):
    signup_page.enter_email(email)

    is_valid = validate_email(email)
    assert is_valid == expected

    if not is_valid:
        assert signup_page.has_email_error()
    else:
        assert not signup_page.has_email_error()
```

### Pattern 4: Security Testing

```python
from utils.helpers.validators import validate_password_strength

def test_password_strength_requirements(signup_page):
    """Test password strength enforcement per NIST 800-63B."""

    test_cases = [
        ("weak", False),            # Too short, no variety
        ("password", False),        # No uppercase/numbers
        ("Password123", True),      # Meets requirements
        ("P@ssw0rd!123", True),    # Strong password
    ]

    for password, should_be_valid in test_cases:
        result = validate_password_strength(password, min_length=8)

        signup_page.enter_password(password)

        if result['valid']:
            assert should_be_valid
            assert not signup_page.has_password_error()
        else:
            assert not should_be_valid
            assert signup_page.has_password_error()

        signup_page.clear_password_field()
```

---

## Best Practices

1. **Use validators for business logic tests, not just functional tests:**
```python
# Good - tests business rule
def test_email_validation():
    if not validate_email(email):
        assert page.shows_error()  # Application enforces the rule

# Avoid - just tests if feature works
def test_email_field():
    page.enter_email("test@example.com")
    assert page.email_field_has_value()
```

2. **Combine validators with data generators:**
```python
from utils.helpers.data_generator import generate_random_email
from utils.helpers.validators import validate_email

email = generate_random_email()
assert validate_email(email)  # Ensure generator produces valid data
```

3. **Use validator feedback for meaningful assertions:**
```python
result = validate_password_strength(password)
if not result['valid']:
    print(f"Password validation failed: {result['feedback']}")
    assert page.shows_specific_errors(result['feedback'])
```

4. **Test edge cases:**
```python
# Test boundaries
assert validate_username("abc") == True  # Min length
assert validate_username("ab") == False  # Below min
assert validate_username("a" * 20) == True  # Max length
assert validate_username("a" * 21) == False  # Above max
```

---

## Standards References

These validators implement or reference the following standards:

- **Email:** RFC 5322 (simplified pattern)
- **Credit Card:** Luhn Algorithm (ISO/IEC 7812)
- **Password:** NIST 800-63B (Digital Identity Guidelines)
- **Postal Codes:** Country-specific standards

---

## Related Documentation

- [Data Generators API](data-generators-api.md) - Generate test data to validate
- [Test Data Guide](../guides/test-fixtures.md) - Managing test data
- [Security Testing Guide](../templates/security-test-template.md) - Security validation tests
