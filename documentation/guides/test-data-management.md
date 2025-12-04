# Test Data Management Guide

Complete guide for generating consistent, realistic test data using DataFactory and specialized generators.

## Overview

The Test Data Management Module provides professional data generation tools:

- **DataFactory** - Central factory for common data types
- **UserGenerator** - Advanced user data with personas
- **ProductGenerator** - Category-specific products with variants
- **AddressGenerator** - Address data with type support
- **PaymentGenerator** - Payment card data with validation

## Why Test Data Management?

Benefits:
- **Consistency** - Reproducible test data with seeds
- **Realism** - Data looks and behaves like production data
- **Efficiency** - Generate hundreds of records instantly
- **Flexibility** - Customize any field
- **Validation Testing** - Generate invalid data for testing

## Quick Start

```python
from utils.test_data.data_factory import DataFactory

# Create factory
factory = DataFactory(seed=42)

# Generate user
user = factory.generate_user()
print(user["username"], user["email"])

# Generate product
product = factory.generate_product()
print(product["name"], product["price"])

# Generate batch
users = factory.generate_batch('generate_user', count=100)
```

## DataFactory

### Initialization

```python
from utils.test_data.data_factory import DataFactory

# Default (English locale)
factory = DataFactory()

# Spanish locale
factory = DataFactory(locale='es_ES')

# With seed for reproducibility
factory = DataFactory(seed=42)
```

### User Generation

```python
# Basic user
user = factory.generate_user()
# Returns: {username, email, first_name, last_name, full_name, phone, password}

# User without password
user = factory.generate_user(include_password=False)

# User with custom fields
user = factory.generate_user(
    username="john_doe",
    email="john@example.com",
    age=25,
    custom_field="value"
)
```

### Product Generation

```python
# Basic product
product = factory.generate_product()
# Returns: {name, description, category, price, sku, stock, brand}

# Product in specific category
product = factory.generate_product(category="Electronics")

# Product with custom price
product = factory.generate_product(price=99.99)
```

### Address Generation

```python
# Basic address
address = factory.generate_address()
# Returns: {street, city, state, postal_code, country, latitude, longitude}

# Address in specific country
address = factory.generate_address(country="United States")
```

### Payment Card Generation

```python
# Random card type
card = factory.generate_payment_card()

# Specific card type
card = factory.generate_payment_card(card_type="visa")
card = factory.generate_payment_card(card_type="mastercard")
```

### Company Generation

```python
company = factory.generate_company()
# Returns: {name, suffix, slogan, website, email, phone, tax_id}
```

### Order Generation

```python
# Order with 3 items
order = factory.generate_order()

# Order with specific number of items
order = factory.generate_order(num_items=10, user_id=123)
# Returns: {order_id, user_id, items[], total, status, created_at}
```

### Batch Generation

```python
# Generate 100 users
users = factory.generate_batch('generate_user', count=100)

# Generate 50 products with custom category
products = factory.generate_batch(
    'generate_product',
    count=50,
    category="Electronics"
)
```

### Unique Generation

```python
# Generate 100 unique emails
emails = factory.generate_unique_emails(count=100)

# Generate 50 unique usernames
usernames = factory.generate_unique_usernames(count=50)
```

### Reproducible Data

```python
# Create factory with seed
factory = DataFactory(seed=42)

# Generate data
user1 = factory.generate_user()

# Reset seed
factory.reset_seed(42)

# Generate again - will be identical
user2 = factory.generate_user()

assert user1 == user2
```

### Convenience Methods

```python
# Random integer
num = factory.random_int(min=1, max=100)

# Random float
price = factory.random_float(min=10.0, max=1000.0, decimals=2)

# Random date
date = factory.random_date(start_date='-1y', end_date='today')

# Random text
description = factory.random_text(max_chars=200)

# Random choice
status = factory.random_choice(['active', 'inactive', 'pending'])

# Random boolean
is_active = factory.random_boolean()
```

## UserGenerator

Advanced user generation with personas and validation data.

### Basic Usage

```python
from utils.test_data.generators import UserGenerator

user_gen = UserGenerator()

# Generate user
user = user_gen.generate()
```

### User Personas

```python
# Admin user
admin = user_gen.generate(persona='admin')
# Returns: {role: 'admin', permissions: [...], is_staff: True, ...}

# Premium customer
premium = user_gen.generate(persona='premium')
# Returns: {role: 'premium_customer', subscription: 'premium', ...}

# Guest user
guest = user_gen.generate(persona='guest')
# Returns: {role: 'guest', is_verified: False, ...}

# Regular customer (default)
customer = user_gen.generate(persona='customer')
```

### Profile Completeness

```python
# Minimal profile (username, email, password only)
minimal = user_gen.generate(profile_completeness='minimal')

# Basic profile (adds phone, date_of_birth)
basic = user_gen.generate(profile_completeness='basic')

# Complete profile (adds bio, avatar, timezone, language)
complete = user_gen.generate(profile_completeness='complete')
```

### Validation Testing

```python
# Valid credentials
credentials = user_gen.generate_valid_credentials()
# Returns: {username, password}

# Invalid email for testing validation
invalid_email = user_gen.generate_invalid_email()
# Returns: "notanemail", "@example.com", etc.

# Weak password for testing validation
weak_pass = user_gen.generate_weak_password()
# Returns: "123456", "password", etc.
```

## ProductGenerator

Category-specific product generation with variants.

### Basic Usage

```python
from utils.test_data.generators import ProductGenerator

product_gen = ProductGenerator()

# Generate product
product = product_gen.generate()
```

### Category-Specific Products

```python
# Electronics (price range: $100-$2000)
electronics = product_gen.generate(category='electronics')

# Clothing (price range: $20-$200)
clothing = product_gen.generate(category='clothing')

# Books (price range: $10-$50)
books = product_gen.generate(category='books')
```

### Stock Control

```python
# In-stock product
in_stock = product_gen.generate(in_stock=True)
assert in_stock['stock'] > 0

# Out-of-stock product
out_of_stock = product_gen.generate(in_stock=False)
assert out_of_stock['stock'] == 0
```

### Product Variants

```python
# Product with 5 color/size variants
product = product_gen.generate_with_variants(num_variants=5)

# Each variant has: {color, size, sku, stock, price_adjustment}
for variant in product['variants']:
    print(f"{variant['color']} - {variant['size']}")
```

## AddressGenerator

Address generation with type support.

### Basic Usage

```python
from utils.test_data.generators import AddressGenerator

address_gen = AddressGenerator()

# Generate address
address = address_gen.generate()
```

### Address Types

```python
# Shipping address (includes delivery instructions)
shipping = address_gen.generate(address_type='shipping')

# Billing address
billing = address_gen.generate(address_type='billing')

# Business address (includes company name)
business = address_gen.generate(address_type='business')
```

### Address Pairs

```python
# Generate billing and shipping together
addresses = address_gen.generate_pair()

billing_addr = addresses['billing']
shipping_addr = addresses['shipping']
```

## PaymentGenerator

Payment card generation with validation support.

### Basic Usage

```python
from utils.test_data.generators import PaymentGenerator

payment_gen = PaymentGenerator()

# Generate card
card = payment_gen.generate_card()
```

### Card Types

```python
# Specific card types
visa = payment_gen.generate_card(card_type='visa')
mastercard = payment_gen.generate_card(card_type='mastercard')
amex = payment_gen.generate_card(card_type='amex')
discover = payment_gen.generate_card(card_type='discover')
```

### Expired Cards

```python
# Generate expired card for testing
expired = payment_gen.generate_card(expired=True)
```

### Invalid Card

```python
# Invalid card for validation testing
invalid = payment_gen.generate_invalid_card()
# Returns: {number: '1234567890123456', expire_date: '00/00', ...}
```

### Payment Methods

```python
# Credit card
card = payment_gen.generate_payment_method(method_type='card')

# PayPal
paypal = payment_gen.generate_payment_method(method_type='paypal')
# Returns: {type: 'paypal', email: '...', verified: True}

# Bank transfer
bank = payment_gen.generate_payment_method(method_type='bank_transfer')
# Returns: {type: 'bank_transfer', account_number: '...', ...}
```

## Complete Test Examples

### User Registration Test

```python
import pytest
from utils.test_data.data_factory import DataFactory

@pytest.fixture
def test_data():
    return DataFactory(seed=42)

def test_user_registration(driver, test_data):
    """Test user registration with generated data."""
    # Generate user data
    user = test_data.generate_user()

    # Navigate to registration
    driver.get("https://example.com/register")

    # Fill form
    driver.find_element(By.ID, "username").send_keys(user['username'])
    driver.find_element(By.ID, "email").send_keys(user['email'])
    driver.find_element(By.ID, "password").send_keys(user['password'])

    # Submit
    driver.find_element(By.ID, "submit").click()

    # Verify
    success = driver.find_element(By.CLASS_NAME, "success-message")
    assert success.is_displayed()
```

### E-commerce Checkout Test

```python
from utils.test_data.generators import AddressGenerator, PaymentGenerator

def test_checkout_flow(driver):
    """Test complete checkout with generated data."""
    address_gen = AddressGenerator()
    payment_gen = PaymentGenerator()

    # Generate data
    addresses = address_gen.generate_pair()
    card = payment_gen.generate_card(card_type='visa')

    # Add items to cart and proceed to checkout
    driver.get("https://example.com/checkout")

    # Fill shipping address
    shipping = addresses['shipping']
    driver.find_element(By.ID, "ship_street").send_keys(shipping['street'])
    driver.find_element(By.ID, "ship_city").send_keys(shipping['city'])
    # ... fill remaining fields

    # Fill payment
    driver.find_element(By.ID, "card_number").send_keys(card['number'])
    driver.find_element(By.ID, "card_name").send_keys(card['cardholder_name'])
    # ... fill remaining fields

    # Complete order
    driver.find_element(By.ID, "place_order").click()
```

### API Testing with Generated Data

```python
from utils.api.api_client import APIClient
from utils.test_data.data_factory import DataFactory

def test_create_user_api():
    """Test user creation API with generated data."""
    client = APIClient(base_url="https://api.example.com")
    factory = DataFactory()

    # Generate user data
    user = factory.generate_user()

    # Send API request
    response = client.post("/users", json=user)

    # Verify
    assert response.status_code == 201
    data = response.json()
    assert data['username'] == user['username']
```

### Data-Driven Testing

```python
import pytest
from utils.test_data.data_factory import DataFactory

@pytest.fixture
def test_users():
    """Generate 10 test users."""
    factory = DataFactory()
    return factory.generate_batch('generate_user', count=10)

@pytest.mark.parametrize("user_index", range(10))
def test_login_with_multiple_users(driver, test_users, user_index):
    """Test login with multiple generated users."""
    user = test_users[user_index]

    driver.get("https://example.com/login")
    driver.find_element(By.ID, "username").send_keys(user['username'])
    driver.find_element(By.ID, "password").send_keys(user['password'])
    driver.find_element(By.ID, "submit").click()

    # Verify login
    assert "dashboard" in driver.current_url
```

### Database Testing

```python
from utils.database.query_executor import QueryExecutor
from utils.test_data.data_factory import DataFactory

def test_user_crud_with_generated_data(db_connection):
    """Test database operations with generated data."""
    executor = QueryExecutor(db_connection)
    factory = DataFactory()

    # Generate user
    user = factory.generate_user()

    # Insert
    executor.insert("users", {
        "username": user['username'],
        "email": user['email'],
        "first_name": user['first_name']
    })

    # Query
    result = executor.select_one("users", {"username": user['username']})

    # Verify
    assert result['email'] == user['email']
```

## Best Practices

### 1. Use Seeds for Reproducibility

```python
# In conftest.py
@pytest.fixture(scope="session")
def data_factory():
    """Shared data factory with fixed seed."""
    return DataFactory(seed=42)
```

### 2. Generate Data at Test Level

```python
def test_feature(data_factory):
    """Generate fresh data for each test."""
    user = data_factory.generate_user()
    # Use user in test
```

### 3. Customize When Needed

```python
# Override specific fields
user = factory.generate_user(
    email="specific@example.com",
    role="admin"
)
```

### 4. Use Specialized Generators

```python
# For complex scenarios
from utils.test_data.generators import UserGenerator

user_gen = UserGenerator()
admin = user_gen.generate(persona='admin', profile_completeness='complete')
```

### 5. Batch Generate for Performance

```python
# Generate 1000 users at once
users = factory.generate_batch('generate_user', count=1000)

# Use for load testing, database population, etc.
```

## Advanced Patterns

### Custom Generator

```python
class OrderGenerator:
    """Custom generator for orders."""

    def __init__(self, data_factory):
        self.factory = data_factory

    def generate_complete_order(self):
        """Generate order with user, products, and payment."""
        return {
            'user': self.factory.generate_user(),
            'products': self.factory.generate_batch('generate_product', count=5),
            'shipping_address': self.factory.generate_address(),
            'payment': self.factory.generate_payment_card(),
            'order_id': self.factory.faker.uuid4()
        }
```

### Locale-Specific Testing

```python
@pytest.mark.parametrize("locale", ['en_US', 'es_ES', 'fr_FR', 'de_DE'])
def test_localized_user_registration(locale):
    """Test registration with locale-specific data."""
    factory = DataFactory(locale=locale)
    user = factory.generate_user()

    # Test with localized data
```

### Test Data Fixtures

```python
# conftest.py
import pytest
from utils.test_data.data_factory import DataFactory

@pytest.fixture
def admin_user():
    """Generate admin user."""
    from utils.test_data.generators import UserGenerator
    return UserGenerator().generate(persona='admin')

@pytest.fixture
def sample_products():
    """Generate sample products."""
    factory = DataFactory()
    return factory.generate_batch('generate_product', count=20)
```

## Integration with Other Modules

### With API Testing

```python
from utils.api.api_client import APIClient
from utils.test_data.data_factory import DataFactory

def test_api_with_generated_data():
    client = APIClient(base_url="https://api.example.com")
    factory = DataFactory()

    # Generate and send
    user = factory.generate_user()
    response = client.post("/users", json=user)

    assert response.status_code == 201
```

### With Database Testing

```python
from utils.database.query_executor import QueryExecutor
from utils.test_data.data_factory import DataFactory

def test_db_with_generated_data(db_connection):
    executor = QueryExecutor(db_connection)
    factory = DataFactory()

    # Generate and insert 100 users
    users = factory.generate_batch('generate_user', count=100)

    for user in users:
        executor.insert("users", user)

    # Verify
    count = executor.count("users")
    assert count == 100
```

## Running Tests

```bash
# Run test data tests
pytest tests/test_data/ -v

# Run with marker
pytest -m test_data -v
```

## Troubleshooting

### Issue: Data Not Reproducible

**Problem**: Same seed produces different data

**Solution**: Ensure seed is set before ANY generation
```python
factory = DataFactory(seed=42)  # Set seed at initialization
```

### Issue: Locale Not Working

**Problem**: Data doesn't match expected locale

**Solution**: Check locale string format
```python
# Correct formats
DataFactory(locale='en_US')
DataFactory(locale='es_ES')
DataFactory(locale='pt_BR')
```

### Issue: Generated Data Fails Validation

**Problem**: Email format rejected by application

**Solution**: Use custom values for strict validation
```python
user = factory.generate_user(email="valid.email@example.com")
```

## Requirements

Already included in requirements.txt:
```bash
Faker==33.1.0
```
