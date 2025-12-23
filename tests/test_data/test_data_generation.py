"""
Test Data Generation Examples
Demonstrates test data generation with DataFactory and specialized generators.

Author: Marc Arévalo
Version: 1.0

These tests demonstrate:
- Basic data generation
- Reproducible data with seeds
- Batch generation
- Specialized generators
- Custom data generation
"""

import pytest

from utils.test_data.data_factory import DataFactory
from utils.test_data.generators import (
    AddressGenerator,
    PaymentGenerator,
    ProductGenerator,
    UserGenerator,
)


@pytest.fixture
def data_factory():
    """Create data factory with fixed seed for reproducibility."""
    return DataFactory(seed=42)


@pytest.fixture
def user_generator():
    """Create user generator."""
    return UserGenerator()


@pytest.fixture
def product_generator():
    """Create product generator."""
    return ProductGenerator()


@pytest.fixture
def address_generator():
    """Create address generator."""
    return AddressGenerator()


@pytest.fixture
def payment_generator():
    """Create payment generator."""
    return PaymentGenerator()


@pytest.mark.test_data
def test_generate_user(data_factory):
    """
    TC-DATA-001: Test basic user generation.

    Validates user data structure and required fields.
    """
    user = data_factory.generate_user()

    # Validate required fields
    assert "username" in user
    assert "email" in user
    assert "first_name" in user
    assert "last_name" in user
    assert "password" in user
    assert "@" in user["email"]
    assert len(user["password"]) >= 12


@pytest.mark.test_data
def test_generate_user_without_password(data_factory):
    """
    TC-DATA-002: Test user generation without password.

    For cases where password is not needed.
    """
    user = data_factory.generate_user(include_password=False)

    assert "password" not in user
    assert "username" in user
    assert "email" in user


@pytest.mark.test_data
def test_generate_user_with_custom_fields(data_factory):
    """
    TC-DATA-003: Test user generation with custom fields.

    Validates custom field override.
    """
    custom_email = "test@example.com"
    user = data_factory.generate_user(email=custom_email, custom_field="value")

    assert user["email"] == custom_email
    assert user["custom_field"] == "value"


@pytest.mark.test_data
def test_generate_product(data_factory):
    """
    TC-DATA-004: Test product generation.

    Validates product data structure.
    """
    product = data_factory.generate_product()

    assert "name" in product
    assert "description" in product
    assert "category" in product
    assert "price" in product
    assert "sku" in product
    assert product["price"] > 0


@pytest.mark.test_data
def test_generate_address(data_factory):
    """
    TC-DATA-005: Test address generation.

    Validates address data structure.
    """
    address = data_factory.generate_address()

    assert "street" in address
    assert "city" in address
    assert "state" in address
    assert "postal_code" in address
    assert "country" in address


@pytest.mark.test_data
def test_generate_payment_card(data_factory):
    """
    TC-DATA-006: Test payment card generation.

    Validates card data structure.
    """
    card = data_factory.generate_payment_card()

    assert "number" in card
    assert "provider" in card
    assert "expire_date" in card
    assert "security_code" in card
    assert len(card["number"]) >= 13


@pytest.mark.test_data
def test_generate_batch_users(data_factory):
    """
    TC-DATA-007: Test batch user generation.

    Validates generating multiple users at once.
    """
    users = data_factory.generate_batch("generate_user", count=10)

    assert len(users) == 10
    assert all("username" in user for user in users)

    # Usernames should be unique (usually)
    usernames = [user["username"] for user in users]
    assert len(set(usernames)) >= 8  # Allow some collisions


@pytest.mark.test_data
def test_reproducible_data_with_seed(data_factory):
    """
    TC-DATA-008: Test reproducible data generation.

    Validates seed produces consistent results.
    """
    # Generate with seed
    user1 = data_factory.generate_user()

    # Reset seed and generate again
    data_factory.reset_seed(42)
    user2 = data_factory.generate_user()

    # Should be identical
    assert user1["username"] == user2["username"]
    assert user1["email"] == user2["email"]


@pytest.mark.test_data
def test_generate_unique_emails(data_factory):
    """
    TC-DATA-009: Test unique email generation.

    Validates all generated emails are unique.
    """
    emails = data_factory.generate_unique_emails(count=50)

    assert len(emails) == 50
    assert len(set(emails)) == 50  # All unique


@pytest.mark.test_data
def test_user_generator_personas(user_generator):
    """
    TC-DATA-010: Test user generator personas.

    Validates different user types.
    """
    # Admin user
    admin = user_generator.generate(persona="admin")
    assert admin["role"] == "admin"
    assert admin["is_staff"] is True

    # Premium user
    premium = user_generator.generate(persona="premium")
    assert premium["role"] == "premium_customer"
    assert "subscription" in premium

    # Guest user
    guest = user_generator.generate(persona="guest")
    assert guest["role"] == "guest"


@pytest.mark.test_data
def test_user_profile_completeness(user_generator):
    """
    TC-DATA-011: Test user profile completeness levels.

    Validates different profile levels.
    """
    # Minimal profile
    minimal = user_generator.generate(profile_completeness="minimal")
    assert "phone" not in minimal

    # Complete profile
    complete = user_generator.generate(profile_completeness="complete")
    assert "phone" in complete
    assert "bio" in complete
    assert "avatar_url" in complete


@pytest.mark.test_data
def test_generate_invalid_email(user_generator):
    """
    TC-DATA-012: Test invalid email generation.

    For testing validation logic.
    """
    invalid_email = user_generator.generate_invalid_email()

    # Should be one of the invalid patterns
    assert "@" not in invalid_email or invalid_email.startswith("@")


@pytest.mark.test_data
def test_generate_weak_password(user_generator):
    """
    TC-DATA-013: Test weak password generation.

    For testing password validation.
    """
    weak_password = user_generator.generate_weak_password()

    assert len(weak_password) <= 8


@pytest.mark.test_data
def test_product_generator_categories(product_generator):
    """
    TC-DATA-014: Test product generation by category.

    Validates category-specific products.
    """
    # Electronics
    electronics = product_generator.generate(category="electronics")
    assert electronics["category"] == "electronics"
    assert 100 <= electronics["price"] <= 2000

    # Clothing
    clothing = product_generator.generate(category="clothing")
    assert clothing["category"] == "clothing"
    assert 20 <= clothing["price"] <= 200


@pytest.mark.test_data
def test_product_with_variants(product_generator):
    """
    TC-DATA-015: Test product with variants.

    Validates product variant generation.
    """
    product = product_generator.generate_with_variants(num_variants=5)

    assert "variants" in product
    assert len(product["variants"]) == 5

    for variant in product["variants"]:
        assert "color" in variant
        assert "size" in variant
        assert "sku" in variant


@pytest.mark.test_data
def test_out_of_stock_product(product_generator):
    """
    TC-DATA-016: Test out-of-stock product generation.

    Validates stock level control.
    """
    product = product_generator.generate(in_stock=False)

    assert product["stock"] == 0


@pytest.mark.test_data
def test_address_types(address_generator):
    """
    TC-DATA-017: Test different address types.

    Validates address type variations.
    """
    # Shipping address
    shipping = address_generator.generate(address_type="shipping")
    assert shipping["type"] == "shipping"
    assert "delivery_instructions" in shipping

    # Billing address
    billing = address_generator.generate(address_type="billing")
    assert billing["type"] == "billing"

    # Business address
    business = address_generator.generate(address_type="business")
    assert business["type"] == "business"
    assert "company_name" in business


@pytest.mark.test_data
def test_address_pair(address_generator):
    """
    TC-DATA-018: Test billing/shipping address pair.

    Validates generating both addresses together.
    """
    addresses = address_generator.generate_pair()

    assert "billing" in addresses
    assert "shipping" in addresses
    assert addresses["billing"]["type"] == "billing"
    assert addresses["shipping"]["type"] == "shipping"


@pytest.mark.test_data
def test_payment_card_types(payment_generator):
    """
    TC-DATA-019: Test different card types.

    Validates card type generation.
    """
    # Visa
    visa = payment_generator.generate_card(card_type="visa")
    assert visa["provider"] == "visa"

    # Mastercard
    mastercard = payment_generator.generate_card(card_type="mastercard")
    assert mastercard["provider"] == "mastercard"


@pytest.mark.test_data
def test_expired_card(payment_generator):
    """
    TC-DATA-020: Test expired card generation.

    For testing expiration validation.
    """
    expired_card = payment_generator.generate_card(expired=True)

    assert "expire_date" in expired_card
    # Expired cards have past dates (cannot easily validate format)


@pytest.mark.test_data
def test_invalid_card(payment_generator):
    """
    TC-DATA-021: Test invalid card generation.

    For testing card validation.
    """
    invalid_card = payment_generator.generate_invalid_card()

    assert invalid_card["number"] == "1234567890123456"
    assert invalid_card["expire_date"] == "00/00"


@pytest.mark.test_data
def test_payment_methods(payment_generator):
    """
    TC-DATA-022: Test different payment methods.

    Validates multiple payment types.
    """
    # Credit card
    card = payment_generator.generate_payment_method(method_type="card")
    assert "number" in card

    # PayPal
    paypal = payment_generator.generate_payment_method(method_type="paypal")
    assert paypal["type"] == "paypal"
    assert "email" in paypal

    # Bank transfer
    bank = payment_generator.generate_payment_method(
        method_type="bank_transfer"
    )
    assert bank["type"] == "bank_transfer"
    assert "account_number" in bank


@pytest.mark.test_data
def test_generate_company(data_factory):
    """
    TC-DATA-023: Test company data generation.

    Validates company data structure.
    """
    company = data_factory.generate_company()

    assert "name" in company
    assert "website" in company
    assert "email" in company
    assert "phone" in company


@pytest.mark.test_data
def test_generate_order(data_factory):
    """
    TC-DATA-024: Test order generation.

    Validates order with items.
    """
    order = data_factory.generate_order(num_items=5)

    assert "order_id" in order
    assert "items" in order
    assert len(order["items"]) == 5
    assert "total" in order
    assert order["total"] > 0


@pytest.mark.test_data
def test_convenience_methods(data_factory):
    """
    TC-DATA-025: Test convenience methods.

    Validates helper methods.
    """
    # Random int
    num = data_factory.random_int(min=1, max=10)
    assert 1 <= num <= 10

    # Random float
    price = data_factory.random_float(min=10.0, max=100.0, decimals=2)
    assert 10.0 <= price <= 100.0

    # Random choice
    colors = ["red", "blue", "green"]
    color = data_factory.random_choice(colors)
    assert color in colors

    # Random boolean
    flag = data_factory.random_boolean()
    assert isinstance(flag, bool)


@pytest.mark.test_data
def test_locale_support(data_factory):
    """
    TC-DATA-026: Test locale support.

    Validates localized data generation.
    """
    # Spanish locale
    es_factory = DataFactory(locale="es_ES")
    user = es_factory.generate_user()

    # Should generate data (validation of format is complex)
    assert "username" in user
    assert "email" in user


@pytest.mark.test_data
@pytest.mark.integration
def test_data_factory_in_test_workflow(data_factory, driver):
    """
    TC-DATA-027: Test data factory in complete test workflow.

    Demonstrates using generated data in actual tests.
    """
    # Generate test user
    user = data_factory.generate_user()

    # Navigate to registration page
    driver.get("https://your-application-url.com")

    # In a real test, you would fill the form with generated data
    # This demonstrates the workflow
    assert user["username"] is not None
    assert user["email"] is not None
    assert user["password"] is not None

    # Generated data is ready to use in form filling, API calls, etc.
