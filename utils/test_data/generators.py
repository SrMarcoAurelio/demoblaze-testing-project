"""
Specialized Data Generators
Advanced generators for specific entity types.

Author: Marc Arévalo
Version: 1.0
"""

import logging
from typing import Any, Dict, List, Optional

from faker import Faker

logger = logging.getLogger(__name__)


class UserGenerator:
    """
    Advanced user data generator.

    Features:
    - Multiple user personas (admin, customer, guest)
    - Valid/invalid email patterns
    - Password complexity control
    - User profile completeness levels
    """

    def __init__(self, faker: Optional[Faker] = None):
        """
        Initialize user generator.

        Args:
            faker: Faker instance (creates new if None)
        """
        self.faker = faker or Faker()

    def generate(
        self,
        persona: str = "customer",
        profile_completeness: str = "complete",
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Generate user with specified persona.

        Args:
            persona: User type (admin, customer, guest, premium)
            profile_completeness: Profile level (minimal, basic, complete)
            **kwargs: Additional fields

        Returns:
            User data dictionary
        """
        # Base user data
        user = {
            "username": self.faker.user_name(),
            "email": self.faker.email(),
            "first_name": self.faker.first_name(),
            "last_name": self.faker.last_name(),
            "password": self._generate_password(),
        }

        # Add persona-specific fields
        if persona == "admin":
            user.update(
                {
                    "role": "admin",
                    "permissions": ["read", "write", "delete", "admin"],
                    "is_staff": True,
                }
            )
        elif persona == "premium":
            user.update(
                {
                    "role": "premium_customer",
                    "subscription": "premium",
                    "subscription_expires": str(self.faker.future_date()),
                }
            )
        elif persona == "guest":
            user.update({"role": "guest", "is_verified": False})
        else:  # customer
            user.update({"role": "customer", "is_verified": True})

        # Add profile completeness
        if profile_completeness in ["basic", "complete"]:
            user.update(
                {
                    "phone": self.faker.phone_number(),
                    "date_of_birth": str(
                        self.faker.date_of_birth(minimum_age=18)
                    ),
                }
            )

        if profile_completeness == "complete":
            user.update(
                {
                    "bio": self.faker.text(max_nb_chars=200),
                    "avatar_url": self.faker.image_url(),
                    "timezone": self.faker.timezone(),
                    "language": self.faker.language_code(),
                }
            )

        user.update(kwargs)
        return user

    def generate_valid_credentials(self) -> Dict[str, str]:
        """
        Generate valid login credentials.

        Returns:
            Dict with username and password
        """
        return {
            "username": self.faker.user_name(),
            "password": self._generate_password(),
        }

    def generate_invalid_email(self) -> str:
        """
        Generate intentionally invalid email for testing.

        Returns:
            Invalid email string
        """
        invalid_patterns = [
            "notanemail",
            "@example.com",
            "user@",
            "user@.com",
            "user name@example.com",
            "user@example",
        ]
        return self.faker.random_element(invalid_patterns)

    def generate_weak_password(self) -> str:
        """
        Generate weak password for testing validation.

        Returns:
            Weak password string
        """
        weak_passwords = [
            "123456",
            "password",
            "qwerty",
            "abc123",
            "admin",
            "letmein",
        ]
        return self.faker.random_element(weak_passwords)

    def _generate_password(self, strength: str = "strong") -> str:
        """Generate password with specified strength."""
        if strength == "strong":
            return self.faker.password(
                length=16, special_chars=True, digits=True, upper_case=True
            )
        elif strength == "medium":
            return self.faker.password(
                length=10, special_chars=False, digits=True, upper_case=True
            )
        else:  # weak
            return self.faker.password(length=8, special_chars=False)


class ProductGenerator:
    """
    Advanced product data generator.

    Features:
    - Category-specific products
    - Price ranges
    - Stock levels
    - Product variants
    """

    CATEGORIES = {
        "electronics": {
            "names": [
                "Smartphone",
                "Laptop",
                "Tablet",
                "Smartwatch",
                "Headphones",
            ],
            "price_range": (100, 2000),
            "brands": ["Apple", "Samsung", "Sony", "LG", "Dell"],
        },
        "clothing": {
            "names": [
                "T-Shirt",
                "Jeans",
                "Dress",
                "Jacket",
                "Sneakers",
            ],
            "price_range": (20, 200),
            "brands": ["Nike", "Adidas", "Zara", "H&M", "Levi's"],
        },
        "books": {
            "names": [
                "Novel",
                "Textbook",
                "Biography",
                "Cookbook",
                "Guide",
            ],
            "price_range": (10, 50),
            "brands": [
                "Penguin",
                "HarperCollins",
                "Random House",
                "O'Reilly",
            ],
        },
    }

    def __init__(self, faker: Optional[Faker] = None):
        """
        Initialize product generator.

        Args:
            faker: Faker instance
        """
        self.faker = faker or Faker()

    def generate(
        self,
        category: Optional[str] = None,
        in_stock: bool = True,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Generate product data.

        Args:
            category: Product category
            in_stock: Whether product is in stock
            **kwargs: Additional fields

        Returns:
            Product data dictionary
        """
        # Select category
        if category is None or category not in self.CATEGORIES:
            category = self.faker.random_element(list(self.CATEGORIES.keys()))

        cat_data = self.CATEGORIES[category]

        # Generate product
        product_name = self.faker.random_element(cat_data["names"])
        min_price, max_price = cat_data["price_range"]

        product = {
            "name": f"{self.faker.random_element(cat_data['brands'])} {product_name}",
            "description": self.faker.text(max_nb_chars=200),
            "category": category,
            "price": float(
                self.faker.random_int(min=min_price, max=max_price)
            ),
            "sku": self.faker.bothify(text="???-########"),
            "brand": self.faker.random_element(cat_data["brands"]),
            "rating": round(
                self.faker.pyfloat(min_value=1.0, max_value=5.0), 1
            ),
            "reviews_count": self.faker.random_int(min=0, max=1000),
        }

        # Stock level
        if in_stock:
            product["stock"] = self.faker.random_int(min=1, max=500)
        else:
            product["stock"] = 0

        product.update(kwargs)
        return product

    def generate_with_variants(
        self, num_variants: int = 3, **kwargs
    ) -> Dict[str, Any]:
        """
        Generate product with variants (sizes, colors, etc).

        Args:
            num_variants: Number of variants
            **kwargs: Additional fields

        Returns:
            Product with variants
        """
        product = self.generate(**kwargs)

        variants = []
        colors = ["Red", "Blue", "Black", "White", "Green"]
        sizes = ["XS", "S", "M", "L", "XL"]

        for _ in range(num_variants):
            variant = {
                "color": self.faker.random_element(colors),
                "size": self.faker.random_element(sizes),
                "sku": self.faker.bothify(text="???-########"),
                "stock": self.faker.random_int(min=0, max=100),
                "price_adjustment": self.faker.random_int(min=-10, max=20),
            }
            variants.append(variant)

        product["variants"] = variants
        return product


class AddressGenerator:
    """
    Advanced address data generator.

    Features:
    - Country-specific formats
    - Address types (billing, shipping)
    - Validation-friendly addresses
    """

    def __init__(self, faker: Optional[Faker] = None):
        """
        Initialize address generator.

        Args:
            faker: Faker instance
        """
        self.faker = faker or Faker()

    def generate(
        self,
        address_type: str = "shipping",
        country: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Generate address data.

        Args:
            address_type: Type (billing, shipping, business)
            country: Specific country
            **kwargs: Additional fields

        Returns:
            Address data dictionary
        """
        address = {
            "type": address_type,
            "street": self.faker.street_address(),
            "city": self.faker.city(),
            "state": self.faker.state(),
            "postal_code": self.faker.postcode(),
            "country": country or self.faker.country(),
        }

        if address_type == "business":
            address.update(
                {
                    "company_name": self.faker.company(),
                    "attention_to": self.faker.name(),
                }
            )

        if address_type in ["shipping", "business"]:
            address["delivery_instructions"] = self.faker.sentence()

        address.update(kwargs)
        return address

    def generate_pair(self) -> Dict[str, Dict[str, Any]]:
        """
        Generate billing and shipping address pair.

        Returns:
            Dict with billing and shipping addresses
        """
        return {
            "billing": self.generate(address_type="billing"),
            "shipping": self.generate(address_type="shipping"),
        }


class PaymentGenerator:
    """
    Advanced payment data generator.

    Features:
    - Multiple card types
    - Valid/invalid card numbers
    - Expiration date validation
    """

    CARD_TYPES = ["visa", "mastercard", "amex", "discover"]

    def __init__(self, faker: Optional[Faker] = None):
        """
        Initialize payment generator.

        Args:
            faker: Faker instance
        """
        self.faker = faker or Faker()

    def generate_card(
        self,
        card_type: Optional[str] = None,
        expired: bool = False,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Generate credit card data.

        Args:
            card_type: Card type (visa, mastercard, etc)
            expired: Generate expired card
            **kwargs: Additional fields

        Returns:
            Card data dictionary
        """
        if card_type not in self.CARD_TYPES:
            card_type = self.faker.random_element(self.CARD_TYPES)

        card = {
            "number": self.faker.credit_card_number(card_type=card_type),
            "provider": card_type,
            "cardholder_name": self.faker.name(),
            "security_code": self.faker.credit_card_security_code(
                card_type=card_type
            ),
        }

        if expired:
            card["expire_date"] = self.faker.credit_card_expire(
                start="now", end="-2y"
            )
        else:
            card["expire_date"] = self.faker.credit_card_expire(
                start="now", end="+5y"
            )

        card.update(kwargs)
        return card

    def generate_invalid_card(self) -> Dict[str, Any]:
        """
        Generate invalid card for testing validation.

        Returns:
            Invalid card data
        """
        return {
            "number": "1234567890123456",  # Invalid
            "provider": "unknown",
            "cardholder_name": "",
            "expire_date": "00/00",
            "security_code": "000",
        }

    def generate_payment_method(
        self, method_type: str = "card"
    ) -> Dict[str, Any]:
        """
        Generate payment method data.

        Args:
            method_type: Payment type (card, paypal, bank_transfer)

        Returns:
            Payment method data
        """
        if method_type == "card":
            return self.generate_card()
        elif method_type == "paypal":
            return {
                "type": "paypal",
                "email": self.faker.email(),
                "verified": True,
            }
        elif method_type == "bank_transfer":
            return {
                "type": "bank_transfer",
                "account_number": self.faker.bban(),
                "routing_number": self.faker.aba(),
                "account_holder": self.faker.name(),
            }
        else:
            return {"type": method_type}
