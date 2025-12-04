"""
Data Factory
Central factory for generating test data.

Author: Marc Arévalo
Version: 1.0
"""

import logging
from typing import Any, Dict, List, Optional

from faker import Faker

logger = logging.getLogger(__name__)


class DataFactory:
    """
    Central factory for generating test data.

    Features:
    - Configurable Faker locale
    - Seed support for reproducibility
    - Built-in generators for common entities
    - Custom generator support
    - Batch generation
    """

    def __init__(self, locale: str = "en_US", seed: Optional[int] = None):
        """
        Initialize data factory.

        Args:
            locale: Faker locale (e.g., 'en_US', 'es_ES', 'fr_FR')
            seed: Random seed for reproducible data generation
        """
        self.faker = Faker(locale)
        if seed is not None:
            Faker.seed(seed)
            logger.debug(f"DataFactory initialized with seed: {seed}")
        else:
            logger.debug(f"DataFactory initialized with locale: {locale}")

    def generate_user(
        self,
        username: Optional[str] = None,
        email: Optional[str] = None,
        include_password: bool = True,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Generate user data.

        Args:
            username: Custom username (generated if None)
            email: Custom email (generated if None)
            include_password: Include password field
            **kwargs: Additional fields to include

        Returns:
            User data dictionary
        """
        user = {
            "username": username or self.faker.user_name(),
            "email": email or self.faker.email(),
            "first_name": self.faker.first_name(),
            "last_name": self.faker.last_name(),
            "full_name": self.faker.name(),
            "phone": self.faker.phone_number(),
            "date_of_birth": str(self.faker.date_of_birth(minimum_age=18)),
        }

        if include_password:
            user["password"] = self.faker.password(
                length=12, special_chars=True, digits=True, upper_case=True
            )

        user.update(kwargs)
        return user

    def generate_product(
        self,
        name: Optional[str] = None,
        category: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Generate product data.

        Args:
            name: Custom product name (generated if None)
            category: Product category (generated if None)
            **kwargs: Additional fields

        Returns:
            Product data dictionary
        """
        categories = [
            "Electronics",
            "Clothing",
            "Books",
            "Home & Garden",
            "Sports",
            "Toys",
        ]

        product = {
            "name": name or self.faker.catch_phrase(),
            "description": self.faker.text(max_nb_chars=200),
            "category": category or self.faker.random_element(categories),
            "price": float(self.faker.random_int(min=10, max=1000)),
            "sku": self.faker.bothify(text="???-########"),
            "stock": self.faker.random_int(min=0, max=1000),
            "brand": self.faker.company(),
        }

        product.update(kwargs)
        return product

    def generate_address(
        self,
        country: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Generate address data.

        Args:
            country: Custom country (generated if None)
            **kwargs: Additional fields

        Returns:
            Address data dictionary
        """
        address = {
            "street": self.faker.street_address(),
            "city": self.faker.city(),
            "state": self.faker.state(),
            "postal_code": self.faker.postcode(),
            "country": country or self.faker.country(),
            "latitude": float(self.faker.latitude()),
            "longitude": float(self.faker.longitude()),
        }

        address.update(kwargs)
        return address

    def generate_payment_card(
        self,
        card_type: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Generate payment card data.

        Args:
            card_type: Card type (visa, mastercard, etc)
            **kwargs: Additional fields

        Returns:
            Payment card data dictionary
        """
        card = {
            "number": self.faker.credit_card_number(card_type=card_type),
            "provider": self.faker.credit_card_provider(card_type=card_type),
            "expire_date": self.faker.credit_card_expire(),
            "security_code": self.faker.credit_card_security_code(
                card_type=card_type
            ),
            "cardholder_name": self.faker.name(),
        }

        card.update(kwargs)
        return card

    def generate_company(self, **kwargs) -> Dict[str, Any]:
        """
        Generate company data.

        Args:
            **kwargs: Additional fields

        Returns:
            Company data dictionary
        """
        company = {
            "name": self.faker.company(),
            "suffix": self.faker.company_suffix(),
            "slogan": self.faker.catch_phrase(),
            "website": self.faker.url(),
            "email": self.faker.company_email(),
            "phone": self.faker.phone_number(),
            "tax_id": self.faker.bothify(text="##-#######"),
        }

        company.update(kwargs)
        return company

    def generate_order(
        self,
        user_id: Optional[int] = None,
        num_items: int = 3,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Generate order data.

        Args:
            user_id: User ID for the order
            num_items: Number of items in order
            **kwargs: Additional fields

        Returns:
            Order data dictionary
        """
        items = [self.generate_product() for _ in range(num_items)]
        total = sum(item["price"] for item in items)

        order = {
            "order_id": self.faker.uuid4(),
            "user_id": user_id or self.faker.random_int(min=1, max=10000),
            "items": items,
            "total": total,
            "status": self.faker.random_element(
                ["pending", "processing", "shipped", "delivered", "cancelled"]
            ),
            "created_at": str(self.faker.date_time_this_year()),
        }

        order.update(kwargs)
        return order

    def generate_batch(
        self, generator_func: str, count: int, **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Generate batch of data using specified generator.

        Args:
            generator_func: Name of generator method (e.g., 'generate_user')
            count: Number of items to generate
            **kwargs: Arguments to pass to generator

        Returns:
            List of generated data

        Example:
            users = factory.generate_batch('generate_user', count=10)
        """
        generator = getattr(self, generator_func)
        return [generator(**kwargs) for _ in range(count)]

    def generate_unique_emails(self, count: int) -> List[str]:
        """
        Generate unique email addresses.

        Args:
            count: Number of emails to generate

        Returns:
            List of unique emails
        """
        emails = set()
        while len(emails) < count:
            emails.add(self.faker.email())
        return list(emails)

    def generate_unique_usernames(self, count: int) -> List[str]:
        """
        Generate unique usernames.

        Args:
            count: Number of usernames to generate

        Returns:
            List of unique usernames
        """
        usernames = set()
        while len(usernames) < count:
            usernames.add(self.faker.user_name())
        return list(usernames)

    def reset_seed(self, seed: int) -> None:
        """
        Reset random seed for reproducible generation.

        Args:
            seed: New seed value
        """
        Faker.seed(seed)
        logger.debug(f"Seed reset to: {seed}")

    # Convenience methods for common operations

    def random_int(self, min: int = 0, max: int = 100) -> int:
        """Generate random integer."""
        return self.faker.random_int(min=min, max=max)

    def random_float(
        self, min: float = 0.0, max: float = 100.0, decimals: int = 2
    ) -> float:
        """Generate random float."""
        return round(
            self.faker.pyfloat(min_value=min, max_value=max), decimals
        )

    def random_date(
        self, start_date: str = "-1y", end_date: str = "today"
    ) -> str:
        """Generate random date."""
        return str(
            self.faker.date_between(start_date=start_date, end_date=end_date)
        )

    def random_text(self, max_chars: int = 200) -> str:
        """Generate random text."""
        return self.faker.text(max_nb_chars=max_chars)

    def random_choice(self, choices: List[Any]) -> Any:
        """Pick random element from list."""
        return self.faker.random_element(choices)

    def random_boolean(self) -> bool:
        """Generate random boolean."""
        return self.faker.boolean()
