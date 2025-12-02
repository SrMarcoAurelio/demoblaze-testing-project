"""
Data Generator - Universal Test Automation Framework
Author: Marc Arévalo
Version: 1.0

Helper functions for generating test data.
Universal and reusable across any web application.
"""

import random
import string
import time
from typing import Optional


def generate_unique_username(prefix: str = "testuser", length: int = 4) -> str:
    """
    Generate a unique username for testing.

    Args:
        prefix: Prefix for the username (default: "testuser")
        length: Length of random suffix (default: 4)

    Returns:
        Unique username string (e.g., "testuser_1234567890_ab12")

    Example:
        >>> username = generate_unique_username()
        >>> print(username)
        testuser_1701234567_a1b2
    """
    timestamp = int(time.time())
    random_suffix = "".join(
        random.choices(string.ascii_lowercase + string.digits, k=length)
    )
    return f"{prefix}_{timestamp}_{random_suffix}"


def generate_random_password(
    length: int = 12,
    include_uppercase: bool = True,
    include_numbers: bool = True,
    include_special: bool = True,
) -> str:
    """
    Generate a random password for testing.

    Args:
        length: Password length (default: 12)
        include_uppercase: Include uppercase letters (default: True)
        include_numbers: Include numbers (default: True)
        include_special: Include special characters (default: True)

    Returns:
        Random password string

    Example:
        >>> password = generate_random_password(length=16)
        >>> print(len(password))
        16
    """
    characters = string.ascii_lowercase
    if include_uppercase:
        characters += string.ascii_uppercase
    if include_numbers:
        characters += string.digits
    if include_special:
        characters += string.punctuation

    return "".join(random.choices(characters, k=length))


def generate_random_email(domain: str = "testmail.com") -> str:
    """
    Generate a random email address for testing.

    Args:
        domain: Email domain (default: "testmail.com")

    Returns:
        Random email address

    Example:
        >>> email = generate_random_email()
        >>> print(email)
        testuser_1701234567_a1b2@testmail.com
    """
    username = generate_unique_username()
    return f"{username}@{domain}"


def generate_credit_card_number(card_type: str = "visa") -> str:
    """
    Generate a test credit card number (Luhn algorithm valid).

    Args:
        card_type: Type of card ("visa", "mastercard", "amex") (default: "visa")

    Returns:
        Test credit card number string

    Note:
        These are TEST ONLY numbers and should NEVER be used for real transactions.

    Example:
        >>> card = generate_credit_card_number("visa")
        >>> print(len(card))
        16
    """
    test_cards = {
        "visa": "4532015112830366",
        "mastercard": "5425233430109903",
        "amex": "374245455400126",
    }
    return test_cards.get(card_type.lower(), test_cards["visa"])


def generate_random_string(
    length: int = 10, charset: Optional[str] = None
) -> str:
    """
    Generate a random string of specified length.

    Args:
        length: Length of the string (default: 10)
        charset: Character set to use (default: ascii letters + digits)

    Returns:
        Random string

    Example:
        >>> random_str = generate_random_string(20)
        >>> print(len(random_str))
        20
    """
    if charset is None:
        charset = string.ascii_letters + string.digits
    return "".join(random.choices(charset, k=length))
