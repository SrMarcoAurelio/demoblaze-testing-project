"""
Unit Tests for data_generator
Author: Marc Arévalo
Version: 1.0

Tests for test data generation utilities.
"""

import re

import pytest

from utils.helpers.data_generator import (
    generate_credit_card_number,
    generate_random_email,
    generate_random_password,
    generate_random_string,
    generate_unique_username,
)


class TestGenerateUniqueUsername:
    """Tests for generate_unique_username function"""

    def test_default_prefix(self):
        """Test username generation with default prefix"""
        username = generate_unique_username()
        assert username.startswith("testuser_")
        assert len(username) > 15  # testuser_ + timestamp + _ + random

    def test_custom_prefix(self):
        """Test username generation with custom prefix"""
        username = generate_unique_username(prefix="admin")
        assert username.startswith("admin_")

    def test_custom_length(self):
        """Test username generation with custom random suffix length"""
        username = generate_unique_username(length=8)
        parts = username.split("_")
        assert len(parts) == 3
        assert len(parts[2]) == 8  # Random suffix

    def test_uniqueness(self):
        """Test that generated usernames are unique"""
        usernames = [generate_unique_username() for _ in range(10)]
        assert len(usernames) == len(set(usernames))

    def test_format(self):
        """Test username format is correct"""
        username = generate_unique_username()
        pattern = r"^testuser_\d+_[a-z0-9]{4}$"
        assert re.match(pattern, username)


class TestGenerateRandomPassword:
    """Tests for generate_random_password function"""

    def test_default_length(self):
        """Test password generation with default length"""
        password = generate_random_password()
        assert len(password) == 12

    def test_custom_length(self):
        """Test password generation with custom length"""
        password = generate_random_password(length=20)
        assert len(password) == 20

    def test_includes_lowercase(self):
        """Test password includes lowercase letters"""
        password = generate_random_password(length=50)
        assert any(c.islower() for c in password)

    def test_includes_uppercase_when_requested(self):
        """Test password includes uppercase when include_uppercase=True"""
        password = generate_random_password(length=50, include_uppercase=True)
        assert any(c.isupper() for c in password)

    def test_no_uppercase_when_not_requested(self):
        """Test password excludes uppercase when include_uppercase=False"""
        password = generate_random_password(length=50, include_uppercase=False)
        assert not any(c.isupper() for c in password)

    def test_includes_numbers_when_requested(self):
        """Test password includes numbers when include_numbers=True"""
        password = generate_random_password(length=50, include_numbers=True)
        assert any(c.isdigit() for c in password)

    def test_includes_special_when_requested(self):
        """Test password includes special chars when include_special=True"""
        password = generate_random_password(length=50, include_special=True)
        special_chars = '!@#$%^&*(),.?":{}|<>'
        assert any(c in special_chars for c in password)

    def test_randomness(self):
        """Test that generated passwords are random"""
        passwords = [generate_random_password() for _ in range(10)]
        assert len(passwords) == len(set(passwords))


class TestGenerateRandomEmail:
    """Tests for generate_random_email function"""

    def test_default_domain(self):
        """Test email generation with default domain"""
        email = generate_random_email()
        assert email.endswith("@testmail.com")

    def test_custom_domain(self):
        """Test email generation with custom domain"""
        email = generate_random_email(domain="example.com")
        assert email.endswith("@example.com")

    def test_email_format(self):
        """Test email has valid format"""
        email = generate_random_email()
        pattern = r"^[a-zA-Z0-9_]+_\d+_[a-z0-9]{4}@testmail\.com$"
        assert re.match(pattern, email)

    def test_uniqueness(self):
        """Test that generated emails are unique"""
        emails = [generate_random_email() for _ in range(10)]
        assert len(emails) == len(set(emails))


class TestGenerateCreditCardNumber:
    """Tests for generate_credit_card_number function"""

    def test_default_visa(self):
        """Test default generates Visa card"""
        card = generate_credit_card_number()
        assert card == "4532015112830366"
        assert len(card) == 16

    def test_visa_card(self):
        """Test Visa card generation"""
        card = generate_credit_card_number("visa")
        assert card.startswith("4")
        assert len(card) == 16

    def test_mastercard(self):
        """Test Mastercard generation"""
        card = generate_credit_card_number("mastercard")
        assert card.startswith("5")
        assert len(card) == 16

    def test_amex(self):
        """Test American Express generation"""
        card = generate_credit_card_number("amex")
        assert card.startswith("3")
        assert len(card) == 15

    def test_invalid_type_defaults_to_visa(self):
        """Test invalid card type defaults to Visa"""
        card = generate_credit_card_number("invalid")
        assert card == "4532015112830366"


class TestGenerateRandomString:
    """Tests for generate_random_string function"""

    def test_default_length(self):
        """Test string generation with default length"""
        string = generate_random_string()
        assert len(string) == 10

    def test_custom_length(self):
        """Test string generation with custom length"""
        string = generate_random_string(length=25)
        assert len(string) == 25

    def test_default_charset(self):
        """Test default charset includes letters and digits"""
        string = generate_random_string(length=50)
        assert any(c.isalpha() for c in string)
        assert any(c.isdigit() for c in string)

    def test_custom_charset(self):
        """Test custom charset"""
        string = generate_random_string(length=20, charset="ABCD")
        assert all(c in "ABCD" for c in string)

    def test_randomness(self):
        """Test that generated strings are random"""
        strings = [generate_random_string() for _ in range(10)]
        assert len(strings) == len(set(strings))
