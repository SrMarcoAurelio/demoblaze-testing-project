"""
Unit Tests for validators
Author: Marc Arévalo
Version: 1.0

Tests for data validation utilities.
"""

import pytest
from utils.helpers.validators import (
    validate_email,
    validate_url,
    validate_credit_card,
    validate_phone_number,
    validate_password_strength,
    validate_date_format,
    validate_postal_code,
    validate_username
)


class TestValidateEmail:
    """Tests for validate_email function"""
    
    @pytest.mark.parametrize("email,expected", [
        ("user@example.com", True),
        ("test.user@example.co.uk", True),
        ("user+tag@example.com", True),
        ("user_name@example.com", True),
        ("invalid.email", False),
        ("@example.com", False),
        ("user@", False),
        ("user", False),
        ("", False),
        ("user@.com", False),
    ])
    def test_email_validation(self, email, expected):
        """Test email validation with various formats"""
        assert validate_email(email) == expected


class TestValidateURL:
    """Tests for validate_url function"""
    
    @pytest.mark.parametrize("url,expected", [
        ("https://www.example.com", True),
        ("http://example.com", True),
        ("https://example.com/path", True),
        ("https://example.com/path?query=1", True),
        ("ftp://files.example.com", True),
        ("not a url", False),
        ("", False),
        ("//example.com", False),
        ("example.com", False),
    ])
    def test_url_validation(self, url, expected):
        """Test URL validation with various formats"""
        assert validate_url(url) == expected


class TestValidateCreditCard:
    """Tests for validate_credit_card function (Luhn algorithm)"""
    
    @pytest.mark.parametrize("card,expected", [
        ("4532015112830366", True),  # Visa test number
        ("5425233430109903", True),  # Mastercard test number
        ("374245455400126", True),   # Amex test number
        ("4532-0151-1283-0366", True),  # With dashes
        ("4532 0151 1283 0366", True),  # With spaces
        ("1234567890123456", False),  # Invalid Luhn
        ("123", False),  # Too short
        ("12345678901234567890", False),  # Too long
        ("abcdabcdabcdabcd", False),  # Not digits
        ("", False),
    ])
    def test_credit_card_validation(self, card, expected):
        """Test credit card validation with Luhn algorithm"""
        assert validate_credit_card(card) == expected


class TestValidatePhoneNumber:
    """Tests for validate_phone_number function"""
    
    @pytest.mark.parametrize("phone,country,expected", [
        ("5551234567", "US", True),
        ("555-123-4567", "US", True),
        ("(555) 123-4567", "US", True),
        ("+15551234567", "US", True),
        ("123", "US", False),
        ("", "US", False),
        ("abcdefghij", "US", False),
    ])
    def test_phone_validation(self, phone, country, expected):
        """Test phone number validation"""
        assert validate_phone_number(phone, country) == expected


class TestValidatePasswordStrength:
    """Tests for validate_password_strength function"""
    
    def test_strong_password(self):
        """Test strong password validation"""
        result = validate_password_strength("MyP@ssw0rd123")
        assert result['valid'] == True
        assert result['score'] == 5
        assert len(result['feedback']) == 0
    
    def test_weak_password_too_short(self):
        """Test weak password (too short)"""
        result = validate_password_strength("Pass1!")
        assert result['valid'] == False
        assert 'at least 8 characters' in result['feedback'][0]
    
    def test_password_no_uppercase(self):
        """Test password without uppercase"""
        result = validate_password_strength("mypassword123!")
        assert 'uppercase' in result['feedback'][0]
    
    def test_password_no_lowercase(self):
        """Test password without lowercase"""
        result = validate_password_strength("MYPASSWORD123!")
        assert 'lowercase' in result['feedback'][0]
    
    def test_password_no_numbers(self):
        """Test password without numbers"""
        result = validate_password_strength("MyPassword!")
        assert 'numbers' in result['feedback'][0]
    
    def test_password_no_special(self):
        """Test password without special characters"""
        result = validate_password_strength("MyPassword123")
        assert 'special' in result['feedback'][0]
    
    def test_custom_min_length(self):
        """Test password with custom minimum length"""
        result = validate_password_strength("Pass1!", min_length=10)
        assert 'at least 10 characters' in result['feedback'][0]


class TestValidateDateFormat:
    """Tests for validate_date_format function"""
    
    @pytest.mark.parametrize("date,expected", [
        ("2025-11-28", True),
        ("2025-01-01", True),
        ("2025-12-31", True),
        ("28/11/2025", False),
        ("11-28-2025", False),
        ("2025/11/28", False),
        ("", False),
        ("invalid", False),
    ])
    def test_date_validation_default_format(self, date, expected):
        """Test date validation with default format (YYYY-MM-DD)"""
        assert validate_date_format(date) == expected
    
    def test_custom_date_format(self):
        """Test date validation with custom format"""
        assert validate_date_format("28/11/2025", r'^\d{2}/\d{2}/\d{4}$') == True
        assert validate_date_format("2025-11-28", r'^\d{2}/\d{2}/\d{4}$') == False


class TestValidatePostalCode:
    """Tests for validate_postal_code function"""
    
    @pytest.mark.parametrize("code,country,expected", [
        ("12345", "US", True),
        ("12345-6789", "US", True),
        ("123", "US", False),
        ("SW1A 1AA", "UK", True),
        ("SW1A1AA", "UK", True),
        ("A1B 2C3", "CA", True),
        ("A1B2C3", "CA", True),
        ("", "US", False),
    ])
    def test_postal_code_validation(self, code, country, expected):
        """Test postal code validation for different countries"""
        assert validate_postal_code(code, country) == expected


class TestValidateUsername:
    """Tests for validate_username function"""
    
    def test_valid_username(self):
        """Test valid username"""
        result = validate_username("user123")
        assert result['valid'] == True
        assert len(result['feedback']) == 0
    
    def test_too_short(self):
        """Test username too short"""
        result = validate_username("ab")
        assert result['valid'] == False
        assert 'at least 3 characters' in result['feedback'][0]
    
    def test_too_long(self):
        """Test username too long"""
        result = validate_username("a" * 25)
        assert result['valid'] == False
        assert 'not exceed 20 characters' in result['feedback'][0]
    
    def test_invalid_characters(self):
        """Test username with invalid characters"""
        result = validate_username("user@123")
        assert result['valid'] == False
        assert 'letters, numbers, and underscores' in result['feedback'][0]
    
    def test_starts_with_number(self):
        """Test username starting with number"""
        result = validate_username("123user")
        assert result['valid'] == False
        assert 'cannot start with a number' in result['feedback'][0]
    
    def test_custom_length_constraints(self):
        """Test username with custom length constraints"""
        result = validate_username("user", min_length=5, max_length=15)
        assert result['valid'] == False
        assert 'at least 5 characters' in result['feedback'][0]
