"""
Validators - Universal Test Automation Framework
Author: Marc Arévalo
Version: 1.0

Helper functions for data validation.
Universal and reusable across any web application.
"""

import re
from urllib.parse import urlparse


def validate_email(email: str) -> bool:
    """
    Validate email address format.

    Args:
        email: Email address to validate

    Returns:
        True if valid email format, False otherwise

    Example:
        >>> validate_email("user@example.com")
        True
        >>> validate_email("invalid.email")
        False
    """
    if not email:
        return False

    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(email_pattern, email))


def validate_url(url: str) -> bool:
    """
    Validate URL format.

    Args:
        url: URL to validate

    Returns:
        True if valid URL format, False otherwise

    Example:
        >>> validate_url("https://www.example.com")
        True
        >>> validate_url("not a url")
        False
    """
    if not url:
        return False

    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def validate_credit_card(card_number: str) -> bool:
    """
    Validate credit card number using Luhn algorithm.

    Args:
        card_number: Credit card number (can include spaces/dashes)

    Returns:
        True if valid by Luhn algorithm, False otherwise

    Example:
        >>> validate_credit_card("4532015112830366")
        True
        >>> validate_credit_card("1234567890123456")
        False
    """
    card_number = re.sub(r"[\s\-]", "", card_number)

    if not card_number.isdigit():
        return False

    if len(card_number) < 13 or len(card_number) > 19:
        return False

    total = 0
    reverse_digits = card_number[::-1]

    for i, digit in enumerate(reverse_digits):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n

    return total % 10 == 0


def validate_phone_number(phone: str, country_code: str = "US") -> bool:
    """
    Validate phone number format.

    Args:
        phone: Phone number to validate
        country_code: Country code for validation rules (default: "US")

    Returns:
        True if valid phone format, False otherwise

    Example:
        >>> validate_phone_number("555-123-4567")
        True
        >>> validate_phone_number("123")
        False
    """
    phone = re.sub(r"[\s\-\(\)\.]", "", phone)

    if country_code == "US":
        return bool(re.match(r"^\+?1?\d{10}$", phone))

    return len(phone) >= 10 and phone.isdigit()


def validate_password_strength(password: str, min_length: int = 8) -> dict:
    """
    Validate password strength and return details.

    Args:
        password: Password to validate
        min_length: Minimum required length (default: 8)

    Returns:
        Dictionary with validation results:
        {
            'valid': bool,
            'score': int (0-5),
            'feedback': list of str
        }

    Example:
        >>> result = validate_password_strength("MyP@ssw0rd")
        >>> print(result['valid'])
        True
        >>> print(result['score'])
        4
    """
    feedback = []
    score = 0

    if len(password) < min_length:
        feedback.append(f"Password must be at least {min_length} characters")
    else:
        score += 1

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Include lowercase letters")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Include uppercase letters")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Include numbers")

    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    else:
        feedback.append("Include special characters")

    return {
        "valid": len(password) >= min_length and score >= 3,
        "score": score,
        "feedback": feedback,
    }


def validate_date_format(
    date_string: str, format_pattern: str = r"^\d{4}-\d{2}-\d{2}$"
) -> bool:
    """
    Validate date string format.

    Args:
        date_string: Date string to validate
        format_pattern: Regex pattern for date format (default: YYYY-MM-DD)

    Returns:
        True if valid format, False otherwise

    Example:
        >>> validate_date_format("2025-11-28")
        True
        >>> validate_date_format("28/11/2025")
        False
    """
    if not date_string:
        return False

    return bool(re.match(format_pattern, date_string))


def validate_postal_code(postal_code: str, country_code: str = "US") -> bool:
    """
    Validate postal/zip code format.

    Args:
        postal_code: Postal code to validate
        country_code: Country code ("US", "UK", "CA", etc.) (default: "US")

    Returns:
        True if valid format, False otherwise

    Example:
        >>> validate_postal_code("12345")
        True
        >>> validate_postal_code("12345-6789")
        True
    """
    patterns = {
        "US": r"^\d{5}(-\d{4})?$",
        "UK": r"^[A-Z]{1,2}\d{1,2}[A-Z]?\s?\d[A-Z]{2}$",
        "CA": r"^[A-Z]\d[A-Z]\s?\d[A-Z]\d$",
    }

    pattern = patterns.get(country_code, r"^\w+$")
    return bool(re.match(pattern, postal_code.upper()))


def validate_username(
    username: str, min_length: int = 3, max_length: int = 20
) -> dict:
    """
    Validate username format and provide feedback.

    Args:
        username: Username to validate
        min_length: Minimum length (default: 3)
        max_length: Maximum length (default: 20)

    Returns:
        Dictionary with validation results

    Example:
        >>> result = validate_username("user123")
        >>> print(result['valid'])
        True
    """
    feedback = []
    valid = True

    if len(username) < min_length:
        feedback.append(f"Username must be at least {min_length} characters")
        valid = False

    if len(username) > max_length:
        feedback.append(f"Username must not exceed {max_length} characters")
        valid = False

    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        feedback.append(
            "Username can only contain letters, numbers, and underscores"
        )
        valid = False

    if username and username[0].isdigit():
        feedback.append("Username cannot start with a number")
        valid = False

    return {"valid": valid, "feedback": feedback}
