"""
Test Data - Universal Test Automation Framework
Author: Marc Arevalo
Version: 6.0

Universal test data structures for any web application.
All application-specific values MUST be provided via environment variables.

This file provides TEMPLATES and STRUCTURES, not actual test data.
Users must adapt these structures to their specific application.
"""

import os
from typing import Dict


class Users:
    """
    Test user credentials template.

    REQUIRED Environment Variables:
        TEST_USERNAME: Valid test username for your application
        TEST_PASSWORD: Valid test password for your application

    SECURITY WARNING:
        - NEVER commit real credentials to version control
        - ALWAYS use environment variables for credentials
        - Use dedicated test accounts, not production accounts
        - Rotate test credentials regularly

    Usage:
        export TEST_USERNAME="your_test_user"
        export TEST_PASSWORD="your_test_password"
    """

    # Valid user credentials (MUST be set via environment variables)
    VALID = {
        "username": os.getenv("TEST_USERNAME", ""),
        "password": os.getenv("TEST_PASSWORD", ""),
    }

    # Invalid username test case
    INVALID_USERNAME = {
        "username": "nonexistent_user_99999",
        "password": "anypassword",
    }

    # Invalid password test case (requires valid username)
    INVALID_PASSWORD = {
        "username": os.getenv("TEST_USERNAME", ""),
        "password": "wrongpassword123",
    }

    # Empty username test case
    EMPTY_USERNAME = {"username": "", "password": "somepassword"}

    # Empty password test case
    EMPTY_PASSWORD = {"username": "someuser", "password": ""}

    # Both empty test case
    BOTH_EMPTY = {"username": "", "password": ""}

    @classmethod
    def validate(cls) -> None:
        """
        Validate that required credentials are set.

        Raises:
            ValueError: If required credentials are missing
        """
        if not cls.VALID["username"] or not cls.VALID["password"]:
            raise ValueError(
                "TEST_USERNAME and TEST_PASSWORD must be set via environment variables.\n"
                "Example:\n"
                "  export TEST_USERNAME='your_test_user'\n"
                "  export TEST_PASSWORD='your_test_password'"
            )


class PurchaseData:
    """
    Purchase/checkout form data template.

    Adapt this structure to match your application's checkout form fields.
    These are EXAMPLES - replace with your actual form fields.

    Example fields shown:
        - name: Customer name
        - country: Country
        - city: City
        - credit_card: Credit card number (test cards only!)
        - month: Expiration month
        - year: Expiration year

    SECURITY NOTE:
        - NEVER use real credit card numbers
        - Use test credit card numbers from payment processor documentation
        - Common test cards:
          - Visa: 4532015112830366
          - Mastercard: 5425233430109903
          - Amex: 374245455400126
    """

    # Valid purchase data (adapt to your form fields)
    VALID_PURCHASE = {
        "name": "Test User",
        "country": "Test Country",
        "city": "Test City",
        "credit_card": "4532015112830366",  # Test Visa card
        "month": "12",
        "year": "2025",
    }

    # Minimal valid purchase data
    MINIMAL_PURCHASE = {
        "name": "User",
        "country": "US",
        "city": "NYC",
        "credit_card": "4111111111111111",  # Test card
        "month": "01",
        "year": "2026",
    }

    # Empty name test case
    EMPTY_NAME = {
        "name": "",
        "country": "Test Country",
        "city": "Test City",
        "credit_card": "4532015112830366",
        "month": "12",
        "year": "2025",
    }

    # Empty credit card test case
    EMPTY_CARD = {
        "name": "Test User",
        "country": "Test Country",
        "city": "Test City",
        "credit_card": "",
        "month": "12",
        "year": "2025",
    }


class SecurityPayloads:
    """
    Universal security testing payloads for vulnerability testing.

    These payloads are application-agnostic and test common vulnerabilities:
        - SQL Injection
        - Cross-Site Scripting (XSS)
        - LDAP Injection
        - XML Injection
        - Command Injection
        - Path Traversal

    IMPORTANT:
        - Only use on applications you have permission to test
        - These are for UI-level input validation testing
        - Use dedicated security tools (OWASP ZAP, Burp Suite) for comprehensive testing
        - Document all findings and report responsibly
    """

    # SQL Injection payloads
    SQL_INJECTION = [
        "' OR '1'='1",
        "admin'--",
        "1' UNION SELECT NULL--",
        "' OR 'a'='a",
        "'; DROP TABLE users--",
        "1' AND '1'='1",
    ]

    # Basic XSS payloads
    XSS_BASIC = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "<iframe src='javascript:alert(1)'>",
    ]

    # Advanced XSS payloads
    XSS_ADVANCED = [
        "<<SCRIPT>alert('XSS');//<</SCRIPT>",
        "<BODY ONLOAD=alert('XSS')>",
        "<INPUT TYPE='IMAGE' SRC='javascript:alert(\"XSS\");'>",
        "<IMG SRC=javascript:alert('XSS')>",
        "<IMG SRC=JaVaScRiPt:alert('XSS')>",
    ]

    # LDAP Injection payloads
    LDAP_INJECTION = [
        "*",
        "*)(&",
        "*)(|(password=*))",
        "admin*",
        "*)(uid=*))(|(uid=*",
    ]

    # XML Injection payloads
    XML_INJECTION = [
        "<foo>test</foo>",
        "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
        "<root><![CDATA[<script>alert('XSS')</script>]]></root>",
    ]

    # Command Injection payloads
    COMMAND_INJECTION = [
        "; ls -la",
        "| cat /etc/passwd",
        "`whoami`",
        "$(cat /etc/passwd)",
        "&& dir",
    ]

    # Path Traversal payloads
    PATH_TRAVERSAL = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ]


class BoundaryValues:
    """
    Universal boundary value testing data.

    Test edge cases for common input types:
        - Usernames
        - Passwords
        - Credit cards
        - Email addresses
        - Phone numbers
        - etc.

    Adapt min/max lengths to match your application's validation rules.
    """

    # Username boundary values (adapt lengths to your app)
    USERNAMES = {
        "too_short": "ab",  # Below minimum
        "min_valid": "abc",  # Minimum valid
        "normal": "testuser123",  # Normal case
        "max_valid": "a" * 50,  # Maximum valid
        "too_long": "a" * 256,  # Above maximum
        "special_chars": "user@#$%^&*()",  # Special characters
        "unicode": "usuario测试용户",  # Unicode
        "emoji": "user😀test",  # Emoji
    }

    # Password boundary values (adapt to your password policy)
    PASSWORDS = {
        "too_short": "12",  # Below minimum
        "min_valid": "123",  # Minimum valid
        "weak": "password",  # Weak password
        "medium": "Pass1234",  # Medium strength
        "strong": "P@ssw0rd!2024",  # Strong password
        "too_long": "a" * 256,  # Above maximum
        "spaces": "pass word 123",  # Contains spaces
        "unicode": "пароль测试",  # Unicode
    }

    # Credit card boundary values (test cards only!)
    CREDIT_CARDS = {
        "too_short": "123",
        "invalid_length": "123456789012",
        "valid_visa": "4532015112830366",  # Test Visa
        "valid_mastercard": "5425233430109903",  # Test Mastercard
        "valid_amex": "374245455400126",  # Test Amex
        "all_zeros": "0000000000000000",
        "alphabetic": "abcdabcdabcdabcd",
        "special_chars": "1234-5678-9012-3456",
    }


class EdgeCases:
    """
    Universal edge case testing data.

    Tests for unusual inputs that applications should handle gracefully:
        - Whitespace variations
        - Special strings (null, undefined, NaN)
        - Unicode characters
        - Control characters
    """

    # Whitespace edge cases
    WHITESPACE = {
        "leading_space": " username",
        "trailing_space": "username ",
        "double_space": "user  name",
        "tab": "user\tname",
        "newline": "user\nname",
        "only_spaces": "     ",
    }

    # Special strings that might break parsing
    SPECIAL_STRINGS = {
        "null": "null",
        "undefined": "undefined",
        "nan": "NaN",
        "true": "true",
        "false": "false",
        "empty_json": "{}",
        "empty_array": "[]",
    }

    # Unicode test cases
    UNICODE = {
        "russian": "Тестовый пользователь",
        "chinese": "测试用户",
        "arabic": "مستخدم اختبار",
        "japanese": "テストユーザー",
        "korean": "테스트 사용자",
        "emoji": "👤📧🔒",
        "mixed": "User用户مستخدم",
    }


def get_user_credentials(user_type: str = "valid") -> Dict[str, str]:
    """
    Get user credentials by type.

    Args:
        user_type: Type of user credentials to retrieve
            Options: 'valid', 'invalid_username', 'invalid_password',
                     'empty_username', 'empty_password', 'both_empty'

    Returns:
        Dict with username and password

    Raises:
        ValueError: If TEST_USERNAME or TEST_PASSWORD not set (for 'valid' type)

    Example:
        >>> creds = get_user_credentials('valid')
        >>> login_page.login(**creds)
    """
    user_map = {
        "valid": Users.VALID,
        "invalid_username": Users.INVALID_USERNAME,
        "invalid_password": Users.INVALID_PASSWORD,
        "empty_username": Users.EMPTY_USERNAME,
        "empty_password": Users.EMPTY_PASSWORD,
        "both_empty": Users.BOTH_EMPTY,
    }

    credentials = user_map.get(user_type, Users.VALID)

    # Validate credentials if requesting valid user
    if user_type == "valid":
        Users.validate()

    return credentials


def get_purchase_data(data_type: str = "valid") -> Dict[str, str]:
    """
    Get purchase/checkout data by type.

    IMPORTANT: Adapt PurchaseData class to match your application's form fields.

    Args:
        data_type: Type of purchase data to retrieve
            Options: 'valid', 'minimal', 'empty_name', 'empty_card'

    Returns:
        Dict with purchase form data

    Example:
        >>> data = get_purchase_data('valid')
        >>> checkout_page.fill_form(**data)
    """
    data_map = {
        "valid": PurchaseData.VALID_PURCHASE,
        "minimal": PurchaseData.MINIMAL_PURCHASE,
        "empty_name": PurchaseData.EMPTY_NAME,
        "empty_card": PurchaseData.EMPTY_CARD,
    }
    return data_map.get(data_type, PurchaseData.VALID_PURCHASE)


# Validation on import (optional - can be disabled if needed)
if __name__ == "__main__":
    print("=" * 70)
    print("UNIVERSAL TEST DATA - CONFIGURATION CHECK")
    print("=" * 70)

    try:
        Users.validate()
        print("\n✓ User credentials are configured")
        print(f"  Username: {Users.VALID['username']}")
        print(f"  Password: {'*' * len(Users.VALID['password'])}")
    except ValueError as e:
        print(f"\n✗ Configuration error: {e}")

    print("\n" + "=" * 70)
    print("SECURITY PAYLOADS AVAILABLE:")
    print("=" * 70)
    print(f"  SQL Injection: {len(SecurityPayloads.SQL_INJECTION)} payloads")
    print(f"  XSS Basic: {len(SecurityPayloads.XSS_BASIC)} payloads")
    print(f"  XSS Advanced: {len(SecurityPayloads.XSS_ADVANCED)} payloads")
    print(f"  LDAP Injection: {len(SecurityPayloads.LDAP_INJECTION)} payloads")
    print(f"  XML Injection: {len(SecurityPayloads.XML_INJECTION)} payloads")
    print(
        f"  Command Injection: {len(SecurityPayloads.COMMAND_INJECTION)} payloads"
    )
    print(f"  Path Traversal: {len(SecurityPayloads.PATH_TRAVERSAL)} payloads")

    print("\n" + "=" * 70)
    print("ADAPT THIS FILE TO YOUR APPLICATION")
    print("=" * 70)
    print("1. Set TEST_USERNAME and TEST_PASSWORD environment variables")
    print("2. Modify PurchaseData to match your checkout form fields")
    print("3. Adjust BoundaryValues min/max lengths for your validation rules")
    print("4. Add application-specific test data classes as needed")
    print("=" * 70)
