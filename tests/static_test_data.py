"""
Test Data - DemoBlaze Test Automation
Author: Marc Arévalo
Version: 1.0

Centralized test data for all test suites.
Separates test data from test logic for better maintainability.

SECURITY WARNING:
- Default credentials are provided for testing purposes only
- Use environment variables for production/sensitive credentials:
  * TEST_USERNAME - Valid test username
  * TEST_PASSWORD - Valid test password
- Never commit real production credentials to version control
"""

import os


class Users:
    """Test user credentials and account data.

    Security Note:
    - Uses environment variables when available
    - Falls back to default test credentials
    - Default credentials are for demo/test environments only
    """

    VALID = {
        "username": os.getenv("TEST_USERNAME", "Apolo2025"),
        "password": os.getenv("TEST_PASSWORD", "apolo2025"),
    }

    INVALID_USERNAME = {
        "username": "nonexistent_user_99999",
        "password": "anypassword",
    }

    INVALID_PASSWORD = {
        "username": "Apolo2025",
        "password": "wrongpassword123",
    }

    EMPTY_USERNAME = {"username": "", "password": "somepassword"}

    EMPTY_PASSWORD = {"username": "someuser", "password": ""}

    BOTH_EMPTY = {"username": "", "password": ""}


class Products:
    """Test product data."""

    SAMSUNG_GALAXY_S6 = "Samsung galaxy s6"
    NOKIA_LUMIA_1520 = "Nokia lumia 1520"
    NEXUS_6 = "Nexus 6"
    SAMSUNG_GALAXY_S7 = "Samsung galaxy s7"
    IPHONE_6_32GB = "Iphone 6 32gb"
    SONY_XPERIA_Z5 = "Sony xperia z5"
    HTC_ONE_M9 = "HTC One M9"

    LAPTOPS = {
        "SONY_VAIO_I5": "Sony vaio i5",
        "SONY_VAIO_I7": "Sony vaio i7",
        "MACBOOK_AIR": "MacBook air",
        "DELL_I7_8GB": "Dell i7 8gb",
        "ASUS_FULL_HD": "2017 Dell 15.6 Inch",
        "MACBOOK_PRO": "MacBook Pro",
    }

    MONITORS = {
        "APPLE_MONITOR_24": "Apple monitor 24",
        "ASUS_FULL_HD": "ASUS Full HD",
    }


class PurchaseData:
    """Test data for purchase/checkout process."""

    VALID_PURCHASE = {
        "name": "Marc Arévalo",
        "country": "Spain",
        "city": "Barcelona",
        "credit_card": "4532015112830366",
        "month": "12",
        "year": "2025",
    }

    MINIMAL_PURCHASE = {
        "name": "Test User",
        "country": "US",
        "city": "NYC",
        "credit_card": "4111111111111111",
        "month": "01",
        "year": "2026",
    }

    EMPTY_NAME = {
        "name": "",
        "country": "Spain",
        "city": "Madrid",
        "credit_card": "4532015112830366",
        "month": "12",
        "year": "2025",
    }

    EMPTY_CARD = {
        "name": "Test User",
        "country": "Spain",
        "city": "Madrid",
        "credit_card": "",
        "month": "12",
        "year": "2025",
    }


class SecurityPayloads:
    """Security testing payloads for vulnerability testing."""

    SQL_INJECTION = [
        "' OR '1'='1",
        "admin'--",
        "1' UNION SELECT NULL--",
        "' OR 'a'='a",
        "'; DROP TABLE users--",
        "1' AND '1'='1",
    ]

    XSS_BASIC = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "<iframe src='javascript:alert(1)'>",
    ]

    XSS_ADVANCED = [
        "<<SCRIPT>alert('XSS');//<</SCRIPT>",
        "<BODY ONLOAD=alert('XSS')>",
        "<INPUT TYPE='IMAGE' SRC='javascript:alert(\"XSS\");'>",
        "<IMG SRC=javascript:alert('XSS')>",
        "<IMG SRC=JaVaScRiPt:alert('XSS')>",
    ]

    LDAP_INJECTION = [
        "*",
        "*)(&",
        "*)(|(password=*))",
        "admin*",
        "*)(uid=*))(|(uid=*",
    ]

    XML_INJECTION = [
        "<foo>test</foo>",
        "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
        "<root><![CDATA[<script>alert('XSS')</script>]]></root>",
    ]

    COMMAND_INJECTION = [
        "; ls -la",
        "| cat /etc/passwd",
        "`whoami`",
        "$(cat /etc/passwd)",
        "&& dir",
    ]

    PATH_TRAVERSAL = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ]


class BoundaryValues:
    """Boundary value testing data."""

    USERNAMES = {
        "too_short": "ab",
        "min_valid": "abc",
        "normal": "testuser123",
        "max_valid": "a" * 50,
        "too_long": "a" * 256,
        "special_chars": "user@#$%^&*()",
        "unicode": "usuario测试용户",
        "emoji": "user😀test",
    }

    PASSWORDS = {
        "too_short": "12",
        "min_valid": "123",
        "weak": "password",
        "medium": "Pass1234",
        "strong": "P@ssw0rd!2024",
        "too_long": "a" * 256,
        "spaces": "pass word 123",
        "unicode": "пароль测试",
    }

    CREDIT_CARDS = {
        "too_short": "123",
        "invalid_length": "123456789012",
        "valid_visa": "4532015112830366",
        "valid_mastercard": "5425233430109903",
        "valid_amex": "374245455400126",
        "all_zeros": "0000000000000000",
        "alphabetic": "abcdabcdabcdabcd",
        "special_chars": "1234-5678-9012-3456",
    }


class EdgeCases:
    """Edge case testing data."""

    WHITESPACE = {
        "leading_space": " username",
        "trailing_space": "username ",
        "double_space": "user  name",
        "tab": "user\tname",
        "newline": "user\nname",
        "only_spaces": "     ",
    }

    SPECIAL_STRINGS = {
        "null": "null",
        "undefined": "undefined",
        "nan": "NaN",
        "true": "true",
        "false": "false",
        "empty_json": "{}",
        "empty_array": "[]",
    }

    UNICODE = {
        "russian": "Тестовый пользователь",
        "chinese": "测试用户",
        "arabic": "مستخدم اختبار",
        "japanese": "テストユーザー",
        "korean": "테스트 사용자",
        "emoji": "👤📧🔒",
        "mixed": "User用户مستخدم",
    }


def get_user_credentials(user_type: str = "valid") -> dict:
    """
    Get user credentials by type.

    Args:
        user_type: Type of user ('valid', 'invalid_username', 'invalid_password', etc.)

    Returns:
        Dict with username and password

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
    return user_map.get(user_type, Users.VALID)


def get_purchase_data(data_type: str = "valid") -> dict:
    """
    Get purchase/checkout data by type.

    Args:
        data_type: Type of purchase data ('valid', 'minimal', 'empty_name', etc.)

    Returns:
        Dict with purchase form data

    Example:
        >>> data = get_purchase_data('valid')
        >>> purchase_page.fill_form(**data)
    """
    data_map = {
        "valid": PurchaseData.VALID_PURCHASE,
        "minimal": PurchaseData.MINIMAL_PURCHASE,
        "empty_name": PurchaseData.EMPTY_NAME,
        "empty_card": PurchaseData.EMPTY_CARD,
    }
    return data_map.get(data_type, PurchaseData.VALID_PURCHASE)
