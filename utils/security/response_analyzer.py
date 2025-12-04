"""
Response Analyzer
Analyzes HTTP responses to detect real vulnerabilities.

Author: Marc Arévalo
Version: 1.0
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class VulnerabilityDetection:
    """Represents a detected vulnerability."""

    vulnerability_type: str
    severity: VulnerabilitySeverity
    description: str
    payload_used: str
    evidence: List[str]
    url: str
    method: str
    status_code: int
    response_body: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity.value,
            "description": self.description,
            "payload_used": self.payload_used,
            "evidence": self.evidence,
            "url": self.url,
            "method": self.method,
            "status_code": self.status_code,
            "response_body": self.response_body[
                :500
            ],  # Truncate for readability
            "timestamp": self.timestamp,
            "remediation": self.remediation,
        }


class ResponseAnalyzer:
    """
    Analyzes HTTP responses to detect real vulnerabilities.

    Looks for:
    - SQL error messages
    - Successful SQL injection indicators
    - XSS script execution
    - Command injection output
    - File disclosure
    - Authentication bypass
    """

    def __init__(self):
        """Initialize response analyzer."""
        self.sql_error_patterns = self._get_sql_error_patterns()
        self.sql_success_patterns = self._get_sql_success_patterns()
        self.xss_patterns = self._get_xss_patterns()
        self.command_injection_patterns = (
            self._get_command_injection_patterns()
        )
        self.file_disclosure_patterns = self._get_file_disclosure_patterns()

    def _get_sql_error_patterns(self) -> List[re.Pattern]:
        """Get SQL error patterns."""
        patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"Oracle error",
            r"quoted string not properly terminated",
            r"SQL Server.*Driver",
            r"Microsoft OLE DB Provider for SQL Server",
            r"\[SQL Server\]",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"ORA-[0-9]+",
            r"DB2 SQL error",
            r"SQLITE_ERROR",
            r"sqlite3.OperationalError:",
            r"SQLite/JDBCDriver",
            r"System\.Data\.SqlClient\.",
            r"Unclosed quotation mark",
        ]
        return [re.compile(p, re.IGNORECASE) for p in patterns]

    def _get_sql_success_patterns(self) -> List[re.Pattern]:
        """Get SQL injection success patterns."""
        patterns = [
            r"(admin|administrator).*logged.*in",
            r"welcome.*admin",
            r"dashboard",
            r"you are logged in",
            r"authentication.*successful",
        ]
        return [re.compile(p, re.IGNORECASE) for p in patterns]

    def _get_xss_patterns(self) -> List[re.Pattern]:
        """Get XSS success patterns."""
        patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"alert\(",
            r"<iframe",
        ]
        return [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns]

    def _get_command_injection_patterns(self) -> List[re.Pattern]:
        """Get command injection success patterns."""
        patterns = [
            r"root:x:[0-9]+:[0-9]+:",
            r"daemon:x:",
            r"www-data:",
            r"uid=[0-9]+\([a-z]+\)",
            r"\[fonts\]",
            r"\[extensions\]",
            r"drwxr-xr-x",
            r"total [0-9]+",
            r"bin/bash",
            r"bin/sh",
        ]
        return [re.compile(p, re.IGNORECASE) for p in patterns]

    def _get_file_disclosure_patterns(self) -> List[re.Pattern]:
        """Get file disclosure patterns."""
        patterns = [
            r"root:x:[0-9]+:[0-9]+:",  # /etc/passwd
            r"\[fonts\]",  # win.ini
            r"<\?php",  # PHP source
            r"define\(['\"]DB_PASSWORD",  # WordPress config
            r"SECRET_KEY\s*=",  # Django settings
        ]
        return [re.compile(p) for p in patterns]

    def analyze_sql_injection(
        self,
        response_body: str,
        status_code: int,
        url: str,
        method: str,
        payload: str,
    ) -> Optional[VulnerabilityDetection]:
        """
        Analyze response for SQL injection vulnerability.

        Args:
            response_body: HTTP response body
            status_code: HTTP status code
            url: Request URL
            method: HTTP method
            payload: Payload used

        Returns:
            VulnerabilityDetection if vulnerability found, None otherwise
        """
        evidence = []

        # Check for SQL errors (indicates vulnerability but not necessarily successful exploitation)
        for pattern in self.sql_error_patterns:
            matches = pattern.findall(response_body)
            if matches:
                evidence.extend([f"SQL error: {m}" for m in matches])

        # Check for successful exploitation indicators
        for pattern in self.sql_success_patterns:
            if pattern.search(response_body):
                evidence.append("Successful authentication bypass detected")

        # Check if status code indicates authentication success
        if status_code in [200, 302] and any(
            keyword in payload.lower() for keyword in ["or", "union", "select"]
        ):
            if "login" in url.lower() or "auth" in url.lower():
                evidence.append(
                    f"Suspicious {status_code} status after SQL injection payload"
                )

        if evidence:
            severity = (
                VulnerabilitySeverity.CRITICAL
                if "bypass" in str(evidence)
                else VulnerabilitySeverity.HIGH
            )

            return VulnerabilityDetection(
                vulnerability_type="SQL Injection",
                severity=severity,
                description="Application is vulnerable to SQL injection attacks",
                payload_used=payload,
                evidence=evidence,
                url=url,
                method=method,
                status_code=status_code,
                response_body=response_body,
                remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL queries.",
            )

        return None

    def analyze_xss(
        self,
        response_body: str,
        status_code: int,
        url: str,
        method: str,
        payload: str,
    ) -> Optional[VulnerabilityDetection]:
        """
        Analyze response for XSS vulnerability.

        Args:
            response_body: HTTP response body
            status_code: HTTP status code
            url: Request URL
            method: HTTP method
            payload: Payload used

        Returns:
            VulnerabilityDetection if vulnerability found, None otherwise
        """
        evidence = []

        # Check if payload appears in response unencoded
        if payload in response_body:
            evidence.append(f"Payload reflected unencoded: {payload[:100]}")

        # Check for specific XSS patterns in response
        for pattern in self.xss_patterns:
            matches = pattern.findall(response_body)
            if matches:
                evidence.extend(
                    [f"XSS pattern found: {m[:100]}" for m in matches]
                )

        # Check if our specific payload markers are present
        if "<script>" in payload and "<script>" in response_body:
            evidence.append("Script tags not filtered")

        if "alert(" in payload and "alert(" in response_body:
            evidence.append("JavaScript execution possible")

        if evidence:
            return VulnerabilityDetection(
                vulnerability_type="Cross-Site Scripting (XSS)",
                severity=VulnerabilitySeverity.HIGH,
                description="Application is vulnerable to XSS attacks",
                payload_used=payload,
                evidence=evidence,
                url=url,
                method=method,
                status_code=status_code,
                response_body=response_body,
                remediation="Encode all user input before displaying. Use Content Security Policy (CSP).",
            )

        return None

    def analyze_command_injection(
        self,
        response_body: str,
        status_code: int,
        url: str,
        method: str,
        payload: str,
    ) -> Optional[VulnerabilityDetection]:
        """
        Analyze response for command injection vulnerability.

        Args:
            response_body: HTTP response body
            status_code: HTTP status code
            url: Request URL
            method: HTTP method
            payload: Payload used

        Returns:
            VulnerabilityDetection if vulnerability found, None otherwise
        """
        evidence = []

        # Check for command output in response
        for pattern in self.command_injection_patterns:
            matches = pattern.findall(response_body)
            if matches:
                evidence.extend(
                    [f"Command output detected: {m[:100]}" for m in matches]
                )

        if evidence:
            return VulnerabilityDetection(
                vulnerability_type="Command Injection",
                severity=VulnerabilitySeverity.CRITICAL,
                description="Application is vulnerable to OS command injection",
                payload_used=payload,
                evidence=evidence,
                url=url,
                method=method,
                status_code=status_code,
                response_body=response_body,
                remediation="Never execute user input as system commands. Use allowlists for allowed operations.",
            )

        return None

    def analyze_path_traversal(
        self,
        response_body: str,
        status_code: int,
        url: str,
        method: str,
        payload: str,
    ) -> Optional[VulnerabilityDetection]:
        """
        Analyze response for path traversal vulnerability.

        Args:
            response_body: HTTP response body
            status_code: HTTP status code
            url: Request URL
            method: HTTP method
            payload: Payload used

        Returns:
            VulnerabilityDetection if vulnerability found, None otherwise
        """
        evidence = []

        # Check for file disclosure
        for pattern in self.file_disclosure_patterns:
            matches = pattern.findall(response_body)
            if matches:
                evidence.extend(
                    [f"File content leaked: {m[:100]}" for m in matches]
                )

        if evidence:
            return VulnerabilityDetection(
                vulnerability_type="Path Traversal / File Disclosure",
                severity=VulnerabilitySeverity.HIGH,
                description="Application discloses sensitive file contents",
                payload_used=payload,
                evidence=evidence,
                url=url,
                method=method,
                status_code=status_code,
                response_body=response_body,
                remediation="Validate and sanitize file paths. Use allowlists for allowed files. Implement proper access controls.",
            )

        return None

    def analyze_authentication_bypass(
        self,
        response_body: str,
        status_code: int,
        url: str,
        method: str,
        payload: str,
        original_status: Optional[int] = None,
    ) -> Optional[VulnerabilityDetection]:
        """
        Analyze response for authentication bypass.

        Args:
            response_body: HTTP response body
            status_code: HTTP status code
            url: Request URL
            method: HTTP method
            payload: Payload used
            original_status: Original status code before payload

        Returns:
            VulnerabilityDetection if vulnerability found, None otherwise
        """
        evidence = []

        # Check if authentication succeeded when it shouldn't
        success_indicators = [
            "welcome",
            "dashboard",
            "logged in",
            "authentication successful",
            "session created",
        ]

        for indicator in success_indicators:
            if indicator in response_body.lower():
                evidence.append(
                    f"Authentication success indicator: {indicator}"
                )

        # Check status code change
        if (
            original_status
            and original_status in [401, 403]
            and status_code == 200
        ):
            evidence.append(f"Status changed from {original_status} to 200")

        # Check for session cookies
        if any(
            keyword in response_body.lower()
            for keyword in ["set-cookie", "sessionid", "auth_token"]
        ):
            evidence.append("Session token detected in response")

        if evidence:
            return VulnerabilityDetection(
                vulnerability_type="Authentication Bypass",
                severity=VulnerabilitySeverity.CRITICAL,
                description="Application authentication can be bypassed",
                payload_used=payload,
                evidence=evidence,
                url=url,
                method=method,
                status_code=status_code,
                response_body=response_body,
                remediation="Implement proper authentication checks. Validate all input. Use prepared statements.",
            )

        return None
