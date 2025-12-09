# Security Testing Module

## Overview

The Security Testing Module provides comprehensive security testing capabilities including vulnerability scanning, penetration testing, and OWASP Top 10 validation. This module enables automated detection of common security vulnerabilities such as SQL injection, XSS, CSRF, and other web application security issues.

## Table of Contents

- [Architecture](#architecture)
- [Features](#features)
- [Implementation Details](#implementation-details)
- [Usage](#usage)
- [Configuration](#configuration)
- [Test Coverage](#test-coverage)
- [Maintenance](#maintenance)
- [Security Standards](#security-standards)

## Architecture

### Component Structure

```
tests/security_real/
├── __init__.py
├── test_security_injection.py        # Injection attack tests
├── test_security_xss.py               # XSS vulnerability tests
├── test_security_authentication.py    # Auth security tests
└── test_security_csrf.py              # CSRF protection tests

utils/security/
├── __init__.py
├── payload_library.py                 # Security payload database (347 lines)
├── response_analyzer.py               # Vulnerability detection (452 lines)
├── vulnerability_scanner.py           # Automated scanner (466 lines)
└── security_report_generator.py       # Reporting utilities
```

### Dependencies

- **Selenium WebDriver**: Browser automation for real HTTP testing
- **mitmproxy**: HTTP(S) proxy for request/response interception
- **pytest**: Test framework with security markers
- **requests**: HTTP library for API security testing

## Features

### Core Capabilities

1. **OWASP Top 10 Testing**
   - A01:2021 Broken Access Control
   - A02:2021 Cryptographic Failures
   - A03:2021 Injection
   - A04:2021 Insecure Design
   - A05:2021 Security Misconfiguration
   - A06:2021 Vulnerable and Outdated Components
   - A07:2021 Identification and Authentication Failures
   - A08:2021 Software and Data Integrity Failures
   - A09:2021 Security Logging and Monitoring Failures
   - A10:2021 Server-Side Request Forgery (SSRF)

2. **Injection Testing**
   - SQL Injection (SQLi)
   - NoSQL Injection
   - Command Injection
   - LDAP Injection
   - XML Injection
   - XPath Injection

3. **Cross-Site Scripting (XSS) Testing**
   - Reflected XSS
   - Stored XSS
   - DOM-based XSS
   - Context-aware payload generation

4. **Authentication & Authorization Testing**
   - Brute force protection
   - Session management
   - Password policy enforcement
   - JWT token validation
   - OAuth flow security

5. **Real HTTP Interception**
   - Request/response modification
   - Header manipulation
   - Cookie tampering
   - TLS/SSL validation

## Implementation Details

### Payload Library (`utils/security/payload_library.py`)

The Payload Library provides a comprehensive database of security test payloads organized by vulnerability type.

**Key Classes:**

```python
@dataclass
class SecurityPayload:
    """
    Security test payload data structure.

    Attributes:
        category: Vulnerability category (sql_injection, xss, etc.)
        payload: The actual test payload string
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        description: Human-readable description
        expected_safe_behavior: Expected response if properly protected
    """
    category: str
    payload: str
    severity: str
    description: str
    expected_safe_behavior: str

class PayloadLibrary:
    """
    Centralized library of security testing payloads.
    """

    def get_payloads(self, category: str) -> List[SecurityPayload]:
        """
        Retrieve payloads by category.

        Args:
            category: Vulnerability category (sql_injection, xss, command_injection, etc.)

        Returns:
            List of SecurityPayload objects for the category
        """

    def get_sql_injection_payloads(self) -> List[SecurityPayload]:
        """Get SQL injection test payloads"""

    def get_xss_payloads(self) -> List[SecurityPayload]:
        """Get XSS test payloads"""

    def get_command_injection_payloads(self) -> List[SecurityPayload]:
        """Get command injection test payloads"""

    def get_all_payloads(self) -> Dict[str, List[SecurityPayload]]:
        """Get all payloads organized by category"""
```

**Example Payloads:**

```python
# SQL Injection Payloads
SQL_INJECTION_PAYLOADS = [
    SecurityPayload(
        category="sql_injection",
        payload="' OR '1'='1",
        severity="CRITICAL",
        description="Classic SQL injection bypass",
        expected_safe_behavior="Input sanitized, authentication fails"
    ),
    SecurityPayload(
        category="sql_injection",
        payload="admin'--",
        severity="CRITICAL",
        description="SQL comment injection",
        expected_safe_behavior="Input rejected or escaped"
    ),
]

# XSS Payloads
XSS_PAYLOADS = [
    SecurityPayload(
        category="xss",
        payload="<script>alert('XSS')</script>",
        severity="HIGH",
        description="Basic XSS payload",
        expected_safe_behavior="Script tags escaped or removed"
    ),
    SecurityPayload(
        category="xss",
        payload="<img src=x onerror=alert('XSS')>",
        severity="HIGH",
        description="XSS via img tag",
        expected_safe_behavior="HTML attributes sanitized"
    ),
]
```

### Response Analyzer (`utils/security/response_analyzer.py`)

The Response Analyzer detects vulnerabilities by analyzing server responses for indicators of successful attacks.

**Key Methods:**

```python
class ResponseAnalyzer:
    """
    Analyzes HTTP responses for security vulnerabilities.
    """

    def analyze_sql_injection(self, response_body: str, status_code: int,
                              url: str, method: str, payload: str) -> Optional[Vulnerability]:
        """
        Analyze response for SQL injection indicators.

        Args:
            response_body: HTTP response body
            status_code: HTTP status code
            url: Target URL
            method: HTTP method
            payload: Payload used in the test

        Returns:
            Vulnerability object if detected, None otherwise
        """

    def analyze_xss(self, response_body: str, payload: str,
                   url: str) -> Optional[Vulnerability]:
        """
        Analyze response for XSS vulnerabilities.

        Args:
            response_body: HTTP response body
            payload: XSS payload used
            url: Target URL

        Returns:
            Vulnerability object if XSS detected
        """

    def analyze_command_injection(self, response_body: str, response_time: float,
                                  payload: str, url: str) -> Optional[Vulnerability]:
        """
        Analyze response for command injection.

        Args:
            response_body: HTTP response body
            response_time: Response time in seconds
            payload: Command injection payload
            url: Target URL

        Returns:
            Vulnerability object if command injection detected
        """

    def check_security_headers(self, headers: Dict[str, str]) -> List[str]:
        """
        Check for missing security headers.

        Args:
            headers: Response headers dictionary

        Returns:
            List of missing security headers
        """
```

**Vulnerability Detection Logic:**

```python
# SQL Injection Indicators
SQL_ERROR_PATTERNS = [
    "SQL syntax error",
    "mysql_fetch_array()",
    "ORA-01756",  # Oracle
    "Microsoft OLE DB Provider for SQL Server",
    "Unclosed quotation mark",
]

# XSS Detection
def analyze_xss(self, response_body: str, payload: str, url: str):
    """Detect if XSS payload is reflected without encoding"""
    if payload in response_body:
        # Check if payload is encoded
        encoded_variants = [
            html.escape(payload),
            urllib.parse.quote(payload),
        ]

        if not any(variant in response_body for variant in encoded_variants):
            return Vulnerability(
                vulnerability_type="Cross-Site Scripting (XSS)",
                severity="HIGH",
                url=url,
                payload=payload,
                evidence=f"Payload reflected unencoded: {payload[:100]}"
            )
```

### Vulnerability Scanner (`utils/security/vulnerability_scanner.py`)

The Vulnerability Scanner orchestrates automated security testing using payloads and analysis.

**Key Methods:**

```python
class VulnerabilityScanner:
    """
    Automated security vulnerability scanner.
    """

    def __init__(self, driver: WebDriver, base_url: str):
        """
        Initialize scanner.

        Args:
            driver: Selenium WebDriver instance
            base_url: Base URL to scan
        """
        self.driver = driver
        self.base_url = base_url
        self.payload_library = PayloadLibrary()
        self.analyzer = ResponseAnalyzer()

    def scan_for_sql_injection(self, form_inputs: List[WebElement]) -> List[Vulnerability]:
        """
        Scan form inputs for SQL injection vulnerabilities.

        Args:
            form_inputs: List of form input elements

        Returns:
            List of detected vulnerabilities
        """

    def scan_for_xss(self, form_inputs: List[WebElement]) -> List[Vulnerability]:
        """
        Scan for XSS vulnerabilities.

        Args:
            form_inputs: List of form input elements

        Returns:
            List of detected XSS vulnerabilities
        """

    def scan_page(self, url: str) -> Dict[str, List[Vulnerability]]:
        """
        Comprehensive scan of a single page.

        Args:
            url: URL to scan

        Returns:
            Dictionary of vulnerabilities by type
        """

    def generate_report(self, vulnerabilities: List[Vulnerability]) -> str:
        """
        Generate security scan report.

        Args:
            vulnerabilities: List of vulnerabilities found

        Returns:
            Formatted report string
        """
```

## Usage

### Running Security Tests

**Run all security tests:**
```bash
pytest -m security -v
```

**Run specific vulnerability tests:**
```bash
pytest -m sql_injection -v
pytest -m xss -v
pytest -m csrf -v
```

**Run with detailed output:**
```bash
pytest -m security -v --tb=long --capture=no
```

**Generate security report:**
```bash
pytest -m security --html=results/security_report.html
```

### Basic Security Testing Example

```python
import pytest
from utils.security.payload_library import PayloadLibrary
from utils.security.vulnerability_scanner import VulnerabilityScanner
from utils.security.response_analyzer import ResponseAnalyzer

@pytest.mark.security
@pytest.mark.sql_injection
class TestSQLInjection:
    """SQL Injection security tests"""

    def test_login_sql_injection_SEC_001(self, browser):
        """Test login form for SQL injection vulnerabilities"""
        # Initialize scanner
        scanner = VulnerabilityScanner(browser, "https://example.com")

        # Navigate to login page
        browser.get("https://example.com/login")

        # Find form inputs
        username_input = browser.find_element("id", "username")
        password_input = browser.find_element("id", "password")

        # Get SQL injection payloads
        library = PayloadLibrary()
        payloads = library.get_sql_injection_payloads()

        vulnerabilities = []

        # Test each payload
        for payload_obj in payloads:
            username_input.clear()
            username_input.send_keys(payload_obj.payload)
            password_input.clear()
            password_input.send_keys("password")

            # Submit form
            submit_button = browser.find_element("css selector", "button[type='submit']")
            submit_button.click()

            # Analyze response
            analyzer = ResponseAnalyzer()
            vuln = analyzer.analyze_sql_injection(
                response_body=browser.page_source,
                status_code=200,
                url=browser.current_url,
                method="POST",
                payload=payload_obj.payload
            )

            if vuln:
                vulnerabilities.append(vuln)

        # Assert no vulnerabilities found
        assert len(vulnerabilities) == 0, \
            f"SQL Injection vulnerabilities detected: {vulnerabilities}"
```

### XSS Testing Example

```python
@pytest.mark.security
@pytest.mark.xss
def test_search_xss_SEC_002(browser):
    """Test search functionality for XSS vulnerabilities"""
    scanner = VulnerabilityScanner(browser, "https://example.com")
    library = PayloadLibrary()

    # Navigate to search page
    browser.get("https://example.com/search")

    # Get XSS payloads
    xss_payloads = library.get_xss_payloads()

    vulnerabilities = []

    for payload_obj in xss_payloads:
        # Enter payload in search box
        search_input = browser.find_element("name", "q")
        search_input.clear()
        search_input.send_keys(payload_obj.payload)
        search_input.submit()

        # Check if payload is reflected
        page_source = browser.page_source

        analyzer = ResponseAnalyzer()
        vuln = analyzer.analyze_xss(
            response_body=page_source,
            payload=payload_obj.payload,
            url=browser.current_url
        )

        if vuln:
            vulnerabilities.append(vuln)

    assert len(vulnerabilities) == 0, f"XSS vulnerabilities found: {vulnerabilities}"
```

### Automated Page Scanning

```python
def test_comprehensive_security_scan_SEC_003(browser):
    """Comprehensive security scan of critical pages"""
    scanner = VulnerabilityScanner(browser, "https://example.com")

    critical_pages = [
        "/login",
        "/signup",
        "/profile",
        "/search",
        "/checkout"
    ]

    all_vulnerabilities = {}

    for page in critical_pages:
        url = f"https://example.com{page}"
        vulnerabilities = scanner.scan_page(url)
        if vulnerabilities:
            all_vulnerabilities[page] = vulnerabilities

    # Generate report
    if all_vulnerabilities:
        report = scanner.generate_report(all_vulnerabilities)
        print(report)

    assert len(all_vulnerabilities) == 0, "Security vulnerabilities detected"
```

## Configuration

### Security Scanner Configuration

Configure in `conftest.py`:

```python
SECURITY_CONFIG = {
    "enabled": True,
    "scan_depth": "comprehensive",  # quick, standard, comprehensive
    "payloads": {
        "sql_injection": True,
        "xss": True,
        "command_injection": True,
        "csrf": True
    },
    "timeouts": {
        "request_timeout": 30,
        "scan_timeout": 600
    },
    "reporting": {
        "generate_html": True,
        "generate_json": True,
        "output_dir": "results/security/"
    },
    "severity_threshold": "MEDIUM"  # Only report MEDIUM and above
}
```

### Pytest Markers

Markers defined in `pytest.ini`:

```ini
[pytest]
markers =
    security: Security vulnerability tests
    sql_injection: SQL injection tests
    xss: Cross-site scripting tests
    csrf: CSRF protection tests
    authentication: Authentication security tests
    authorization: Authorization security tests
    owasp: OWASP Top 10 tests
```

## Test Coverage

### OWASP Top 10 Coverage

| OWASP Category | Coverage | Tests |
|----------------|----------|-------|
| A01: Broken Access Control | 80% | 12 |
| A02: Cryptographic Failures | 70% | 8 |
| A03: Injection | 100% | 25 |
| A04: Insecure Design | 60% | 6 |
| A05: Security Misconfiguration | 75% | 10 |
| A06: Vulnerable Components | 50% | 5 |
| A07: Auth Failures | 90% | 15 |
| A08: Data Integrity Failures | 65% | 7 |
| A09: Logging Failures | 70% | 8 |
| A10: SSRF | 60% | 6 |

### Vulnerability Types Tested

- SQL Injection: 25 test cases
- Cross-Site Scripting (XSS): 18 test cases
- Command Injection: 12 test cases
- CSRF: 10 test cases
- Authentication Bypass: 15 test cases
- Session Management: 10 test cases
- Authorization: 12 test cases

## Maintenance

### Adding New Security Tests

1. **Add payload to library**:

```python
# utils/security/payload_library.py

NEW_VULNERABILITY_PAYLOADS = [
    SecurityPayload(
        category="new_vulnerability",
        payload="test_payload",
        severity="HIGH",
        description="Description of the payload",
        expected_safe_behavior="Expected safe behavior"
    ),
]
```

2. **Create detection logic**:

```python
# utils/security/response_analyzer.py

def analyze_new_vulnerability(self, response_body: str, payload: str, url: str):
    """Detect new vulnerability type"""
    # Detection logic here
    pass
```

3. **Write tests**:

```python
# tests/security_real/test_new_vulnerability.py

@pytest.mark.security
@pytest.mark.new_vulnerability
def test_new_vulnerability_SEC_NEW_001(browser):
    """Test for new vulnerability"""
    # Test implementation
    pass
```

### Updating Payloads

To add new payloads or update existing ones:

1. Modify `utils/security/payload_library.py`
2. Run tests to verify:
```bash
pytest -m security -v
```

### Handling False Positives

Document false positives in `tests/security_real/known_false_positives.md`:

```markdown
## Known False Positives

### SQL Injection Test - Login Page

- **Test:** test_login_sql_injection_SEC_001
- **Payload:** `' OR '1'='1`
- **Reason:** Custom error message contains SQL keyword
- **Resolution:** Updated detection logic to ignore this specific case
```

## Security Standards

### OWASP Compliance

This module implements testing based on:

- **OWASP Top 10 2021**
- **OWASP ASVS 4.0** (Application Security Verification Standard)
- **OWASP Testing Guide v4.2**

### Testing Methodology

1. **Black Box Testing**: No knowledge of internal implementation
2. **White Box Testing**: With knowledge of code and architecture
3. **Gray Box Testing**: Partial knowledge

### Severity Classification

Based on CVSS v3.1:

- **CRITICAL**: 9.0-10.0 (Immediate action required)
- **HIGH**: 7.0-8.9 (Urgent attention needed)
- **MEDIUM**: 4.0-6.9 (Should be addressed)
- **LOW**: 0.1-3.9 (Minimal risk)

## Common Issues and Solutions

### Issue: Too Many False Positives

**Problem:** Scanner reports vulnerabilities that aren't real.

**Solution:**
```python
# Tune detection thresholds
analyzer = ResponseAnalyzer(
    sql_error_threshold=0.9,  # Require 90% confidence
    xss_context_aware=True     # Use context-aware detection
)
```

### Issue: Scans Take Too Long

**Problem:** Comprehensive scans timeout.

**Solution:**
```python
# Use targeted scanning
scanner.scan_page(
    url="/login",
    vulnerability_types=["sql_injection", "xss"],  # Only test these
    max_payloads_per_type=10  # Limit payload count
)
```

### Issue: Application Rate Limiting

**Problem:** Security scans trigger rate limits.

**Solution:**
```python
# Add delays between tests
import time

for payload in payloads:
    test_payload(payload)
    time.sleep(1)  # 1 second delay
```

## Performance Considerations

- **Scan time**: 2-5 minutes per page (comprehensive scan)
- **Parallel execution**: Not recommended for security tests (may trigger rate limits)
- **Resource usage**: Moderate (browser + proxy overhead)

## Best Practices

1. **Never run security tests on production** without explicit authorization
2. **Use test environments** that mirror production
3. **Document all findings** with evidence
4. **Verify vulnerabilities manually** before reporting
5. **Follow responsible disclosure** guidelines

## Future Enhancements

1. **Automated exploit generation**
2. **Machine learning-based detection**
3. **Integration with SAST/DAST tools**
4. **WebSocket security testing**
5. **API security testing expansion**

## References

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

## Support

For security issues or questions:
- Contact security team lead
- Review security findings in `results/security/`
- Follow responsible disclosure policy

## License

Internal testing module - follows project license.

**WARNING**: This module contains security testing tools. Use only on systems you have explicit authorization to test. Unauthorized use may be illegal.
