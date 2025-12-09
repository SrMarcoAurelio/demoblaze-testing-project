# Security Utilities

## Overview

Comprehensive security testing utilities for OWASP Top 10 validation.

## Files (1,265 lines total)

- `payload_library.py` (347 lines) - Security test payloads database
- `response_analyzer.py` (452 lines) - Vulnerability detection engine
- `vulnerability_scanner.py` (466 lines) - Automated security scanner
- `security_report_generator.py` - Security report generation

## Key Classes

### PayloadLibrary (15 unit tests)

Centralized security payload database.

**Methods:**
- `get_payloads(category)` - Get payloads by category
- `get_sql_injection_payloads()` - SQL injection payloads
- `get_xss_payloads()` - XSS payloads
- `get_command_injection_payloads()` - Command injection payloads

### ResponseAnalyzer (12 unit tests)

Analyzes responses for vulnerability indicators.

**Methods:**
- `analyze_sql_injection(response_body, status_code, url, method, payload)` - SQL injection detection
- `analyze_xss(response_body, payload, url)` - XSS detection
- `analyze_command_injection(response_body, response_time, payload, url)` - Command injection detection
- `check_security_headers(headers)` - Security headers validation

### VulnerabilityScanner (10 unit tests)

Automated vulnerability scanning orchestration.

**Methods:**
- `scan_for_sql_injection(form_inputs)` - SQL injection scanning
- `scan_for_xss(form_inputs)` - XSS scanning
- `scan_page(url)` - Comprehensive page scan
- `generate_report(vulnerabilities)` - Report generation

## Usage

```python
from utils.security.payload_library import PayloadLibrary
from utils.security.vulnerability_scanner import VulnerabilityScanner

# Get payloads
library = PayloadLibrary()
sql_payloads = library.get_sql_injection_payloads()

# Scan for vulnerabilities
scanner = VulnerabilityScanner(driver, base_url)
vulnerabilities = scanner.scan_page("/login")

assert len(vulnerabilities) == 0, "Vulnerabilities detected!"
```

## WARNING

Only use on authorized systems. Unauthorized security testing may be illegal.

## Documentation

See [Security Testing Module](../../documentation/modules/security-testing.md)
