# Security Tests

## Overview

OWASP Top 10 2021 compliance testing with real HTTP interception and vulnerability scanning.

## Test Coverage (102+ tests)

- SQL Injection (25 tests)
- Cross-Site Scripting / XSS (18 tests)
- Command Injection (12 tests)
- CSRF Protection (10 tests)
- Authentication Security (15 tests)
- Authorization Security (12 tests)
- Session Management (10 tests)

## Utilities

- `utils/security/payload_library.py` (347 lines)
- `utils/security/response_analyzer.py` (452 lines)
- `utils/security/vulnerability_scanner.py` (466 lines)

## Running Tests

```bash
pytest -m security -v
pytest tests/security_real/ -v
```

## WARNING

Only use on authorized systems. Unauthorized security testing may be illegal.

## Documentation

See [Security Testing Module](../../documentation/modules/security-testing.md)
