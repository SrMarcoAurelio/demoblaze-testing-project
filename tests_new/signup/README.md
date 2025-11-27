# SIGNUP Module - Test Suite Documentation

## Overview

Complete test coverage for the SIGNUP/Registration functionality of DemoBlaze, following the **Page Object Model (POM)** architecture and **DISCOVER philosophy** (EXECUTE → OBSERVE → DECIDE).

**Author:** Marc Arévalo
**Version:** 1.0
**Architecture:** Page Object Model (POM)

---

## Test Files Structure

```
tests_new/signup/
├── test_signup_functional.py    # Core functionality tests (6 tests)
├── test_signup_business.py      # Business rules & standards (19 tests)
├── test_signup_security.py      # Security vulnerability discovery (13 tests)
└── README.md                    # This file
```

**Page Object:**
```
pages/signup_page.py             # SignupPage POM class
```

---

## Test Statistics

| Category | Test Functions | Total Executions* | Coverage |
|----------|---------------|-------------------|----------|
| **Functional** | 6 | 6 | Core features |
| **Business Rules** | 19 | ~30 | Standards compliance |
| **Security** | 13 | ~25 | Vulnerability discovery |
| **TOTAL** | **38** | **~61** | 100% parity |

*With parametrization

---

## 1. Functional Tests (test_signup_functional.py)

### Purpose
Verify core signup functionality works correctly under normal conditions.

### Tests (6)

| Test ID | Test Name | Priority | Description |
|---------|-----------|----------|-------------|
| FUNC-001 | `test_valid_signup_with_unique_credentials` | CRITICAL | Valid signup with unique username/password |
| FUNC-002 | `test_duplicate_username_rejected` | CRITICAL | Duplicate username properly rejected |
| FUNC-003 | `test_empty_username_rejected` | HIGH | Empty username field validation |
| FUNC-004 | `test_empty_password_rejected` | HIGH | Empty password field validation |
| FUNC-005 | `test_signup_with_enter_key` | MEDIUM | Signup submission via Enter key |
| FUNC-006 | `test_signup_modal_close_button` | MEDIUM | Modal close functionality |

### Execution
```bash
# Run all functional tests
pytest tests_new/signup/test_signup_functional.py -v

# Run critical tests only
pytest tests_new/signup/test_signup_functional.py -m "critical" -v
```

---

## 2. Business Rules Tests (test_signup_business.py)

### Purpose
Validate compliance with industry standards (OWASP, NIST, ISO, WCAG, PCI-DSS).

### Standards Validated
- **OWASP ASVS v5.0** - Authentication & Input Validation
- **NIST SP 800-63B** - Digital Identity Guidelines
- **ISO 27001** - Information Security Management
- **ISO 25010** - Software Quality Model
- **WCAG 2.1** - Web Accessibility
- **PCI-DSS 4.0.1** - Payment Card Security

### Tests (19)

| Test ID | Test Name | Standard | Priority | Parametrized |
|---------|-----------|----------|----------|--------------|
| BR-001 | `test_minimum_username_length` | ISO 27001 | HIGH | ✓ (3 cases) |
| BR-002 | `test_maximum_username_length` | ISO 25010 | HIGH | ✓ (3 cases) |
| BR-003 | `test_minimum_password_length` | NIST SP 800-63B | CRITICAL | ✓ (4 cases) |
| BR-004 | `test_maximum_password_length` | ISO 25010 | MEDIUM | ✗ |
| BR-005 | `test_special_characters_username` | ISO 25010 | MEDIUM | ✓ (5 cases) |
| BR-006 | `test_case_sensitivity_username` | ISO 27001 | MEDIUM | ✗ |
| BR-007 | `test_case_sensitivity_password` | NIST SP 800-63B | CRITICAL | ✗ |
| BR-008 | `test_username_with_spaces` | ISO 25010 | MEDIUM | ✗ |
| BR-009 | `test_password_with_spaces` | NIST SP 800-63B | MEDIUM | ✗ |
| BR-010 | `test_leading_trailing_whitespace` | ISO 25010 | MEDIUM | ✗ |
| BR-011 | `test_sql_injection_prevention` | OWASP ASVS 1.2.5 | CRITICAL | ✓ (4 cases) |
| BR-012 | `test_xss_prevention` | OWASP ASVS 5.3.3 | CRITICAL | ✓ (3 cases) |
| BR-013 | `test_password_complexity_enforcement` | NIST SP 800-63B | MEDIUM | ✓ (6 cases) |
| BR-014 | `test_account_lockout_rate_limiting` | OWASP ASVS 2.2.1 | HIGH | ✗ |
| BR-015 | `test_captcha_bot_protection` | OWASP ASVS 2.2.1 | MEDIUM | ✗ |
| BR-016 | `test_email_verification_requirement` | NIST SP 800-63B | LOW | ✗ |
| BR-017 | `test_keyboard_navigation_accessibility` | WCAG 2.1 | MEDIUM | ✗ |
| BR-018 | `test_screen_reader_accessibility` | WCAG 2.1 | MEDIUM | ✗ |
| BR-019 | `test_username_enumeration_prevention` | OWASP ASVS 2.2.2 | MEDIUM | ✗ |

### Execution
```bash
# Run all business rules tests
pytest tests_new/signup/test_signup_business.py -v

# Run critical tests only
pytest tests_new/signup/test_signup_business.py -m "critical" -v

# Run by standard
pytest tests_new/signup/test_signup_business.py -k "sql_injection" -v
pytest tests_new/signup/test_signup_business.py -k "password_complexity" -v
```

---

## 3. Security Tests (test_signup_security.py)

### Purpose
**DISCOVER** security vulnerabilities through active exploitation attempts.

### CVSS Severity Distribution
- **CRITICAL (9.0-10.0):** 4 tests
- **HIGH (7.0-8.9):** 5 tests
- **MEDIUM (4.0-6.9):** 3 tests
- **LOW (0.1-3.9):** 1 test

### Tests (13)

| Test ID | Test Name | CWE | CVSS | Parametrized |
|---------|-----------|-----|------|--------------|
| SEC-001 | `test_sql_injection_username_field` | CWE-89 | 9.8 CRITICAL | ✓ (6 payloads) |
| SEC-002 | `test_sql_injection_password_field` | CWE-89 | 9.8 CRITICAL | ✓ (3 payloads) |
| SEC-003 | `test_xss_username_field` | CWE-79 | 7.1 HIGH | ✓ (5 payloads) |
| SEC-004 | `test_stored_xss_via_username` | CWE-79 | 8.7 HIGH | ✗ |
| SEC-005 | `test_brute_force_protection` | CWE-307 | 7.5 HIGH | ✗ |
| SEC-006 | `test_account_enumeration_timing` | CWE-208 | 5.3 MEDIUM | ✗ |
| SEC-007 | `test_username_enumeration` | CWE-204 | 5.3 MEDIUM | ✗ |
| SEC-008 | `test_session_fixation` | CWE-384 | 7.5 HIGH | ✗ |
| SEC-009 | `test_cookie_security_flags` | CWE-614 | 6.5 MEDIUM | ✗ |
| SEC-010 | `test_csrf_token_validation` | CWE-352 | 6.5 MEDIUM | ✗ |
| SEC-011 | `test_security_headers` | CWE-693 | 7.5 HIGH | ✗ |
| SEC-012 | `test_password_transmitted_plaintext` | CWE-319 | 7.4 HIGH | ✗ |
| SEC-013 | `test_verbose_error_messages` | CWE-209 | 3.7 LOW | ✗ |

### Attack Vectors Tested

**Injection Attacks:**
- SQL Injection (username/password fields)
- Command Injection
- LDAP Injection

**Cross-Site Attacks:**
- Reflected XSS
- Stored XSS
- DOM-based XSS

**Authentication Security:**
- Brute force attacks
- Account enumeration (timing & error messages)
- Credential stuffing

**Session Security:**
- Session fixation
- Cookie security (Secure, HttpOnly flags)

**Security Controls:**
- CSRF protection
- Security headers (X-Frame-Options, CSP, HSTS, etc.)
- Error handling (verbose messages)
- HTTPS enforcement

### Execution
```bash
# Run all security tests
pytest tests_new/signup/test_signup_security.py -v

# Run critical vulnerabilities only
pytest tests_new/signup/test_signup_security.py -m "critical" -v

# Run by attack type
pytest tests_new/signup/test_signup_security.py -k "sql_injection" -v
pytest tests_new/signup/test_signup_security.py -k "xss" -v
pytest tests_new/signup/test_signup_security.py -k "brute_force" -v

# Run by severity
pytest tests_new/signup/test_signup_security.py -m "high" -v
pytest tests_new/signup/test_signup_security.py -m "medium" -v
```

---

## DISCOVER Philosophy

All tests follow the **DISCOVER pattern**:

### 1. EXECUTE
- Perform actual actions against the application
- No mocking, no assumptions
- Real browser interactions via Selenium

### 2. OBSERVE
- Capture actual system responses
- Measure real timing, read real alerts, check real page sources
- Document exactly what happened

### 3. DECIDE
- Compare observations against objective standards (OWASP, NIST, ISO, CWE)
- Pass/fail based on real evidence, not expectations
- Log discoveries with full context

### Example:

```python
# EXECUTE: Attempt SQL injection
signup_page.signup("' OR '1'='1", "password")

# OBSERVE: What actually happened?
alert_text = signup_page.get_alert_text(timeout=5)

# DECIDE: Based on observation vs. standard
if alert_text and "success" in alert_text.lower():
    pytest.fail("DISCOVERED: SQL Injection vulnerability")
else:
    logging.info("✓ SQL payload handled safely")
```

---

## Page Object Model (POM)

### SignupPage Class (`pages/signup_page.py`)

**Key Methods:**
- `signup(username, password)` - Complete signup flow
- `open_signup_modal()` - Open signup modal
- `fill_signup_username(username)` - Fill username field
- `fill_signup_password(password)` - Fill password field
- `click_signup_submit()` - Click signup button
- `login_after_signup(username, password)` - Login with new account
- `generate_unique_username()` - Generate unique test username
- `is_user_logged_in()` - Check if user is logged in
- `logout()` - Logout current user

**Locators (Centralized):**
```python
SIGNUP_BUTTON_NAV = (By.ID, "signin2")
SIGNUP_MODAL = (By.ID, "signInModal")
SIGNUP_USERNAME_FIELD = (By.ID, "sign-username")
SIGNUP_PASSWORD_FIELD = (By.ID, "sign-password")
SIGNUP_SUBMIT_BUTTON = (By.XPATH, "//button[text()='Sign up']")
```

---

## Running All Signup Tests

```bash
# Run entire signup module
pytest tests_new/signup/ -v

# Run with HTML report
pytest tests_new/signup/ --html=reports/signup_report.html --self-contained-html

# Run by priority
pytest tests_new/signup/ -m "critical" -v
pytest tests_new/signup/ -m "high" -v

# Run by category
pytest tests_new/signup/ -k "functional" -v
pytest tests_new/signup/ -k "security" -v
pytest tests_new/signup/ -k "business" -v

# Run in parallel (faster)
pytest tests_new/signup/ -n auto -v
```

---

## Test Markers

```python
@pytest.mark.functional      # Core functionality tests
@pytest.mark.security        # Security vulnerability tests
@pytest.mark.business_rules  # Standards compliance tests

@pytest.mark.critical        # Severity: Critical
@pytest.mark.high            # Severity: High
@pytest.mark.medium          # Severity: Medium
@pytest.mark.low             # Severity: Low

@pytest.mark.injection       # Injection attack tests
@pytest.mark.xss             # Cross-site scripting tests
@pytest.mark.csrf            # CSRF protection tests
@pytest.mark.session         # Session security tests
@pytest.mark.enumeration     # Account enumeration tests
```

---

## Expected Results

### Functional Tests
- **Expected Pass:** 6/6 (100%)
- Tests verify normal operation

### Business Rules Tests
- **Expected Pass:** ~15-17/19 (~85%)
- Some standards may not be implemented (e.g., CAPTCHA, email verification)
- Failures = **Discoveries** of missing features/protections

### Security Tests
- **Expected Pass:** ~5-8/13 (~40-60%)
- Many vulnerabilities expected to be discovered
- Failures = **Critical Discoveries** requiring remediation

> **Note:** In security testing, **failures are discoveries**. A failing test means a real vulnerability was found.

---

## Migration from Original Tests

This module achieves **100% parity** with original signup tests:

**Original:**
- `tests/signup/functional-tests/test_signup_functionality.py` (25 tests)
- `tests/signup/security-tests/test_signup_security.py` (13 tests)

**New POM Architecture:**
- `tests_new/signup/test_signup_functional.py` (6 tests)
- `tests_new/signup/test_signup_business.py` (19 tests)
- `tests_new/signup/test_signup_security.py` (13 tests)

**Total:** 38 test functions, ~61 total executions with parametrization

---

## Dependencies

```python
# Core
selenium>=4.0.0
pytest>=7.0.0
pytest-html>=3.1.0

# Additional
requests>=2.28.0  # For header validation (SEC-011)
```

---

## Continuous Integration

```yaml
# Example CI configuration
- name: Run SIGNUP Tests
  run: |
    pytest tests_new/signup/ -v --html=reports/signup.html

- name: Run Critical Security Tests
  run: |
    pytest tests_new/signup/test_signup_security.py -m "critical" -v
```

---

## Contact

**Author:** Marc Arévalo
**Project:** DemoBlaze Test Automation (POM Restructuring)
**Date:** 2025

---

## References

- [OWASP ASVS v5.0](https://owasp.org/www-project-application-security-verification-standard/)
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1)
- [WCAG 2.1 Guidelines](https://www.w3.org/WAI/WCAG21/quickref/)
- [PCI-DSS 4.0.1](https://www.pcisecuritystandards.org/)
