# Login Functional Testing Suite - README

**Test File:** `test_login_functionality.py`  
**Version:** 2.0 - Complete DISCOVER Philosophy Implementation  
**Last Updated:** November 2025  
**Author:** QA Testing Team

---

## Table of Contents

1. [Overview](#overview)
2. [Philosophy: DISCOVER Methodology](#philosophy)
3. [Test Coverage](#coverage)
4. [Quick Start](#quick-start)
5. [Configuration](#configuration)
6. [Test Inventory](#inventory)
7. [Helper Functions](#helpers)
8. [Execution Guide](#execution)
9. [Expected Results](#expected)
10. [Understanding Test Failures](#understanding)
11. [Troubleshooting](#troubleshooting)
12. [Standards Reference](#standards)
13. [Version History](#version)

---

<a name="overview"></a>
## 1. Overview

### Purpose

This test suite validates the **Login & Authentication** functionality following the **DISCOVER methodology**. Tests execute actions, observe system responses, and make decisions based on objective industry standards.

**Module Under Test:** Login & Authentication  
**Application:** DemoBlaze (https://www.demoblaze.com/)

### Scope

This suite covers:

1. **Functional Tests** (7 tests)
   - Valid login with correct credentials
   - Invalid username/password rejection
   - Empty credentials handling
   - Complete login-logout flow
   - Modal interaction
   - Session persistence

2. **Business Rules Tests** (22 tests)
   - Input validation (username/password length, whitespace, special chars, case sensitivity)
   - Security validation (SQL injection, XSS, rate limiting, 2FA, password complexity, CAPTCHA)
   - Accessibility compliance (keyboard navigation, screen reader support)
   - Session security (timeout enforcement)
   - Password reset mechanism

### Key Metrics

- **Total Test Functions:** 29
- **Total Test Runs:** 35+ (includes parametrized tests)
- **Standards Validated:** OWASP ASVS v5.0, NIST SP 800-63B, ISO 27001, WCAG 2.1, ISO 25010
- **Test Execution Time:** ~120-180 seconds (depending on network)

---

<a name="philosophy"></a>
## 2. Philosophy: DISCOVER Methodology

### Core Principle

> **Tests DISCOVER behavior by EXECUTING actions and OBSERVING results.**  
> **Tests NEVER ASSUME how the application will behave.**

### The DISCOVER Formula

```
DISCOVER = EXECUTE + OBSERVE + DECIDE

1. EXECUTE: Run the actual action (login, validate, submit)
2. OBSERVE: Capture the real system response  
3. DECIDE: Compare against objective standards (OWASP, NIST, ISO, WCAG)
```

### Example: How DISCOVER Works

#### WRONG (Assuming):
```python
def test_2fa():
    # "I know DemoBlaze doesn't have 2FA"
    pytest.skip("DemoBlaze doesn't implement 2FA")  # WRONG!
```

#### CORRECT (Discovering):
```python
def test_2fa_mfa_enforcement_BR_018():
    """
    NIST 800-63B Section 5.2.3: MFA should be required
    
    Discovers if system has multi-factor authentication.
    """
    # EXECUTE: Login with password
    perform_login(browser, username, password)
    
    # OBSERVE: Check if 2FA prompt appears
    mfa_prompt_exists = check_for_mfa_elements(browser)
    
    # DECIDE: According to NIST 800-63B, 2FA should exist
    if not mfa_prompt_exists:
        logging.critical("SECURITY VIOLATION: NO 2FA/MFA")
        logging.critical("Standard: NIST 800-63B 5.2.3")
        logging.critical("CVSS Score: 7.5 (HIGH)")
        pytest.fail("DISCOVERED: NO 2FA - Violates NIST 800-63B")
    else:
        assert True  # DISCOVERED: 2FA implemented
```

### Why This Matters

**Code is universal:**
- Change `BASE_URL` + `LOCATORS` = works on ANY login system
- Tests discover actual behavior objectively
- Same tests work on Amazon, banking apps, government sites

**Tests are honest:**
- Don't hide missing features
- Report violations against industry standards
- Provide clear evidence for security assessments

---

<a name="coverage"></a>
## 3. Test Coverage

### 3.1 Functional Tests (Expected to PASS)

| Test ID | Test Name | Description | Expected Result |
|---------|-----------|-------------|-----------------|
| FUNC-001 | `test_valid_login_success` | Valid credentials login | PASS - User authenticates |
| FUNC-002 | `test_invalid_username_rejected` | Non-existent username | PASS - Login rejected |
| FUNC-003 | `test_invalid_password_rejected` | Wrong password | PASS - Login rejected |
| FUNC-004 | `test_empty_credentials_rejected` | Empty fields | PASS - Login rejected |
| FUNC-005 | `test_complete_login_logout_flow` | Full authentication cycle | PASS - Both operations work |
| FUNC-006 | `test_modal_close_button` | Modal interaction | PASS - Can close modal |
| FUNC-007 | `test_session_persistence_after_reload` | Session management | PASS - Session persists |

### 3.2 Business Rules Tests - Input Validation

| Test ID | Test Name | Standard | Expected Result |
|---------|-----------|----------|-----------------|
| BR-001 | `test_username_max_length` | ISO 25010 | PASS - Rejects or handles long input |
| BR-002 | `test_password_max_length` | NIST 800-63B 5.1.1 | PASS - Handles long passwords |
| BR-003 | `test_whitespace_only_username` | ISO 27001 A.9.4 | PASS - Rejects whitespace |
| BR-004 | `test_whitespace_only_password` | NIST 800-63B 5.1.1 | PASS - Rejects whitespace |
| BR-005 | `test_username_whitespace_normalization` | ISO 25010 | MIXED - May or may not trim |
| BR-006 | `test_special_characters_in_username` | OWASP ASVS 2.3.1 | PASS - Handles appropriately |
| BR-007 | `test_case_sensitivity_username` | ISO 27001 A.9.4 | PASS - Documents behavior |
| BR-008 | `test_case_sensitivity_password` | NIST 800-63B 5.1.1 | PASS - Must be case-sensitive |
| BR-009 | `test_empty_username_only` | WCAG 2.1 SC 3.3.1 | PASS - Validates individually |
| BR-010 | `test_empty_password_only` | WCAG 2.1 SC 3.3.1 | PASS - Validates individually |
| BR-011 | `test_numeric_only_username` | ISO 25010 | PASS - Documents behavior |
| BR-012 | `test_unicode_characters` | ISO 25010 | PASS - Documents support |

### 3.3 Business Rules Tests - Security (Parametrized)

| Test ID | Test Name | Standard | Payloads | Expected Result |
|---------|-----------|----------|----------|-----------------|
| BR-013 | `test_sql_injection_prevention` | OWASP ASVS 1.2.5 | 4 SQL payloads | PASS - Blocks injections |
| BR-014 | `test_xss_prevention` | OWASP ASVS 1.2.1 | 4 XSS payloads | PASS - Prevents XSS |
| BR-019 | `test_password_complexity_enforcement` | NIST 800-63B 5.1.1.2 | 6 weak passwords | **FAIL** - Accepts weak passwords |

### 3.4 Business Rules Tests - Accessibility

| Test ID | Test Name | Standard | Expected Result |
|---------|-----------|----------|-----------------|
| BR-015 | `test_keyboard_navigation` | WCAG 2.1 SC 2.1.1 | PASS - Keyboard accessible |
| BR-016 | `test_form_labels_for_screen_readers` | WCAG 2.1 SC 1.3.1 | PASS - Labels present |

### 3.5 Expected Test Failures (Discoveries)

**CRITICAL:** These tests DISCOVER missing security features and report them as violations:

| Test ID | Feature Tested | Standard | CVSS | Expected Result for DemoBlaze |
|---------|----------------|----------|------|-------------------------------|
| BR-017 | Account Lockout / Rate Limiting | OWASP ASVS 2.2.1 | 7.5 | **FAIL** - No rate limiting detected |
| BR-018 | 2FA/MFA Enforcement | NIST 800-63B 5.2.3 | 7.5 | **FAIL** - No 2FA detected |
| BR-019 | Password Complexity | NIST 800-63B 5.1.1.2 | 6.5 | **FAIL** - Weak passwords accepted |
| BR-020 | CAPTCHA Protection | OWASP ASVS 2.2.3 | 6.5 | **FAIL** - No CAPTCHA detected |
| BR-021 | Password Reset | OWASP ASVS 2.5.6 | 5.0 | **FAIL** - No reset mechanism |
| BR-022 | Session Timeout | OWASP ASVS 3.3.2 | 5.3 | **FAIL** - Timeout not clearly configured |

**Important:** These failures are NOT bugs in the tests - they are DISCOVERIES of missing security controls that violate industry standards. This is the correct behavior of DISCOVER tests.

---

<a name="quick-start"></a>
## 4. Quick Start

### Prerequisites

```bash
pip install pytest selenium webdriver-manager
```

### Run All Tests

```bash
pytest test_login_functionality.py -v
```

### Run Specific Categories

```bash
# Functional tests only
pytest test_login_functionality.py -k "FUNC" -v

# Business rules only
pytest test_login_functionality.py -k "BR" -v

# Security tests only
pytest test_login_functionality.py -k "security" -v

# Accessibility tests only
pytest test_login_functionality.py -k "accessibility" -v
```

### Generate HTML Report

```bash
pytest test_login_functionality.py --html=report_login_functional.html --self-contained-html
```

---

<a name="configuration"></a>
## 5. Configuration

### Global Configuration

```python
BASE_URL = "https://www.demoblaze.com/"
TEST_USERNAME = "Apolo2025"
TEST_PASSWORD = "apolo2025"
```

**To test a different application:**
1. Update `BASE_URL`
2. Update `LOCATORS` dictionary (LOGIN_BUTTON_NAV, LOGIN_USERNAME_FIELD, etc.)
3. Update test credentials
4. Run tests

### Timeout Configuration

```python
TIMEOUT = 10         # Standard element wait
TIMEOUT_SHORT = 2    # Quick checks (logged in status)
TIMEOUT_MEDIUM = 5   # Alert waits
```

### Test Credentials

**IMPORTANT:** The test user `Apolo2025` must exist in DemoBlaze before running tests.

To create test user:
1. Go to https://www.demoblaze.com/
2. Click "Sign up"
3. Create user: `Apolo2025` / `apolo2025`

---

<a name="inventory"></a>
## 6. Test Inventory

### Functional Tests

**FUNC-001: test_valid_login_success**
- Purpose: Verify successful authentication with valid credentials
- Priority: CRITICAL
- Expected: User logs in, welcome message appears

**FUNC-002: test_invalid_username_rejected**
- Purpose: Verify system rejects non-existent usernames
- Priority: HIGH (Security)
- Expected: Login fails, error message appears

**FUNC-003: test_invalid_password_rejected**
- Purpose: Verify system rejects wrong passwords
- Priority: CRITICAL (Security)
- Expected: Login fails, error message appears

**FUNC-004: test_empty_credentials_rejected**
- Purpose: Verify validation for empty fields
- Priority: HIGH
- Expected: Login fails, validation message appears

**FUNC-005: test_complete_login_logout_flow**
- Purpose: Verify full authentication cycle
- Priority: CRITICAL
- Expected: Both login and logout work correctly

**FUNC-006: test_modal_close_button**
- Purpose: Verify modal can be closed
- Priority: MEDIUM (UX)
- Expected: Modal closes, user remains logged out

**FUNC-007: test_session_persistence_after_reload**
- Purpose: Verify session management
- Priority: HIGH
- Expected: User remains logged in after refresh

### Business Rules Tests - Input Validation

**BR-001 to BR-012:** Input validation tests covering:
- Maximum length handling
- Whitespace validation and normalization
- Special characters
- Case sensitivity
- Empty field validation
- Numeric usernames
- Unicode support

### Business Rules Tests - Security

**BR-013: test_sql_injection_prevention (4 payloads)**
- Standard: OWASP ASVS v5.0 Section 1.2.5
- CVSS: 9.8 (CRITICAL)
- Payloads: `' OR '1'='1`, `admin'--`, `' OR '1'='1' --`, `') OR ('1'='1`
- Purpose: Discover if SQL injection is possible

**BR-014: test_xss_prevention (4 payloads)**
- Standard: OWASP ASVS v5.0 Section 1.2.1
- CVSS: 7.5 (HIGH)
- Payloads: `<script>alert('XSS')</script>`, `<img src=x onerror=alert('XSS')>`, etc.
- Purpose: Discover if XSS is possible

**BR-017: test_account_lockout_enforcement**
- Standard: OWASP ASVS 2.2.1, NIST 800-63B 5.2.2
- CVSS: 7.5 (HIGH)
- Purpose: Discover if rate limiting exists (prevents brute force)
- **Expected for DemoBlaze: FAIL** - No rate limiting detected

**BR-018: test_2fa_mfa_enforcement**
- Standard: NIST 800-63B 5.2.3, ISO 27001 A.9.4.2
- CVSS: 7.5 (HIGH)
- Purpose: Discover if 2FA/MFA is required
- **Expected for DemoBlaze: FAIL** - No 2FA detected

**BR-019: test_password_complexity_enforcement (6 weak passwords)**
- Standard: NIST 800-63B 5.1.1.2
- CVSS: 6.5 (MEDIUM)
- Payloads: `123456`, `password`, `abc`, `test`, `qwerty`, `12345678`
- Purpose: Discover if weak passwords are rejected
- **Expected for DemoBlaze: FAIL** - Weak passwords accepted

**BR-020: test_captcha_bot_protection**
- Standard: OWASP ASVS 2.2.3
- CVSS: 6.5 (MEDIUM)
- Purpose: Discover if CAPTCHA exists (prevents bots)
- **Expected for DemoBlaze: FAIL** - No CAPTCHA detected

**BR-021: test_password_reset_mechanism**
- Standard: OWASP ASVS 2.5.6
- CVSS: 5.0 (MEDIUM)
- Purpose: Discover if password reset functionality exists
- **Expected for DemoBlaze: FAIL** - No reset mechanism found

**BR-022: test_session_timeout_enforcement**
- Standard: OWASP ASVS 3.3.2, ISO 27001 A.9.4.2
- CVSS: 5.3 (MEDIUM)
- Purpose: Discover if session timeout is configured
- **Expected for DemoBlaze: FAIL** - Timeout not clearly configured

### Business Rules Tests - Accessibility

**BR-015: test_keyboard_navigation**
- Standard: WCAG 2.1 SC 2.1.1
- Purpose: Verify keyboard-only navigation works
- Expected: User can Tab through fields and submit with Enter

**BR-016: test_form_labels_for_screen_readers**
- Standard: WCAG 2.1 SC 1.3.1
- Purpose: Verify form labels for assistive technology
- Expected: Fields have aria-labels or placeholders

---

<a name="helpers"></a>
## 7. Helper Functions

### Core Helper Functions

```python
def wait_for_alert_and_get_text(browser, timeout=TIMEOUT_MEDIUM)
```
Waits for JavaScript alert, captures text, accepts alert. Returns alert text or None.

```python
def perform_login(browser, username, password, timeout=TIMEOUT)
```
Executes complete login flow: opens modal, fills fields, submits. Returns success boolean.

```python
def is_user_logged_in(browser, timeout=TIMEOUT_MEDIUM)
```
Checks if user is authenticated by looking for welcome message. Returns boolean.

```python
def perform_logout(browser, timeout=TIMEOUT)
```
Clicks logout button and waits. Returns success boolean.

**Purpose:** These helpers follow DISCOVER philosophy - they EXECUTE actions but don't make assumptions. Validation is done separately in test functions.

---

<a name="execution"></a>
## 8. Execution Guide

### Command Reference

```bash
# Run all tests with verbose output
pytest test_login_functionality.py -v

# Run with detailed logging
pytest test_login_functionality.py -v --log-cli-level=INFO

# Run and stop at first failure
pytest test_login_functionality.py -v -x

# Run specific test
pytest test_login_functionality.py::test_valid_login_success_FUNC_001 -v

# Run tests matching pattern
pytest test_login_functionality.py -v -k "username"

# Run with coverage
pytest test_login_functionality.py --cov=. --cov-report=html
```

### Execution Flags

- `-v` / `--verbose`: Show detailed test output
- `-s`: Show print statements and logging
- `--tb=short`: Shorter traceback format
- `-x`: Stop at first failure
- `--maxfail=N`: Stop after N failures
- `-k EXPRESSION`: Run tests matching expression
- `-m MARKER`: Run tests with specific marker (functional, business_rules, security, accessibility)

---

<a name="expected"></a>
## 9. Expected Results

### Overall Summary

| Category | Total Tests | Expected PASS | Expected FAIL | Pass Rate |
|----------|-------------|---------------|---------------|-----------|
| Functional | 7 | 7 | 0 | 100% |
| Business Rules - Validation | 12 | 12 | 0 | 100% |
| Business Rules - Security (Parametrized) | 14+ | 8+ | 6 | ~57% |
| Business Rules - Accessibility | 2 | 2 | 0 | 100% |
| **TOTAL** | **35+** | **29+** | **6** | **83%** |

### Detailed Expected Results

**Functional Tests: 7/7 PASS**
- All functional tests should pass on DemoBlaze
- Core login/logout functionality works correctly

**Business Rules - Validation: 12/12 PASS**
- Input validation tests should pass
- DemoBlaze handles basic input validation adequately

**Business Rules - Security: ~57% PASS**
- SQL Injection tests (4 runs): Expected PASS - DemoBlaze blocks SQL injection
- XSS tests (4 runs): Expected PASS - DemoBlaze prevents XSS
- **Rate Limiting (BR-017): Expected FAIL** - DemoBlaze has no rate limiting
- **2FA Enforcement (BR-018): Expected FAIL** - DemoBlaze has no 2FA
- **Password Complexity (BR-019, 6 runs): Expected FAIL** - Weak passwords accepted
- **CAPTCHA Protection (BR-020): Expected FAIL** - No CAPTCHA
- **Password Reset (BR-021): Expected FAIL** - No reset mechanism
- **Session Timeout (BR-022): Expected FAIL** - Timeout not configured

**Business Rules - Accessibility: 2/2 PASS**
- Keyboard navigation works
- Basic form labels exist

---

<a name="understanding"></a>
## 10. Understanding Test Failures

### Types of Failures

#### Expected Failures (Discoveries)

Tests that discover missing features as designed:

```
FAILED test_account_lockout_enforcement_BR_017
CRITICAL: NO ACCOUNT LOCKOUT / RATE LIMITING
Standard: OWASP ASVS 2.2.1
CVSS Score: 7.5 (HIGH)
```

**This is CORRECT behavior:**
- Test discovered a missing security feature
- Violation is reported with standard reference and CVSS score
- Provides evidence for security assessments

**Action:** Document finding, recommend implementation to development team

#### Unexpected Failures (Bugs)

Tests that should pass but fail:

```
FAILED test_valid_login_success_FUNC_001
AssertionError: Login rejected with alert: 'User does not exist.'
```

**This indicates a problem:**
- Could be application bug
- Could be changed UI/behavior
- Could be test credentials invalid
- Could be test environment issue

**Action:** Investigate root cause, fix application or update test

### Reading Test Output

**Successful Discovery (Expected Failure):**
```
TC-LOGIN-BR-018: NIST 800-63B 5.2.3 - Testing 2FA/MFA enforcement
CRITICAL: CRITICAL SECURITY VIOLATION: NO 2FA/MFA ENFORCEMENT
CRITICAL: Issue: No Multi-Factor Authentication (MFA/2FA)
CRITICAL: Standard: NIST SP 800-63B Section 5.2.3
CRITICAL: CVSS Score: 7.5
CRITICAL: Impact: Account vulnerable to password compromise alone
FAILED - DISCOVERED: NO 2FA/MFA - Violates NIST 800-63B 5.2.3
```

**Interpretation:** Test is working correctly. It discovered that 2FA is missing and reported this as a security violation per NIST standards.

**Successful Pass:**
```
TC-LOGIN-BR-013: OWASP ASVS 1.2.5 - SQL injection test with: ' OR '1'='1
DISCOVERED: SQL injection attempt blocked: ' OR '1'='1
PASSED
```

**Interpretation:** Test discovered that SQL injection is properly blocked. This is good security.

---

<a name="troubleshooting"></a>
## 11. Troubleshooting

### Common Issues

#### Issue: All tests fail immediately
**Symptoms:** Setup failures, browser won't start

**Solutions:**
1. Verify WebDriver is installed: `pip install webdriver-manager`
2. Check Chrome browser is installed
3. Update Chrome driver: `pip install --upgrade webdriver-manager`
4. Check BASE_URL is accessible

#### Issue: Test user doesn't exist
**Symptoms:** `test_valid_login_success_FUNC_001` fails with "User does not exist"

**Solutions:**
1. Create test user in DemoBlaze:
   - Go to https://www.demoblaze.com/
   - Click "Sign up"
   - Username: `Apolo2025`
   - Password: `apolo2025`
   - Click "Sign up" button

#### Issue: Tests timeout frequently
**Symptoms:** `TimeoutException` errors

**Solutions:**
1. Increase timeout values if testing slow network/system
2. Check internet connection stability
3. Verify DemoBlaze website is accessible
4. Consider running in non-headless mode for debugging

#### Issue: Security tests pass unexpectedly
**Symptoms:** BR-017, BR-018, BR-020, etc. pass instead of fail

**Solutions:**
1. This is GOOD - it means the application has those security features
2. Verify the test logic is correct (maybe a different application added these features)
3. Update expected results documentation

### Debug Mode

Run with maximum verbosity:
```bash
pytest test_login_functionality.py -v -s --log-cli-level=DEBUG --tb=long
```

Run in visible browser (edit test file):
```python
# Comment out headless mode in browser fixture
# options.add_argument('--headless')
```

---

<a name="standards"></a>
## 12. Standards Reference

### OWASP ASVS v5.0

**Sections Validated:**
- **1.2.1:** XSS Prevention
- **1.2.5:** SQL Injection Prevention
- **2.2.1:** Anti-Automation (Rate Limiting)
- **2.2.3:** Anti-Automation (CAPTCHA)
- **2.3.1:** Input Validation
- **2.5.6:** Credential Recovery (Password Reset)
- **3.3.2:** Session Timeout

**Reference:** https://owasp.org/www-project-application-security-verification-standard/

### NIST SP 800-63B

**Sections Validated:**
- **5.1.1:** Password Requirements (Length, Complexity)
- **5.1.1.2:** Password Complexity
- **5.2.2:** Rate Limiting
- **5.2.3:** Multi-Factor Authentication

**Reference:** https://pages.nist.gov/800-63-3/sp800-63b.html

### ISO 27001:2022

**Controls Validated:**
- **A.9.4:** Access Control and Authentication
- **A.9.4.2:** Secure Authentication

**Reference:** https://www.iso.org/standard/27001

### WCAG 2.1

**Success Criteria Validated:**
- **1.3.1:** Info and Relationships (Form Labels)
- **2.1.1:** Keyboard Accessible
- **3.3.1:** Error Identification

**Reference:** https://www.w3.org/WAI/WCAG21/quickref/

### ISO 25010

**Quality Characteristics Validated:**
- Functional Suitability
- Usability (User Error Protection)
- Portability (Adaptability for Internationalization)

**Reference:** https://iso25000.com/index.php/en/iso-25000-standards/iso-25010

---

<a name="version"></a>
## 13. Version History

### Version 2.0 - November 2025 (Current)

**Major Update - Complete DISCOVER Implementation**

**Test Coverage:**
- 7 functional tests
- 22 business rules tests (16 base + 6 parametrized variants)
- Total: 29 functions, 35+ test runs

**Key Changes from v1.0:**
- **ADDED:** 6 critical security tests that were missing:
  - Account lockout/rate limiting enforcement
  - 2FA/MFA enforcement
  - Password complexity enforcement (parametrized with 6 weak passwords)
  - CAPTCHA/bot protection
  - Password reset mechanism
  - Session timeout enforcement
- **PHILOSOPHY:** 100% DISCOVER methodology - all tests EXECUTE + OBSERVE + DECIDE
- **NO ASSUMPTIONS:** Tests discover actual behavior, don't assume missing features

**Code Quality:**
- Professional logging with appropriate levels (INFO/WARNING/ERROR/CRITICAL)
- Standardized timeout strategy
- Universal configuration (BASE_URL, TEST_USERNAME, TEST_PASSWORD)
- Clean helper functions following DRY principle

**Documentation:**
- Comprehensive README with DISCOVER philosophy explanation
- Expected test failures clearly documented as "discoveries"
- CVSS scores for all security findings
- Clear mapping to industry standards

### Version 1.0 - Initial Release

**Test Coverage:**
- 7 functional tests
- 16 business rules tests
- Total: 23 functions

**Issues:**
- Missing critical security tests
- README had "OUT OF SCOPE" sections that violated DISCOVER philosophy

---

**End of Documentation**

**Related Documents:**
- [DISCOVER_PHILOSOPHY.md](DISCOVER_PHILOSOPHY.md) - Master philosophy document
- [test_login_security.py](test_login_security.py) - Security/exploitation tests
- [README_test_login_security.md](README_test_login_security.md) - Security tests documentation

**For questions about DISCOVER philosophy, refer to DISCOVER_PHILOSOPHY.md**
