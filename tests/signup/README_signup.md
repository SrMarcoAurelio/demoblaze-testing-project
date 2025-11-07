# DemoBlaze Signup Testing Suite

Comprehensive test suite for user registration functionality on DemoBlaze e-commerce platform.

Version: 1.0
Author: QA Testing Team
Last Updated: 2025-11-07

---

## Table of Contents

1. [Overview](#overview)
2. [Test Environment](#test-environment)
3. [Test Scope](#test-scope)
4. [Test Cases](#test-cases)
5. [Execution Instructions](#execution-instructions)
6. [Test Data Strategy](#test-data-strategy)
7. [Known Issues](#known-issues)
8. [Dependencies](#dependencies)
9. [Cross-Browser Testing](#cross-browser-testing)
10. [HTML Reports](#html-reports)
11. [Helper Methods](#helper-methods)
12. [Security Testing](#security-testing)
13. [Boundary Testing](#boundary-testing)
14. [Integration Testing](#integration-testing)
15. [Test Metrics](#test-metrics)
16. [Future Enhancements](#future-enhancements)
17. [Related Documents](#related-documents)

---

## 1. Overview

This test suite validates the signup/registration functionality of DemoBlaze, covering:
- Valid user registration
- Duplicate username detection
- Input validation
- Security vulnerabilities (SQL Injection, XSS)
- Boundary conditions
- Edge cases
- Integration with login functionality

Total test cases: 30

---

## 2. Test Environment

**Application Under Test:**
- URL: https://www.demoblaze.com
- Environment: Production
- Browser Support: Chrome, Firefox, Edge

**Test Framework:**
- pytest 7.x
- Selenium WebDriver 4.x
- Python 3.8+

**Key Components:**
- Signup modal (ID: signInModal)
- Username field (ID: sign-username)
- Password field (ID: sign-password)
- Sign up button (XPath: //button[text()='Sign up'])

---

## 3. Test Scope

### In Scope:
- User registration with valid credentials
- Duplicate username validation
- Empty field validation
- Weak password acceptance (security concern)
- SQL Injection testing
- XSS vulnerability testing
- Special characters handling
- Whitespace handling
- Boundary testing (very long inputs)
- Unicode and emoji support
- Modal interaction (open/close)
- Integration with login after signup

### Out of Scope:
- Email verification (not implemented in DemoBlaze)
- Password strength requirements (not enforced)
- Account activation workflows
- CAPTCHA testing
- Password recovery
- User profile management after signup

---

## 4. Test Cases

### Positive Test Cases

**TC-SIGNUP-001: Valid User Registration**
- Input: Unique username + valid password
- Expected: "Sign up successful." alert
- Status: PASS

**TC-SIGNUP-023: Signup Then Login**
- Input: Register new user, then login with same credentials
- Expected: Successful login with welcome message
- Status: PASS

**TC-SIGNUP-021: Username With Numbers**
- Input: Alphanumeric username
- Expected: Registration successful
- Status: PASS

**TC-SIGNUP-022: Username Numbers Only**
- Input: Numeric-only username
- Expected: Registration successful
- Status: PASS

**TC-SIGNUP-017: Valid Special Characters**
- Input: Username/password with @#$!
- Expected: Registration successful
- Status: PASS

**TC-SIGNUP-027: Unicode Username**
- Input: Username with Chinese/Japanese characters
- Expected: Registration successful
- Status: PASS

**TC-SIGNUP-028: Emoji Username**
- Input: Username with emoji characters
- Expected: Registration successful
- Status: PASS

### Negative Test Cases

**TC-SIGNUP-002: Existing User**
- Input: Previously registered username
- Expected: "This user already exist." alert
- Status: PASS

**TC-SIGNUP-003: Empty Username**
- Input: Blank username field
- Expected: "Please fill out Username and Password." alert
- Status: PASS

**TC-SIGNUP-004: Empty Password**
- Input: Blank password field
- Expected: "Please fill out Username and Password." alert
- Status: PASS

**TC-SIGNUP-005: Both Fields Empty**
- Input: Both fields blank
- Expected: "Please fill out Username and Password." alert
- Status: PASS

**TC-SIGNUP-024: Multiple Rapid Signups**
- Input: Attempt to register same username multiple times rapidly
- Expected: First attempt succeeds, subsequent attempts show "user already exist"
- Status: PASS

### Security Test Cases

**TC-SIGNUP-008: SQL Injection - Username**
- Input: SQL payloads in username field
- Payloads tested:
  - admin' OR '1'='1
  - admin'--
  - ' OR 1=1--
  - admin' DROP TABLE users--
- Expected: System should sanitize input or reject
- Actual: Accepts SQL characters without sanitization
- Status: PASS (but security vulnerability exists)
- Severity: HIGH

**TC-SIGNUP-009: SQL Injection - Password**
- Input: SQL payload in password field
- Expected: Proper input sanitization
- Actual: Accepts SQL characters
- Status: PASS (vulnerability exists)

**TC-SIGNUP-010: XSS - Username**
- Input: JavaScript/HTML payloads in username
- Payloads tested:
  - &lt;script&gt;alert('XSS')&lt;/script&gt;
  - &lt;img src=x onerror=alert('XSS')&gt;
  - javascript:alert('XSS')
- Expected: Input sanitization/encoding
- Actual: Accepts script tags without encoding
- Status: PASS (vulnerability exists)
- Severity: HIGH

**TC-SIGNUP-011: XSS - Password**
- Input: XSS payload in password field
- Expected: Proper encoding
- Actual: Accepts without encoding
- Status: PASS (vulnerability exists)

### Boundary Test Cases

**TC-SIGNUP-018: Very Long Username**
- Input: Username with 200+ characters
- Expected: Character limit enforcement or proper handling
- Actual: Accepts without limit
- Status: PASS
- Note: No maximum length validation

**TC-SIGNUP-019: Very Long Password**
- Input: Password with 200+ characters
- Expected: Character limit or proper handling
- Actual: Accepts without limit
- Status: PASS
- Note: No maximum length validation

**TC-SIGNUP-006: Weak Password - Single Character**
- Input: Password with 1 character
- Expected: Password strength validation
- Actual: Accepts weak password
- Status: PASS
- Bug Reference: Weak password policy

**TC-SIGNUP-007: Weak Password - Two Characters**
- Input: Password with 2 characters
- Expected: Minimum password length enforcement
- Actual: Accepts weak password
- Status: PASS
- Bug Reference: No minimum password requirements

### Edge Cases

**TC-SIGNUP-012: Leading Whitespace Username**
- Input: Username starting with spaces
- Expected: Trimming or validation
- Actual: Accepts with spaces
- Status: PASS

**TC-SIGNUP-013: Trailing Whitespace Username**
- Input: Username ending with spaces
- Expected: Trimming or validation
- Actual: Accepts with spaces
- Status: PASS

**TC-SIGNUP-014: Whitespace-Only Username**
- Input: Username containing only spaces
- Expected: Validation error
- Actual: May accept or reject
- Status: PASS

**TC-SIGNUP-015: Whitespace in Password**
- Input: Password with leading/trailing spaces
- Expected: Exact password storage
- Actual: Accepts spaces in password
- Status: PASS

**TC-SIGNUP-016: Password with Spaces Middle**
- Input: Password like "Pass Word 123"
- Expected: Accept spaces as valid characters
- Actual: Accepts
- Status: PASS

**TC-SIGNUP-020: Case Sensitivity Test**
- Input: Same username in different cases (user1 vs USER1)
- Expected: Case-insensitive or case-sensitive behavior
- Actual: May treat as different users
- Status: PASS
- Note: Documents system behavior

### UI Interaction Cases

**TC-SIGNUP-029: Modal Close Without Action**
- Input: Open modal and close via X button
- Expected: Modal closes without registration
- Status: PASS

**TC-SIGNUP-030: Modal Cancel Button**
- Input: Click Cancel button in modal
- Expected: Modal closes without registration
- Status: PASS

---

## 5. Execution Instructions

### Run All Signup Tests

```bash
pytest tests/signup/test_signup.py -v
```

### Run Specific Test

```bash
pytest tests/signup/test_signup.py::TestSignup::test_signup_valid_credentials -v
```

### Run with Specific Browser

```bash
pytest tests/signup/ --browser=chrome
pytest tests/signup/ --browser=firefox
pytest tests/signup/ --browser=edge
```

### Run Security Tests Only

```bash
pytest tests/signup/test_signup.py -v -k "sql_injection or xss"
```

### Run Boundary Tests Only

```bash
pytest tests/signup/test_signup.py -v -k "very_long or weak_password"
```

### Run with HTML Report (Manual)

```bash
pytest tests/signup/ --html=report.html --self-contained-html
```

Note: HTML reports are automatically generated by conftest.py in test_results/signup/ directory.

---

## 6. Test Data Strategy

### Username Generation
- Dynamic timestamps used to ensure uniqueness
- Format: `[prefix]_[timestamp]`
- Example: `testuser_1699369200`

### Password Strategy
- Varies by test case
- Valid passwords: Mix of letters, numbers, symbols
- Weak passwords: Single/double characters for boundary testing
- Security payloads: SQL/XSS attack vectors

### Why Timestamps?
- Prevents test interference
- Allows parallel execution
- No cleanup required
- Realistic unique user simulation

---

## 7. Known Issues

### Bug #13: No Password Strength Requirements
**Severity:** HIGH
**Description:** System accepts passwords of any length, including single character
**Impact:** Weak account security
**Tests Affected:** TC-SIGNUP-006, TC-SIGNUP-007

### Bug #14: SQL Injection Vulnerability
**Severity:** CRITICAL
**Description:** Username and password fields accept SQL syntax without sanitization
**Impact:** Potential database compromise
**Tests Affected:** TC-SIGNUP-008, TC-SIGNUP-009

### Bug #15: XSS Vulnerability
**Severity:** CRITICAL
**Description:** Script tags and JavaScript in username/password not properly encoded
**Impact:** Cross-site scripting attacks possible
**Tests Affected:** TC-SIGNUP-010, TC-SIGNUP-011

### Bug #16: No Input Length Limits
**Severity:** MEDIUM
**Description:** No maximum character limit on username/password fields
**Impact:** Potential buffer overflow or database issues
**Tests Affected:** TC-SIGNUP-018, TC-SIGNUP-019

### Bug #17: Whitespace Handling
**Severity:** LOW
**Description:** Leading/trailing whitespace in usernames not trimmed
**Impact:** User confusion, duplicate-like usernames
**Tests Affected:** TC-SIGNUP-012, TC-SIGNUP-013

---

## 8. Dependencies

### Required Python Packages

```txt
selenium>=4.0.0
pytest>=7.0.0
pytest-html>=3.1.1
webdriver-manager>=3.8.0
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### System Requirements
- Python 3.8 or higher
- Chrome/Firefox/Edge browser installed
- Internet connection for webdriver-manager

---

## 9. Cross-Browser Testing

Tests are designed to run on multiple browsers using pytest parametrization via conftest.py.

### Browser Configuration

Configured in project root `conftest.py`:
- Chrome (default)
- Firefox
- Edge

### Browser Selection

```bash
pytest tests/signup/ --browser=chrome
pytest tests/signup/ --browser=firefox
pytest tests/signup/ --browser=edge
```

### Headless Mode

To enable headless mode, uncomment in conftest.py:

```python
options.add_argument("--headless")
```

---

## 10. HTML Reports

### Automatic Report Generation

The `conftest.py` automatically generates HTML reports organized by test folder.

**Report Location:**
```
test_results/
└── signup/
    ├── report_chrome_2025-11-07_14-30-45.html
    ├── report_firefox_2025-11-07_14-35-22.html
    └── report_edge_2025-11-07_14-40-18.html
```

**Filename Format:**
```
report_[browser]_[YYYY-MM-DD_HH-MM-SS].html
```

### Report Features
- Self-contained (no external dependencies)
- Screenshots on failure (if configured)
- Execution time per test
- Pass/Fail summary
- Detailed error messages

---

## 11. Helper Methods

### wait_for_alert(browser, timeout=5)
**Purpose:** Waits for JavaScript alert and retrieves text
**Parameters:**
- browser: WebDriver instance
- timeout: Maximum wait time in seconds
**Returns:** Alert text or None if no alert
**Usage:** Handle success/error messages from signup

### open_signup_modal(browser)
**Purpose:** Navigates to homepage and opens signup modal
**Parameters:** browser - WebDriver instance
**Actions:**
- Loads base URL
- Clicks signup link (ID: signin2)
- Waits for modal visibility
**Usage:** Setup for all signup tests

### fill_signup_form(browser, username, password)
**Purpose:** Fills username and password fields
**Parameters:**
- browser: WebDriver instance
- username: String to enter in username field
- password: String to enter in password field
**Actions:**
- Clears existing values
- Enters new values
**Usage:** Input test data

### click_signup_button(browser)
**Purpose:** Clicks the Sign up button in modal
**Parameters:** browser - WebDriver instance
**Usage:** Submit signup form

### verify_login_works(browser, username, password)
**Purpose:** Verifies newly registered user can login
**Parameters:**
- browser: WebDriver instance
- username: Registered username
- password: Registered password
**Actions:**
- Opens login modal
- Enters credentials
- Verifies welcome message
**Usage:** Integration testing after signup

---

## 12. Security Testing

### SQL Injection Testing

**Methodology:**
- Common SQL injection payloads injected in username/password
- System should reject or sanitize dangerous input
- Tests verify system behavior (not necessarily secure behavior)

**Payloads Used:**
```sql
admin' OR '1'='1
admin'--
' OR 1=1--
admin' DROP TABLE users--
```

**Current Behavior:**
System accepts SQL syntax without validation or sanitization. This is a CRITICAL security vulnerability.

### XSS Testing

**Methodology:**
- JavaScript and HTML payloads injected
- System should encode or reject script tags
- Tests monitor for unexpected alert dialogs

**Payloads Used:**
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
javascript:alert('XSS')
```

**Current Behavior:**
System accepts script tags without encoding. XSS vulnerability exists.

---

## 13. Boundary Testing

### Long Input Testing

**Purpose:** Verify system handles extreme input lengths
**Test Cases:**
- 200+ character usernames
- 200+ character passwords

**Expected Behavior:**
- Character limit enforcement
- Graceful handling if no limit
- No system crashes

**Actual Behavior:**
No maximum length validation exists. System accepts very long inputs.

### Weak Password Testing

**Purpose:** Verify password strength requirements
**Test Cases:**
- Single character passwords
- Two character passwords

**Expected Behavior:**
Minimum password length enforcement (typically 8+ characters)

**Actual Behavior:**
No minimum password requirements. Accepts 1-character passwords.

---

## 14. Integration Testing

### Signup-to-Login Flow

**Test:** TC-SIGNUP-023
**Purpose:** Verify end-to-end user registration and authentication flow
**Steps:**
1. Register new user
2. Verify success message
3. Attempt login with same credentials
4. Verify welcome message displays

**Importance:**
- Confirms user creation in database
- Validates authentication system integration
- Simulates real user journey

---

## 15. Test Metrics

**Total Test Cases:** 30

**Category Breakdown:**
- Positive Tests: 8 (27%)
- Negative Tests: 6 (20%)
- Security Tests: 4 (13%)
- Boundary Tests: 4 (13%)
- Edge Cases: 6 (20%)
- UI Interaction: 2 (7%)

**Severity Distribution:**
- Critical Bugs: 2 (SQL Injection, XSS)
- High Severity: 1 (Weak passwords)
- Medium Severity: 1 (No input limits)
- Low Severity: 1 (Whitespace handling)

**Execution Time:**
- Average per test: 3-5 seconds
- Full suite: ~2-3 minutes
- Varies by browser and network speed

---

## 16. Future Enhancements

### Potential Additions:

**Email Validation:**
- Add email field to registration (if implemented)
- Test email format validation
- Test duplicate email detection

**Password Confirmation:**
- Test password/confirm password matching
- Test mismatch scenarios

**CAPTCHA Testing:**
- Automated CAPTCHA bypass (if added)
- Manual verification steps

**Rate Limiting:**
- Test multiple signup attempts from same IP
- Verify anti-spam measures

**Account Activation:**
- Email verification workflows
- Token expiration testing

**Accessibility Testing:**
- Screen reader compatibility
- Keyboard navigation
- ARIA labels validation

---

## 17. Related Documents

- [Test Plan](../../docs/test-plan.md)
- [Test Summary Report](../../docs/Test_Summary_Report.md)
- [User Flows](../../docs/users-flow.md)
- [DemoBlaze Test Cases](../../docs/DemoBlaze_Test_Cases.xlsx)
- Bug #13: Weak Password Policy (documented in Test Summary Report)
- Bug #14: SQL Injection Vulnerability (documented in Test Summary Report)
- Bug #15: XSS Vulnerability (documented in Test Summary Report)
- Bug #16: No Input Length Limits (documented in Test Summary Report)
- Bug #17: Whitespace Handling (documented in Test Summary Report)

---

End of Document
