# Test Suite: Signup & Registration Functionality

**Module:** `test_signup.py`  
**Author:** Arévalo, Marc  
**Created:** November 2025  
**Version:** 1.0 - Clean code, comprehensive security testing  
**Application Under Test:** DemoBlaze (https://www.demoblaze.com/)

---

## Table of Contents

1. [Overview](#overview)
2. [Test Cases Covered](#test-cases)
3. [Related Bugs](#bugs)
4. [Code Architecture](#architecture)
5. [Imports Explanation](#imports)
6. [Configuration Variables](#configuration)
7. [Fixtures Deep Dive](#fixtures)
8. [Helper Functions](#helpers)
9. [Test Functions Breakdown](#tests)
10. [Execution Guide](#execution)
11. [Expected Results](#results)
12. [Troubleshooting](#troubleshooting)
13. [Best Practices Applied](#practices)

---

<a name="overview"></a>
## 1. Overview

### Purpose

This test suite automates comprehensive validation of DemoBlaze's user registration functionality, including:
- Valid user registration flow
- Duplicate username detection
- Empty field validation
- Password strength testing (or lack thereof)
- Security testing (SQL Injection, XSS)
- Boundary testing (very long inputs)
- Whitespace handling
- Special characters support
- Unicode and emoji support
- Modal interaction
- Integration with login after signup

### Scope

**In Scope:**
- User registration with valid credentials
- Duplicate username validation
- Empty field validation (username, password, both)
- Weak password acceptance testing
- SQL Injection testing in username and password
- XSS vulnerability testing in username and password
- Special characters handling
- Whitespace handling (leading, trailing, whitespace-only)
- Boundary testing (200+ character inputs)
- Case sensitivity testing
- Unicode character support (Chinese, Japanese, etc.)
- Emoji support in usernames
- Modal interaction (open, close, cancel)
- Integration testing (signup then login)
- Multiple rapid signup attempts

**Out of Scope:**
- Email verification (not implemented in DemoBlaze)
- Password strength requirements enforcement (not implemented)
- Account activation workflows
- CAPTCHA testing
- Password recovery/reset
- User profile management after signup
- Social media login integration
- Two-factor authentication

### Version History

**v1.0 (Current):**
- Initial release with 30 comprehensive test cases
- Security testing (SQL Injection, XSS)
- Boundary testing (very long inputs)
- Clean code architecture
- Integration with login testing

---

<a name="test-cases"></a>
## 2. Test Cases Covered

### Functional Tests - Valid Registration


#### TC-SIGNUP-001: Valid User Registration
**Priority:** Critical  
**Type:** Positive Test  

**Test Steps:**
1. Open signup modal
2. Generate unique username with timestamp
3. Enter username and password
4. Click "Sign up" button
5. Wait for alert to appear

**Expected Result:**
- Alert displays: "Sign up successful."
- User account created in database
- No errors or exceptions

**Why This Test Matters:**
Core functionality - users must be able to register accounts. Validates basic signup flow works correctly.

---

#### TC-SIGNUP-002: Existing User Registration
**Priority:** High  
**Type:** Negative Test  

**Test Steps:**
1. Register new user successfully
2. Wait for success confirmation
3. Attempt to register again with same username
4. Click "Sign up" button
5. Observe alert message

**Expected Result:**
- Alert displays: "This user already exist."
- Duplicate registration prevented
- Original account unchanged

**Why This Test Matters:**
Prevents duplicate accounts, ensures username uniqueness constraint enforced at application level.

---

#### TC-SIGNUP-003: Empty Username Field
**Priority:** High  
**Type:** Negative Test  

**Test Steps:**
1. Open signup modal
2. Leave username field empty
3. Enter password
4. Click "Sign up" button

**Expected Result:**
- Alert displays: "Please fill out Username and Password."
- Registration blocked
- No account created

---

#### TC-SIGNUP-004: Empty Password Field
**Priority:** High  
**Type:** Negative Test  

**Test Steps:**
1. Open signup modal
2. Enter username
3. Leave password field empty
4. Click "Sign up" button

**Expected Result:**
- Alert displays: "Please fill out Username and Password."
- Registration blocked
- No account created

---

#### TC-SIGNUP-005: Both Fields Empty
**Priority:** High  
**Type:** Negative Test  

**Test Steps:**
1. Open signup modal
2. Leave both fields empty
3. Click "Sign up" button

**Expected Result:**
- Alert displays: "Please fill out Username and Password."
- Registration blocked
- Clear validation message

---

### Functional Tests - Password Strength

#### TC-SIGNUP-006: Weak Password - Single Character
**Priority:** High  
**Type:** Security/Validation Test  

**Test Steps:**
1. Open signup modal
2. Enter unique username
3. Enter single character password: "1"
4. Click "Sign up" button

**Current Behavior (BUG):**
- Alert displays: "Sign up successful."
- Account created with weak password

**Expected Behavior (Post-Fix):**
- Alert displays: "Password must be at least 8 characters."
- Registration blocked

**Security Impact:**
- Weak passwords easily cracked
- Account compromise risk
- Poor security posture

**Bug Reference:** [GitHub Issue #19](https://github.com/SrMarcoAurelio/demoblaze-testing-project/issues/19)

---

#### TC-SIGNUP-007: Weak Password - Two Characters
**Priority:** High  
**Type:** Security/Validation Test  

**Test Steps:**
1. Open signup modal
2. Enter unique username
3. Enter two character password: "ab"
4. Click "Sign up" button

**Current Behavior (BUG):**
- Alert displays: "Sign up successful."
- Account created with weak password

**Expected Behavior (Post-Fix):**
- Alert displays: "Password must be at least 8 characters."
- Registration blocked

**Bug Reference:** [GitHub Issue #19](https://github.com/SrMarcoAurelio/demoblaze-testing-project/issues/19)

---

### Security Tests - SQL Injection

#### TC-SIGNUP-008: SQL Injection in Username
**Priority:** Critical  
**Type:** Security Test  

**Test Steps:**
1. Open signup modal
2. Enter SQL payload in username field
3. Payloads tested:
   - `admin' OR '1'='1`
   - `admin'--`
   - `' OR 1=1--`
   - `admin' DROP TABLE users--`
4. Enter valid password
5. Click "Sign up" button

**Current Behavior (VULNERABILITY):**
- System accepts SQL syntax without sanitization
- Alert displays: "Sign up successful." or "This user already exist."
- No input validation or escaping

**Expected Behavior (Secure):**
- SQL characters rejected or escaped
- Alert displays: "Invalid characters in username."
- No SQL execution possible

**Security Impact:**
- Potential database manipulation
- Authentication bypass possible
- Data breach risk

**Severity:** CRITICAL  
**Bug Reference:** [GitHub Issue #14](https://github.com/SrMarcoAurelio/demoblaze-testing-project/issues/14)

---

#### TC-SIGNUP-009: SQL Injection in Password
**Priority:** Critical  
**Type:** Security Test  

**Test Steps:**
1. Open signup modal
2. Enter valid username
3. Enter SQL payload in password: `' OR '1'='1`
4. Click "Sign up" button

**Current Behavior (VULNERABILITY):**
- System accepts SQL syntax in password
- Alert displays: "Sign up successful."
- Password stored without sanitization

**Expected Behavior (Secure):**
- SQL characters properly escaped
- Password stored safely
- No SQL execution risk

**Severity:** CRITICAL  
**Bug Reference:** [GitHub Issue #14](https://github.com/SrMarcoAurelio/demoblaze-testing-project/issues/14)

---

### Security Tests - Cross-Site Scripting (XSS)

#### TC-SIGNUP-010: XSS in Username
**Priority:** Critical  
**Type:** Security Test  

**Test Steps:**
1. Open signup modal
2. Enter XSS payload in username field
3. Payloads tested:
   - `<script>alert('XSS')</script>`
   - `<img src=x onerror=alert('XSS')>`
   - `javascript:alert('XSS')`
4. Enter valid password
5. Click "Sign up" button

**Current Behavior (VULNERABILITY):**
- System accepts script tags without encoding
- Alert displays: "Sign up successful." or "This user already exist."
- No XSS protection

**Expected Behavior (Secure):**
- HTML/JavaScript encoded or rejected
- Alert displays: "Invalid characters in username."
- No script execution possible

**Security Impact:**
- XSS attacks possible
- Session hijacking risk
- Phishing potential

**Severity:** CRITICAL  
**Note:** This test will determine if XSS vulnerability exists. Bug report to be filed if vulnerability confirmed.

---

#### TC-SIGNUP-011: XSS in Password
**Priority:** Critical  
**Type:** Security Test  

**Test Steps:**
1. Open signup modal
2. Enter valid username
3. Enter XSS payload in password: `<script>alert('XSS')</script>`
4. Click "Sign up" button

**Current Behavior (VULNERABILITY):**
- System accepts script tags in password
- Alert displays: "Sign up successful."
- No XSS encoding

**Expected Behavior (Secure):**
- HTML properly encoded
- Password stored safely
- No XSS risk

**Severity:** CRITICAL  
**Note:** This test will determine if XSS vulnerability exists in password field.

---

### Edge Cases - Whitespace Handling

#### TC-SIGNUP-012: Leading Whitespace in Username
**Priority:** Medium  
**Type:** Edge Case Test  

**Test Steps:**
1. Open signup modal
2. Enter username with leading spaces: `"   user123"`
3. Enter valid password
4. Click "Sign up" button

**Current Behavior:**
- System accepts username with spaces
- Alert displays: "Sign up successful."
- Spaces not trimmed

**Expected Behavior:**
- Leading/trailing whitespace trimmed
- Or validation error shown

**Impact:**
- User confusion (username not what they typed)
- Duplicate-like usernames possible
- Poor UX

**Note:** This test will determine if whitespace trimming is implemented.

---

#### TC-SIGNUP-013: Trailing Whitespace in Username
**Priority:** Medium  
**Type:** Edge Case Test  

**Test Steps:**
1. Open signup modal
2. Enter username with trailing spaces: `"user123   "`
3. Enter valid password
4. Click "Sign up" button

**Current Behavior:**
System will either trim spaces or accept them as-is. This test documents actual behavior.

**Note:** Bug report to be filed if spaces are not trimmed.

---

#### TC-SIGNUP-014: Whitespace-Only Username
**Priority:** Medium  
**Type:** Edge Case Test  

**Test Steps:**
1. Open signup modal
2. Enter only spaces in username: `"     "`
3. Enter valid password
4. Click "Sign up" button

**Expected Result:**
- Alert displays: "Please fill out Username and Password."
- Or: "Sign up successful." (documents current behavior)

**Note:**
Tests how system handles whitespace-only input.

---

#### TC-SIGNUP-015: Whitespace in Password
**Priority:** Low  
**Type:** Edge Case Test  

**Test Steps:**
1. Open signup modal
2. Enter valid username
3. Enter password with spaces: `"   spaces   "`
4. Click "Sign up" button

**Expected Result:**
- Alert displays: "Sign up successful."
- Spaces preserved in password (valid characters)

**Why This Test Matters:**
Validates spaces are valid password characters and stored correctly.

---

#### TC-SIGNUP-016: Password with Spaces in Middle
**Priority:** Low  
**Type:** Positive Test  

**Test Steps:**
1. Open signup modal
2. Enter valid username
3. Enter password with spaces: `"Pass Word 123"`
4. Click "Sign up" button

**Expected Result:**
- Alert displays: "Sign up successful."
- Password with spaces accepted
- Spaces preserved

---

### Functional Tests - Special Characters

#### TC-SIGNUP-017: Valid Special Characters
**Priority:** Medium  
**Type:** Positive Test  

**Test Steps:**
1. Open signup modal
2. Enter username with special chars: `"user_@#$_[timestamp]"`
3. Enter password with special chars: `"P@ssw0rd!#$"`
4. Click "Sign up" button

**Expected Result:**
- Alert displays: "Sign up successful."
- Special characters accepted
- Account created successfully

**Why This Test Matters:**
Validates system accepts reasonable special characters in usernames/passwords.

---

### Boundary Tests - Input Length

#### TC-SIGNUP-018: Very Long Username
**Priority:** High  
**Type:** Boundary Test  

**Test Steps:**
1. Open signup modal
2. Enter username with 200+ characters
3. Enter valid password
4. Click "Sign up" button

**Current Behavior:**
- System accepts very long username
- Alert displays: "Sign up successful." or "This user already exist."
- No maximum length validation

**Expected Behavior:**
- Character limit enforced (e.g., 50 chars)
- Alert displays: "Username too long."

**Expected Behavior:**
- Character limit enforced (e.g., 50 chars)
- Or graceful handling without errors

**Note:** This test will determine if input length validation exists. Bug report to be filed if no limits enforced.

---

#### TC-SIGNUP-019: Very Long Password
**Priority:** High  
**Type:** Boundary Test  

**Test Steps:**
1. Open signup modal
2. Enter valid username
3. Enter password with 200+ characters
4. Click "Sign up" button

**Current Behavior:**
- System accepts very long password
- Alert displays: "Sign up successful."
- No maximum length validation

**Expected Behavior:**
- Reasonable maximum length (e.g., 128 chars)
- Or handled gracefully with no errors

**Note:** This test will determine if password length validation exists.

---

### Functional Tests - Username Variations

#### TC-SIGNUP-021: Username With Numbers
**Priority:** Low  
**Type:** Positive Test  

**Test Steps:**
1. Open signup modal
2. Enter alphanumeric username: `"user123456_[timestamp]"`
3. Enter valid password
4. Click "Sign up" button

**Expected Result:**
- Alert displays: "Sign up successful."
- Alphanumeric usernames accepted

---

#### TC-SIGNUP-022: Username Numbers Only
**Priority:** Low  
**Type:** Positive Test  

**Test Steps:**
1. Open signup modal
2. Enter numeric-only username: `"123456[timestamp]"`
3. Enter valid password
4. Click "Sign up" button

**Expected Result:**
- Alert displays: "Sign up successful."
- Numeric usernames accepted

---

#### TC-SIGNUP-020: Case Sensitivity Test
**Priority:** Medium  
**Type:** Functional Test  

**Test Steps:**
1. Register user with lowercase username: `"casetest_[timestamp]"`
2. Verify success
3. Attempt to register with uppercase version: `"CASETEST_[TIMESTAMP]"`
4. Observe result

**Purpose:**
Documents whether system treats usernames as case-sensitive or case-insensitive.

**Expected Result:**
- Either "Sign up successful." (case-sensitive system)
- Or "This user already exist." (case-insensitive system)

---

### Integration Tests

#### TC-SIGNUP-023: Signup Then Login
**Priority:** Critical  
**Type:** Integration Test  

**Test Steps:**
1. Register new user successfully
2. Verify "Sign up successful." alert
3. Wait for modal to close
4. Open login modal
5. Enter same username and password
6. Click "Log in" button
7. Verify welcome message appears

**Expected Result:**
- Registration successful
- Login with new credentials successful
- Welcome message displays: "Welcome [username]"
- End-to-end user creation validated

**Why This Test Matters:**
Most important integration test - validates:
- User actually created in database
- Credentials stored correctly
- Authentication system integration works
- Complete user journey functional

---

### Functional Tests - Rapid Actions

#### TC-SIGNUP-024: Multiple Rapid Signup Attempts
**Priority:** Medium  
**Type:** Robustness Test  

**Test Steps:**
1. Register user successfully
2. Immediately attempt to register same username 3 more times
3. Verify each subsequent attempt

**Expected Result:**
- First attempt: "Sign up successful."
- Attempts 2-4: "This user already exist."
- System handles rapid requests
- No race conditions

**Why This Test Matters:**
Validates duplicate detection works even with rapid consecutive requests.

---

### Functional Tests - Unicode Support

#### TC-SIGNUP-027: Unicode Username
**Priority:** Medium  
**Type:** Internationalization Test  

**Test Steps:**
1. Open signup modal
2. Enter username with Chinese characters: `"用户_[timestamp]"`
3. Enter valid password
4. Click "Sign up" button

**Expected Result:**
- Alert displays: "Sign up successful." or "This user already exist."
- Unicode characters handled
- No encoding errors

**Why This Test Matters:**
Validates international character support for global users.

---

#### TC-SIGNUP-028: Emoji Username
**Priority:** Low  
**Type:** Internationalization Test  

**Test Steps:**
1. Open signup modal
2. Enter username with emojis: `"user😀🎉_[timestamp]"`
3. Enter valid password
4. Click "Sign up" button

**Expected Result:**
- Alert displays: "Sign up successful." or "This user already exist."
- Emoji characters handled
- No encoding errors

---

### UI Interaction Tests

#### TC-SIGNUP-029: Modal Close Without Action
**Priority:** Low  
**Type:** UI Test  

**Test Steps:**
1. Open signup modal
2. Verify modal visible
3. Click X (close) button
4. Verify modal closes

**Expected Result:**
- Modal closes without error
- User returns to home page
- No registration performed

---

#### TC-SIGNUP-030: Modal Cancel Button
**Priority:** Low  
**Type:** UI Test  

**Test Steps:**
1. Open signup modal
2. Verify modal visible
3. Click "Cancel" button
4. Verify modal closes

**Expected Result:**
- Modal closes without error
- User returns to home page
- No registration performed

---

## 3. Related Bugs


| Bug ID | Severity | Title | Test Case | Status |
|--------|----------|-------|-----------|--------|
| #19 | High | No password complexity requirements | TC-SIGNUP-006, TC-SIGNUP-007 | Closed |
| #14 | Critical | SQL Injection vulnerability | TC-SIGNUP-008, TC-SIGNUP-009 | Closed |
| #15 | High | Username enumeration - "User already exist" | TC-SIGNUP-002 | Closed |

**Note:** Additional bugs may be discovered during automated test execution and will be documented in future test reports.

**Bug #19 Details: No password complexity requirements**
- **GitHub Issue:** [#19](https://github.com/SrMarcoAurelio/demoblaze-testing-project/issues/19)
- **Severity:** High (security)
- **Area:** Authentication
- **Impact:** Weak passwords allow easy account compromise
- **Recommendation:** Enforce minimum 8 characters, require mix of letters/numbers/symbols
- **Expected Fix:** Add password strength validation before account creation

**Bug #14 Details: SQL Injection vulnerability**
- **GitHub Issue:** [#14](https://github.com/SrMarcoAurelio/demoblaze-testing-project/issues/14)
- **Severity:** Critical (security)
- **Area:** Authentication (signup and login)
- **Impact:** SQL Injection in username/password fields could allow:
  - Database manipulation
  - Authentication bypass
  - Data breach
- **Recommendation:** Implement parameterized queries and input sanitization
- **Expected Fix:** Properly escape or reject SQL syntax in all inputs

**Bug #15 Details: Username enumeration**
- **GitHub Issue:** [#15](https://github.com/SrMarcoAurelio/demoblaze-testing-project/issues/15)
- **Severity:** High (security)
- **Area:** Authentication
- **Impact:** "User already exist" message reveals valid usernames, enabling:
  - Targeted phishing attacks
  - Account enumeration
  - Brute-force attack preparation
- **Recommendation:** Use generic error message for both cases (e.g., "Registration unsuccessful")
- **Expected Fix:** Return same message regardless of username validity
- **Recommendation:** Trim leading/trailing whitespace on username field
- **Expected Fix:** Add trim() function before validation

---

<a name="architecture"></a>
## 4. Code Architecture

### File Structure

```
project_root/
├── tests/
│   ├── login/
│   │   └── ...
│   ├── purchase/
│   │   └── ...
│   └── signup/
│       ├── __init__.py
│       ├── test_signup.py
│       └── README.md (this file)
├── test_results/
│   └── signup/
│       └── report_chrome_YYYY-MM-DD_HH-MM-SS.html
├── conftest.py
└── requirements.txt
```

### Code Organization

The Python file is organized into 4 sections:

1. **IMPORTS** - External libraries (pytest, selenium, time)
2. **TEST CLASS** - TestSignup class containing all tests
3. **HELPER METHODS** - Reusable functions for common actions
4. **TEST FUNCTIONS** - Individual test cases

---

<a name="imports"></a>
## 5. Imports Explanation

### Core Selenium Imports

```python
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
```

Same imports as login and purchase modules:
- `By` - Locator strategies (ID, XPATH, etc.)
- `WebDriverWait` - Explicit waits for elements
- `expected_conditions` (EC) - Pre-built wait conditions
- `TimeoutException` - Handle wait timeouts
- `UnexpectedAlertPresentException` - Handle unexpected alerts

### Additional Imports

```python
import time
```

**Purpose:** Used for:
- Generating unique usernames via `int(time.time())`
- Small delays between rapid actions
- Wait for alert processing

**Why timestamps in usernames:**
Creates unique usernames for each test run, preventing conflicts and eliminating need for cleanup.

---

<a name="configuration"></a>
## 6. Configuration Variables

### Base Configuration

```python
BASE_URL = "https://www.demoblaze.com/index.html"
```

Signup modal accessed from homepage.

### Locators Organization

Locators grouped by functionality:

**Modal and Navigation:**
```python
SIGNUP_LINK = (By.ID, "signin2")
SIGNUP_USERNAME = (By.ID, "sign-username")
SIGNUP_PASSWORD = (By.ID, "sign-password")
SIGNUP_BUTTON = (By.XPATH, "//button[text()='Sign up']")
CLOSE_BUTTON = (By.XPATH, "//div[@id='signInModal']//button[@class='close']")
CANCEL_BUTTON = (By.XPATH, "//div[@id='signInModal']//button[contains(@class, 'btn-secondary')]")
```

**Login Modal (for integration test):**
```python
LOGIN_LINK = (By.ID, "login2")
LOGIN_USERNAME = (By.ID, "loginusername")
LOGIN_PASSWORD = (By.ID, "loginpassword")
LOGIN_BUTTON = (By.XPATH, "//button[text()='Log in']")
WELCOME_MESSAGE = (By.ID, "nameofuser")
```

### How Locators Were Obtained

1. Open DemoBlaze homepage
2. Click "Sign up" link
3. Right-click username field → Inspect
4. HTML shows: `<input type="text" id="sign-username">`
5. Extract: `(By.ID, "sign-username")`

Repeated for all elements.

---

<a name="fixtures"></a>
## 7. Fixtures Deep Dive

### Fixture: `browser`

Defined in root `conftest.py`. Provides cross-browser support (Chrome, Firefox, Edge).

See purchase README section 7 for details.

**Used by all signup tests:**
```python
def test_signup_valid_credentials(self, browser):
    # browser instance provided by fixture
```

---

<a name="helpers"></a>
## 8. Helper Functions

All helper methods are part of the `TestSignup` class.

---

### `wait_for_alert(self, browser, timeout=5)`

**Purpose:** Wait for JavaScript alert and retrieve text

**Parameters:**
- `browser` - WebDriver instance
- `timeout` - Maximum wait time (default 5 seconds)

**Returns:**
- Alert text (string)
- `None` if no alert appears

**How it works:**
```python
try:
    WebDriverWait(browser, timeout).until(EC.alert_is_present())
    alert = browser.switch_to.alert
    alert_text = alert.text
    alert.accept()
    return alert_text
except TimeoutException:
    return None
```

**Usage in tests:**
```python
alert_text = self.wait_for_alert(browser)
assert alert_text == "Sign up successful."
```

**Why needed:**
DemoBlaze uses JavaScript alerts for all feedback. This centralizes alert handling logic.

---

### `open_signup_modal(self, browser)`

**Purpose:** Navigate to homepage and open signup modal

**What it does:**
1. Navigate to BASE_URL
2. Wait for signup link to be clickable
3. Click signup link
4. Wait for username field to appear
5. Short sleep for modal animation

**Usage:**
```python
self.open_signup_modal(browser)
# Modal now open and ready for interaction
```

**Why needed:**
Every test starts with opening the modal. Centralizes this logic.

---

### `fill_signup_form(self, browser, username, password)`

**Purpose:** Fill username and password fields

**Parameters:**
- `browser` - WebDriver instance
- `username` - String to enter in username field
- `password` - String to enter in password field

**What it does:**
1. Find username field
2. Clear existing value
3. Send keys for username
4. Repeat for password field

**Usage:**
```python
self.fill_signup_form(browser, "testuser_123", "SecurePass")
```

**Why needed:**
Avoids repeating 6 lines of code in every test.

---

### `click_signup_button(self, browser)`

**Purpose:** Click the "Sign up" button

**What it does:**
1. Find signup button via XPath
2. Click button

**Usage:**
```python
self.click_signup_button(browser)
```

---

### `verify_login_works(self, browser, username, password)`

**Purpose:** Verify newly registered user can login

**Used in:** TC-SIGNUP-023 (integration test)

**What it does:**
1. Wait for and click login link
2. Wait for login modal to appear
3. Fill username and password
4. Click "Log in" button
5. Wait for welcome message
6. Assert welcome message contains username

**Why critical:**
Validates that:
- User actually created in database
- Credentials stored correctly
- Authentication system works
- End-to-end signup flow functional

**Usage:**
```python
self.verify_login_works(browser, "testuser_123", "SecurePass")
# If no assertion error → login successful
```

---

<a name="tests"></a>
## 9. Test Functions Breakdown

### `test_signup_valid_credentials(self, browser)`

**Test ID:** TC-SIGNUP-001

**Flow:**
1. Generate unique username with timestamp
2. Open signup modal
3. Fill form with username and "TestPass123"
4. Click signup button
5. Wait for alert
6. Assert alert says "Sign up successful."

**Key Line:**
```python
timestamp = int(time.time())
username = f"testuser_{timestamp}"
```

Creates unique username for each test run.

**Why This Test Matters:**
Most basic and critical test - validates core signup functionality works.

---

### `test_signup_existing_user(self, browser)`

**Test ID:** TC-SIGNUP-002

**Flow:**
1. Generate unique username
2. Register user (first attempt)
3. Verify success
4. Wait 1 second
5. Attempt to register again with same username
6. Verify "This user already exist." alert

**Key Assertion:**
```python
assert alert_text == "This user already exist."
```

**Why This Test Matters:**
Validates duplicate prevention at application level (not just database constraint).

---

### `test_signup_empty_username(self, browser)`

**Test ID:** TC-SIGNUP-003

**Flow:**
1. Open modal
2. Fill empty string for username
3. Fill valid password
4. Click signup
5. Verify validation alert

**Expected Alert:**
"Please fill out Username and Password."

---

### `test_signup_empty_password(self, browser)`

**Test ID:** TC-SIGNUP-004

**Flow:**
1. Open modal
2. Fill valid username
3. Fill empty string for password
4. Click signup
5. Verify validation alert

---

### `test_signup_both_fields_empty(self, browser)`

**Test ID:** TC-SIGNUP-005

**Flow:**
1. Open modal
2. Fill empty strings for both fields
3. Click signup
4. Verify validation alert

---

### `test_signup_weak_password_single_char(self, browser)`

**Test ID:** TC-SIGNUP-006

**Flow:**
1. Generate unique username
2. Set password = "1" (single character)
3. Fill form
4. Click signup
5. Observe success (BUG)

**Current Behavior:**
System accepts single-character password. This is a security vulnerability (Bug #13).

**Expected Behavior (Post-Fix):**
Should reject with "Password must be at least 8 characters."

---

### `test_signup_weak_password_two_chars(self, browser)`

**Test ID:** TC-SIGNUP-007

Similar to TC-SIGNUP-006 but with 2-character password.

Documents that even 2-character passwords accepted (Bug #13).

---

### `test_signup_sql_injection_username(self, browser)`

**Test ID:** TC-SIGNUP-008

**Flow:**
1. Define SQL payloads list
2. Loop through each payload:
   - Open modal
   - Enter SQL payload as username
   - Enter valid password
   - Click signup
   - Verify signup completes or fails gracefully
   - Wait 1 second
3. No database errors expected

**Payloads Tested:**
```python
sql_payloads = [
    "admin' OR '1'='1",
    "admin'--",
    "' OR 1=1--",
    "admin' DROP TABLE users--"
]
```

**Current Behavior:**
System accepts SQL syntax without sanitization (Bug #14 - CRITICAL).

**Assertion:**
```python
assert alert_text in ["Sign up successful.", "This user already exist."]
```

Test passes regardless of alert (documents current behavior). Real-world fix would reject SQL syntax.

---

### `test_signup_sql_injection_password(self, browser)`

**Test ID:** TC-SIGNUP-009

**Flow:**
1. Generate unique username
2. Set password = `' OR '1'='1'` (SQL payload)
3. Fill form
4. Click signup
5. Verify completes without SQL execution

**Current Behavior:**
Accepts SQL syntax in password (Bug #14).

---

### `test_signup_xss_username(self, browser)`

**Test ID:** TC-SIGNUP-010

**Flow:**
1. Define XSS payloads list
2. Loop through each payload:
   - Open modal
   - Enter XSS payload as username
   - Enter valid password
   - Click signup
   - Wait for alert with timeout=3
   - If alert appears, verify it's success/exists message (not XSS execution)
3. Wait 1 second between iterations

**Payloads Tested:**
```python
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')"
]
```

**Current Behavior:**
System accepts script tags without encoding (Bug #15 - CRITICAL).

**Critical Check:**
If alert contains 'XSS' → XSS executed → security vulnerability confirmed.

---

### `test_signup_xss_password(self, browser)`

**Test ID:** TC-SIGNUP-011

Similar to TC-SIGNUP-010 but tests XSS in password field.

---

### `test_signup_whitespace_username_leading(self, browser)`

**Test ID:** TC-SIGNUP-012

**Flow:**
1. Generate username with leading spaces: `"   leadingspace_123"`
2. Fill form
3. Click signup
4. Verify success

**Current Behavior:**
Spaces not trimmed (Bug #17).

**Expected Behavior:**
Leading/trailing whitespace should be trimmed automatically.

---

### `test_signup_whitespace_username_trailing(self, browser)`

**Test ID:** TC-SIGNUP-013

Same as TC-SIGNUP-012 but with trailing spaces.

---

### `test_signup_whitespace_only_username(self, browser)`

**Test ID:** TC-SIGNUP-014

**Flow:**
1. Set username = `"     "` (only spaces)
2. Fill form
3. Click signup
4. Verify alert (either validation error or success)

**Assertion:**
```python
assert alert_text in ["Please fill out Username and Password.", "Sign up successful."]
```

Documents system behavior for whitespace-only input.

---

### `test_signup_whitespace_password(self, browser)`

**Test ID:** TC-SIGNUP-015

**Flow:**
1. Generate unique username
2. Set password = `"   spaces   "` (spaces around)
3. Fill form
4. Click signup
5. Verify success

**Why This Test Matters:**
Validates that spaces are valid password characters.

---

### `test_signup_special_characters_valid(self, browser)`

**Test ID:** TC-SIGNUP-017

**Flow:**
1. Generate username with special chars: `"user_@#$_123"`
2. Set password with special chars: `"P@ssw0rd!#$"`
3. Fill form
4. Click signup
5. Verify success

**Why This Test Matters:**
Validates system accepts reasonable special characters.

---

### `test_signup_username_very_long(self, browser)`

**Test ID:** TC-SIGNUP-018

**Flow:**
1. Generate username with 200+ characters
2. Fill form
3. Click signup
4. Verify completes without error

**Current Behavior:**
No maximum length validation (Bug #16).

**Expected Behavior:**
Should enforce reasonable limit (e.g., 50 characters).

---

### `test_signup_password_very_long(self, browser)`

**Test ID:** TC-SIGNUP-019

Similar to TC-SIGNUP-018 but tests 200+ character password.

---

### `test_signup_username_with_numbers(self, browser)`

**Test ID:** TC-SIGNUP-021

**Flow:**
1. Generate alphanumeric username: `"user123456_123"`
2. Fill form
3. Click signup
4. Verify success

**Why This Test Matters:**
Validates alphanumeric usernames accepted (common requirement).

---

### `test_signup_username_numbers_only(self, browser)`

**Test ID:** TC-SIGNUP-022

**Flow:**
1. Generate numeric-only username: `"123456123"`
2. Fill form
3. Click signup
4. Verify success

**Why This Test Matters:**
Documents whether numeric-only usernames allowed (varies by system).

---

### `test_signup_case_sensitivity_uppercase(self, browser)`

**Test ID:** TC-SIGNUP-020

**Flow:**
1. Generate lowercase username: `"casetest_123"`
2. Register with lowercase
3. Verify success
4. Wait 1 second
5. Attempt to register with uppercase version: `"CASETEST_123"`
6. Observe result

**Possible Results:**
- "Sign up successful." → System is case-sensitive
- "This user already exist." → System is case-insensitive

**Why This Test Matters:**
Documents system behavior for case handling in usernames.

---

### `test_signup_then_login(self, browser)`

**Test ID:** TC-SIGNUP-023

**Flow:**
1. Generate unique credentials
2. Register user
3. Verify success
4. Wait 1 second
5. Call `verify_login_works()` helper
6. Helper performs login and verifies welcome message

**Why This Test Matters:**
Most important integration test - validates:
- User actually created in database
- Credentials stored correctly
- Password hashing works
- Authentication integration works
- Complete end-to-end flow functional

---

### `test_signup_multiple_rapid_same_username(self, browser)`

**Test ID:** TC-SIGNUP-024

**Flow:**
1. Generate unique username
2. Register user (first attempt)
3. Verify success
4. Loop 3 times:
   - Wait 0.5 seconds
   - Attempt to register same username
   - Verify "This user already exist."

**Why This Test Matters:**
Validates duplicate detection works even with rapid consecutive requests (no race conditions).

---

### `test_signup_unicode_username(self, browser)`

**Test ID:** TC-SIGNUP-027

**Flow:**
1. Generate username with Chinese characters: `"用户_123"`
2. Fill form
3. Click signup
4. Verify completes without encoding errors

**Why This Test Matters:**
Validates international character support for global users.

---

### `test_signup_emoji_username(self, browser)`

**Test ID:** TC-SIGNUP-028

**Flow:**
1. Generate username with emojis: `"user😀🎉_123"`
2. Fill form
3. Click signup
4. Verify completes without encoding errors

---

### `test_signup_modal_close_without_action(self, browser)`

**Test ID:** TC-SIGNUP-029

**Flow:**
1. Open signup modal
2. Click X (close) button
3. Wait 1 second
4. Verify modal no longer displayed or not found

**Why This Test Matters:**
Validates users can cancel signup without side effects.

---

### `test_signup_modal_cancel_button(self, browser)`

**Test ID:** TC-SIGNUP-030

**Flow:**
1. Open signup modal
2. Click "Cancel" button
3. Wait 1 second
4. Verify modal no longer displayed

---

### `test_signup_password_with_spaces_middle(self, browser)`

**Test ID:** TC-SIGNUP-016

**Flow:**
1. Generate unique username
2. Set password = `"Pass Word 123"` (spaces in middle)
3. Fill form
4. Click signup
5. Verify success

**Why This Test Matters:**
Validates spaces are valid password characters (should be preserved).

---

<a name="execution"></a>
## 10. Execution Guide

### Prerequisites

```bash
# Install dependencies
pip install -r requirements.txt
```

### Running Tests

**Run all signup tests:**
```bash
pytest tests/signup/
```

**Run with specific browser:**
```bash
pytest tests/signup/ --browser=chrome
pytest tests/signup/ --browser=firefox
pytest tests/signup/ --browser=edge
```

**Run specific test:**
```bash
pytest tests/signup/test_signup.py::TestSignup::test_signup_valid_credentials
```

**Run with verbose output:**
```bash
pytest tests/signup/ -v
```

**Run with live logging:**
```bash
pytest tests/signup/ -s
```

**Run only security tests:**
```bash
pytest tests/signup/ -v -k "sql_injection or xss"
```

**Run only boundary tests:**
```bash
pytest tests/signup/ -v -k "very_long or weak_password"
```

**Run only positive tests:**
```bash
pytest tests/signup/ -v -k "valid or unicode or emoji or special_characters"
```

### HTML Reports

Reports generated automatically in:
```
test_results/signup/report_[browser]_[timestamp].html
```

Example:
```
test_results/signup/report_chrome_2025-11-07_14-30-45.html
```

---

<a name="results"></a>
## 11. Expected Results

### Test Execution Summary

| Test Category | Tests | Expected Result |
|--------------|-------|-----------------|
| Valid Registration | 1 | PASS |
| Negative Tests | 4 | PASS |
| Password Strength | 2 | PASS (documents bug) |
| SQL Injection | 2 | PASS (documents vulnerability) |
| XSS Testing | 2 | PASS (documents vulnerability) |
| Whitespace Handling | 5 | PASS |
| Special Characters | 1 | PASS |
| Boundary Tests | 2 | PASS (documents missing validation) |
| Username Variations | 3 | PASS |
| Integration | 1 | PASS |
| Rapid Actions | 1 | PASS |
| Unicode Support | 2 | PASS |
| UI Interaction | 2 | PASS |
| **TOTAL TESTS** | **30** | **30 PASS** |

### Success Criteria

Test suite PASSED if:
- All 30 tests pass
- No unexpected failures
- Execution time under 3 minutes

### Performance Benchmarks

**Expected execution times:**
- Simple tests: 3-5 seconds each
- SQL/XSS tests (multiple payloads): 8-12 seconds
- Integration test (signup + login): 8-10 seconds
- Total suite: ~2-3 minutes

---

<a name="troubleshooting"></a>
## 12. Troubleshooting

### Issue: Alert not found

**Cause:** Alert appeared and disappeared before test checked

**Solution:** Reduce timeout or check immediately after clicking signup button

---

### Issue: "This user already exist" on first attempt

**Cause:** Username not truly unique (timestamp collision or previous test run)

**Solution:** Add random component to username generation:
```python
import random
timestamp = int(time.time())
random_suffix = random.randint(1000, 9999)
username = f"testuser_{timestamp}_{random_suffix}"
```

---

### Issue: Modal doesn't close

**Cause:** JavaScript animation not complete

**Solution:** Increase sleep time after clicking close button from 1 to 2 seconds

---

### Issue: XSS test triggers actual alert

**Cause:** XSS vulnerability exists

**Solution:** This is expected for security tests. Test documents the vulnerability.

---

### Issue: Test hangs on modal open

**Cause:** Modal load slow or JavaScript error

**Solution:** Check browser console for errors. Increase wait timeout.

---

<a name="practices"></a>
## 13. Best Practices Applied

### Code Quality

**DRY Principle:**
- `wait_for_alert()` used in all tests
- `open_signup_modal()` eliminates repetition
- `fill_signup_form()` centralizes form filling
- `verify_login_works()` for integration testing

**Clean Code:**
- No excessive comments in code
- All documentation in README
- Clear function names
- Consistent structure

### Testing Best Practices

**Unique Test Data:**
- Timestamps ensure unique usernames
- No test interference
- No cleanup required
- Realistic data generation

**Security Testing:**
- Multiple SQL payloads tested
- Multiple XSS vectors tested
- Documents vulnerabilities clearly
- Severity levels assigned

**Boundary Testing:**
- Tests extreme input lengths
- Documents missing validation
- Validates system robustness

**Integration Testing:**
- End-to-end signup-to-login flow
- Validates complete user journey
- Confirms database integration

### Selenium Best Practices

**Wait Strategy:**
- Wait for element clickable before clicking
- Wait for alert with timeout
- Custom wait logic for alerts

**Locator Strategy:**
- ID when available (fastest, most reliable)
- XPath for text-based elements
- Consistent naming convention

**Error Handling:**
- Try/except for alerts
- TimeoutException handling
- Graceful failure messages

---

## 14. Maintenance Guide

### When to Update Tests

**Site Redesign:**
- Update locators if HTML structure changes
- Verify alert messages unchanged
- Test on all browsers

**Bug Fixes:**
- Update expected behaviors when bugs fixed
- Remove "documents bug" comments
- Re-verify tests pass with fixes

**New Features:**
- Add email field tests if email verification added
- Add CAPTCHA tests if CAPTCHA implemented
- Add password confirmation tests if added

---

## 15. Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | Nov 2025 | Initial release with 30 comprehensive test cases |

---

## 16. Related Documents

- [Test Plan](../../docs/test-plan.md)
- [Test Summary Report](../../docs/Test_Summary_Report.md)
- [User Flows](../../docs/users-flow.md)
- [DemoBlaze Test Cases](../../docs/DemoBlaze_Test_Cases.xlsx)
- [Login Module README](../login/README.md)
- [Purchase Module README](../purchase/README.md)
- [GitHub Issue #19](https://github.com/SrMarcoAurelio/demoblaze-testing-project/issues/19): No password complexity requirements
- [GitHub Issue #14](https://github.com/SrMarcoAurelio/demoblaze-testing-project/issues/14): SQL Injection vulnerability
- [GitHub Issue #15](https://github.com/SrMarcoAurelio/demoblaze-testing-project/issues/15): Username enumeration

---

**End of Documentation**
