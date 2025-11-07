# Test Suite: Login & Authentication

**Module:** `test_dem_login.py`  
**Author:** Arévalo, Marc  
**Created:** November 2025  
**Version:** 3.1 - Cross-Browser Support Added  
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
10. [How to Obtain Locators](#locators)
11. [Execution Guide](#execution)
12. [Expected Results](#results)
13. [Troubleshooting](#troubleshooting)
14. [Best Practices Applied](#practices)

---

<a name="overview"></a>
## 1. Overview

### Purpose

This test suite automates comprehensive validation of DemoBlaze's authentication system, including:
- Standard login/logout functionality
- Security vulnerability testing (SQL injection, XSS, brute force)
- Input validation (special characters, Unicode, boundary tests)
- UI component interaction (modals, buttons)

### Scope

**In Scope:**
- Valid login with correct credentials
- Invalid login scenarios (wrong password, non-existent user, empty fields)
- SQL Injection attempts (username and password fields)
- Cross-Site Scripting (XSS) attacks
- Special characters and Unicode input handling
- Boundary tests (very long inputs, whitespace)
- Case sensitivity validation
- Null bytes and path traversal attempts
- Security vulnerabilities (weak passwords, username enumeration, brute force)
- Modal interaction and UI state verification
- Cross-browser testing (Chrome, Firefox, Edge)

**Out of Scope:**
- Password recovery functionality
- Remember me checkbox
- Social login integrations
- Multi-factor authentication (not implemented in DemoBlaze)

### Version History

**v3.1 (Current):**
- Added cross-browser support (Chrome, Firefox, Edge)
- Enhanced logging for real-time feedback
- Improved helper functions for robust state verification
- Fixed modal interaction test (TC-LOGIN-022)

**v3.0:**
- Added comprehensive security testing
- Parametrized tests for SQL injection and XSS
- Added special character and Unicode testing
- Boundary and edge case tests

**v1.0:**
- Initial release with basic login tests

---

<a name="test-cases"></a>
## 2. Test Cases Covered

### Basic Authentication Tests

#### TC-LOGIN-001: Valid Login
**Priority:** Critical  
**Type:** Positive Test  

**Test Steps:**
1. Navigate to login modal
2. Enter valid credentials
3. Submit form

**Expected Result:**
- User authenticated successfully
- "Log out" button visible
- Welcome message displays username
- Modal closes automatically

---

#### TC-LOGIN-002: Invalid Password
**Priority:** High  
**Type:** Negative Test  

**Test Steps:**
1. Enter valid username + wrong password
2. Submit form

**Expected Result:**
- Login rejected
- Alert: "Wrong password."
- User remains logged out

---

#### TC-LOGIN-003: Non-existent User
**Priority:** High  
**Type:** Negative Test  

**Expected Result:**
- Alert: "User does not exist."
- Login rejected

---

#### TC-LOGIN-004: Empty Fields
**Priority:** Medium  
**Type:** Negative Test  

**Expected Result:**
- Alert: "Please fill out Username and Password."
- Form not submitted to server

---

#### TC-LOGIN-005: Empty Username Only
**Priority:** Medium  
**Type:** Negative Test  

**Expected Result:**
- Validation error displayed
- Login rejected

---

#### TC-LOGIN-006: Empty Password Only
**Priority:** Medium  
**Type:** Negative Test  

**Expected Result:**
- Validation error displayed
- Login rejected

---

### Security Tests - SQL Injection

#### TC-LOGIN-007: SQL Injection in Username Field
**Priority:** Critical  
**Type:** Security Test (Parametrized)  

**Payloads tested:**
- `' OR '1'='1`
- `' OR 1=1--`
- `admin'--`
- `' OR 'a'='a`
- `1' OR '1' = '1`
- `' UNION SELECT NULL--`
- `admin' OR '1'='1'--`

**Expected Result:**
- All payloads rejected
- No unauthorized access granted
- User remains logged out

**Security Impact:**
If any payload succeeds, the system is vulnerable to SQL injection attacks, allowing attackers to:
- Bypass authentication
- Access unauthorized accounts
- Extract database information
- Modify or delete data

---

#### TC-LOGIN-008: SQL Injection in Password Field
**Priority:** Critical  
**Type:** Security Test (Parametrized)  

**Payloads tested:**
- `' OR '1'='1`
- `' OR 1=1--`
- `password' OR '1'='1`

**Expected Result:**
- All payloads blocked
- Login rejected
- No SQL queries manipulated

---

### Security Tests - Cross-Site Scripting (XSS)

#### TC-LOGIN-009: XSS in Username Field
**Priority:** Critical  
**Type:** Security Test (Parametrized)  

**Payloads tested:**
- `<script>alert('XSS')</script>`
- `<img src=x onerror=alert('XSS')>`
- `javascript:alert('XSS')`
- `<svg/onload=alert('XSS')>`

**Expected Result:**
- No script execution
- Input sanitized or rejected
- User remains logged out

**Security Impact:**
XSS vulnerabilities allow attackers to:
- Steal session cookies
- Hijack user accounts
- Deface website content
- Redirect users to malicious sites

---

### Input Validation Tests

#### TC-LOGIN-010: Special Characters in Username
**Priority:** Medium  
**Type:** Negative Test (Parametrized)  

**Test inputs:**
- `user@#$%`
- `user!@#$%^&*()`
- `user<>?:`
- `user|\\`
- `user{}[]`
- `user'"`
- `user\n\t\r`

**Expected Result:**
- System handles gracefully
- No crashes or errors
- Login rejected appropriately

---

#### TC-LOGIN-011: Unicode/International Characters
**Priority:** Medium  
**Type:** Negative Test (Parametrized)  

**Test inputs:**
- Chinese: `用户名`
- Russian: `Пользователь`
- French: `utilisateur`
- Arabic: `المستخدم`
- Japanese: `ユーザー`
- Emojis: `😀😎🔥`

**Expected Result:**
- System handles international input
- No encoding errors
- Appropriate rejection or handling

---

### Boundary Tests

#### TC-LOGIN-012: Very Long Username (1000 chars)
**Priority:** Medium  
**Type:** Boundary Test  

**Expected Result:**
- System handles without crashing
- Appropriate error or truncation
- No buffer overflow

---

#### TC-LOGIN-013: Very Long Password (1000 chars)
**Priority:** Medium  
**Type:** Boundary Test  

**Expected Result:**
- Long input handled safely
- No memory issues
- Login rejected appropriately

---

#### TC-LOGIN-014: Whitespace in Username
**Priority:** Low  
**Type:** Edge Case (Parametrized)  

**Test inputs:**
- `   user   ` (spaces around)
- ` user` (leading space)
- `user ` (trailing space)
- `   ` (only spaces)

**Expected Result:**
- Whitespace handled consistently
- Proper trimming or validation

---

#### TC-LOGIN-015: Case Sensitivity in Username
**Priority:** Medium  
**Type:** Negative Test (Parametrized)  

**Test inputs:**
- All uppercase
- All lowercase
- Title case

**Expected Result:**
- Login is case-sensitive
- Different case = rejected

---

### Advanced Security Tests

#### TC-LOGIN-016: Null Bytes in Input
**Priority:** High  
**Type:** Security Test (Parametrized)  

**Test inputs:**
- `user\x00admin`
- `user\x00`
- `\x00user`

**Expected Result:**
- Null bytes handled safely
- No string truncation exploits
- Login rejected

---

#### TC-LOGIN-017: Path Traversal Attempts
**Priority:** High  
**Type:** Security Test (Parametrized)  

**Test inputs:**
- `../../../etc/passwd`
- `..\\..\\..\\windows\\system32`
- `....//....//....//etc/passwd`

**Expected Result:**
- Path traversal blocked
- No file system access
- Login rejected

---

### Known Vulnerability Tests (xfail)

#### TC-LOGIN-018: Weak Password Vulnerability
**Priority:** Critical  
**Type:** Security Test  
**Status:** Expected to fail (Bug #11)

**Test:**
- Register user with password "123"
- Verify system accepts it

**Current Behavior (BUG):**
- System accepts weak passwords
- No complexity requirements

**Expected Behavior (Post-Fix):**
- Reject passwords not meeting requirements:
  - Minimum 8 characters
  - At least 1 uppercase letter
  - At least 1 lowercase letter
  - At least 1 number
  - At least 1 special character

---

#### TC-LOGIN-019: Username Enumeration Vulnerability
**Priority:** Critical  
**Type:** Security Test  
**Status:** Expected to fail (Bug #10)

**Test:**
- Login with existing user + wrong password
- Login with non-existent user + any password
- Compare error messages

**Current Behavior (BUG):**
- Different messages reveal username validity:
  - "Wrong password." = username exists
  - "User does not exist." = username invalid

**Expected Behavior (Post-Fix):**
- Generic message for all failures: "Invalid username or password."

**Security Impact:**
- Attackers can enumerate valid usernames
- Enables targeted password attacks
- OWASP Top 10 vulnerability

---

#### TC-LOGIN-020: Brute Force Protection
**Priority:** Critical  
**Type:** Security Test  
**Status:** Expected to fail (Bug #12)

**Test:**
- Attempt 7 consecutive failed logins
- Verify account lockout or rate limiting

**Current Behavior (BUG):**
- No rate limiting implemented
- Unlimited login attempts allowed

**Expected Behavior (Post-Fix):**
- Account locked after N failed attempts
- Error: "Account locked" or "Too many attempts"

---

### UI Interaction Tests

#### TC-LOGIN-021: Login Modal Close Button
**Priority:** Low  
**Type:** Functional Test  

**Test Steps:**
1. Open login modal
2. Click 'X' close button
3. Verify modal closes

**Expected Result:**
- Modal closes completely
- Can reopen modal successfully

---

#### TC-LOGIN-022: Sign Up and Login Modal Interaction
**Priority:** Low  
**Type:** Functional Test  

**Test Steps:**
1. Open Sign Up modal
2. Verify it's visible
3. Close it
4. Open Login modal
5. Verify it's visible

**Expected Result:**
- Both modals open/close independently
- No interference between modals
- Clean state transitions

---

<a name="bugs"></a>
## 3. Related Bugs

| Bug ID | Severity | Title | Test Case | Status |
|--------|----------|-------|-----------|--------|
| #10 | High | Username enumeration vulnerability | TC-LOGIN-019 | Open |
| #11 | High | System accepts weak passwords | TC-LOGIN-018 | Open |
| #12 | High | No rate limiting on login attempts | TC-LOGIN-020 | Open |

---

<a name="architecture"></a>
## 4. Code Architecture

### File Structure

```
project_root/
├── docs/
│   ├── DemoBlaze_Test_Cases.xlsx
│   ├── test-plan.md
│   ├── Test_Summary_Report.md
│   └── users-flow.md
├── tests/
│   ├── login/
│   │   ├── __init__.py
│   │   ├── test_dem_login.py
│   │   └── README.md (this file)
│   └── purchase/
│       ├── test_dem_login_doc.md
│       └── test_purchase.py
├── test_results/              # Auto-generated by conftest.py
│   └── login/                 # Reports grouped by test folder
│       └── report_chrome_YYYY-MM-DD_HH-MM-SS.html
├── conftest.py                # Root pytest configuration
├── requirements.txt
└── .gitignore
```

### Code Organization

The Python file is organized into 6 sections:

1. **IMPORTS** - External libraries and dependencies
2. **CONFIGURATION** - Constants, locators, and test data
3. **FIXTURES** - Setup/teardown automation
4. **HELPER FUNCTIONS** - Reusable utility functions
5. **TEST CASES** - Actual test functions
6. **EXECUTION BLOCK** - Optional direct execution

### Design Pattern: Page Object Model (Simplified)

Follows POM principles:
- Locators centralized in CONFIGURATION
- Business logic separated from test logic
- Helper functions encapsulate page interactions
- Tests focus on "what" not "how"

---

<a name="imports"></a>
## 5. Imports Explanation

### Core Selenium Imports

```python
from selenium import webdriver
```
Controls browser automation - opens/closes browsers, manages sessions.

```python
from selenium.webdriver.common.by import By
```
Defines how to find elements (ID, XPath, CSS). Modern approach replacing deprecated methods.

```python
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
```
Explicit waits for dynamic content. More reliable than `time.sleep()`.

```python
from selenium.common.exceptions import TimeoutException, NoSuchElementException
```
Handle errors gracefully when elements not found or waits timeout.

```python
from selenium.webdriver.chrome.service import Service
```
Manages ChromeDriver service process.

### WebDriver Manager Imports

```python
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager
from webdriver_manager.microsoft import EdgeChromiumDriverManager
```

**Purpose:** Automatic driver management
- Downloads correct driver version automatically
- Matches browser version
- Eliminates manual setup

**Example usage:**
```python
service = Service(ChromeDriverManager().install())
driver = webdriver.Chrome(service=service)
```

### Testing Framework

```python
import pytest
```
Testing framework providing:
- Test discovery and execution
- Fixtures for setup/teardown
- Parametrization
- Reporting
- Assertions

```python
import time
```
Generate timestamps for unique usernames and add delays when needed.

```python
import logging
```
Real-time feedback during test execution for debugging and monitoring.

---

<a name="configuration"></a>
## 6. Configuration Variables

### Base Configuration

```python
BASE_URL = "https://www.demoblaze.com/"
```
Central point for application URL. Easy to switch between environments.

```python
TIMEOUT = 10
EXPLICIT_WAIT = 5
```
- `TIMEOUT`: Maximum wait time for elements (industry standard: 10 seconds)
- `EXPLICIT_WAIT`: Shorter wait for specific operations

### Test Credentials

```python
TEST_USERNAME = "testuser_qa_2024"
TEST_PASSWORD = "SecurePass123!"
```

**Prerequisites:**
- Account must be pre-registered in DemoBlaze
- Password demonstrates security best practices (contrast with weak password tests)

### Locators

All element locators centralized:

```python
LOGIN_BUTTON_NAV = (By.ID, "login2")
LOGIN_USERNAME_FIELD = (By.ID, "loginusername")
LOGIN_PASSWORD_FIELD = (By.ID, "loginpassword")
LOGIN_SUBMIT_BUTTON = (By.XPATH, "//button[text()='Log in']")
LOGOUT_BUTTON = (By.ID, "logout2")
WELCOME_USER_TEXT = (By.ID, "nameofuser")
SIGNUP_BUTTON = (By.ID, "signin2")
SIGNUP_USERNAME_FIELD = (By.ID, "sign-username")
SIGNUP_PASSWORD_FIELD = (By.ID, "sign-password")
SIGNUP_SUBMIT_BUTTON = (By.XPATH, "//button[text()='Sign up']")
LOGIN_MODAL_CLOSE_BUTTON = (By.XPATH, "//div[@id='logInModal']//button[@class='close']")
LOGIN_MODAL = (By.ID, "logInModal")
```

**Locator Strategy:**
1. Prefer ID (fastest, most reliable)
2. Use XPath when no unique ID exists
3. XPath with text for buttons (readable and distinctive)

---

<a name="fixtures"></a>
## 7. Fixtures Deep Dive

### Fixtures

Located in project root `conftest.py`, which provides:

**1. Browser Fixture (`browser`)**
- Parametrized cross-browser support
- Automatic driver management
- Clean setup/teardown

**2. Automatic Report Generation (`pytest_configure` hook)**

The `conftest.py` automatically generates HTML reports without manual `--html` flags:

```python
@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    # Detects test folder (e.g., "login", "purchase")
    # Creates: test_results/[folder]/report_[browser]_[timestamp].html
    # Example: test_results/login/report_chrome_2025-11-07_14-30-45.html
```

**Report Organization:**
- Root folder: `test_results/`
- Subfolders by test group: `login/`, `purchase/`, etc.
- Filenames: `report_[browser]_[YYYY-MM-DD_HH-MM-SS].html`
- Self-contained HTML (no external dependencies)

**Why this approach:**
- No need to specify `--html` in every command
- Reports organized automatically
- Easy to compare results across browsers
- Historical test data preserved

---

### Fixture: `browser`

**Purpose:** Provides browser instance based on command-line argument

**Cross-Browser Support:**
```python
@pytest.fixture(scope="function")
def browser(request):
    browser_name = request.config.getoption("--browser").lower()
```

**Supported browsers:**
- Chrome (default)
- Firefox
- Edge

**What it does:**
1. Reads `--browser` option from command line
2. Installs appropriate driver (ChromeDriver, GeckoDriver, EdgeDriver)
3. Initializes browser with options
4. Maximizes window
5. Sets implicit wait
6. **Yields** browser to test
7. Quits browser after test (cleanup)

**Usage:**
```bash
pytest test_dem_login.py --browser=chrome
pytest test_dem_login.py --browser=firefox
pytest test_dem_login.py --browser=edge
```

**Headless mode:**
Uncomment in fixture:
```python
options.add_argument("--headless")
```

---

### Fixture: `login_page`

**Purpose:** Opens browser AND navigates to login modal

**What it does:**
1. Navigate to homepage
2. Wait for page load
3. Click login button
4. Wait for modal to open
5. Return browser (with modal ready)

**Usage in tests:**
```python
def test_login_valid_credentials(login_page):
    # Modal already open, ready to test
    perform_login(login_page, username, password)
```

---

<a name="helpers"></a>
## 8. Helper Functions

### `perform_login(browser, username, password)`

Encapsulates login action:
1. Clear and enter username
2. Clear and enter password
3. Click submit button

**Why helper function:**
- Login action repeated in every test
- Single point of maintenance
- Clean, readable test code

---

### `wait_for_alert_and_get_text(browser, timeout=EXPLICIT_WAIT)`

Safely handles JavaScript alerts:
1. Wait for alert (with timeout)
2. Switch to alert context
3. Get alert text
4. Accept (close) alert
5. Return text or `None`

**Error handling:**
- Returns `None` if no alert appears
- Prevents test crashes

**Usage:**
```python
alert_text = wait_for_alert_and_get_text(browser)
if alert_text:
    assert "Wrong password" in alert_text
```

---

### `check_user_is_logged_in(browser, timeout=EXPLICIT_WAIT)`

**Robust verification** that user is authenticated:

1. Wait for login modal to disappear
2. Wait for "Log out" button to become **visible**
3. Return `True` if logged in, `False` otherwise

**Why "visibility" check:**
- Element may exist in DOM but be hidden
- Visibility confirms user sees the button
- More reliable than simple presence check

**Usage:**
```python
assert check_user_is_logged_in(browser), "User should be logged in"
```

---

### `check_user_is_logged_out(browser, timeout=EXPLICIT_WAIT)`

**Inverse verification** - confirms user is NOT authenticated:

1. Wait until "Log out" button is **NOT visible**
2. Return `True` if logged out, `False` if still logged in

**Usage:**
```python
assert check_user_is_logged_out(browser), "User should NOT be logged in"
```

---

<a name="tests"></a>
## 9. Test Functions Breakdown

### Basic Login Tests

#### `test_login_valid_credentials(login_page)`

**Flow:**
1. Perform login with valid credentials
2. Assert user is logged in (logout button visible)
3. Assert welcome message contains username

**Key assertions:**
- `check_user_is_logged_in()` returns `True`
- Welcome text contains `TEST_USERNAME`

---

#### `test_login_invalid_password(login_page)`

**Flow:**
1. Login with valid username + wrong password
2. Capture alert text
3. Assert error message is "Wrong password."
4. Assert user remains logged out

---

#### `test_login_nonexistent_user(login_page)`

**Flow:**
1. Login with non-existent username
2. Capture alert text
3. Assert error message is "User does not exist."
4. Assert user remains logged out

---

#### `test_login_empty_fields(login_page)`

**Flow:**
1. Submit login form with empty fields
2. Capture validation message
3. Assert message is "Please fill out Username and Password."

---

### Security Tests - SQL Injection

#### `test_login_sql_injection_username(login_page, payload)`

**Parametrized test** - runs once for each payload:

```python
@pytest.mark.parametrize("payload", [
    "' OR '1'='1",
    "' OR 1=1--",
    # ... 7 different SQL injection payloads
])
```

**Flow:**
1. Attempt login with SQL injection payload in username
2. Wait for alert (if any)
3. **Critical check:** If user is logged in → FAIL with security warning
4. Assert user remains logged out

**Security logging:**
If payload succeeds, logs critical warning:
```
🚨🚨🚨 VULNERABILIDAD DETECTADA 🚨🚨🚨
El login fue EXITOSO con el payload de SQLi: [payload]
```

---

#### `test_login_sql_injection_password(login_page, payload)`

Same logic as username injection, but tests password field.

---

### Security Tests - XSS

#### `test_login_xss_username(login_page, payload)`

**Parametrized test** with XSS payloads:

```python
@pytest.mark.parametrize("payload", [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "<svg/onload=alert('XSS')>",
])
```

**Flow:**
1. Enter XSS payload in username
2. Wait for alert
3. **If alert contains 'XSS'** → XSS vulnerability detected
4. Assert user not logged in

---

### Input Validation Tests

#### `test_login_special_characters_username(login_page, test_input)`

Tests special characters: `@#$%^&*()`, `<>?:`, `|\`, etc.

**Expected:** System handles gracefully without crashing.

---

#### `test_login_unicode_characters(login_page, test_input)`

Tests international characters and emojis.

**Expected:** Proper encoding handling, appropriate rejection.

---

### Boundary Tests

#### `test_login_very_long_username(login_page)`
#### `test_login_very_long_password(login_page)`

Tests 1000-character inputs.

**Expected:** No buffer overflow, system handles safely.

---

#### `test_login_whitespace_username(login_page, test_input)`

Tests leading/trailing spaces, spaces-only input.

---

#### `test_login_case_sensitivity_username(login_page, username_variant)`

Tests if login is case-sensitive (UPPER, lower, Title).

**Expected:** Login rejected with different case.

---

### Advanced Security Tests

#### `test_login_null_bytes(login_page, test_input)`

Tests null byte injection: `user\x00admin`

**Expected:** No string truncation exploits.

---

#### `test_login_path_traversal(login_page, test_input)`

Tests path traversal: `../../../etc/passwd`

**Expected:** No file system access.

---

### Known Vulnerability Tests (xfail)

#### `test_login_weak_password_vulnerability(browser)`

**Marked as xfail:**
```python
@pytest.mark.xfail(reason="Bug #11: System accepts weak passwords")
```

**Test:**
1. Register new user with password "123"
2. Check if system rejects it

**Current behavior:** Accepts weak password (test fails as expected)

**When fixed:** Test will pass, remove `@pytest.mark.xfail`

---

#### `test_username_enumeration_vulnerability(login_page)`

**Marked as xfail (Bug #10)**

**Test:**
1. Login with existing user + wrong password
2. Note error: "Wrong password."
3. Login with non-existent user
4. Note error: "User does not exist."
5. Assert messages should be identical

**Current behavior:** Different messages (test fails as expected)

---

#### `test_login_brute_force_lockout(browser)`

**Marked as xfail (Bug #12)**

**Test:**
1. Attempt 7 consecutive failed logins
2. Check for account lockout or rate limiting

**Current behavior:** No protection (test fails as expected)

---

### UI Interaction Tests

#### `test_login_modal_close_button(login_page)`

**Test:**
1. Verify modal is open
2. Click close button
3. Wait for modal to disappear
4. Assert modal is closed

---

#### `test_login_modal_interaction_signup_login(browser)`

**Test:**
1. Open Sign Up modal
2. Verify visibility
3. Close it
4. Open Login modal
5. Verify visibility

**Expected:** Modals don't interfere with each other.

---

<a name="locators"></a>
## 10. How to Obtain Locators

### Using Browser DevTools

**Step 1:** Navigate to https://www.demoblaze.com/

**Step 2:** Open DevTools
- Press F12, or
- Right-click → Inspect

**Step 3:** Use element picker
- Click cursor icon in DevTools
- Or press Ctrl+Shift+C

**Step 4:** Click target element

**Step 5:** Read HTML and extract locator

**Example - Login Button:**
```html
<a id="login2" data-toggle="modal" data-target="#logInModal">Log in</a>
```

Extract: `By.ID, "login2"`

### Locator Strategy Decision Tree

**Has unique ID?** → Use ID (best option)

**Has unique name?** → Use NAME

**Has distinctive class?** → Use CSS Selector

**Has unique text?** → Use XPath with text

**Example XPath:**
```python
By.XPATH, "//button[text()='Log in']"
```

Breakdown:
- `//button` - Any button element
- `[text()='Log in']` - With text "Log in"

---

<a name="execution"></a>
## 11. Execution Guide

### Prerequisites

```bash
# Verify Python 3.8+
python --version

# Install dependencies from requirements.txt
pip install -r requirements.txt
```

**requirements.txt includes:**
- selenium
- pytest
- pytest-html
- webdriver-manager

### Running Tests

**Run all login tests (Chrome default):**
```bash
pytest tests/login/
```

**Run with specific browser:**
```bash
pytest tests/login/ --browser=chrome
pytest tests/login/ --browser=firefox
pytest tests/login/ --browser=edge
```

**Run specific test:**
```bash
pytest tests/login/test_dem_login.py::test_login_valid_credentials
```

**Run with verbose output:**
```bash
pytest tests/login/ -v
```

**Run with print statements (debugging):**
```bash
pytest tests/login/ -s
```

**Run only xfail tests:**
```bash
pytest tests/login/ -m xfail
```

**Run excluding xfail tests:**
```bash
pytest tests/login/ -m "not xfail"
```

**CI/CD Command (with fail-fast):**
```bash
pytest tests/login/ --browser=chrome --maxfail=1 -v
```
Note: HTML report is generated automatically by `conftest.py`

### HTML Reports

Reports are **automatically generated** by `conftest.py` in the root directory.

**Report location:**
```
test_results/login/report_[browser]_[timestamp].html
```

**Example:**
```
test_results/login/report_chrome_2025-11-07_14-30-45.html
test_results/login/report_firefox_2025-11-07_14-35-20.html
```

**Features:**
- Automatic report generation (no need to specify `--html`)
- Reports grouped by test folder (`login`, `purchase`, etc.)
- Self-contained HTML (includes CSS/JS)
- Timestamped filenames with browser name
- `test_results/` folder created automatically

### Cross-Browser Testing

**Test on all browsers:**
```bash
pytest tests/login/ --browser=chrome
pytest tests/login/ --browser=firefox
pytest tests/login/ --browser=edge
```

**Note:** The `conftest.py` in the project root handles:
- Browser selection via `--browser` parameter
- Automatic HTML report generation
- Report organization by test folder
- Timestamp and browser name in filename

---

<a name="results"></a>
## 12. Expected Results

### Test Execution Summary

| Test Category | Tests | Pass | Xfail | Total |
|--------------|-------|------|-------|-------|
| Basic Login | 6 | 6 | 0 | 6 |
| SQL Injection | 10 | 10 | 0 | 10 |
| XSS | 4 | 4 | 0 | 4 |
| Input Validation | 2 | 2 | 0 | 2 |
| Boundary | 4 | 4 | 0 | 4 |
| Advanced Security | 2 | 2 | 0 | 2 |
| Known Vulnerabilities | 3 | 0 | 3 | 3 |
| UI Interaction | 2 | 2 | 0 | 2 |
| **TOTAL** | **33** | **30** | **3** | **33** |

### Success Criteria

Test suite PASSED if:
- 30 stable tests pass
- 3 xfail tests fail as expected (Bugs #10, #11, #12)
- No unexpected failures
- Execution time under 5 minutes

### Performance Benchmarks

**Expected execution times:**
- Basic tests: 5-8 seconds each
- Parametrized tests: 3-5 seconds per iteration
- Security tests: 6-10 seconds each
- Total suite: ~4 minutes (varies by browser)

---

<a name="troubleshooting"></a>
## 13. Troubleshooting

### Issue: ChromeDriver version mismatch

**Error:**
```
SessionNotCreatedException: This version of ChromeDriver only supports Chrome version XX
```

**Solution:**
```bash
pip uninstall webdriver-manager
pip install webdriver-manager
rm -rf ~/.wdm  # Clear cache
```

---

### Issue: Element not found

**Error:**
```
NoSuchElementException: Unable to locate element
```

**Solutions:**
1. Add explicit wait
2. Verify locator still valid (inspect element)
3. Check if element inside iframe

---

### Issue: Test hangs

**Causes:**
- Alert not handled
- Infinite wait
- Modal not closed

**Solution:**
- Add timeout to operations
- Check logging output for clues

---

### Issue: Tests pass locally but fail in CI

**Solutions:**
1. Increase timeouts for CI
2. Use headless mode
3. Check browser/driver versions match

---

<a name="practices"></a>
## 14. Best Practices Applied

### Code Quality

**DRY (Don't Repeat Yourself)**
- Helper functions for repeated actions
- Fixtures for setup/teardown
- Centralized configuration

**Single Responsibility Principle**
- Each function does one thing
- Clear, focused purpose

**Explicit is Better Than Implicit**
- Named constants instead of magic strings
- Descriptive variable names
- Clear function names

### Testing Best Practices

**Test Isolation**
- Each test gets fresh browser
- No shared state
- Tests run in any order

**AAA Pattern (Arrange-Act-Assert)**
```python
def test_example():
    # Arrange (setup)
    username = "test"
    
    # Act (perform action)
    perform_login(browser, username, password)
    
    # Assert (verify)
    assert check_user_is_logged_in(browser)
```

**Parametrization**
- Test multiple inputs efficiently
- Single test function, multiple scenarios
- Clear test data separation

**Expected Failures (xfail)**
- Documents known bugs
- Regression testing ready
- Clear status distinction

### Selenium Best Practices

**Explicit Waits**
- Use `WebDriverWait` instead of `time.sleep()`
- Faster and more reliable

**WebDriver Manager**
- Auto-manages driver versions
- No manual downloads
- Cross-platform compatible

**Locator Strategy Hierarchy**
1. ID (best)
2. Name
3. CSS Selector
4. XPath (when necessary)

**Cross-Browser Testing**
- Test on multiple browsers
- Catch browser-specific issues early

---

## 15. Maintenance Guide

### When to Update Tests

**Site Redesign:**
- Update locators
- Re-verify element IDs
- Test all scenarios

**Bug Fixes:**
- Remove `@pytest.mark.xfail`
- Update expected behavior
- Re-run regression tests

**New Features:**
- Add new test cases
- Update documentation
- Maintain structure

### Adding New Tests

1. Add test case to documentation
2. Write test function following AAA pattern
3. Update this README
4. Run full test suite to verify

---

## 16. Version History

| Version | Date | Changes |
|---------|------|---------|
| 3.1 | Nov 2025 | Cross-browser support, enhanced logging, improved helpers |
| 3.0 | Nov 2025 | Security tests (SQL injection, XSS), parametrization |
| 1.0 | Nov 2025 | Initial release with basic tests |

---

## 17. Related Documents

- [Test Plan](../../docs/test-plan.md)
- [Test Summary Report](../../docs/Test_Summary_Report.md)
- [User Flows](../../docs/users-flow.md)
- [DemoBlaze Test Cases](../../docs/DemoBlaze_Test_Cases.xlsx)
- Bug #10: Username Enumeration (documented in Test Summary Report)
- Bug #11: Weak Passwords (documented in Test Summary Report)
- Bug #12: No Rate Limiting (documented in Test Summary Report)

---

**End of Documentation**
