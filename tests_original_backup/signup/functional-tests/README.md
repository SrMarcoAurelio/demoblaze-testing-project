# Test Suite: Signup & Registration Functionality

**Module:** `test_signup_functionality.py`
**Author:** QA Testing Team
**Application Under Test:** DemoBlaze (https://www.demoblaze.com/)
**Current Version:** 1.0

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Test Cases Summary](#test-cases-summary)
4. [Code Architecture](#architecture)
5. [Configuration & Locators](#configuration)
6. [Fixtures](#fixtures)
7. [Helper Functions](#helpers)
8. [Test Cases Details](#test-details)
9. [Execution Guide](#execution)
10. [Expected Results](#results)
11. [Troubleshooting](#troubleshooting)
12. [Related Bugs](#bugs)
13. [Best Practices](#practices)
14. [Version History](#version-history)

---

<a name="overview"></a>
## 1. Overview

### Purpose

This test suite validates the **Signup & Registration** functionality of DemoBlaze following the **DISCOVER philosophy** (EXECUTE + OBSERVE + DECIDE). Tests never assume application behavior but instead discover actual functionality by executing actions, observing responses, and making decisions based on objective industry standards.

### Philosophy: DISCOVER Methodology

**Core Principle:** Tests must DISCOVER what the application does, not assume or excuse missing features.

**The Formula:**
```
EXECUTE → OBSERVE → DECIDE
```

- **EXECUTE:** Perform the action (signup with various inputs)
- **OBSERVE:** Capture actual application response (alerts, errors, success messages)
- **DECIDE:** Compare against industry standards (OWASP, NIST, ISO, WCAG)

**Critical Rule:** When a security feature is missing (e.g., no CAPTCHA), the test reports it as a **security violation** with appropriate CVSS scoring, not as "out of scope."

### Standards Validated

| Standard | Version | Focus Area | Compliance |
|----------|---------|------------|------------|
| **OWASP ASVS** | v5.0 | Chapter 2: Authentication Verification | SQL Injection, XSS, Rate Limiting, CAPTCHA |
| **NIST SP 800-63B** | Latest | Section 5.1.1: Password Guidelines | Password complexity, length, common passwords |
| **ISO 27001** | 2013 | A.9.4: Access Control | User registration security |
| **WCAG** | 2.1 | SC 2.1.1, 1.3.1, 3.3.1 | Keyboard navigation, labels, error identification |
| **ISO 25010** | 2011 | Software Quality | Functional suitability, usability, portability |

### Scope

**In Scope:**
- Valid signup with unique credentials
- Duplicate username detection
- Empty field validation
- Username/password business rules (length, special chars, whitespace)
- Security testing (SQL injection, XSS prevention)
- Password complexity enforcement
- Rate limiting detection
- CAPTCHA protection detection
- Email verification requirements
- Accessibility compliance (keyboard navigation, labels)
- Username enumeration prevention

**Expected Test Failures:**

The following tests **discover security violations** by executing standard security checks. When these tests fail, they are reporting objective findings against industry standards, not test code defects:

| Test ID | Test Name | Expected Result | CVSS Score | Impact |
|---------|-----------|-----------------|------------|--------|
| BR-013 | Password Complexity Enforcement | FAIL | 6.5 (MEDIUM) | Weak passwords accepted |
| BR-014 | Signup Rate Limiting | FAIL | 7.5 (HIGH) | Unlimited signup attempts |
| BR-015 | CAPTCHA Protection | FAIL | 6.1 (MEDIUM) | No bot prevention |
| BR-016 | Email Verification Requirement | FAIL | 5.3 (MEDIUM) | Unverified accounts active |

These failures represent objective discoveries of missing security controls that violate industry standards. The test failures are correct behavior - they indicate real security gaps that require remediation.

---

<a name="quick-start"></a>
## 2. Quick Start

### Prerequisites

```bash
# Install required packages
pip install pytest selenium pytest-html

# Verify ChromeDriver is installed and in PATH
chromedriver --version
```

### Run All Tests

```bash
# Run complete suite with verbose output
pytest test_signup_functionality.py -v

# Generate HTML report
pytest test_signup_functionality.py --html=report_signup.html --self-contained-html
```

### Run Specific Test Categories

```bash
# Functional tests only
pytest test_signup_functionality.py -k "FUNC" -v

# Business rules only
pytest test_signup_functionality.py -k "BR" -v

# Security tests only
pytest test_signup_functionality.py -k "security" -v

# Critical security tests
pytest test_signup_functionality.py -m "critical" -v

# Accessibility tests
pytest test_signup_functionality.py -m "accessibility" -v
```

### Expected Execution Time

- Full suite: ~3-5 minutes
- Functional tests only: ~1 minute
- Business rules only: ~2-3 minutes
- Security tests: ~1-2 minutes

---

<a name="test-cases-summary"></a>
## 3. Test Cases Summary

### Test Inventory

**Total Tests:** 32+ test runs (27 test functions, with parametrization)

#### Functional Tests (6 tests)

| ID | Test Name | Priority | Description |
|----|-----------|----------|-------------|
| FUNC-001 | Valid Signup with Unique Credentials | CRITICAL | Happy path: successful registration |
| FUNC-002 | Duplicate Username Rejected | CRITICAL | System prevents duplicate usernames |
| FUNC-003 | Empty Credentials Rejected | HIGH | Both fields empty validation |
| FUNC-004 | Empty Username Only | HIGH | Username field validation |
| FUNC-005 | Empty Password Only | HIGH | Password field validation |
| FUNC-006 | Signup Modal Close Functionality | MEDIUM | Modal can be closed properly |

#### Business Rules Tests (21+ tests with parametrization)

**Input Validation (9 tests):**

| ID | Test Name | Priority | Standard |
|----|-----------|----------|----------|
| BR-001 | Username Maximum Length | MEDIUM | ISO 25010 |
| BR-002 | Password Maximum Length | MEDIUM | NIST 800-63B |
| BR-003 | Username Whitespace Handling | MEDIUM | ISO 25010 |
| BR-004 | Password Whitespace Significance | HIGH | NIST 800-63B |
| BR-005 | Special Characters in Username | MEDIUM | ISO 25010 |
| BR-006 | Numeric-Only Username | LOW | ISO 25010 |
| BR-007 | Unicode Characters | MEDIUM | ISO 25010 |
| BR-008 | Username Whitespace Normalization | MEDIUM | ISO 25010 |
| BR-009 | Username Case Sensitivity | MEDIUM | ISO 25010 |
| BR-010 | Identical Username and Password | HIGH | NIST 800-63B |

**Security Tests (6 parametrized + 6 tests = 12 runs):**

| ID | Test Name | Priority | Standard | Payloads |
|----|-----------|----------|----------|----------|
| BR-011 | SQL Injection Prevention | CRITICAL | OWASP ASVS 1.2.5 | 4 payloads |
| BR-012 | XSS Prevention | CRITICAL | OWASP ASVS 1.4.1 | 4 payloads |
| BR-013 | Password Complexity Enforcement | CRITICAL | NIST 800-63B | 3 weak passwords |
| BR-014 | Signup Rate Limiting | CRITICAL | OWASP ASVS 2.2.1 | Single test |
| BR-015 | CAPTCHA Protection | HIGH | OWASP ASVS 2.2.3 | Single test |
| BR-016 | Email Verification Requirement | HIGH | OWASP ASVS 2.1.12 | Single test |
| BR-019 | Username Enumeration Prevention | MEDIUM | OWASP ASVS 2.2.2 | Single test |

**Accessibility Tests (2 tests):**

| ID | Test Name | Priority | Standard |
|----|-----------|----------|----------|
| BR-017 | Keyboard Navigation Support | HIGH | WCAG 2.1 SC 2.1.1 |
| BR-018 | Form Labels Accessibility | HIGH | WCAG 2.1 SC 1.3.1 |

---

<a name="architecture"></a>
## 4. Code Architecture

### File Structure

```
test_signup_functionality.py
├── CONFIGURATION (Lines 40-44)
│   ├── BASE_URL
│   ├── TIMEOUT constants
│
├── LOCATORS (Lines 49-63)
│   ├── Signup form elements
│   ├── Login form elements (for verification)
│   └── Session indicators
│
├── FIXTURES (Lines 68-73)
│   └── browser (Chrome WebDriver)
│
├── HELPER FUNCTIONS (Lines 78-164)
│   ├── generate_unique_username()
│   ├── wait_for_alert_and_get_text()
│   ├── perform_signup()
│   ├── perform_login()
│   ├── is_user_logged_in()
│   └── perform_logout()
│
├── FUNCTIONAL TESTS (Lines 169-390)
│   └── 6 test functions
│
└── BUSINESS RULES TESTS (Lines 395-999)
    └── 21 test functions (15 + 6 parametrized)
```

### Design Patterns

**1. Page Object Pattern Elements:**
- Centralized locators
- Reusable interaction methods
- Separation of test logic from element location

**2. Helper Function Pattern:**
- `perform_signup()`: Encapsulates signup workflow
- `wait_for_alert_and_get_text()`: Handles alert interactions
- `generate_unique_username()`: Creates unique test data

**3. Test Isolation:**
- Each test generates unique username
- Browser fixture ensures clean state
- No test dependencies

**4. Parametrized Testing:**
- SQL injection: 4 payload variants
- XSS attacks: 4 payload variants
- Weak passwords: 3 common weak passwords

---

<a name="configuration"></a>
## 5. Configuration & Locators

### Configuration Constants

```python
BASE_URL = "https://www.demoblaze.com/"
TIMEOUT = 10           # Standard wait time
TIMEOUT_MEDIUM = 15    # Extended wait for complex operations
TIMEOUT_LONG = 20      # Maximum wait time
```

**Modifying Configuration:**

To test another application, update these values:

```python
BASE_URL = "https://your-application.com/"
TIMEOUT = 15  # Adjust based on application response time
```

### Locators

**Signup Form:**

```python
SIGNUP_BUTTON_NAV = (By.ID, "signin2")
SIGNUP_MODAL = (By.ID, "signInModal")
SIGNUP_USERNAME_FIELD = (By.ID, "sign-username")
SIGNUP_PASSWORD_FIELD = (By.ID, "sign-password")
SIGNUP_SUBMIT_BUTTON = (By.XPATH, "//button[contains(text(),'Sign up')]")
SIGNUP_CLOSE_BUTTON = (By.XPATH, "//div[@id='signInModal']//button[@class='close']")
```

**Login Form (for verification):**

```python
LOGIN_BUTTON_NAV = (By.ID, "login2")
LOGIN_MODAL = (By.ID, "logInModal")
LOGIN_USERNAME_FIELD = (By.ID, "loginusername")
LOGIN_PASSWORD_FIELD = (By.ID, "loginpassword")
LOGIN_SUBMIT_BUTTON = (By.XPATH, "//button[contains(text(),'Log in')]")
```

**Session Indicators:**

```python
LOGOUT_BUTTON = (By.ID, "logout2")
WELCOME_USER_LINK = (By.ID, "nameofuser")
```

### Unused Locators for Future Expansion

The following locators are not used in this test suite but are available for testing other applications with additional features:

```python
# Email verification (if application implements it)
SIGNUP_EMAIL_FIELD = (By.ID, "sign-email")
EMAIL_VERIFICATION_MESSAGE = (By.CLASS_NAME, "verification-notice")

# Password confirmation field
SIGNUP_PASSWORD_CONFIRM = (By.ID, "sign-password-confirm")

# CAPTCHA elements
CAPTCHA_IFRAME = (By.XPATH, "//iframe[contains(@src, 'recaptcha')]")
CAPTCHA_CHECKBOX = (By.CLASS_NAME, "recaptcha-checkbox")

# Terms and conditions
TERMS_CHECKBOX = (By.ID, "accept-terms")
TERMS_LINK = (By.LINK_TEXT, "Terms and Conditions")

# Password strength indicator
PASSWORD_STRENGTH = (By.CLASS_NAME, "password-strength")

# Error messages
ERROR_MESSAGE_USERNAME = (By.ID, "username-error")
ERROR_MESSAGE_PASSWORD = (By.ID, "password-error")
```

---

<a name="fixtures"></a>
## 6. Fixtures

### Browser Fixture

```python
@pytest.fixture
def browser():
    driver = webdriver.Chrome()
    driver.maximize_window()
    yield driver
    driver.quit()
```

**Behavior:**
- Creates new Chrome browser instance
- Maximizes window for consistent viewport
- Automatically closes after test completes
- Ensures test isolation (no shared state)

**Customization Options:**

```python
# Headless mode for CI/CD
@pytest.fixture
def browser():
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    driver = webdriver.Chrome(options=options)
    yield driver
    driver.quit()

# Use Firefox instead
@pytest.fixture
def browser():
    driver = webdriver.Firefox()
    driver.maximize_window()
    yield driver
    driver.quit()

# Add implicit wait
@pytest.fixture
def browser():
    driver = webdriver.Chrome()
    driver.maximize_window()
    driver.implicitly_wait(5)
    yield driver
    driver.quit()
```

---

<a name="helpers"></a>
## 7. Helper Functions

### generate_unique_username()

Generates unique username for test data isolation.

```python
def generate_unique_username():
    timestamp = int(time.time())
    random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
    return f"testuser_{timestamp}_{random_suffix}"
```

**Returns:** String like `"testuser_1699876543_a3f9"`

**Usage:**
```python
unique_user = generate_unique_username()
perform_signup(browser, unique_user, "TestPass123!")
```

### wait_for_alert_and_get_text()

Waits for JavaScript alert and captures text before accepting.

```python
def wait_for_alert_and_get_text(browser, timeout=5):
    try:
        WebDriverWait(browser, timeout).until(EC.alert_is_present())
        alert = browser.switch_to.alert
        alert_text = alert.text
        logging.info(f"Alert detected: {alert_text}")
        alert.accept()
        return alert_text
    except TimeoutException:
        logging.warning("No alert appeared")
        return None
```

**Parameters:**
- `browser`: WebDriver instance
- `timeout`: Wait time in seconds (default: 5)

**Returns:** Alert text string or None

**Usage:**
```python
perform_signup(browser, "testuser", "password")
time.sleep(1)
alert_text = wait_for_alert_and_get_text(browser)
if alert_text and "success" in alert_text.lower():
    # Signup successful
```

### perform_signup()

Executes complete signup workflow.

```python
def perform_signup(browser, username, password, timeout=TIMEOUT):
    # Opens modal, fills form, submits
    # Returns True if successful, False otherwise
```

**Parameters:**
- `browser`: WebDriver instance
- `username`: Username to enter
- `password`: Password to enter
- `timeout`: Wait time for elements (default: TIMEOUT)

**Returns:** Boolean - True if form submission successful

**Workflow:**
1. Click signup button in navigation
2. Wait for modal to appear
3. Enter username
4. Enter password
5. Click submit button

### perform_login()

Executes login workflow for account verification.

```python
def perform_login(browser, username, password, timeout=TIMEOUT):
    # Opens login modal, fills credentials, submits
    # Returns True if successful, False otherwise
```

**Usage:** Verify newly created accounts can log in

### is_user_logged_in()

Checks if user is currently logged in.

```python
def is_user_logged_in(browser, timeout=TIMEOUT):
    try:
        WebDriverWait(browser, timeout).until(
            EC.visibility_of_element_located(WELCOME_USER_LINK)
        )
        return True
    except (TimeoutException, NoSuchElementException):
        return False
```

**Returns:** Boolean - True if welcome message visible

### perform_logout()

Logs out current user.

```python
def perform_logout(browser, timeout=TIMEOUT):
    # Clicks logout button
    # Returns True if successful
```

---

<a name="test-details"></a>
## 8. Test Cases Details

### Functional Tests

#### TC-SIGNUP-FUNC-001: Valid Signup with Unique Credentials

**Priority:** CRITICAL
**Category:** Functional
**Purpose:** Verify happy path signup flow

**Steps:**
1. Navigate to BASE_URL
2. Generate unique username
3. Perform signup with valid credentials
4. Verify success alert appears
5. Attempt login with new credentials
6. Verify login successful
7. Logout

**Expected Result:**
- Signup succeeds
- Success alert contains "success" or "signed up"
- Can log in with new account
- Welcome message displays username

**Failure Scenarios:**
- Alert text doesn't contain success indicator
- Cannot log in after successful signup
- No alert appears

#### TC-SIGNUP-FUNC-002: Duplicate Username Rejected

**Priority:** CRITICAL
**Category:** Functional
**Purpose:** Verify duplicate username prevention

**Steps:**
1. Create account with unique username
2. Verify success
3. Attempt second signup with same username
4. Verify rejection

**Expected Result:**
- First signup succeeds
- Second signup fails
- Alert contains "exist", "already", or "taken"

**Security Implication:** Prevents account hijacking

#### TC-SIGNUP-FUNC-003 to FUNC-006

See inline test documentation for remaining functional tests.

### Business Rules Tests

#### TC-SIGNUP-BR-011: SQL Injection Prevention

**Priority:** CRITICAL
**Category:** Security
**Standard:** OWASP ASVS v5.0 Section 1.2.5
**CVSS Score:** 9.8 (CRITICAL)

**Payloads Tested:**
```python
"' OR '1'='1"
"admin'--"
"' OR '1'='1' --"
"') OR ('1'='1"
```

**Expected Behavior:**
- System rejects malicious payloads
- No account created
- Alert indicates invalid username or error

**Failure Condition:**
- Success alert appears
- Account created with SQL payload as username

**Impact if Failed:**
- Complete database compromise
- Unauthorized access to all accounts
- Data exfiltration possible

#### TC-SIGNUP-BR-012: XSS Prevention

**Priority:** CRITICAL
**Category:** Security
**Standard:** OWASP ASVS v5.0 Section 1.4.1
**CVSS Score:** 7.1 (HIGH)

**Payloads Tested:**
```python
"<script>alert('XSS')</script>"
"javascript:alert('XSS')"
"<img src=x onerror=alert('XSS')>"
"<svg/onload=alert('XSS')>"
```

**Test Logic:**
1. Attempt signup with XSS payload
2. If accepted, check page source for unescaped payload
3. Report critical finding if payload reflected

**Impact if Failed:**
- Session hijacking
- Cookie theft
- Phishing attacks

#### TC-SIGNUP-BR-013: Password Complexity Enforcement

**Priority:** CRITICAL
**Category:** Security
**Standard:** NIST SP 800-63B Section 5.1.1.2
**CVSS Score:** 6.5 (MEDIUM)

**Weak Passwords Tested:**
```python
"123456"
"password"
"12345678"
```

**Expected Behavior (Production):**
- System rejects weak passwords
- Error message explains requirements
- Minimum 8 characters enforced
- Check against common password lists

**Discovered Result:**
- Test fails when weak passwords are accepted
- Indicates missing password complexity enforcement
- Represents security violation per NIST SP 800-63B

#### TC-SIGNUP-BR-014: Signup Rate Limiting

**Priority:** CRITICAL
**Category:** Security
**Standard:** OWASP ASVS v5.0 Section 2.2.1
**CVSS Score:** 7.5 (HIGH)

**Test Method:**
1. Attempt 5 rapid signups
2. Check for rate limit alert
3. Report if no limits detected

**Expected Behavior (Production):**
- After 3-5 attempts, rate limiting triggers
- Alert: "Too many attempts" or "Please wait"

**Discovered Result:**
- Test fails when unlimited signup attempts are possible
- Indicates missing rate limiting controls
- Represents security violation per OWASP ASVS 2.2.1

#### TC-SIGNUP-BR-015: CAPTCHA Protection

**Priority:** HIGH
**Category:** Security
**Standard:** OWASP ASVS v5.0 Section 2.2.3
**CVSS Score:** 6.1 (MEDIUM)

**Test Method:**
1. Open signup modal
2. Search for CAPTCHA elements:
   - reCAPTCHA iframe
   - CAPTCHA div
   - CAPTCHA images

**Expected Behavior (Production):**
- CAPTCHA present on form
- Must solve before submission

**Discovered Result:**
- Test fails when no CAPTCHA elements are found
- Indicates missing bot protection controls
- Represents security violation per OWASP ASVS 2.2.3

#### TC-SIGNUP-BR-016: Email Verification Requirement

**Priority:** HIGH
**Category:** Security
**Standard:** OWASP ASVS v5.0 Section 2.1.12
**CVSS Score:** 5.3 (MEDIUM)

**Test Method:**
1. Create account
2. Immediately attempt login
3. Check if account is active without verification

**Expected Behavior (Production):**
- Account created but inactive
- Email verification required
- Login blocked until verification

**Discovered Result:**
- Test fails when accounts are active without email verification
- Indicates missing verification requirement
- Represents security violation per OWASP ASVS 2.1.12

### Accessibility Tests

#### TC-SIGNUP-BR-017: Keyboard Navigation Support

**Standard:** WCAG 2.1 Success Criterion 2.1.1

**Test Method:**
1. Open signup modal
2. Use TAB to navigate fields
3. Use ENTER to submit
4. Verify form submittable without mouse

**Expected Result:**
- All fields reachable via TAB
- Form submittable via ENTER key
- Modal closable via ESC key

#### TC-SIGNUP-BR-018: Form Labels Accessibility

**Standard:** WCAG 2.1 Success Criterion 1.3.1

**Test Method:**
1. Open signup modal
2. Check for aria-label, placeholder, or title attributes
3. Verify screen reader compatibility

**Expected Result:**
- All fields have accessible labels
- Screen readers can identify field purpose

---

<a name="execution"></a>
## 9. Execution Guide

### Running Tests

**Complete Suite:**
```bash
pytest test_signup_functionality.py -v
```

**With HTML Report:**
```bash
pytest test_signup_functionality.py --html=report.html --self-contained-html
```

**Specific Categories:**
```bash
# Functional only
pytest test_signup_functionality.py -k "FUNC" -v

# Business rules only
pytest test_signup_functionality.py -k "BR" -v

# Security tests
pytest test_signup_functionality.py -k "security" -v

# Critical tests
pytest test_signup_functionality.py -m "critical" -v
```

**Specific Test:**
```bash
pytest test_signup_functionality.py::test_valid_signup_with_unique_credentials_FUNC_001 -v
```

### Pytest Markers

```python
@pytest.mark.functional       # Functional tests
@pytest.mark.business_rules    # Business rules tests
@pytest.mark.security          # Security-related tests
@pytest.mark.critical          # High-priority security tests
@pytest.mark.accessibility     # WCAG compliance tests
```

**Use markers:**
```bash
pytest test_signup_functionality.py -m "security" -v
pytest test_signup_functionality.py -m "critical and security" -v
```

### Parallel Execution

```bash
# Install pytest-xdist
pip install pytest-xdist

# Run with 4 workers
pytest test_signup_functionality.py -n 4
```

### Debugging

**Verbose Logging:**
```bash
pytest test_signup_functionality.py -v --log-cli-level=DEBUG
```

**Stop on First Failure:**
```bash
pytest test_signup_functionality.py -x
```

**Run Failed Tests Only:**
```bash
pytest test_signup_functionality.py --lf
```

---

<a name="results"></a>
## 10. Expected Results

### Pass/Fail Summary

**Expected to PASS:** ~20-22 tests

- All functional tests (6)
- Input validation tests (10)
- Parametrized SQL/XSS tests (8)
- Accessibility tests (2)

**Expected to FAIL:** 4-6 tests

These tests discover missing security controls:

| Test | Reason for Failure |
|------|-------------------|
| BR-013 (x3) | Weak passwords accepted |
| BR-014 | No rate limiting |
| BR-015 | No CAPTCHA |
| BR-016 | No email verification |

**Important:** These failures are **expected** and represent discoveries of missing security features, not bugs in test code.

### Understanding Test Failures

When tests fail with logging like:

```
CRITICAL: SECURITY VIOLATION: WEAK PASSWORD ACCEPTED: '123456'
Standard: NIST SP 800-63B Section 5.1.1.2
Severity: MEDIUM
CVSS Score: 6.5
Impact: Users can set easily crackable passwords
Recommendation: Enforce min 8 chars, check common passwords
```

This is the test **successfully discovering** a security gap. The test itself is functioning correctly.

### Sample Test Run Output

```
test_signup_functionality.py::test_valid_signup_with_unique_credentials_FUNC_001 PASSED
test_signup_functionality.py::test_duplicate_username_rejected_FUNC_002 PASSED
test_signup_functionality.py::test_empty_credentials_rejected_FUNC_003 PASSED
test_signup_functionality.py::test_sql_injection_prevention_BR_011[' OR '1'='1] PASSED
test_signup_functionality.py::test_sql_injection_prevention_BR_011[admin'--] PASSED
test_signup_functionality.py::test_password_complexity_enforcement_BR_013[123456] FAILED
test_signup_functionality.py::test_signup_rate_limiting_BR_014 FAILED
test_signup_functionality.py::test_captcha_protection_BR_015 FAILED

====================== 25 passed, 4 failed in 3.45s =======================
```

---

<a name="troubleshooting"></a>
## 11. Troubleshooting

### Common Issues

**Issue 1: ChromeDriver Version Mismatch**

```
Error: SessionNotCreatedException: session not created:
This version of ChromeDriver only supports Chrome version XX
```

**Solution:**
```bash
# Update ChromeDriver to match your Chrome version
# Or use webdriver-manager
pip install webdriver-manager

# Update browser fixture:
from webdriver_manager.chrome import ChromeDriverManager
driver = webdriver.Chrome(ChromeDriverManager().install())
```

**Issue 2: Element Not Found**

```
Error: NoSuchElementException: Unable to locate element: {"method":"id","selector":"signin2"}
```

**Solution:**
- Verify BASE_URL is correct
- Check if application structure changed
- Increase TIMEOUT values
- Use explicit waits instead of time.sleep()

**Issue 3: Signup Fails Intermittently**

**Possible Causes:**
- Network latency
- Application server issues
- Rate limiting from server side
- Browser cache issues

**Solutions:**
```python
# Increase timeouts
TIMEOUT = 15
TIMEOUT_MEDIUM = 20

# Clear cookies between tests
@pytest.fixture
def browser():
    driver = webdriver.Chrome()
    driver.delete_all_cookies()
    yield driver
    driver.quit()

# Add retry logic
from pytest import mark
@mark.flaky(reruns=2, reruns_delay=5)
def test_signup_...
```

**Issue 4: Alert Not Appearing**

**Debugging:**
```python
# Add explicit wait before alert check
time.sleep(2)  # Increase from 1 second

# Log page source for debugging
logging.info(f"Page source: {browser.page_source[:500]}")

# Check for non-alert error messages
try:
    error = browser.find_element(By.CLASS_NAME, "error-message")
    logging.info(f"Error message instead of alert: {error.text}")
except:
    pass
```

**Issue 5: Tests Pass But Should Fail**

If security tests pass when they should fail (e.g., weak password test passes):

**This means:** The application may have implemented the security control

**Action:** Review test logic and verify application behavior has changed

---

<a name="bugs"></a>
## 12. Related Bugs

### Discovered Security Violations

**Issue 1: No Password Complexity Enforcement**

- **Severity:** MEDIUM
- **CVSS Score:** 6.5
- **Impact:** Users can set weak, easily guessable passwords
- **Test:** TC-SIGNUP-BR-013
- **Recommendation:** Implement NIST 800-63B guidelines

**Issue 2: Missing Rate Limiting**

- **Severity:** HIGH
- **CVSS Score:** 7.5
- **Impact:** Automated bot signups possible
- **Test:** TC-SIGNUP-BR-014
- **Recommendation:** Limit signups to 5 per IP per hour

**Issue 3: No CAPTCHA Protection**

- **Severity:** MEDIUM
- **CVSS Score:** 6.1
- **Impact:** Bot registrations not prevented
- **Test:** TC-SIGNUP-BR-015
- **Recommendation:** Implement reCAPTCHA v3

**Issue 4: Missing Email Verification**

- **Severity:** MEDIUM
- **CVSS Score:** 5.3
- **Impact:** Fake accounts can be created
- **Test:** TC-SIGNUP-BR-016
- **Recommendation:** Require email verification before activation

**Issue 5: Possible Username Enumeration**

- **Severity:** MEDIUM
- **CVSS Score:** 5.3
- **Impact:** Attackers can discover valid usernames
- **Test:** TC-SIGNUP-BR-019
- **Recommendation:** Use generic error messages

### Future Test Enhancements

1. **Password Strength Indicator Testing**
   - Verify visual feedback on password strength
   - Test real-time validation messages

2. **Social Registration Testing**
   - OAuth integration tests
   - Google/Facebook signup

3. **Multi-Step Registration**
   - Test wizard-style signup flow
   - Verify data persistence between steps

4. **Account Activation Flow**
   - Email verification link testing
   - Token expiration testing

---

<a name="practices"></a>
## 13. Best Practices

### Test Development

**1. Follow DISCOVER Philosophy**
```python
# BAD - Assumes behavior
def test_signup():
    # Skip test because DemoBlaze doesn't have 2FA
    pytest.skip("2FA not implemented")

# GOOD - Discovers missing feature
def test_2fa_enforcement():
    perform_signup(...)
    # Check for 2FA prompt
    # Report as security violation if missing
    pytest.fail("DISCOVERED: No 2FA enforcement (CVSS 6.5)")
```

**2. Use Descriptive Test Names**
```python
# BAD
def test_1():

# GOOD
def test_password_complexity_enforcement_BR_013():
```

**3. Comprehensive Logging**
```python
logging.info("=" * 80)
logging.info("TC-SIGNUP-BR-001: Testing feature X")
logging.info(f"Input: {test_value}")
logging.info(f"DISCOVERED: {actual_behavior}")
```

**4. Standards-Based Validation**
```python
# Always reference standards
logging.critical("SECURITY VIOLATION: Feature missing")
logging.critical("Standard: OWASP ASVS v5.0 Section X.X.X")
logging.critical("CVSS Score: X.X")
```

### Test Execution

**1. Run Tests in Logical Order**
```bash
# First: Functional (ensure basic features work)
pytest test_signup_functionality.py -k "FUNC" -v

# Then: Business Rules
pytest test_signup_functionality.py -k "BR" -v

# Finally: Security
pytest test_signup_functionality.py -k "security" -v
```

**2. Generate Reports**
```bash
pytest test_signup_functionality.py --html=report.html --self-contained-html
```

**3. Use CI/CD Integration**
```yaml
# Example .github/workflows/test.yml
- name: Run Signup Tests
  run: |
    pytest test_signup_functionality.py -v --junitxml=results.xml
```

### Test Maintenance

**1. Update Locators When UI Changes**
```python
# Keep locators section updated
SIGNUP_BUTTON_NAV = (By.ID, "signin2")  # Update if ID changes
```

**2. Version Control for Standards**
```python
# Document standard versions in comments
# OWASP ASVS v5.0 (2023)
# NIST SP 800-63B (June 2017, updated March 2020)
```

**3. Regular Review**
- Review tests quarterly
- Update to latest standard versions
- Add new test cases for emerging threats

---

<a name="version-history"></a>
## 14. Version History

### Version 1.0 - November 2025 (Current)

**Initial Release:**

**Test Coverage:**
- 6 functional tests
- 21 business rules tests (15 base + 6 parametrized variants)
- Total: 27 functions, 32+ test runs with parametrization

**Key Features:**
- Complete signup workflow validation
- Input validation (length, whitespace, special chars, case sensitivity)
- Security testing (SQL injection, XSS, weak passwords)
- Rate limiting detection
- CAPTCHA detection
- Email verification detection
- Accessibility testing (keyboard navigation, screen reader support)
- DISCOVER philosophy implementation
- Standards-based validation (OWASP, NIST, ISO, WCAG)

**Code Quality:**
- Clean helper functions
- Professional logging with CVSS scoring
- Comprehensive documentation
- Parametrized security tests
- Test isolation via unique usernames

**Documentation:**
- Complete README with 14 sections
- Inline test documentation
- Standards references
- Expected failure documentation
- Troubleshooting guide

**Standards Compliance:**
- OWASP ASVS v5.0
- NIST SP 800-63B
- ISO 27001
- ISO 25010
- WCAG 2.1

---

**End of Documentation**

**Related Documents:**
- [DISCOVER_PHILOSOPHY.md](DISCOVER_PHILOSOPHY.md) - Testing methodology
- [test_signup_security.py](test_signup_security.py) - Security exploitation tests
- [README_test_signup_security.md](README_test_signup_security.md) - Security tests documentation
- [test_login_functionality.py](test_login_functionality.py) - Login functionality tests
- [README_test_login_functionality.md](README_test_login_functionality.md) - Login tests documentation

**For Questions:**
- Review DISCOVER_PHILOSOPHY.md for methodology questions
- Check troubleshooting section for common issues
- Review inline test comments for specific test logic
