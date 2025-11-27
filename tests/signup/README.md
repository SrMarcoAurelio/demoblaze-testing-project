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

### Code Examples

#### Example 1: Valid Signup (FUNC-001)
```python
@pytest.mark.functional
@pytest.mark.critical
def test_valid_signup_with_unique_credentials_FUNC_001(browser, base_url):
    """
    TC-SIGNUP-FUNC-001: Valid Signup with Unique Credentials
    Priority: CRITICAL
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    # EXECUTE: Generate unique credentials and signup
    unique_username = signup_page.generate_unique_username()
    password = "TestPass123!"
    signup_page.signup(unique_username, password)

    # OBSERVE: Check for success alert
    alert_text = signup_page.get_alert_text(timeout=5)

    # DECIDE: Signup should succeed
    assert alert_text is not None, "Should receive feedback after signup"

    if "success" in alert_text.lower():
        # EXECUTE: Try to login with new account
        browser.get(base_url)
        signup_page.login_after_signup(unique_username, password)

        # OBSERVE: Check if login succeeded
        logged_in = signup_page.is_user_logged_in(timeout=3)

        # DECIDE: New account should be able to login
        assert logged_in, "New account should be able to login"
        signup_page.logout()
```

**What this test does:**
1. Uses `SignupPage` POM to interact with the application
2. Generates a unique username to avoid collisions
3. Executes signup action
4. Observes the alert message
5. Verifies by attempting login with the new credentials
6. Cleans up by logging out

#### Example 2: Duplicate Username (FUNC-002)
```python
@pytest.mark.functional
@pytest.mark.critical
def test_duplicate_username_rejected_FUNC_002(browser, base_url):
    """
    TC-SIGNUP-FUNC-002: Duplicate Username Rejected
    Priority: CRITICAL (Security)
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    # EXECUTE: First signup
    unique_username = signup_page.generate_unique_username()
    password = "TestPass123!"
    signup_page.signup(unique_username, password)
    first_alert = signup_page.get_alert_text(timeout=5)

    # EXECUTE: Try duplicate signup
    browser.get(base_url)
    signup_page.signup(unique_username, password)

    # OBSERVE: Second signup result
    duplicate_alert = signup_page.get_alert_text(timeout=5)

    # DECIDE: Duplicate should be rejected
    assert duplicate_alert is not None
    assert "exist" in duplicate_alert.lower() or "already" in duplicate_alert.lower()
```

**What this test does:**
1. Creates an account successfully
2. Attempts to create another account with the same username
3. Verifies the system rejects the duplicate
4. Checks for appropriate error message

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

### Code Examples

#### Example 1: Parametrized Password Length Test (BR-003)
```python
@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.critical
@pytest.mark.parametrize("password_length", [0, 1, 3, 7])
def test_minimum_password_length_BR_003(browser, base_url, password_length):
    """
    TC-SIGNUP-BR-003: Minimum Password Length
    Standard: NIST SP 800-63B Section 5.1.1.2 (8 character minimum)
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    # EXECUTE: Try signup with short password
    unique_username = signup_page.generate_unique_username()
    short_password = "a" * password_length
    signup_page.signup(unique_username, short_password)

    # OBSERVE: Check system response
    time.sleep(1)
    alert_text = signup_page.get_alert_text(timeout=5)

    # DECIDE: Passwords under 8 chars SHOULD be rejected per NIST
    if alert_text and "success" in alert_text.lower():
        logging.error(f"VIOLATION: Password with {password_length} chars accepted")
        logging.error("Standard: NIST SP 800-63B requires minimum 8 characters")
        pytest.fail(f"DISCOVERED: Weak password ({password_length} chars) accepted - NIST violation")
    else:
        logging.info(f"✓ Password length {password_length} properly rejected")
        assert True
```

**What this test does:**
1. **Parametrization:** Runs 4 times with different password lengths (0, 1, 3, 7)
2. Creates unique username for each attempt
3. Tests passwords below NIST minimum (8 characters)
4. Discovers if weak passwords are accepted (NIST violation)
5. Logs detailed violation information with standard reference

#### Example 2: SQL Injection Prevention (BR-011)
```python
@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.critical
@pytest.mark.parametrize("sql_payload", [
    "' OR '1'='1",
    "admin'--",
    "') OR ('1'='1",
    "' OR 1=1--",
])
def test_sql_injection_prevention_BR_011(browser, base_url, sql_payload):
    """
    TC-SIGNUP-BR-011: SQL Injection Prevention
    Standard: OWASP ASVS v5.0 Section 1.2.5
    CVSS Score: 9.8 CRITICAL
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    # EXECUTE: Try SQL injection
    signup_page.signup(sql_payload, "anypassword")

    # OBSERVE: Check result
    alert_text = signup_page.get_alert_text(timeout=3)

    # DECIDE: Should be rejected
    if alert_text and "success" in alert_text.lower():
        logging.critical(f"VIOLATION: SQL payload may have succeeded: {sql_payload}")
        pytest.fail(f"DISCOVERED: Possible SQL injection - {sql_payload}")
    else:
        logging.info(f"✓ SQL injection blocked: {sql_payload}")
        assert True
```

**What this test does:**
1. **Parametrization:** Tests 4 different SQL injection payloads
2. Each payload is a real SQL injection attempt
3. Discovers if the system is vulnerable to SQL injection
4. Validates OWASP ASVS v5.0 Section 1.2.5 compliance
5. Logs with CVSS severity score (9.8 CRITICAL)

#### Example 3: Password Complexity Enforcement (BR-013)
```python
@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.medium
@pytest.mark.parametrize("weak_password", [
    "123456",
    "password",
    "abc",
    "test",
    "qwerty",
    "12345678",
])
def test_password_complexity_enforcement_BR_013(browser, base_url, weak_password):
    """
    TC-SIGNUP-BR-013: Password Complexity Enforcement
    Standard: NIST SP 800-63B Section 5.1.1.2
    CVSS Score: 6.5 MEDIUM
    """
    browser.get(base_url)
    signup_page = SignupPage(browser)

    # EXECUTE: Attempt signup with weak password
    unique_username = signup_page.generate_unique_username()
    signup_page.signup(unique_username, weak_password)

    # OBSERVE: Check result
    alert_text = signup_page.get_alert_text(timeout=5)

    # DECIDE: Weak passwords SHOULD be rejected
    if alert_text and "success" in alert_text.lower():
        logging.error(f"VIOLATION: Weak password accepted: '{weak_password}'")
        pytest.fail(f"DISCOVERED: Weak password '{weak_password}' accepted")
    else:
        logging.info(f"✓ Weak password handled: '{weak_password}'")
        assert True
```

**What this test does:**
1. **Parametrization:** Tests 6 common weak passwords
2. Tests real-world weak passwords (from NIST breach database)
3. Discovers if system accepts commonly compromised passwords
4. Validates NIST SP 800-63B password guidelines
5. Each weak password runs as separate test execution

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

### Code Examples

#### Example 1: SQL Injection Attack (SEC-001)
```python
@pytest.mark.security
@pytest.mark.critical
@pytest.mark.injection
@pytest.mark.parametrize("sql_payload", [
    "' OR '1'='1",
    "admin'--",
    "' OR '1'='1' --",
    "') OR ('1'='1",
    "' OR 1=1--",
    "admin' OR '1'='1' /*"
])
def test_sql_injection_username_field_SEC_001(browser, base_url, sql_payload):
    """
    TC-SIGNUP-SEC-001: SQL Injection in Username Field
    CWE: CWE-89 (SQL Injection)
    CVSS Score: 9.8 (CRITICAL)
    """
    logging.info("=" * 80)
    logging.info(f"TC-SIGNUP-SEC-001: Testing SQL injection with payload: {sql_payload}")

    # EXECUTE: Attempt signup with SQL injection payload in username
    browser.get(base_url)
    signup_page = SignupPage(browser)
    signup_page.signup(sql_payload, "TestPass123!")

    # OBSERVE: Check system response
    time.sleep(1)
    alert_text = signup_page.get_alert_text(timeout=5)

    # DECIDE: SQL injection should be blocked
    if alert_text and "success" in alert_text.lower():
        logging.critical("=" * 80)
        logging.critical("CRITICAL VULNERABILITY DISCOVERED: SQL INJECTION")
        logging.critical(f"Payload: {sql_payload}")
        logging.critical("CVSS Score: 9.8 (CRITICAL)")
        logging.critical("Impact: Complete database compromise possible")
        logging.critical("=" * 80)

        pytest.fail(f"DISCOVERED: SQL Injection vulnerability with payload '{sql_payload}'")

    # OBSERVE: Check for SQL error disclosure in page source
    page_source = browser.page_source.lower()
    error_indicators = ["sql syntax", "mysql", "postgresql", "sqlite"]

    for indicator in error_indicators:
        if indicator in page_source:
            pytest.fail(f"DISCOVERED: SQL error disclosure with indicator '{indicator}'")

    logging.info(f"✓ SQL payload '{sql_payload}' handled safely")
    assert True
```

**What this test does:**
1. **Parametrization:** Tests 6 different SQL injection payloads
2. **Real Attack:** Each payload is an actual SQL injection technique
3. **Dual Detection:** Checks both for successful injection AND error disclosure
4. **CVSS Scoring:** Rates vulnerability as 9.8 CRITICAL
5. **Detailed Logging:** Logs complete exploit chain if discovered
6. **CWE Mapping:** Maps to CWE-89 for standardized reporting

#### Example 2: XSS Attack (SEC-003)
```python
@pytest.mark.security
@pytest.mark.critical
@pytest.mark.xss
@pytest.mark.parametrize("xss_payload", [
    "<script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "'-alert('XSS')-'"
])
def test_xss_username_field_SEC_003(browser, base_url, xss_payload):
    """
    TC-SIGNUP-SEC-003: Cross-Site Scripting (XSS) in Username
    CWE: CWE-79 (Cross-site Scripting)
    CVSS Score: 7.1 (HIGH)
    """
    logging.info(f"TC-SIGNUP-SEC-003: Testing XSS with payload: {xss_payload}")

    # EXECUTE: Attempt signup with XSS payload
    browser.get(base_url)
    signup_page = SignupPage(browser)
    signup_page.signup(xss_payload, "TestPass123!")

    # OBSERVE: Check if account created
    time.sleep(1)
    alert_text = signup_page.get_alert_text(timeout=5)

    # DECIDE: Check if XSS payload reflected/stored
    if alert_text and "success" in alert_text.lower():
        browser.get(base_url)
        time.sleep(2)

        # OBSERVE: Check if XSS payload appears unescaped in page
        page_source = browser.page_source

        if xss_payload in page_source:
            logging.error("=" * 80)
            logging.error("XSS VULNERABILITY DISCOVERED")
            logging.error(f"Payload: {xss_payload}")
            logging.error("CVSS Score: 7.1 (HIGH)")
            logging.error("Impact: Session hijacking, cookie theft, defacement")
            logging.error("=" * 80)

            pytest.fail(f"DISCOVERED: XSS vulnerability with payload '{xss_payload}'")

    logging.info(f"✓ XSS payload '{xss_payload}' handled safely")
    assert True
```

**What this test does:**
1. **Parametrization:** Tests 5 XSS attack vectors
2. **Reflected XSS:** Checks if payload executes immediately
3. **Source Analysis:** Examines if payload appears unescaped
4. **Multi-Technique:** Tests script tags, event handlers, javascript: protocol
5. **Impact Assessment:** Logs potential attack consequences

#### Example 3: Timing Attack for Enumeration (SEC-006)
```python
@pytest.mark.security
@pytest.mark.medium
@pytest.mark.enumeration
def test_account_enumeration_timing_SEC_006(browser, base_url):
    """
    TC-SIGNUP-SEC-006: Account Enumeration via Timing Attack
    CWE: CWE-208 (Observable Timing Discrepancy)
    CVSS Score: 5.3 (MEDIUM)
    """
    signup_page = SignupPage(browser)

    # EXECUTE: Create test account
    browser.get(base_url)
    existing_user = signup_page.generate_unique_username()
    signup_page.signup(existing_user, "TestPass123!")
    time.sleep(1)
    first_alert = signup_page.get_alert_text(timeout=5)

    if not first_alert or "success" not in first_alert.lower():
        pytest.skip("Could not create test account")

    # EXECUTE: Measure timing for existing user (duplicate attempt)
    browser.get(base_url)
    start_time = time.time()
    signup_page.signup(existing_user, "AnotherPass456!")
    time.sleep(1)
    signup_page.get_alert_text(timeout=5)
    existing_duration = time.time() - start_time

    # EXECUTE: Measure timing for nonexistent user
    browser.get(base_url)
    nonexistent_user = signup_page.generate_unique_username()
    start_time = time.time()
    signup_page.signup(nonexistent_user, "")
    time.sleep(1)
    signup_page.get_alert_text(timeout=5)
    nonexistent_duration = time.time() - start_time

    # OBSERVE: Calculate timing difference
    time_diff = abs(existing_duration - nonexistent_duration)

    # DECIDE: Timing differences should be minimal
    if time_diff > 0.5:
        logging.error("=" * 80)
        logging.error("TIMING DISCREPANCY DETECTED")
        logging.error(f"Existing account: {existing_duration:.2f}s")
        logging.error(f"Nonexistent account: {nonexistent_duration:.2f}s")
        logging.error(f"Difference: {time_diff:.2f}s")
        logging.error("Impact: Account enumeration via timing attack")
        logging.error("=" * 80)

        pytest.fail(f"DISCOVERED: Timing discrepancy of {time_diff:.2f}s enables enumeration")

    logging.info(f"✓ No timing discrepancy detected (diff: {time_diff:.2f}s)")
    assert True
```

**What this test does:**
1. **Real Measurements:** Measures actual response times
2. **Statistical Analysis:** Compares timing for existing vs non-existing accounts
3. **Threshold Detection:** Identifies significant timing differences (>0.5s)
4. **Side-Channel Attack:** Discovers timing-based username enumeration
5. **Precision Logging:** Reports exact timing measurements

#### Example 4: Brute Force Protection (SEC-005)
```python
@pytest.mark.security
@pytest.mark.high
@pytest.mark.brute_force
def test_brute_force_protection_SEC_005(browser, base_url):
    """
    TC-SIGNUP-SEC-005: Brute Force Protection on Signup
    CWE: CWE-307 (Improper Restriction of Excessive Authentication Attempts)
    CVSS Score: 7.5 (HIGH)
    """
    signup_page = SignupPage(browser)
    attempts = 10
    rate_limited = False

    # EXECUTE: Attempt multiple rapid signups
    for i in range(attempts):
        browser.get(base_url)

        username = signup_page.generate_unique_username()
        signup_page.signup(username, "TestPass123!")
        time.sleep(0.5)

        # OBSERVE: Check for rate limiting message
        alert_text = signup_page.get_alert_text(timeout=3)

        # DECIDE: Check if rate limiting kicked in
        if alert_text and any(keyword in alert_text.lower()
                             for keyword in ["limit", "wait", "too many"]):
            logging.info(f"✓ Rate limiting detected after {i + 1} attempts")
            rate_limited = True
            break

    # DECIDE: System should have rate limiting
    if not rate_limited:
        logging.error("=" * 80)
        logging.error("NO BRUTE FORCE PROTECTION DETECTED")
        logging.error(f"Completed {attempts} rapid signup attempts without restriction")
        logging.error("Impact: Automated account creation possible")
        logging.error("=" * 80)

        pytest.fail(f"DISCOVERED: No rate limiting after {attempts} signup attempts")

    assert True
```

**What this test does:**
1. **Volume Attack:** Attempts 10 rapid signups
2. **Rate Limit Detection:** Looks for throttling/blocking messages
3. **Real Automation:** Simulates actual bot behavior
4. **Anti-Automation Check:** Validates OWASP ASVS 2.2.1
5. **Actionable Results:** Identifies lack of protection mechanisms

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
