# DISCOVER Philosophy - QA Testing Methodology

> **Master Document - Mandatory Reading for All QA Testers**

---

## 📋 Table of Contents

1. [What is DISCOVER?](#what-is-discover)
2. [The Core Principle](#core-principle)
3. [The DISCOVER Formula](#discover-formula)
4. [Why DISCOVER Matters](#why-discover-matters)
5. [CORRECT vs INCORRECT: Real Examples](#examples)
6. [Mandatory Requirements](#mandatory-requirements)
7. [Common Violations and How to Avoid Them](#violations)
8. [Standards We Follow](#standards)
9. [Implementation Checklist](#checklist)

---

<a name="what-is-discover"></a>
## 1. What is DISCOVER?

**DISCOVER** is a testing methodology that ensures tests are **objective, universal, and standards-based**.

### The Problem We Solve

Traditional testing often falls into this trap:

```python
# ❌ WRONG APPROACH
def test_login():
    # "I know this demo site doesn't have 2FA, so I won't test it"
    pytest.skip("Application doesn't implement 2FA")
```

**Problems with this approach:**
- Tests become application-specific
- Missing security features go unreported
- Tests can't be reused on other systems
- No objective measure of security compliance

### The DISCOVER Solution

```python
# ✅ CORRECT APPROACH
def test_2fa_enforcement():
    """NIST 800-63B Section 5.2.3: MFA should be required"""

    # EXECUTE: Perform login action
    perform_login(username, password)

    # OBSERVE: Check if 2FA prompt appears
    mfa_prompt_exists = check_for_mfa_elements()

    # DECIDE: Based on NIST 800-63B standard
    if not mfa_prompt_exists:
        logging.critical("SECURITY VIOLATION: NO 2FA/MFA")
        logging.critical("Standard: NIST 800-63B Section 5.2.3")
        logging.critical("CVSS Score: 7.5 (HIGH)")
        pytest.fail("DISCOVERED: NO 2FA - Violates NIST 800-63B 5.2.3")
```

**Benefits:**
- Test discovers actual behavior objectively
- Missing features are reported as violations
- Same test works on any login system
- Clear evidence for security assessments

---

<a name="core-principle"></a>
## 2. The Core Principle

> **Tests DISCOVER behavior by EXECUTING actions and OBSERVING results.**
> **Tests NEVER ASSUME how the application will behave.**

### Key Concepts

1. **No Assumptions**: Never skip tests because "the app doesn't have this feature"
2. **Objective Standards**: Always validate against industry standards (OWASP, NIST, ISO)
3. **Discovery-Based**: Tests discover what EXISTS and what is MISSING
4. **Universal Code**: Tests should work on ANY application by changing config

---

<a name="discover-formula"></a>
## 3. The DISCOVER Formula

```
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   DISCOVER = EXECUTE + OBSERVE + DECIDE                 ║
║                                                          ║
║   1. EXECUTE: Run the actual action                     ║
║   2. OBSERVE: Capture the real system response          ║
║   3. DECIDE: Compare against objective standards        ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
```

### Breaking Down Each Step

#### EXECUTE: Run the Action
```python
# Perform the actual operation on the system
perform_login(browser, username, password)
add_to_cart(browser, product_id)
submit_form(browser, form_data)
```

#### OBSERVE: Capture Response
```python
# Collect objective data about what happened
response_time = measure_response_time()
error_message = get_error_text()
security_headers = check_http_headers()
session_cookie = get_session_cookie()
mfa_prompt = check_for_mfa_elements()
```

#### DECIDE: Compare to Standards
```python
# Make decision based on industry standards
if response_time > 3.0:  # WCAG 2.1 Success Criterion 2.2.2
    pytest.fail(f"Response time {response_time}s exceeds WCAG 2.1 limit")

if not security_headers['X-Frame-Options']:  # OWASP ASVS 14.4.1
    pytest.fail("Missing X-Frame-Options header - OWASP ASVS 14.4.1")

if not mfa_prompt:  # NIST 800-63B Section 5.2.3
    pytest.fail("NO 2FA detected - Violates NIST 800-63B 5.2.3")
```

---

<a name="why-discover-matters"></a>
## 4. Why DISCOVER Matters

### Code is Universal

```python
# Change only configuration = works on ANY system
BASE_URL = "https://www.example.com/"  # Works on Amazon
BASE_URL = "https://banking.site.com/"  # Works on bank
BASE_URL = "https://government.gov/"    # Works on gov site
```

**Same tests. Different applications. Objective results.**

### Tests are Honest

- ✅ Don't hide missing security features
- ✅ Report violations against industry standards
- ✅ Provide clear evidence for security assessments
- ✅ Help developers understand what needs fixing

### Professional QA Practice

Following DISCOVER methodology means:
- Your tests meet international standards
- Your reports are credible and actionable
- Your code can be reused across projects
- You provide real value to organizations

---

<a name="examples"></a>
## 5. CORRECT vs INCORRECT: Real Examples

### Example 1: Testing 2FA/MFA

#### ❌ INCORRECT (Assuming Behavior)
```python
def test_2fa():
    """Test 2FA functionality"""
    # PROBLEM: Assumes app doesn't have 2FA
    pytest.skip("DemoBlaze doesn't implement 2FA")

# Result: No test runs, no discovery, feature absence unreported
```

**Why this is WRONG:**
- Makes assumptions about the application
- Doesn't discover actual behavior
- Missing security feature goes unreported
- Code is not reusable on other systems

#### ✅ CORRECT (Discovering Behavior)
```python
def test_2fa_enforcement_BR_016():
    """
    NIST 800-63B Section 5.2.3: Multi-Factor Authentication

    Discovers whether the system enforces MFA/2FA.
    This test EXECUTES login, OBSERVES response, and DECIDES based on standards.
    """
    # EXECUTE: Perform login with valid credentials
    perform_login(browser, TEST_USERNAME, TEST_PASSWORD)
    wait_for_page_load(browser)

    # OBSERVE: Check if 2FA prompt appears
    mfa_elements = [
        "//input[@id='mfa-code']",
        "//div[contains(text(), 'verification code')]",
        "//input[@type='tel' and @placeholder='Enter code']",
        "//button[contains(text(), 'Verify')]"
    ]

    mfa_prompt_exists = False
    for locator in mfa_elements:
        try:
            element = browser.find_element(By.XPATH, locator)
            if element.is_displayed():
                mfa_prompt_exists = True
                break
        except NoSuchElementException:
            continue

    # DECIDE: Based on NIST 800-63B Section 5.2.3
    if not mfa_prompt_exists:
        logging.critical("=" * 80)
        logging.critical("SECURITY VIOLATION DISCOVERED")
        logging.critical("=" * 80)
        logging.critical("Issue: NO Multi-Factor Authentication (MFA/2FA)")
        logging.critical("Standard: NIST 800-63B Section 5.2.3")
        logging.critical("Severity: HIGH")
        logging.critical("CVSS Score: 7.5")
        logging.critical("Impact: Account takeover vulnerability")
        logging.critical("Recommendation: Implement TOTP, SMS, or hardware token MFA")
        logging.critical("=" * 80)

        pytest.fail("DISCOVERED: NO 2FA/MFA enforcement - Violates NIST 800-63B 5.2.3")
    else:
        logging.info("✓ DISCOVERED: 2FA/MFA is enforced (complies with NIST 800-63B)")
        assert True
```

**Why this is CORRECT:**
- Executes actual login action
- Observes real system response
- Decides based on NIST standard
- Reports violation clearly with CVSS score
- Works on any login system

---

### Example 2: Testing Rate Limiting

#### ❌ INCORRECT (Assuming Behavior)
```python
def test_rate_limiting():
    """Test for rate limiting"""
    # PROBLEM: Assumes rate limiting doesn't exist
    pytest.skip("Out of scope - DemoBlaze doesn't have rate limiting")

# Result: Brute force vulnerability unreported
```

**Why this is WRONG:**
- Excuses missing security control as "out of scope"
- Critical vulnerability goes undiscovered
- Test suite appears complete but isn't

#### ✅ CORRECT (Discovering Behavior)
```python
def test_account_lockout_enforcement_BR_013():
    """
    OWASP ASVS 2.2.1: Account Lockout Controls

    Discovers whether system implements rate limiting / account lockout.
    Tests by executing multiple failed login attempts.
    """
    # EXECUTE: Attempt multiple failed logins
    failed_attempts = 10
    lockout_detected = False

    for attempt in range(failed_attempts):
        perform_login(browser, TEST_USERNAME, "WRONG_PASSWORD")

        # OBSERVE: Check for lockout indicators
        lockout_indicators = [
            "account locked",
            "too many attempts",
            "temporarily disabled",
            "wait before trying again"
        ]

        page_text = browser.find_element(By.TAG_NAME, "body").text.lower()

        for indicator in lockout_indicators:
            if indicator in page_text:
                lockout_detected = True
                logging.info(f"✓ DISCOVERED: Lockout after {attempt + 1} attempts")
                break

        if lockout_detected:
            break

    # DECIDE: Based on OWASP ASVS 2.2.1
    if not lockout_detected:
        logging.critical("=" * 80)
        logging.critical("SECURITY VIOLATION DISCOVERED")
        logging.critical("=" * 80)
        logging.critical("Issue: NO account lockout or rate limiting")
        logging.critical("Standard: OWASP ASVS v5.0 Requirement 2.2.1")
        logging.critical("Severity: HIGH")
        logging.critical("CVSS Score: 7.5")
        logging.critical(f"Evidence: {failed_attempts} failed attempts with no lockout")
        logging.critical("Impact: Brute force attacks possible")
        logging.critical("Recommendation: Implement progressive delays or CAPTCHA")
        logging.critical("=" * 80)

        pytest.fail(f"DISCOVERED: NO rate limiting after {failed_attempts} attempts - Violates OWASP ASVS 2.2.1")
    else:
        assert True
```

**Why this is CORRECT:**
- Actually tests for rate limiting by executing attempts
- Discovers whether control exists
- Reports violation with evidence
- Provides actionable recommendations

---

### Example 3: Testing Password Complexity

#### ❌ INCORRECT (Assuming Behavior)
```python
def test_password_complexity():
    """Test password strength requirements"""
    # PROBLEM: Doesn't test because "app allows weak passwords"
    pass  # Not implemented - DemoBlaze accepts any password

# Result: Security gap unreported
```

#### ✅ CORRECT (Discovering Behavior)
```python
def test_password_complexity_enforcement_BR_015():
    """
    NIST 800-63B Section 5.1.1.2: Password Strength

    Discovers whether system enforces password complexity requirements.
    """
    weak_passwords = [
        "123",           # Too short
        "password",      # Common word
        "12345678",      # Sequential numbers
        "aaaaaaaa"       # Repeated characters
    ]

    complexity_enforced = False

    for weak_password in weak_passwords:
        # EXECUTE: Attempt signup/password change with weak password
        result = attempt_password_set(browser, TEST_USERNAME, weak_password)

        # OBSERVE: Check if rejected
        rejection_indicators = [
            "password too weak",
            "must contain",
            "minimum length",
            "complexity requirement"
        ]

        if any(indicator in result.lower() for indicator in rejection_indicators):
            complexity_enforced = True
            break

    # DECIDE: Based on NIST 800-63B
    if not complexity_enforced:
        logging.critical("=" * 80)
        logging.critical("SECURITY VIOLATION DISCOVERED")
        logging.critical("=" * 80)
        logging.critical("Issue: NO password complexity enforcement")
        logging.critical("Standard: NIST 800-63B Section 5.1.1.2")
        logging.critical("Severity: MEDIUM")
        logging.critical("CVSS Score: 6.5")
        logging.critical("Evidence: System accepts weak passwords")
        logging.critical("Impact: Weak credentials allowed, easy to crack")
        logging.critical("Recommendation: Enforce 8+ chars, check against common passwords")
        logging.critical("=" * 80)

        pytest.fail("DISCOVERED: Weak passwords accepted - Violates NIST 800-63B 5.1.1.2")
```

---

<a name="mandatory-requirements"></a>
## 6. Mandatory Requirements

### Every Test MUST Follow This Structure

```python
def test_feature_name():
    """
    STANDARD: [Standard name and section]

    Brief description of what this test discovers.
    """
    # 1. EXECUTE
    # Perform the action being tested

    # 2. OBSERVE
    # Capture actual system response

    # 3. DECIDE
    # Compare to standard and report result
```

### Every Test MUST Include

1. **Standards Reference**: Which standard is being validated (OWASP, NIST, ISO, WCAG)
2. **Execution Step**: Actual action performed on the system
3. **Observation Step**: Data collected about system response
4. **Decision Logic**: Comparison against objective standard
5. **Violation Reporting**: If standard not met, log CRITICAL with:
   - Issue description
   - Standard violated
   - Severity and CVSS score
   - Evidence
   - Impact
   - Recommendation

### Every Test MUST NOT

1. ❌ Skip tests because "app doesn't have feature"
2. ❌ Use phrases like "out of scope" or "not applicable"
3. ❌ Make assumptions about application behavior
4. ❌ Hide missing features behind "limitations" sections
5. ❌ Have application-specific hardcoded logic

---

<a name="violations"></a>
## 7. Common Violations and How to Avoid Them

### Violation 1: Using pytest.skip() for Missing Features

#### ❌ WRONG
```python
def test_captcha():
    pytest.skip("Application doesn't implement CAPTCHA")
```

#### ✅ CORRECT
```python
def test_captcha_protection_BR_017():
    """OWASP ASVS 2.2.3: Anti-automation Controls"""

    # Execute multiple rapid logins
    for i in range(5):
        perform_login(browser, "user", "pass")

    # Observe for CAPTCHA
    captcha_present = check_for_captcha_elements(browser)

    # Decide based on OWASP ASVS 2.2.3
    if not captcha_present:
        pytest.fail("DISCOVERED: NO CAPTCHA - Violates OWASP ASVS 2.2.3")
```

---

### Violation 2: README Sections That Assume Behavior

#### ❌ WRONG - README Structure
```markdown
## Tests Not Implemented

The following tests are not implemented because DemoBlaze doesn't have these features:
- 2FA Testing (no 2FA implemented)
- Rate Limiting (no rate limiting)
- CAPTCHA Testing (no CAPTCHA)

These are out of scope for this demo application.
```

**Why this is WRONG:**
- Treats missing features as "acceptable limitations"
- Implies tests can't be written
- Hides security gaps

#### ✅ CORRECT - README Structure
```markdown
## Expected Test Failures

The following tests DISCOVER security violations on DemoBlaze:

| Test ID | Feature Tested | Standard | Expected Result |
|---------|----------------|----------|-----------------|
| BR-016 | 2FA/MFA Enforcement | NIST 800-63B 5.2.3 | ❌ FAIL - NO 2FA detected |
| BR-013 | Rate Limiting | OWASP ASVS 2.2.1 | ❌ FAIL - NO rate limiting |
| BR-017 | CAPTCHA Protection | OWASP ASVS 2.2.3 | ❌ FAIL - NO CAPTCHA |

**Important:** These failures are NOT bugs in the tests. They are DISCOVERIES
of missing security controls that violate industry standards.
```

**Why this is CORRECT:**
- Clearly states tests discover violations
- No excuse for missing features
- Educates reader that failures = discoveries

---

### Violation 3: Application-Specific Hardcoded Logic

#### ❌ WRONG
```python
def test_login():
    # Hardcoded for DemoBlaze only
    browser.get("https://www.demoblaze.com")
    browser.find_element(By.ID, "login2").click()
    # ... DemoBlaze-specific code ...
```

#### ✅ CORRECT
```python
# Configuration at top
BASE_URL = "https://www.demoblaze.com/"
LOCATORS = {
    "login_link": ("ID", "login2"),
    "username_field": ("ID", "loginusername"),
    # ...
}

def test_login():
    # Universal code
    browser.get(BASE_URL)
    login_link = browser.find_element(*LOCATORS["login_link"])
    login_link.click()
    # ...
```

**Why this is CORRECT:**
- Change BASE_URL and LOCATORS = works on any app
- Code is reusable across projects
- Easier to maintain

---

<a name="standards"></a>
## 8. Standards We Follow

### Primary Standards

1. **OWASP ASVS v5.0** (Application Security Verification Standard)
   - Authentication (2.x)
   - Session Management (3.x)
   - Access Control (4.x)
   - Validation (5.x)

2. **NIST SP 800-63B** (Digital Identity Guidelines - Authentication)
   - Password requirements (5.1.1.x)
   - Multi-factor authentication (5.2.x)
   - Session management (7.x)

3. **ISO 27001:2022** (Information Security Management)
   - Access control (A.9)
   - Cryptography (A.10)
   - Operations security (A.12)

4. **WCAG 2.1** (Web Content Accessibility Guidelines)
   - Perceivable (1.x)
   - Operable (2.x)
   - Understandable (3.x)
   - Robust (4.x)

### When to Apply Each Standard

- **Functional Testing**: WCAG 2.1, OWASP ASVS functional requirements
- **Security Testing**: OWASP ASVS, NIST 800-63B, ISO 27001
- **Performance Testing**: WCAG 2.1 timing requirements
- **Accessibility Testing**: WCAG 2.1

---

<a name="checklist"></a>
## 9. Implementation Checklist

### Before Writing Tests

- [ ] Read all relevant standards sections
- [ ] Identify what SHOULD exist according to standards
- [ ] Plan tests that discover presence/absence of features
- [ ] Design tests to work on any application

### While Writing Tests

- [ ] Use EXECUTE + OBSERVE + DECIDE structure
- [ ] Reference specific standard and section
- [ ] Never use pytest.skip() for missing features
- [ ] Log CRITICAL violations with full details
- [ ] Include CVSS scores for security issues
- [ ] Make code universal (configurable BASE_URL and LOCATORS)

### When Writing READMEs

- [ ] Never use "Out of Scope" or "Not Implemented" sections
- [ ] Include "Expected Test Failures" table explaining discoveries
- [ ] Add "Philosophy: DISCOVER Methodology" section
- [ ] Show examples of CORRECT vs INCORRECT approaches
- [ ] Explain that failures = discoveries, not test bugs

### Before Submitting Code

- [ ] All tests follow DISCOVER formula
- [ ] No assumptions about application behavior
- [ ] All violations logged with standards references
- [ ] Code works with just config changes
- [ ] README explains philosophy clearly

---

## 10. Final Words

### Remember This

> **A test that skips because a feature is missing is a test that FAILS its purpose.**
>
> **A test that discovers a missing feature and reports it IS DOING ITS JOB.**

### The Goal

Write tests that:
- Work on ANY application
- Discover ACTUAL behavior objectively
- Report violations against STANDARDS
- Provide ACTIONABLE evidence

### Questions?

If ever in doubt, ask yourself:

1. **Am I assuming behavior?** → If yes, stop and discover instead
2. **Does this work on other apps?** → If no, make it configurable
3. **What standard says this should exist?** → Reference it explicitly
4. **What do I observe if I execute this?** → That's your test

---

**Document Version:** 1.0
**Last Updated:** November 2025
**Status:** Mandatory for all QA testing
**Author:** QA Testing Standards Committee

---

**END OF DOCUMENT**
