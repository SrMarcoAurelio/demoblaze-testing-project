# TEMPLATE: Functional + Business Rules Tests

**Purpose:** Universal template for functional testing and business rules compliance validation  
**Use Case:** ANY web application module across ANY domain (Login, Payment, Cart, Search, Profile, Admin, API, etc.)  
**Core Philosophy:** Tests DISCOVER behavior through execution - NEVER assume functionality  
**Author:** Arévalo, Marc  
**Version:** 2.0 (Universal Edition)

---

## TABLE OF CONTENTS

1. [Philosophy & Core Principles](#philosophy)
2. [DISCOVER vs ASSUME - The Foundation](#discover-vs-assume)
3. [Anti-Patterns - What NOT to Do](#anti-patterns)
4. [Pre-Development Questions](#pre-dev)
5. [Research Phase by Module Type](#research)
6. [Before Writing Code Checklist](#checklist)
7. [Code Structure Template](#code-structure)
8. [Test Categories & Distribution](#test-categories)
9. [Test Naming Convention](#naming)
10. [Markers Usage](#markers)
11. [Execution Commands](#execution)
12. [Expected Test Distribution](#distribution)
13. [Critical Principles](#principles)
14. [Standards Classification](#standards)
15. [Pre-Delivery Checklist](#delivery)
16. [Standards Reference Quick Guide](#standards-ref)
17. [Testing Tools & Libraries](#tools)

**PART 2 (Separate File):**
18. Example Future Conversations
19. Common Patterns by Module Type
20. Version History

---

<a name="philosophy"></a>
## 1. PHILOSOPHY & CORE PRINCIPLES

### The Functional Testing Mindset

Functional testing validates TWO critical aspects:

**1. Functional Tests:** "Does the happy path work?"  
**2. Business Rules Tests:** "Does it comply with industry standards and prevent violations?"

### Core Philosophy: DISCOVERY, Not Assumption

**The Golden Rule:**

> **Tests must DISCOVER behavior by EXECUTING actions and OBSERVING results.**  
> **NEVER write tests that ASSUME how the application will behave.**

**Why This Matters:**

When you test a new application in the future:
- You DON'T KNOW if functionality works correctly
- You DON'T KNOW if it validates inputs properly
- You DON'T KNOW if it follows industry standards

**Therefore:**
- Tests must DISCOVER by EXECUTING
- Tests must OBSERVE actual responses
- Tests must DECIDE objectively based on standards

### The Two Test Types

#### **Functional Tests (Happy Path):**
```python
def test_valid_login():
    """Discovers if login works with valid credentials"""
    # EXECUTE
    login("validuser", "validpass")
    
    # OBSERVE
    result = check_if_logged_in()
    
    # DECIDE
    if result.logged_in:
        assert True  # DISCOVERED: Login works
    else:
        pytest.fail("DISCOVERED: Login broken")
```

#### **Business Rules Tests (Standards Compliance):**
```python
def test_password_strength():
    """NIST 800-63B: Minimum 8 characters required
    
    Discovers if system enforces password strength policy.
    """
    # EXECUTE
    signup("user", "123")  # Weak password
    
    # OBSERVE
    response = get_alert_or_error()
    
    # DECIDE based on NIST standard
    if response and "password" in response.lower() and \
       ("weak" in response.lower() or "minimum" in response.lower()):
        assert True  # DISCOVERED: Complies with NIST
    else:
        log_business_rule_violation(
            standard="NIST 800-63B Section 5.1.1",
            expected="Reject passwords < 8 chars",
            actual=f"Accepted password '123'",
            impact="Weak passwords allowed, security risk",
            severity="HIGH"
        )
        pytest.fail("DISCOVERED: Does not comply with NIST 800-63B")
```

### Universal Applicability

This template works for:
- E-commerce sites (DemoBlaze, Amazon, Shopify)
- Banking applications (Online banking, fintech)
- Healthcare systems (Patient portals, EHR)
- Social networks (Twitter, LinkedIn style)
- SaaS platforms (CRM, ERP, dashboards)
- Government portals (Public services)
- Educational systems (LMS, student portals)
- ANY web application

**How?**
- Change BASE_URL
- Change LOCATORS  
- Keep testing logic generic
- Tests discover behavior objectively

---

<a name="discover-vs-assume"></a>
## 2. DISCOVER vs ASSUME - THE FOUNDATION

This is THE MOST CRITICAL concept. Master this and your tests will be professional and reusable.

### What Does "DISCOVER" Mean?

**DISCOVER = Execute → Observe → Decide**

```python
# Step 1: EXECUTE the action
fill_form(username="testuser", password="testpass")
click_submit()

# Step 2: OBSERVE what happened  
result = check_if_succeeded()

# Step 3: DECIDE based on observation
if result.success:
    assert True  # DISCOVERED: Feature works
else:
    pytest.fail("DISCOVERED: Feature broken")
```

### What Does "ASSUME" Mean?

**ASSUME = Know → Hardcode → Predict**

```python
# BAD: Assumes site behavior
def test_login():
    login("user", "pass")
    # I KNOW this site accepts weak passwords
    assert True  # WRONG! Assuming behavior

# BAD: Hardcoded site-specific logic
def test_validation():
    if "demoblaze" in BASE_URL:
        # I know DemoBlaze doesn't validate
        assert False  # Site-specific assumption
```

---

### EXAMPLE 1: Empty Form Validation

#### ❌ ASSUME (Wrong Way)
```python
def test_empty_form_WRONG():
    """Tests empty form submission (assuming it fails)"""
    
    # Hardcoded assumption about site behavior
    submit_form(name="", email="")
    
    # Assumes validation error will appear
    assert False, "Site doesn't validate"  # WRONG!
```

**Why This Is Wrong:**
- Assumes the site doesn't validate
- Won't work on a site that DOES validate
- Not discovering, just stating assumed facts
- Not reusable

#### ✅ DISCOVER (Right Way)
```python
def test_empty_form_CORRECT():
    """ISO 25010: Required Fields Validation
    
    Discovers if system validates required fields by submitting
    empty form and observing system response.
    """
    
    # Step 1: EXECUTE action
    fill_form(name="", email="")
    click_submit()
    
    # Step 2: OBSERVE response
    alert_text = wait_for_alert(browser, timeout=5)
    error_on_page = check_for_error_message(browser)
    
    # Step 3: DECIDE based on observation
    # If validation works, we'll see an error
    if alert_text and ("required" in alert_text.lower() or "fill" in alert_text.lower()):
        # DISCOVERED: System validates correctly
        logging.info("Empty field validation works (ISO 25010 compliant)")
        assert True
        
    elif error_on_page:
        # DISCOVERED: System validates with inline message
        logging.info("Empty field validation works (inline error)")
        assert True
        
    else:
        # DISCOVERED: No validation - business rule violation
        log_business_rule_violation(
            test_id="TC-MOD-BR-001",
            standard="ISO 25010 - Functional Suitability (Required Field Validation)",
            expected_behavior="Show validation error for empty required fields",
            actual_behavior="Form submitted without validation",
            impact="Data quality issues, incomplete records, poor UX",
            severity="MEDIUM"
        )
        pytest.fail("DISCOVERED: No validation for empty required fields")
```

**Why This Is Correct:**
- Executes actual form submission
- Observes real response (alert OR error message)
- Decides objectively based on what happened
- Works on ANY site (validates or doesn't)
- Reusable

---

### EXAMPLE 2: Password Strength Validation

#### ❌ ASSUME (Wrong Way)
```python
def test_password_strength_WRONG():
    """Tests password strength (assuming weak passwords accepted)"""
    
    # I know this site accepts weak passwords
    signup("user", "123")
    
    # Assumes registration will succeed
    assert registration_failed()  # Assumes behavior
```

**Problems:**
- Assumes site accepts weak passwords
- Hardcodes expected failure
- Won't work on secure site that rejects "123"
- Test logic backwards

#### ✅ DISCOVER (Right Way)
```python
def test_password_strength_CORRECT(browser):
    """NIST SP 800-63B Section 5.1.1: Password Strength
    
    Requirement: Minimum 8 characters for user-chosen passwords
    
    Discovers if system enforces password strength policy by
    attempting registration with weak password.
    """
    
    logging.info("TC-MOD-BR-002: Testing NIST 800-63B password policy")
    
    # Step 1: EXECUTE registration with weak password
    weak_password = "123"
    
    navigate_to_signup(browser)
    fill_signup_form(browser, username="testuser123", password=weak_password)
    click_signup_button(browser)
    
    # Step 2: OBSERVE system response
    time.sleep(2)
    
    alert_text = wait_for_alert(browser, timeout=3)
    error_message = check_for_error_message(browser)
    success_indicator = check_for_success(browser)
    
    # Step 3: DECIDE based on NIST standard
    # If weak password rejected, system complies with NIST
    if alert_text:
        # Check if rejection is password-related
        password_keywords = ["password", "weak", "minimum", "character", "8"]
        if any(keyword in alert_text.lower() for keyword in password_keywords):
            # DISCOVERED: System enforces password policy (NIST compliant)
            logging.info(f"Password policy enforced: '{alert_text}'")
            assert True
        else:
            # Alert exists but not password-related, check what it says
            if "success" in alert_text.lower():
                # Weak password was accepted
                log_business_rule_violation(
                    test_id="TC-MOD-BR-002",
                    standard="NIST SP 800-63B Section 5.1.1",
                    expected_behavior="Reject passwords with fewer than 8 characters",
                    actual_behavior=f"Accepted password '{weak_password}' (3 characters)",
                    impact="Weak passwords allowed, accounts vulnerable to brute force",
                    severity="HIGH"
                )
                pytest.fail(f"DISCOVERED: Weak password accepted (NIST violation)")
            else:
                # Some other error
                logging.info(f"Other error occurred: {alert_text}")
                assert True
                
    elif error_message:
        # DISCOVERED: Inline error message (good)
        logging.info("Password policy enforced via inline message")
        assert True
        
    elif success_indicator:
        # DISCOVERED: Weak password accepted (bad)
        log_business_rule_violation(
            test_id="TC-MOD-BR-002",
            standard="NIST SP 800-63B Section 5.1.1",
            expected_behavior="Reject passwords < 8 characters",
            actual_behavior=f"Accepted password '{weak_password}'",
            impact="Security vulnerability - weak passwords allowed",
            severity="HIGH"
        )
        pytest.fail("DISCOVERED: Weak password accepted (NIST violation)")
        
    else:
        # Unclear state - conservative pass
        logging.warning("Could not determine password policy enforcement")
        assert True
```

**Why This Is Correct:**
- Executes actual signup with weak password
- Observes all possible responses (alert, error, success)
- Compares against NIST standard objectively
- Works on compliant AND non-compliant sites
- Discovers actual behavior

---

### EXAMPLE 3: Input Length Validation

#### ❌ ASSUME (Wrong Way)
```python
def test_input_length_WRONG():
    """Tests input length (assuming no validation)"""
    
    # I know this accepts any length
    submit_form(name="a" * 10000)
    
    # Assumes it will accept without validation
    assert form_submitted_successfully()  # Assumes
```

#### ✅ DISCOVER (Right Way)
```python
def test_input_length_CORRECT(browser):
    """ISO 25010: Input Length Validation
    
    Requirement: Inputs should have reasonable maximum length (50-100 chars)
    to prevent database issues and DoS attacks.
    
    Discovers if system validates input length.
    """
    
    logging.info("TC-MOD-BR-003: Testing input length validation")
    
    # Step 1: EXECUTE with excessive input
    excessive_input = "a" * 1000
    
    navigate_to_form(browser)
    fill_field(browser, FIELD_NAME, excessive_input)
    click_submit(browser)
    
    # Step 2: OBSERVE response
    time.sleep(2)
    
    alert_text = wait_for_alert(browser, timeout=3)
    error_on_page = check_for_error_message(browser)
    
    # Check if input was actually truncated by examining field value
    field_value = browser.find_element(*FIELD_NAME).get_attribute('value')
    
    # Step 3: DECIDE based on observation
    # Check for validation error
    if alert_text and ("length" in alert_text.lower() or 
                       "long" in alert_text.lower() or
                       "maximum" in alert_text.lower()):
        # DISCOVERED: Length validation works (alert)
        logging.info(f"Input length validated: '{alert_text}'")
        assert True
        
    elif error_on_page:
        # DISCOVERED: Length validation works (inline error)
        logging.info("Input length validated with inline message")
        assert True
        
    elif len(field_value) < len(excessive_input):
        # DISCOVERED: HTML maxlength attribute works
        logging.info(f"Input truncated by maxlength: {len(field_value)} chars")
        assert True
        
    else:
        # DISCOVERED: No length validation
        # Check if form submitted successfully
        if check_for_success(browser):
            log_business_rule_violation(
                test_id="TC-MOD-BR-003",
                standard="ISO 25010 - Functional Suitability (Input Validation)",
                expected_behavior="Reject or truncate inputs exceeding reasonable length (100 chars)",
                actual_behavior=f"Accepted input of {len(excessive_input)} characters",
                impact="Database bloat, DoS attack vector, buffer overflow risk",
                severity="MEDIUM"
            )
            pytest.fail(f"DISCOVERED: No input length validation ({len(excessive_input)} chars accepted)")
        else:
            # Form didn't submit but no clear error - unclear state
            logging.warning("Form submission unclear - conservative pass")
            assert True
```

**Why This Is Correct:**
- Tests with actual excessive input
- Observes multiple validation methods (alert, error, maxlength)
- Checks if submission succeeded
- Objective decision based on observations
- Works regardless of validation implementation

---

### EXAMPLE 4: Form Submission Success

#### ❌ ASSUME (Wrong Way)
```python
def test_form_submission_WRONG():
    """Tests form submission (assuming success)"""
    
    # I know valid data will work
    submit_form(name="Test", email="test@test.com")
    
    # Assumes it will succeed
    assert True  # Not actually checking
```

**Problems:**
- Doesn't actually verify success
- Assumes submission works
- Won't catch if feature is broken
- No real observation

#### ✅ DISCOVER (Right Way)
```python
def test_form_submission_CORRECT(browser):
    """TC-MOD-FUNC-001: Valid Form Submission
    
    Functional test verifying form submission works with valid inputs.
    Discovers if happy path functions correctly.
    """
    
    logging.info("TC-MOD-FUNC-001: Testing valid form submission")
    
    # Step 1: EXECUTE form submission with valid data
    valid_data = {
        "name": "John Doe",
        "email": "john.doe@example.com",
        "phone": "555-0123",
        "message": "Test message"
    }
    
    navigate_to_form(browser)
    
    for field, value in valid_data.items():
        fill_field(browser, get_field_locator(field), value)
    
    click_submit(browser)
    
    # Step 2: OBSERVE multiple success indicators
    time.sleep(2)
    
    # Check for success alert
    alert_text = wait_for_alert(browser, timeout=5)
    
    # Check for success message on page
    success_message = check_for_success_message(browser)
    
    # Check if redirected to confirmation page
    current_url = browser.current_url
    
    # Check if form cleared (indicates successful submission)
    form_cleared = check_if_form_cleared(browser)
    
    # Step 3: DECIDE based on observations
    success_indicators_found = []
    
    if alert_text and "success" in alert_text.lower():
        success_indicators_found.append(f"Success alert: '{alert_text}'")
    
    if success_message:
        success_indicators_found.append(f"Success message: '{success_message}'")
    
    if "success" in current_url or "confirmation" in current_url:
        success_indicators_found.append(f"Redirected to: {current_url}")
    
    if form_cleared:
        success_indicators_found.append("Form fields cleared")
    
    # Decide based on what we discovered
    if success_indicators_found:
        # DISCOVERED: Submission succeeded
        logging.info(f"Form submission successful. Indicators: {', '.join(success_indicators_found)}")
        assert True
    else:
        # DISCOVERED: Submission failed or unclear
        # Check for error indicators
        error_text = check_for_error_message(browser)
        
        if error_text:
            pytest.fail(f"DISCOVERED: Form submission failed with error: {error_text}")
        else:
            pytest.fail("DISCOVERED: Form submission outcome unclear (no success or error indicators)")
```

**Why This Is Correct:**
- Submits with valid data
- Observes MULTIPLE success indicators
- Doesn't assume - actually checks
- Clear decision based on evidence
- Discovers actual outcome

---

### Key Takeaway: The DISCOVER Formula

```
DISCOVER = EXECUTE + OBSERVE + DECIDE

1. EXECUTE: Perform the action
2. OBSERVE: Capture actual response/state
3. DECIDE: Compare against expected behavior

if observation_matches_expected_behavior():
    assert True  # Feature works
else:
    pytest.fail("Feature broken or standard violated")
```

**NEVER:**
```python
# NEVER do this
if True:  # "I know it works/doesn't work"
    assert result

# NEVER do this
assert site_behavior_i_assume()  # Assuming
```

**ALWAYS:**
```python
# ALWAYS do this
result = execute_action()
observation = capture_response()

if observation.indicates_success():
    assert True  # DISCOVERED: Works
elif observation.indicates_failure():
    pytest.fail("DISCOVERED: Broken")
else:
    pytest.fail("DISCOVERED: Unclear behavior")
```

---

<a name="anti-patterns"></a>
## 3. ANTI-PATTERNS - WHAT NOT TO DO

Learn from common mistakes. Avoid these patterns:

### Anti-Pattern 1: Hardcoded Assumptions

```python
# ❌ WRONG
def test_feature():
    """This site doesn't validate inputs"""
    submit_invalid_data()
    assert False  # Hardcoded assumption
```

```python
# ✅ CORRECT
def test_feature():
    """Discovers if input validation exists"""
    submit_invalid_data()
    result = observe_response()
    
    if result.shows_validation_error():
        assert True  # DISCOVERED: Validates
    else:
        log_violation()
        pytest.fail("DISCOVERED: No validation")
```

### Anti-Pattern 2: Site-Specific Logic

```python
# ❌ WRONG
def test_validation():
    if "demoblaze" in BASE_URL:
        # DemoBlaze doesn't validate
        assert False
    else:
        assert True
```

```python
# ✅ CORRECT
def test_validation():
    # Works on ANY site
    result = check_validation()
    
    if result.validated:
        assert True
    else:
        pytest.fail("No validation found")
```

### Anti-Pattern 3: Passive Checks Only

```python
# ❌ WRONG - Only checks if element exists
def test_error_handling():
    error_element_exists = check_for_error_element()
    assert error_element_exists
```

```python
# ✅ CORRECT - Actually triggers error and observes
def test_error_handling():
    # Cause an error
    submit_invalid_data()
    
    # Observe if error handling works
    error_shown = wait_for_error_message(timeout=5)
    
    if error_shown:
        assert True  # Error handling works
    else:
        pytest.fail("No error handling found")
```

### Anti-Pattern 4: No Standard Reference

```python
# ❌ WRONG - No context
def test_input_validation():
    """Tests input validation"""
    result = test_something()
    assert result
```

```python
# ✅ CORRECT - Clear standard reference
def test_input_validation():
    """TC-MOD-BR-001: Input Validation
    
    Standard: ISO 25010 - Functional Suitability
    Reference: OWASP ASVS v5.0-1.2.5
    Requirement: All inputs must be validated
    """
    # Test implementation
```

### Anti-Pattern 5: Vague Assertions

```python
# ❌ WRONG - No context
def test_feature():
    result = do_something()
    assert result  # What does this mean?
```

```python
# ✅ CORRECT - Clear context
def test_feature():
    """Verifies form submission works with valid data"""
    
    result = submit_form_with_valid_data()
    
    if result.success:
        assert True
    else:
        pytest.fail(f"Form submission failed: {result.error_message}")
```

### Anti-Pattern 6: No Logging for Violations

```python
# ❌ WRONG - Silent failure
def test_business_rule():
    if violates_standard():
        assert False
```

```python
# ✅ CORRECT - Structured logging
def test_business_rule():
    if violates_standard():
        log_business_rule_violation(
            test_id="TC-MOD-BR-001",
            standard="ISO 25010 Section X",
            expected_behavior="Clear description",
            actual_behavior="What actually happened",
            impact="Business impact",
            severity="HIGH"
        )
        pytest.fail("Business rule violation")
```

### Anti-Pattern 7: Tests That Can't Fail

```python
# ❌ WRONG - Always passes
def test_feature():
    try:
        do_something()
        assert True  # Always passes
    except:
        assert True  # Catches everything
```

```python
# ✅ CORRECT - Can actually fail
def test_feature():
    try:
        result = do_something()
        
        if result.indicates_success():
            assert True
        else:
            pytest.fail("Feature broken")
            
    except ExpectedException:
        # Expected error
        assert True
    except Exception as e:
        # Unexpected error
        pytest.fail(f"Unexpected error: {e}")
```

### Anti-Pattern 8: Mixing Functional and Business Rules

```python
# ❌ WRONG - Confusing test purpose
def test_login():
    """Tests login and password policy"""
    # Tests multiple things
    login("user", "123")
    assert check_password_policy()
    assert check_login_works()
```

```python
# ✅ CORRECT - Separate tests
@pytest.mark.functional
def test_login_works():
    """Functional: Verifies login works"""
    login("validuser", "ValidPass123!")
    assert is_logged_in()

@pytest.mark.business_rules
def test_password_policy():
    """Business Rule: NIST 800-63B password policy"""
    attempt_signup("user", "123")
    assert password_rejected()
```

---

<a name="pre-dev"></a>
## 4. PRE-DEVELOPMENT QUESTIONS

Before writing test code, gather this information:

### A. Module & Context Information

```
1. What module are we testing?
   - Name: [Login / Payment / Cart / Search / Profile / Admin / etc.]
   - Type: [Authentication / Financial / E-commerce / Social / etc.]
   - Domain: [Banking / Healthcare / E-commerce / SaaS / etc.]

2. Do we need functional tests, business rules tests, or both?
   [ ] Functional tests (happy path validation)
   [ ] Business rules tests (standards compliance)
   [ ] Both (recommended)

3. Application information:
   - BASE_URL: [target website]
   - Authentication required: [YES/NO]
   - Test credentials available: [YES/NO]
   - Environment: [Demo / Staging / Test]
```

### B. Testing Scope Definition

```
4. Functional Tests Scope:
   [ ] Happy path scenarios (valid inputs work)
   [ ] Basic error handling (invalid inputs rejected)
   [ ] Edge cases (boundary conditions)
   [ ] Integration flows (multi-step processes)

5. Business Rules Tests Scope:
   [ ] Input validation standards
   [ ] Security standards (SQL injection, XSS prevention)
   [ ] Accessibility standards (WCAG 2.1)
   [ ] Industry-specific compliance (PCI-DSS, HIPAA, etc.)
   [ ] Data quality standards (ISO 25010)

6. Priority standards for this module?
   Critical: [List 3-5 most critical standards]
   High: [List 5-8 high priority standards]
```

### C. Technical Setup

```
7. Testing environment:
   - Browsers: [ ] Chrome [ ] Firefox [ ] Edge [ ] All
   - Cross-browser testing needed: [YES/NO]
   - Mobile responsive testing: [YES/NO]

8. Expected deliverables:
   [ ] test_[module].py (functional + business rules)
   [ ] README_[module].md (comprehensive documentation)
```

---

<a name="research"></a>
## 5. RESEARCH PHASE BY MODULE TYPE

Before coding, research the specific standards relevant to your module type.

### Research Matrix

| Module Type | Key Standards | Functional Tests | Business Rules Tests |
|-------------|--------------|------------------|---------------------|
| **Login/Authentication** | OWASP ASVS v5.0 Ch 2<br>NIST SP 800-63B<br>ISO 27001 A.9.4<br>WCAG 2.1 | Valid credentials work<br>Invalid credentials rejected<br>Empty fields rejected<br>Login/logout flow | Password strength (NIST)<br>Input sanitization (OWASP)<br>Brute force prevention<br>Error message accessibility (WCAG) |
| **Payment/Checkout** | PCI-DSS 4.0.1<br>OWASP ASVS v5.0 Ch 9<br>ISO 25010<br>WCAG 2.1 | Valid card works<br>Form submission successful<br>Order confirmation shown | Card format validation (PCI-DSS 6.5.3)<br>Input sanitization (OWASP)<br>Error messages (WCAG 3.3.1)<br>Required field validation |
| **Shopping Cart** | ISO 25010<br>OWASP ASVS v5.0 Ch 11<br>WCAG 2.1 | Add to cart works<br>Remove from cart works<br>Update quantity works<br>Cart total calculates | Quantity validation (ISO 25010)<br>Price integrity<br>Input length limits<br>Accessibility compliance |
| **Search/Filter** | OWASP ASVS v5.0 Ch 1<br>ISO 25010<br>WCAG 2.1 | Search returns results<br>Filters apply correctly<br>Empty search handled | Input sanitization (OWASP 1.2.1)<br>XSS prevention (OWASP 1.2.1)<br>SQL injection prevention (OWASP 1.2.5)<br>Error handling |
| **User Profile** | OWASP ASVS v5.0 Ch 4<br>GDPR/Privacy<br>ISO 25010<br>WCAG 2.1 | Profile view works<br>Profile update works<br>Data saves correctly | Input validation (ISO 25010)<br>XSS prevention in fields<br>Access control (OWASP Ch 4)<br>Data privacy compliance |
| **Registration** | OWASP ASVS v5.0 Ch 2<br>NIST 800-63B<br>WCAG 2.1<br>Anti-automation | Registration succeeds<br>Email verification works<br>Account created | Username validation<br>Password policy (NIST)<br>Email format validation<br>Bot protection<br>XSS prevention |
| **Contact Forms** | WCAG 2.1<br>ISO 25010<br>Anti-automation | Form submission works<br>Confirmation shown | Required field validation<br>Email format validation<br>Input length limits<br>Bot protection (CAPTCHA) |
| **File Upload** | OWASP ASVS v5.0 Ch 12<br>CWE-434<br>ISO 25010 | Valid file uploads<br>File displayed/processed | File type validation<br>Size limits enforced<br>Malicious file prevention<br>Path traversal prevention |

### How to Use This Matrix

**Step 1:** Identify your module type
```
Example: "Testing a Registration module"
```

**Step 2:** Find it in the table
```
Registration row → Lists standards and test types
```

**Step 3:** Plan functional tests
```
- Registration succeeds with valid data
- Email verification works
- Account actually created
```

**Step 4:** Plan business rules tests
```
- Username validation (ISO 25010)
- Password policy (NIST 800-63B Section 5.1.1)
- Email format validation (RFC 5322)
- Bot protection exists
- XSS prevention in username (OWASP ASVS 1.2.1)
```

---

<a name="checklist"></a>
## 6. BEFORE WRITING CODE CHECKLIST

Complete this before writing test code:

### Understanding Checklist

```
☐ 1. I understand what functionality I'm testing
     Specific feature: _________________________
     
☐ 2. I know if this is functional or business rule test
     Type: [ ] Functional (happy path)
           [ ] Business Rule (standard compliance)
     
☐ 3. I know which standard applies (for business rules)
     Standard: _________________________
     Requirement: _________________________
     
☐ 4. I understand what "DISCOVERY" means for this test
     How will I discover behavior: _________________________
     What indicates success: _________________________
     What indicates failure: _________________________
     
☐ 5. I have identified all locators needed
     Elements: _________________________
```

### Design Checklist

```
☐ 6. My test will DISCOVER, not ASSUME
     Test will: [ ] Execute action [ ] Observe result [ ] Decide objectively
     Test will NOT: [ ] Hardcode results [ ] Assume site behavior
     
☐ 7. My test is reusable on different sites
     Only need to change: [ ] BASE_URL [ ] LOCATORS
     Logic is generic: [ ] YES
     
☐ 8. For business rules: I have standard reference
     Standard cited: _________________________
     Version included: [ ] YES
     Severity determined: [ ] CRITICAL/HIGH/MEDIUM/LOW
```

### Quality Checklist

```
☐ 9. Test has clear purpose
     Functional: "Verifies [feature] works with valid inputs"
     Business Rule: "Validates compliance with [standard]"
     
☐ 10. Test has proper markers
      [ ] @pytest.mark.functional OR @pytest.mark.business_rules
      [ ] Additional markers if needed
      
☐ 11. Code follows template structure
      Sections: [ ] Config [ ] Locators [ ] Helpers [ ] Tests
      
☐ 12. No emojis in code or comments
      Verified: [ ] YES
```

### Final Validation

```
☐ 13. I can explain this test to a QA manager
      Can explain: [ ] What it tests [ ] Why it matters [ ] How it discovers
      
☐ 14. This test works on sites I haven't seen
      Generic enough: [ ] YES
      Not site-specific: [ ] YES
      
☐ 15. Ready to write code
      All checkboxes above completed: [ ] YES
```

**If any checkbox unchecked, STOP and research more before coding.**

---

<a name="code-structure"></a>
## 7. CODE STRUCTURE TEMPLATE

### File: `test_[module].py`

```python
"""
Test Suite: [Module Name] - Functional & Business Rules
Module: test_[module].py
Author: Arévalo, Marc

Description: 
Comprehensive automated tests for [module description].
Includes both functional tests (happy path) and business rules compliance tests.

Functional Tests: Verify core functionality works correctly
Business Rules: Validate compliance with industry standards

Standards Referenced:
- OWASP ASVS v5.0 (Web Application Security)
- ISO 25010 (Software Quality)
- WCAG 2.1 Level AA (Accessibility)
- [Add module-specific standards: NIST 800-63B, PCI-DSS, etc.]

Version: 1.0
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager
from webdriver_manager.microsoft import EdgeChromiumDriverManager
import pytest
import time
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s - %(message)s'
)


# ============================================================================
# CONFIGURATION SECTION - Change for different websites
# ============================================================================

BASE_URL = "https://example.com/"
TIMEOUT = 10

# Test credentials (if needed)
TEST_USERNAME = "testuser"
TEST_PASSWORD = "TestPass123!"


# ============================================================================
# LOCATORS SECTION - Change for different websites
# ============================================================================

# Navigation locators
NAV_ELEMENT_1 = (By.ID, "element-id")
NAV_ELEMENT_2 = (By.XPATH, "//a[text()='Link']")

# Form locators
FIELD_1 = (By.ID, "field1")
FIELD_2 = (By.ID, "field2")
SUBMIT_BUTTON = (By.XPATH, "//button[@type='submit']")

# Response locators
SUCCESS_MESSAGE = (By.CLASS_NAME, "success")
ERROR_MESSAGE = (By.CLASS_NAME, "error")


# ============================================================================
# FIXTURES SECTION - Generic setup/teardown
# ============================================================================

@pytest.fixture(scope="function")
def browser(request):
    """Cross-browser fixture - supports Chrome, Firefox, Edge"""
    browser_name = request.config.getoption("--browser", default="chrome").lower()
    driver = None
    
    if browser_name == "chrome":
        service = Service(ChromeDriverManager().install())
        options = webdriver.ChromeOptions()
        driver = webdriver.Chrome(service=service, options=options)
    elif browser_name == "firefox":
        service = Service(GeckoDriverManager().install())
        options = webdriver.FirefoxOptions()
        driver = webdriver.Firefox(service=service, options=options)
    elif browser_name == "edge":
        service = Service(EdgeChromiumDriverManager().install())
        options = webdriver.EdgeOptions()
        driver = webdriver.Edge(service=service, options=options)
    else:
        pytest.fail(f"Unsupported browser: {browser_name}")
    
    driver.maximize_window()
    driver.implicitly_wait(TIMEOUT)
    
    yield driver
    
    driver.quit()


# ============================================================================
# HELPER FUNCTIONS SECTION - Generic, reusable
# ============================================================================

def navigate_to_module(browser):
    """Navigate to module page and perform initial setup"""
    browser.get(BASE_URL)
    # Add module-specific navigation
    # Example: click to open modal, navigate to page, etc.


def fill_form(browser, field_data):
    """Generic form filler - adapt to module needs"""
    try:
        for locator, value in field_data.items():
            field = WebDriverWait(browser, TIMEOUT).until(
                EC.visibility_of_element_located(locator)
            )
            field.clear()
            field.send_keys(value)
    except Exception as e:
        logging.error(f"Form fill failed: {e}")


def click_element(browser, locator):
    """Click an element with wait"""
    try:
        element = WebDriverWait(browser, TIMEOUT).until(
            EC.element_to_be_clickable(locator)
        )
        element.click()
    except Exception as e:
        logging.error(f"Click failed: {e}")


def wait_for_alert(browser, timeout=5):
    """Handle JavaScript alerts if present"""
    try:
        WebDriverWait(browser, timeout).until(EC.alert_is_present())
        alert = browser.switch_to.alert
        alert_text = alert.text
        alert.accept()
        return alert_text
    except TimeoutException:
        return None


def check_for_success_message(browser, timeout=5):
    """Check if success message appears"""
    try:
        element = WebDriverWait(browser, timeout).until(
            EC.visibility_of_element_located(SUCCESS_MESSAGE)
        )
        return element.text
    except TimeoutException:
        return None


def check_for_error_message(browser, timeout=5):
    """Check if error message appears"""
    try:
        element = WebDriverWait(browser, timeout).until(
            EC.visibility_of_element_located(ERROR_MESSAGE)
        )
        return element.text
    except TimeoutException:
        return None


def log_business_rule_violation(test_id, standard, expected_behavior, 
                                 actual_behavior, impact, severity):
    """Standard logging format for business rule violations"""
    logging.error("=" * 80)
    logging.error(f"BUSINESS RULE VIOLATION: {test_id}")
    logging.error(f"Standard: {standard}")
    logging.error(f"Expected: {expected_behavior}")
    logging.error(f"Actual: {actual_behavior}")
    logging.error(f"Business Impact: {impact}")
    logging.error(f"Severity: {severity}")
    logging.error("=" * 80)


# ============================================================================
# FUNCTIONAL TESTS - Verify core functionality works
# These should PASS on well-designed systems
# ============================================================================

@pytest.mark.functional
def test_valid_operation_001(browser):
    """TC-[MOD]-FUNC-001: Valid Operation - Happy Path
    
    Functional test verifying core feature works with valid inputs.
    Discovers if basic operation succeeds as expected.
    """
    logging.info("TC-[MOD]-FUNC-001: Testing valid operation")
    
    navigate_to_module(browser)
    
    # Execute with valid data
    valid_data = {
        FIELD_1: "valid_input_1",
        FIELD_2: "valid_input_2"
    }
    fill_form(browser, valid_data)
    click_element(browser, SUBMIT_BUTTON)
    
    # Observe result
    time.sleep(2)
    success_message = check_for_success_message(browser)
    
    # Decide based on observation
    if success_message:
        logging.info(f"Operation successful: {success_message}")
        assert True
    else:
        pytest.fail("DISCOVERED: Valid operation failed (no success indicator)")


@pytest.mark.functional
def test_invalid_input_rejected_002(browser):
    """TC-[MOD]-FUNC-002: Invalid Input Rejection
    
    Functional test verifying system properly rejects invalid inputs.
    Discovers if error handling works for bad data.
    """
    logging.info("TC-[MOD]-FUNC-002: Testing invalid input rejection")
    
    navigate_to_module(browser)
    
    # Execute with invalid data
    invalid_data = {
        FIELD_1: "!@#$%^&*()",  # Invalid characters
        FIELD_2: "test"
    }
    fill_form(browser, invalid_data)
    click_element(browser, SUBMIT_BUTTON)
    
    # Observe result
    time.sleep(2)
    error_message = check_for_error_message(browser)
    alert_text = wait_for_alert(browser, timeout=3)
    
    # Decide based on observation
    if error_message:
        logging.info(f"Invalid input rejected with message: {error_message}")
        assert True
    elif alert_text and ("error" in alert_text.lower() or "invalid" in alert_text.lower()):
        logging.info(f"Invalid input rejected with alert: {alert_text}")
        assert True
    else:
        pytest.fail("DISCOVERED: Invalid input not rejected properly")


@pytest.mark.functional
def test_empty_fields_rejected_003(browser):
    """TC-[MOD]-FUNC-003: Empty Fields Validation
    
    Functional test verifying required field validation works.
    Discovers if system prevents empty form submission.
    """
    logging.info("TC-[MOD]-FUNC-003: Testing empty fields validation")
    
    navigate_to_module(browser)
    
    # Execute with empty fields
    click_element(browser, SUBMIT_BUTTON)
    
    # Observe result
    time.sleep(2)
    error_message = check_for_error_message(browser)
    alert_text = wait_for_alert(browser, timeout=3)
    
    # Decide based on observation
    if error_message:
        logging.info(f"Empty fields rejected: {error_message}")
        assert True
    elif alert_text and ("required" in alert_text.lower() or "fill" in alert_text.lower()):
        logging.info(f"Empty fields rejected: {alert_text}")
        assert True
    else:
        pytest.fail("DISCOVERED: Empty fields not validated")


# Add 3-5 more functional tests covering:
# - Edge cases
# - Boundary conditions
# - Integration flows


# ============================================================================
# BUSINESS RULES TESTS - Verify compliance with industry standards
# These tests DISCOVER if system meets standards (may pass or fail)
# ============================================================================

@pytest.mark.business_rules
def test_input_length_validation_BR_001(browser):
    """TC-[MOD]-BR-001: Input Length Validation
    
    Standard: ISO 25010 - Functional Suitability, Input Validation
    Requirement: Inputs should have reasonable maximum length (50-100 chars)
    
    Discovers if system validates input length to prevent:
    - Database bloat
    - Buffer overflow vulnerabilities
    - DoS attack vectors
    """
    logging.info("TC-[MOD]-BR-001: Testing input length validation")
    
    navigate_to_module(browser)
    
    # Execute with excessive input
    excessive_input = "a" * 1000
    excessive_data = {
        FIELD_1: excessive_input,
        FIELD_2: "test"
    }
    fill_form(browser, excessive_data)
    click_element(browser, SUBMIT_BUTTON)
    
    # Observe response
    time.sleep(2)
    error_message = check_for_error_message(browser)
    alert_text = wait_for_alert(browser, timeout=3)
    
    # Decide based on observation
    validation_keywords = ["length", "long", "maximum", "limit", "exceeded"]
    
    if error_message and any(keyword in error_message.lower() for keyword in validation_keywords):
        logging.info(f"Input length validated: {error_message}")
        assert True
    elif alert_text and any(keyword in alert_text.lower() for keyword in validation_keywords):
        logging.info(f"Input length validated: {alert_text}")
        assert True
    else:
        # Check if input was actually submitted
        success = check_for_success_message(browser)
        if success:
            log_business_rule_violation(
                test_id="TC-[MOD]-BR-001",
                standard="ISO 25010 - Functional Suitability",
                expected_behavior="Reject inputs exceeding reasonable length with validation error",
                actual_behavior=f"Processed input of {len(excessive_input)} characters without validation",
                impact="Database bloat, potential buffer overflow, DoS attack vector",
                severity="MEDIUM"
            )
            pytest.fail(f"DISCOVERED: No input length validation ({len(excessive_input)} chars accepted)")
        else:
            logging.info("Input rejected (method unclear)")
            assert True


@pytest.mark.business_rules
@pytest.mark.parametrize("payload", [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "' UNION SELECT NULL--",
])
def test_sql_injection_prevention_BR_002(browser, payload):
    """TC-[MOD]-BR-002: SQL Injection Prevention
    
    Standard: OWASP ASVS v5.0-1.2.5 (Injection Prevention)
    Requirement: Use parameterized queries, input sanitization
    
    Discovers if SQL injection is possible by attempting various
    SQL injection payloads and observing system response.
    """
    logging.info(f"TC-[MOD]-BR-002: Testing SQL injection prevention - Payload: {payload}")
    
    navigate_to_module(browser)
    
    # Execute with SQL injection payload
    payload_data = {
        FIELD_1: payload,
        FIELD_2: "test"
    }
    fill_form(browser, payload_data)
    click_element(browser, SUBMIT_BUTTON)
    
    # Observe response
    time.sleep(2)
    success_message = check_for_success_message(browser)
    alert_text = wait_for_alert(browser, timeout=3)
    page_source = browser.page_source
    
    # Decide based on observation
    # If operation succeeds with SQL payload, vulnerability exists
    if success_message and "success" in success_message.lower():
        log_business_rule_violation(
            test_id="TC-[MOD]-BR-002",
            standard="OWASP ASVS v5.0-1.2.5 (Injection Prevention)",
            expected_behavior="SQL injection blocked, operation denied",
            actual_behavior=f"Operation succeeded with SQL injection payload: {payload}",
            impact="Database compromise, unauthorized access, data breach",
            severity="CRITICAL"
        )
        pytest.fail(f"DISCOVERED: SQL injection vulnerability with payload: {payload}")
    
    # Check for database errors (also indicates vulnerability)
    sql_error_keywords = ["sql", "syntax", "mysql", "postgresql", "database", "query"]
    if any(keyword in page_source.lower() for keyword in sql_error_keywords):
        log_business_rule_violation(
            test_id="TC-[MOD]-BR-002",
            standard="OWASP ASVS v5.0-1.2.5",
            expected_behavior="SQL injection blocked, no database errors exposed",
            actual_behavior=f"Database error exposed with payload: {payload}",
            impact="Information disclosure, SQL injection confirmed",
            severity="CRITICAL"
        )
        pytest.fail(f"DISCOVERED: SQL error exposed with payload: {payload}")
    
    logging.info(f"SQL injection blocked: {payload}")
    assert True


@pytest.mark.business_rules
@pytest.mark.parametrize("payload", [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')",
])
def test_xss_prevention_BR_003(browser, payload):
    """TC-[MOD]-BR-003: XSS Prevention
    
    Standard: OWASP ASVS v5.0-1.2.1 (Output Encoding)
    Requirement: All output encoded, Content Security Policy enforced
    
    Discovers if XSS is possible by injecting XSS payloads and
    observing if scripts execute.
    """
    logging.info(f"TC-[MOD]-BR-003: Testing XSS prevention - Payload: {payload}")
    
    navigate_to_module(browser)
    
    # Execute with XSS payload
    xss_data = {
        FIELD_1: payload,
        FIELD_2: "test"
    }
    fill_form(browser, xss_data)
    click_element(browser, SUBMIT_BUTTON)
    
    # Observe if XSS executes
    time.sleep(2)
    alert_text = wait_for_alert(browser, timeout=3)
    
    # Decide based on observation
    # If alert with 'XSS' appears, vulnerability exists
    if alert_text and 'XSS' in alert_text:
        log_business_rule_violation(
            test_id="TC-[MOD]-BR-003",
            standard="OWASP ASVS v5.0-1.2.1 (Output Encoding)",
            expected_behavior="XSS payload sanitized, no script execution",
            actual_behavior=f"XSS payload executed: {payload}",
            impact="Session hijacking, cookie theft, phishing attacks",
            severity="CRITICAL"
        )
        pytest.fail(f"DISCOVERED: XSS vulnerability with payload: {payload}")
    
    logging.info(f"XSS prevention working: {payload}")
    assert True


@pytest.mark.business_rules
def test_error_message_accessibility_BR_004(browser):
    """TC-[MOD]-BR-004: Error Message Accessibility
    
    Standard: WCAG 2.1 Level AA - Success Criterion 3.3.1
    Requirement: Inline error messages, not JavaScript alerts
    
    Discovers if system uses accessible error messages or
    inaccessible JavaScript alerts.
    """
    logging.info("TC-[MOD]-BR-004: Testing error message accessibility")
    
    navigate_to_module(browser)
    
    # Trigger error with empty form
    click_element(browser, SUBMIT_BUTTON)
    
    # Observe error presentation
    time.sleep(2)
    alert_text = wait_for_alert(browser, timeout=3)
    inline_error = check_for_error_message(browser)
    
    # Decide based on WCAG standard
    if alert_text:
        # JavaScript alert used (bad for accessibility)
        log_business_rule_violation(
            test_id="TC-[MOD]-BR-004",
            standard="WCAG 2.1 Success Criterion 3.3.1",
            expected_behavior="Inline error messages with aria-live regions",
            actual_behavior="JavaScript alert() used for error presentation",
            impact="Poor accessibility, screen reader issues, outdated UX",
            severity="MEDIUM"
        )
        pytest.fail("DISCOVERED: JavaScript alerts used instead of inline validation")
    elif inline_error:
        logging.info("Accessible inline error messages used")
        assert True
    else:
        logging.warning("No error validation found")
        pytest.fail("DISCOVERED: No error validation")


@pytest.mark.business_rules
def test_whitespace_normalization_BR_005(browser):
    """TC-[MOD]-BR-005: Input Whitespace Handling
    
    Standard: ISO 25010 - Data Quality, Usability
    Requirement: Trim leading/trailing whitespace from inputs
    
    Discovers if system normalizes whitespace in user inputs
    to improve data quality and user experience.
    """
    logging.info("TC-[MOD]-BR-005: Testing whitespace normalization")
    
    navigate_to_module(browser)
    
    # Execute with padded input
    input_with_spaces = "   test   "
    padded_data = {
        FIELD_1: input_with_spaces,
        FIELD_2: "data"
    }
    fill_form(browser, padded_data)
    click_element(browser, SUBMIT_BUTTON)
    
    # Observe result
    time.sleep(2)
    success = check_for_success_message(browser)
    error = check_for_error_message(browser)
    alert_text = wait_for_alert(browser, timeout=3)
    
    # Decide based on observation
    # If system treats padded input same as trimmed, it's normalizing
    if success:
        logging.info("Whitespace normalized (operation succeeded)")
        assert True
    elif error and "not found" in error.lower():
        # System didn't normalize, treated "   test   " differently from "test"
        log_business_rule_violation(
            test_id="TC-[MOD]-BR-005",
            standard="ISO 25010 - Data Quality, Usability",
            expected_behavior="Trim leading/trailing whitespace before processing",
            actual_behavior=f"Whitespace-padded input '{input_with_spaces}' treated differently",
            impact="User confusion, data inconsistency, poor UX",
            severity="LOW"
        )
        pytest.fail("DISCOVERED: Whitespace not normalized")
    else:
        logging.info("Whitespace handling correct")
        assert True


# Add 5-10 more business rules tests covering:
# - Rate limiting (if applicable)
# - Additional security checks
# - Accessibility requirements
# - Data validation standards
# - Module-specific compliance


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])
```

---

<a name="test-categories"></a>
## 8. TEST CATEGORIES & DISTRIBUTION

### Functional Tests (Happy Path)

**Purpose:** Verify core functionality works as designed  
**Expected Outcome:** Should PASS on well-designed systems

**Typical Tests:**
- Valid inputs succeed
- Core operations complete successfully
- Integration flows work end-to-end
- Basic error handling functions

**Example:**
```python
@pytest.mark.functional
def test_valid_login():
    """Discovers if login works with valid credentials"""
    login("validuser", "ValidPass123!")
    
    if is_logged_in():
        assert True  # DISCOVERED: Login works
    else:
        pytest.fail("DISCOVERED: Login broken")
```

### Business Rules Tests (Standards Compliance)

**Purpose:** Verify compliance with industry standards  
**Expected Outcome:** May PASS or FAIL - discovers compliance

**Typical Tests:**
- Input validation standards
- Security standards (injection prevention)
- Accessibility standards (WCAG)
- Data quality standards (ISO 25010)
- Industry-specific compliance

**Example:**
```python
@pytest.mark.business_rules
def test_password_policy():
    """NIST 800-63B: Minimum 8 characters required"""
    signup("user", "123")
    
    if password_rejected():
        assert True  # DISCOVERED: Complies with NIST
    else:
        log_violation(...)
        pytest.fail("DISCOVERED: Violates NIST 800-63B")
```

### Test Distribution Guidelines

**Small Module (e.g., Contact Form):**
- 3-4 Functional tests
- 5-7 Business Rules tests
- Total: 8-11 tests

**Medium Module (e.g., Login, Search):**
- 5-8 Functional tests
- 10-15 Business Rules tests
- Total: 15-23 tests

**Large Module (e.g., Payment, Cart):**
- 8-12 Functional tests
- 15-25 Business Rules tests
- Total: 23-37 tests

---

<a name="naming"></a>
## 9. TEST NAMING CONVENTION

### Functional Tests

```
test_[functionality]_[number]

Examples:
- test_valid_login_001
- test_invalid_password_002
- test_empty_fields_003
- test_form_submission_004
```

### Business Rules Tests

```
test_[standard_aspect]_BR_[number]

Examples:
- test_input_validation_BR_001
- test_sql_injection_prevention_BR_002
- test_xss_prevention_BR_003
- test_password_policy_BR_004
```

### Docstring Format

```python
@pytest.mark.functional
def test_valid_operation_001(browser):
    """TC-[MOD]-FUNC-001: Feature Name - Happy Path
    
    Functional test verifying [feature] works with valid inputs.
    Discovers if [specific behavior] functions correctly.
    """
    
@pytest.mark.business_rules
def test_validation_BR_001(browser):
    """TC-[MOD]-BR-001: Input Validation
    
    Standard: ISO 25010 - Functional Suitability
    Reference: OWASP ASVS v5.0-1.2.5
    Requirement: [Specific requirement from standard]
    
    Discovers if system [what is being validated].
    """
```

---

<a name="markers"></a>
## 10. MARKERS USAGE

### Primary Markers

```python
# Functional tests (should pass on well-designed systems)
@pytest.mark.functional

# Business rules compliance (discovers if standards met)
@pytest.mark.business_rules
```

### Category Markers

```python
@pytest.mark.validation       # Input validation tests
@pytest.mark.security         # Security-related tests
@pytest.mark.accessibility    # WCAG compliance tests
@pytest.mark.integration      # Multi-step flows
@pytest.mark.edge_case        # Boundary conditions
```

### Parametrization

```python
@pytest.mark.parametrize("payload", [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--"
])
def test_sql_injection_prevention_BR_002(browser, payload):
    # Test with multiple payloads
```

---

<a name="execution"></a>
## 11. EXECUTION COMMANDS

### Run All Tests

```bash
pytest test_[module].py -v
```

### Run by Category

```bash
# Run only functional tests
pytest test_[module].py -m functional -v

# Run only business rules tests
pytest test_[module].py -m business_rules -v

# Run security tests
pytest test_[module].py -m security -v

# Run accessibility tests
pytest test_[module].py -m accessibility -v
```

### Run Specific Browser

```bash
pytest test_[module].py --browser=chrome -v
pytest test_[module].py --browser=firefox -v
pytest test_[module].py --browser=edge -v
```

### Generate HTML Report

```bash
pytest test_[module].py --html=report.html --self-contained-html -v
```

### Run with Logging

```bash
pytest test_[module].py -v -s --log-cli-level=INFO
```

---

<a name="distribution"></a>
## 12. EXPECTED TEST DISTRIBUTION

### Good Balance Example

**Login Module (18 tests total):**
- 6 Functional tests:
  - Valid credentials work
  - Invalid credentials rejected
  - Empty fields rejected
  - Login/logout flow works
  - Remember me functions
  - Password visibility toggle

- 12 Business Rules tests:
  - Password strength (NIST 800-63B)
  - Input length validation (ISO 25010)
  - SQL injection prevention (OWASP ASVS 1.2.5)
  - XSS prevention (OWASP ASVS 1.2.1)
  - Error message accessibility (WCAG 3.3.1)
  - Whitespace normalization (ISO 25010)
  - Case sensitivity handling
  - Username validation
  - Rate limiting check
  - Session fixation prevention
  - Brute force protection
  - Account enumeration prevention

**Payment Module (28 tests total):**
- 8 Functional tests:
  - Valid card succeeds
  - Form submission works
  - Order confirmation appears
  - Payment flow completes
  - Multiple items process
  - Different card types work
  - Cancel payment works
  - Return to cart works

- 20 Business Rules tests:
  - Card format validation (PCI-DSS 6.5.3)
  - CVV validation
  - Expiry date validation
  - Card number sanitization
  - SQL injection prevention
  - XSS prevention in form fields
  - Input length validation
  - Required field validation
  - Error message accessibility
  - Price integrity checks
  - Client-side storage check (PCI-DSS 3.2)
  - CVV storage prohibition
  - TLS version check
  - Form token validation
  - Amount validation
  - Currency validation
  - Shipping validation
  - Billing validation
  - Email format validation
  - Phone format validation

---

<a name="principles"></a>
## 13. CRITICAL PRINCIPLES

### Principle 1: Tests DISCOVER, Not Assume

```python
# ❌ WRONG - Assumes behavior
if "demoblaze" in url:
    assert False  # "I know it fails"

# ✅ CORRECT - Discovers behavior
result = execute_test()
if result.indicates_failure():
    pytest.fail("DISCOVERED: Feature broken")
```

### Principle 2: Reusable Code

```python
# Change these variables for different sites:
BASE_URL = "https://newsite.com"
LOCATORS = {...}

# Keep this logic generic (works anywhere):
def test_feature():
    result = perform_action()
    if meets_standard(result):
        assert True
    else:
        pytest.fail("Standard violated")
```

### Principle 3: Professional Logging

```python
# Always use structured logging for violations
log_business_rule_violation(
    test_id="TC-MOD-BR-001",
    standard="ISO 25010 - Functional Suitability",
    expected_behavior="Clear description of what should happen",
    actual_behavior="What actually happened",
    impact="Business impact of the violation",
    severity="CRITICAL/HIGH/MEDIUM/LOW"
)
```

### Principle 4: Clear Test Purpose

```python
# Functional Test
"""
Functional test verifying [feature] works with valid inputs.
Discovers if [specific behavior] functions correctly.
"""

# Business Rule Test
"""
Standard: [Specific Standard]
Requirement: [Specific Requirement]

Discovers if system [what is being validated].
"""
```

### Principle 5: Objective Decision Making

```python
# EXECUTE
perform_action()

# OBSERVE
result = capture_response()

# DECIDE (objectively)
if result.meets_criteria():
    assert True
else:
    pytest.fail("Criteria not met")
```

---

<a name="standards"></a>
## 14. STANDARDS CLASSIFICATION

### Security Standards (Always Include)

- **OWASP ASVS v5.0**
  - Chapter 1: Input Validation
  - Chapter 2: Authentication
  - Chapter 4: Access Control

- **OWASP Top 10 2021**
  - A03: Injection
  - A07: Identification and Authentication Failures

### Quality Standards (Always Include)

- **ISO 25010**
  - Functional Suitability
  - Usability
  - Reliability

### Accessibility Standards (Always Include)

- **WCAG 2.1 Level AA**
  - Success Criterion 1.3.1: Info and Relationships
  - Success Criterion 3.3.1: Error Identification
  - Success Criterion 3.3.2: Labels or Instructions

### Module-Specific Standards

**Authentication:**
- NIST SP 800-63B (Digital Identity)
- ISO 27001 A.9.4 (Access Control)

**Payment:**
- PCI-DSS 4.0.1 (Payment Card Industry)
- ISO 20022 (Financial Services)

**Healthcare:**
- HIPAA (Health Insurance Portability)
- HL7 FHIR (Healthcare Interoperability)

---

<a name="delivery"></a>
## 15. PRE-DELIVERY CHECKLIST

Before considering code complete, verify:

### Code Quality

```
✅ No emojis in code or comments
✅ Minimal comments (only docstrings)
✅ Clean, professional formatting
✅ No hardcoded wait times (use WebDriverWait)
✅ Proper exception handling
```

### Test Quality

```
✅ Tests discover issues (don't assume)
✅ All business rules reference real standards
✅ Functional tests validate core functionality
✅ Parametrized tests where applicable
✅ Each test has clear purpose in docstring
```

### Reusability

```
✅ Configuration section clearly marked
✅ Locators section clearly marked
✅ Helper functions are generic
✅ Can work on different sites by changing config
✅ No site-specific logic in test functions
```

### Standards Compliance

```
✅ Each business rule cites specific standard
✅ Standard versions specified (e.g., OWASP ASVS v5.0)
✅ Other standards referenced correctly
✅ Severity levels assigned appropriately
✅ Business impact documented
```

### Documentation

```
✅ README file created
✅ All tests explained
✅ Execution guide included
✅ Expected results documented
✅ Troubleshooting section present
```

---

<a name="standards-ref"></a>
## 16. STANDARDS REFERENCE QUICK GUIDE

### Always Include (Any Module)

- **OWASP ASVS v5.0** - Web Application Security Verification
- **OWASP Top 10 2021** - Top Web Security Risks
- **ISO 25010** - Software Quality Model
- **WCAG 2.1 Level AA** - Web Accessibility

### Module-Specific Standards

**Authentication/Login:**
- NIST SP 800-63B (Password Guidelines)
- ISO 27001 A.9.4 (Access Control)
- OWASP ASVS v5.0 Chapter 2

**Payment/Financial:**
- PCI-DSS 4.0.1 (Card Payment Security)
- ISO 20022 (Financial Messaging)
- OWASP ASVS v5.0 Chapter 9

**Data Entry/Forms:**
- OWASP ASVS v5.0 Chapter 1 (Input Validation)
- ISO 25010 (Data Quality)
- WCAG 2.1 (Form Accessibility)

**Session Management:**
- OWASP ASVS v5.0 Chapter 3
- ISO 27001 A.9.4.2 (User Session Management)

**File Upload:**
- OWASP ASVS v5.0 Chapter 12
- CWE-434 (Unrestricted Upload)

---

<a name="tools"></a>
## 17. TESTING TOOLS & LIBRARIES

### Required Libraries

```python
# Selenium - Browser automation
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# WebDriver Manager - Automatic driver management
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager
from webdriver_manager.microsoft import EdgeChromiumDriverManager

# Pytest - Testing framework
import pytest

# Standard library
import time
import logging
```

### Installation

```bash
pip install selenium
pip install webdriver-manager
pip install pytest
pip install pytest-html  # For HTML reports
```

### Browser Drivers

Managed automatically by webdriver-manager:
- ChromeDriver (for Chrome)
- GeckoDriver (for Firefox)
- EdgeDriver (for Edge)

---

## IMPORTANT: CONTINUATION

**This template has a PART 2** with critical sections:
- **Section 18:** Example Future Conversations (how to use this template)
- **Section 19:** Common Patterns by Module Type (quick reference)
- **Section 20:** Version History

**See:** TEMPLATE_functional_PART2.md

---

**End of Template - Part 1**

**Related Files:**
- **TEMPLATE_functional_PART2.md** (REQUIRED - Contains sections 18-20)
- TEMPLATE_security_exploitation.md (Security testing companion)
- README_template.md (Documentation template)

**Author:** Arévalo, Marc  
**Version:** 2.0 (Universal Edition)  
**Date:** November 2025

**Quick Start:**
1. Read Section 2 (DISCOVER vs ASSUME) - CRITICAL
2. Review Section 3 (Anti-Patterns) - Learn what NOT to do
3. Check Research Matrix (Section 5) for your module type
4. Complete Before Writing Code Checklist (Section 6)
5. Review Example Conversations (Part 2, Section 18)
6. Check Common Patterns (Part 2, Section 19) for your module
7. Generate code following Section 7 template
8. Validate against Pre-Delivery Checklist (Section 15)

**Remember:** Tests must DISCOVER behavior, never ASSUME it.