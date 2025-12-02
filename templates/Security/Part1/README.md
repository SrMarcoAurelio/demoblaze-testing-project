# TEMPLATE: Security & Exploitation Tests

**Purpose:** Universal template for active security testing and vulnerability exploitation
**Use Case:** ANY web application module across ANY domain (Login, Payment, Cart, Search, Profile, Admin, API, etc.)
**Core Philosophy:** Tests DISCOVER vulnerabilities through active exploitation - NEVER assume behavior
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
8. [Test Categories & Examples](#test-categories)
9. [Test Naming Convention](#naming)
10. [Markers Usage](#markers)
11. [Execution Commands](#execution)
12. [Expected Test Distribution](#distribution)
13. [Critical Principles](#principles)
14. [CVSS Scoring Guide](#cvss)
15. [Pre-Delivery Checklist](#delivery)
16. [Security Standards Reference](#standards)
17. [Exploitation Tools & Libraries](#tools)
18. [Example Future Conversation](#example-conversation)
19. [Common Vulnerabilities by Module](#vulnerabilities-by-module)
20. [Version History](#version)

---

<a name="philosophy"></a>
## 1. PHILOSOPHY & CORE PRINCIPLES

### The Security Testing Mindset

Security testing is fundamentally different from functional testing:

**Functional Testing:** "Does it work as designed?"
**Security Testing:** "Can I break it? Can I exploit it? Can I bypass it?"

### Core Philosophy: DISCOVERY, Not Assumption

**The Golden Rule:**

> **Tests must DISCOVER vulnerabilities by EXECUTING exploits and OBSERVING results.**
> **NEVER write tests that ASSUME the application's behavior.**

**Why This Matters:**

When you test a new application in the future:
- You DON'T KNOW if it's vulnerable
- You DON'T KNOW how it behaves
- You DON'T KNOW what defenses it has

**Therefore:**
- Tests must DISCOVER by TRYING
- Tests must OBSERVE what happens
- Tests must DECIDE objectively if a vulnerability exists

### The Three Questions

Before writing ANY security test, ask:

1. **"What am I testing for?"**
   - Specific vulnerability or exploit
   - Industry standard being validated

2. **"How would an attacker exploit this?"**
   - Actual payload or attack technique
   - Expected behavior if vulnerable

3. **"How will I DISCOVER if it's vulnerable?"**
   - Execute the attack
   - Observe the response
   - Compare against secure behavior

### Universal Applicability

This template works for:
- E-commerce sites (DemoBlaze, Amazon, etc.)
- Banking applications
- Social networks
- SaaS platforms
- APIs
- Admin panels
- ANY web application

**How?**
- Change BASE_URL
- Change LOCATORS
- Keep exploitation logic generic
- Tests discover behavior objectively

---

<a name="discover-vs-assume"></a>
## 2. DISCOVER vs ASSUME - THE FOUNDATION

This is THE MOST CRITICAL concept. Master this and your tests will be professional and reusable.

### What Does "DISCOVER" Mean?

**DISCOVER = Execute → Observe → Decide**

```python
# Step 1: EXECUTE the attack
inject_sql_payload(browser, "' OR '1'='1")

# Step 2: OBSERVE what happened
result = get_response(browser)

# Step 3: DECIDE if vulnerable
if "success" in result or "welcome" in result:
    # DISCOVERED: SQL injection works
    pytest.fail("VULNERABILITY: SQL Injection")
else:
    # DISCOVERED: SQL injection blocked
    assert True
```

### What Does "ASSUME" Mean?

**ASSUME = Know → Hardcode → Predict**

```python
# BAD: Assumes site is vulnerable
def test_sql_injection():
    inject_sql_payload()
    # I KNOW DemoBlaze is vulnerable, so I assume it will fail
    assert False  # WRONG!

# BAD: Assumes site behavior
def test_negative_quantity():
    # I KNOW this site accepts negative quantities
    add_to_cart(quantity=-5)
    assert cart_total < 0  # Assumes specific behavior
```

---

### EXAMPLE 1: SQL Injection

#### ❌ ASSUME (Wrong Way)
```python
def test_sql_injection_WRONG():
    """I know DemoBlaze is vulnerable to SQL injection"""

    # Hardcoded assumption about site behavior
    inject_payload("' OR '1'='1")

    # Assumes injection will work
    assert False, "Site is vulnerable"  # WRONG!
```

**Why This Is Wrong:**
- Assumes DemoBlaze behavior
- Won't work on a secure site
- Not discovering, just stating known facts
- Not reusable

#### ✅ DISCOVER (Right Way)
```python
def test_sql_injection_CORRECT():
    """OWASP ASVS v5.0-1.2.5: SQL Injection Prevention

    Discovers if SQL injection is possible by attempting exploitation
    and observing system response.
    """

    # Step 1: EXECUTE exploit
    payload = "' OR '1'='1"
    inject_payload(browser, payload)
    browser.find_element(*SUBMIT_BUTTON).click()

    # Step 2: OBSERVE response
    response = wait_for_alert(browser)
    page_source = browser.page_source

    # Step 3: DECIDE based on objective criteria
    # If exploit succeeds, system is vulnerable
    if (response and "success" in response.lower()) or \
       ("welcome" in page_source.lower() and "dashboard" in page_source.lower()):

        # DISCOVERED: Vulnerability exists
        log_exploitation_attempt(
            vulnerability="SQL Injection",
            payload=payload,
            result="EXPLOITED - SQL injection successful",
            standard="OWASP ASVS v5.0-1.2.5"
        )
        pytest.fail(f"VULNERABILITY: SQL injection with payload: {payload}")

    # If exploit fails, system is secure
    else:
        # DISCOVERED: System is secure
        logging.info("SQL injection blocked (system secure)")
        assert True
```

**Why This Is Correct:**
- Executes actual exploit
- Observes real response
- Decides objectively
- Works on ANY site (secure or vulnerable)
- Reusable

---

### EXAMPLE 2: Negative Quantity Exploit

#### ❌ ASSUME (Wrong Way)
```python
def test_negative_quantity_WRONG():
    """Tests negative quantity (assuming it fails)"""

    # I know this site accepts negative quantities
    add_item(quantity=-5)

    # Assumes cart will have negative total
    cart_total = get_cart_total()
    assert cart_total < 0  # Assumes specific behavior
```

**Problems:**
- Assumes site accepts negative quantities
- Won't work on secure site
- Test would fail on secure site (incorrectly)

#### ✅ DISCOVER (Right Way)
```python
def test_negative_quantity_CORRECT(browser):
    """OWASP WSTG-BUSL-10: Business Logic - Negative Quantity

    Discovers if application accepts negative quantities by
    attempting the exploit and observing cart behavior.
    """

    # Step 1: EXECUTE exploit attempt
    browser.get(BASE_URL + "/product/1")

    # Try to inject negative quantity via JavaScript
    browser.execute_script("""
        document.querySelector('#quantity').value = '-5';
    """)

    browser.find_element(*ADD_TO_CART_BUTTON).click()
    time.sleep(2)

    # Navigate to cart
    browser.find_element(*CART_LINK).click()
    time.sleep(2)

    # Step 2: OBSERVE what happened
    cart_items = browser.find_elements(By.CSS_SELECTOR, ".cart-item")
    cart_total_element = browser.find_element(*CART_TOTAL)
    cart_total = parse_price(cart_total_element.text)

    # Step 3: DECIDE based on observation
    # Check if negative quantity was accepted
    negative_found = False
    for item in cart_items:
        quantity_text = item.find_element(By.CSS_SELECTOR, ".quantity").text
        if "-" in quantity_text:
            negative_found = True
            break

    # If negative quantity accepted = vulnerable
    if negative_found or cart_total < 0:
        # DISCOVERED: Business logic flaw exists
        log_exploitation_attempt(
            vulnerability="Negative quantity accepted",
            payload="quantity=-5",
            result=f"EXPLOITED - Cart total: {cart_total}",
            standard="OWASP WSTG-BUSL-10"
        )
        pytest.fail(f"VULNERABILITY: Negative quantities accepted")

    # If rejected = secure
    else:
        # DISCOVERED: System validates correctly
        logging.info("Negative quantity blocked (system secure)")
        assert True
```

**Why This Is Correct:**
- Tries to exploit without assuming
- Observes actual cart state
- Works on secure AND vulnerable sites
- Discovers behavior objectively

---

### EXAMPLE 3: Rate Limiting

#### ❌ ASSUME (Wrong Way)
```python
def test_rate_limiting_WRONG():
    """Tests rate limiting (assuming no protection)"""

    # I know this site has no rate limiting
    for i in range(1000):
        submit_form()

    # Assumes all requests succeed
    assert True  # Assumes no protection
```

**Problems:**
- Assumes no rate limiting exists
- Doesn't observe actual responses
- Won't discover if rate limiting IS present

#### ✅ DISCOVER (Right Way)
```python
def test_rate_limiting_CORRECT(browser):
    """OWASP API Security - API6: Unrestricted Access

    Discovers if rate limiting is implemented by sending
    rapid requests and observing when blocking occurs.
    """

    browser.get(BASE_URL)

    # Counters to track discoveries
    successful_requests = 0
    blocked_requests = 0
    rate_limit_triggered = False

    # Step 1: EXECUTE rapid requests
    for i in range(100):  # Try 100 rapid requests
        try:
            browser.find_element(*SUBMIT_BUTTON).click()
            time.sleep(0.01)  # Very fast

            # Step 2: OBSERVE response
            page_source = browser.page_source.lower()

            # Check for rate limit indicators
            if ("rate limit" in page_source or
                "too many requests" in page_source or
                "429" in page_source or
                "slow down" in page_source):

                # DISCOVERED: Rate limiting exists!
                rate_limit_triggered = True
                blocked_requests += 1
                logging.info(f"Rate limit discovered after {successful_requests} requests")
                break

            # Check if request succeeded
            if "success" in page_source or check_success_indicator(browser):
                successful_requests += 1
            else:
                blocked_requests += 1

        except Exception as e:
            # Exception might indicate rate limiting
            if "429" in str(e) or "timeout" in str(e).lower():
                rate_limit_triggered = True
                logging.info("Rate limit discovered via exception")
                break

    # Step 3: DECIDE based on discovery
    if rate_limit_triggered:
        # DISCOVERED: Rate limiting works
        logging.info(f"Rate limiting OK - Triggered after {successful_requests} requests")
        assert True

    elif successful_requests >= 50:
        # DISCOVERED: No rate limiting (50+ requests succeeded)
        log_exploitation_attempt(
            vulnerability="No rate limiting",
            payload=f"{successful_requests} rapid automated requests",
            result=f"EXPLOITED - All {successful_requests} requests succeeded",
            standard="OWASP API Security - API6"
        )
        pytest.fail(f"VULNERABILITY: No rate limiting - {successful_requests} requests succeeded")

    else:
        # Unclear - maybe rate limiting, maybe other protection
        logging.info(f"Rate limiting status unclear - {successful_requests} succeeded, {blocked_requests} blocked")
        assert True  # Conservative pass
```

**Why This Is Correct:**
- Executes actual rapid requests
- Observes each response
- Discovers when/if blocking occurs
- Objective decision based on observation
- Works on sites with OR without rate limiting

---

### EXAMPLE 4: Price Manipulation

#### ❌ ASSUME (Wrong Way)
```python
def test_price_manipulation_WRONG():
    """Tests price manipulation (assuming it works)"""

    # I know prices are client-side
    change_price_to_zero()

    # Assumes checkout will accept $0
    assert final_price == 0  # Assumes vulnerability
```

#### ✅ DISCOVER (Right Way)
```python
def test_price_manipulation_CORRECT(browser):
    """OWASP Top 10 - A04: Insecure Design - Price Manipulation

    Discovers if client-side price manipulation is possible by
    attempting to modify price and observing if change persists.
    """

    browser.get(BASE_URL + "/product/1")

    # Step 1: CAPTURE original price
    original_price_element = browser.find_element(*PRICE_ELEMENT)
    original_price = parse_price(original_price_element.text)
    logging.info(f"Original price: ${original_price}")

    # Step 2: EXECUTE manipulation attempt
    manipulated_price = "0.01"
    browser.execute_script(f"""
        document.querySelector('#price').innerText = '${manipulated_price}';
        document.querySelector('#price').setAttribute('data-price', '{manipulated_price}');
    """)

    time.sleep(1)

    # Add to cart
    browser.find_element(*ADD_TO_CART_BUTTON).click()
    time.sleep(2)

    # Go to cart
    browser.find_element(*CART_LINK).click()
    time.sleep(2)

    # Step 3: OBSERVE cart price
    cart_price_element = browser.find_element(*CART_ITEM_PRICE)
    cart_price = parse_price(cart_price_element.text)
    logging.info(f"Cart price: ${cart_price}")

    # Proceed to checkout
    browser.find_element(*CHECKOUT_BUTTON).click()
    time.sleep(2)

    # Fill checkout form
    fill_checkout_form(browser)

    # Get final price at checkout
    final_price_element = browser.find_element(*FINAL_TOTAL)
    final_price = parse_price(final_price_element.text)
    logging.info(f"Final checkout price: ${final_price}")

    # Step 4: DECIDE based on observation
    # If ANY stage shows manipulated price, vulnerability exists
    if (cart_price == float(manipulated_price) or
        final_price == float(manipulated_price)):

        # DISCOVERED: Price manipulation works
        log_exploitation_attempt(
            vulnerability="Client-side price manipulation",
            payload=f"JavaScript: price changed to ${manipulated_price}",
            result=f"EXPLOITED - Final price: ${final_price} (original: ${original_price})",
            standard="OWASP Top 10 - A04"
        )
        pytest.fail(f"VULNERABILITY: Price manipulation - Final: ${final_price}, Original: ${original_price}")

    # If all stages show original price, server-side validation works
    elif (cart_price == original_price and final_price == original_price):
        # DISCOVERED: Server-side validation works
        logging.info(f"Price manipulation blocked - All stages show original ${original_price}")
        assert True

    else:
        # Unclear state
        logging.warning(f"Price state unclear - Cart: ${cart_price}, Final: ${final_price}")
        assert True  # Conservative pass
```

**Why This Is Correct:**
- Captures original state
- Attempts manipulation
- Observes through entire flow
- Compares prices objectively
- Discovers whether vulnerability exists

---

### Key Takeaway: The DISCOVER Formula

```
DISCOVER = EXECUTE + OBSERVE + DECIDE

1. EXECUTE: Run the exploit attempt
2. OBSERVE: Capture the actual response
3. DECIDE: Compare against secure behavior

if observation_matches_vulnerable_behavior():
    pytest.fail("VULNERABILITY FOUND")
else:
    assert True  # System is secure
```

**NEVER:**
```python
# NEVER do this
if True:  # "I know it's vulnerable"
    assert False

# NEVER do this
assert site_is_vulnerable()  # Assuming
```

**ALWAYS:**
```python
# ALWAYS do this
result = attempt_exploit()
if result.indicates_vulnerability():
    pytest.fail("DISCOVERED: Vulnerable")
else:
    assert True  # DISCOVERED: Secure
```

---

<a name="anti-patterns"></a>
## 3. ANTI-PATTERNS - WHAT NOT TO DO

Learn from common mistakes. Avoid these patterns:

### Anti-Pattern 1: Hardcoded Assumptions

```python
# ❌ WRONG
def test_vulnerability():
    """This site is vulnerable to XSS"""
    inject_xss()
    assert False  # Hardcoded assumption
```

```python
# ✅ CORRECT
def test_vulnerability():
    """Discovers if XSS is possible"""
    inject_xss()
    result = observe_execution()
    if result.xss_executed:
        pytest.fail("DISCOVERED: XSS")
    else:
        assert True
```

### Anti-Pattern 2: Site-Specific Logic

```python
# ❌ WRONG
def test_security():
    if "demoblaze" in BASE_URL:
        # Special handling for DemoBlaze
        assert False  # Assumes DemoBlaze behavior
    else:
        assert True
```

```python
# ✅ CORRECT
def test_security():
    # Works on ANY site
    result = attempt_exploit()
    if vulnerable(result):
        pytest.fail("DISCOVERED: Vulnerable")
    else:
        assert True
```

### Anti-Pattern 3: Passive Checks Only

```python
# ❌ WRONG - Only checks if feature exists
def test_captcha():
    captcha_present = check_for_captcha_element()
    assert captcha_present
```

```python
# ✅ CORRECT - Attempts to bypass
def test_captcha():
    captcha_present = check_for_captcha_element()

    if not captcha_present:
        pytest.fail("No CAPTCHA found")

    # Additionally: try to bypass it
    for i in range(100):
        result = attempt_automated_submission()
        if blocked:
            break

    if i >= 99:
        pytest.fail("CAPTCHA can be bypassed")
    else:
        assert True
```

### Anti-Pattern 4: No Exploitation Attempt

```python
# ❌ WRONG - Just checks documentation
def test_sql_injection():
    """Checks if SQL injection is documented as fixed"""
    changelog = read_changelog()
    assert "SQL injection fixed" in changelog
```

```python
# ✅ CORRECT - Actually attempts injection
def test_sql_injection():
    """Attempts SQL injection exploitation"""
    payloads = ["' OR '1'='1", "' UNION SELECT"]

    for payload in payloads:
        result = inject_and_observe(payload)
        if result.exploited:
            pytest.fail(f"DISCOVERED: SQL injection with {payload}")

    assert True  # All payloads blocked
```

### Anti-Pattern 5: Vague Assertions

```python
# ❌ WRONG - No context
def test_security():
    result = do_something()
    assert result  # What does this mean?
```

```python
# ✅ CORRECT - Clear exploitation context
def test_security():
    payload = "' OR '1'='1"
    result = inject_payload(payload)

    if result.indicates_sql_injection():
        log_exploitation_attempt(
            vulnerability="SQL Injection",
            payload=payload,
            result="Authentication bypassed",
            standard="OWASP ASVS v5.0-1.2.5"
        )
        pytest.fail(f"VULNERABILITY: SQL injection successful with: {payload}")
    else:
        assert True
```

### Anti-Pattern 6: No Standard References

```python
# ❌ WRONG - No context about severity
def test_problem():
    """Tests a problem"""
    assert something
```

```python
# ✅ CORRECT - Clear standards and severity
def test_problem():
    """TC-SEC-MOD-INJ-001: SQL Injection Vulnerability

    Severity: CRITICAL
    CVSS: 9.8
    Standard: OWASP Top 10 2021 - A03 (Injection)
    Reference: OWASP ASVS v5.0-1.2.5
    CWE: CWE-89 (SQL Injection)
    """
    # Test implementation
```

### Anti-Pattern 7: No Logging of Exploits

```python
# ❌ WRONG - Silent failure
def test_exploit():
    if exploited:
        assert False
```

```python
# ✅ CORRECT - Structured logging
def test_exploit():
    if exploited:
        log_exploitation_attempt(
            test_id="TC-SEC-MOD-XXX-001",
            vulnerability="Specific vulnerability name",
            payload="Actual payload used",
            result="What happened - evidence",
            cvss_score="9.1 CRITICAL",
            standard="OWASP reference"
        )
        pytest.fail("VULNERABILITY: Detailed description")
```

### Anti-Pattern 8: Tests That Can't Fail

```python
# ❌ WRONG - Always passes
def test_security():
    try:
        attempt_exploit()
        assert True  # Always passes regardless
    except:
        assert True  # Catches everything
```

```python
# ✅ CORRECT - Can discover vulnerabilities
def test_security():
    try:
        result = attempt_exploit()

        if result.exploited:
            pytest.fail("VULNERABILITY FOUND")
        else:
            assert True

    except SecurityException as e:
        # Expected security block
        assert True
    except Exception as e:
        # Unexpected error
        pytest.fail(f"Test error: {e}")
```

---

<a name="pre-dev"></a>
## 4. PRE-DEVELOPMENT QUESTIONS

Before writing a single line of exploitation code, gather this information:

### A. Module & Context Information

```
1. What module are we testing?
   - Name: [Login / Payment / Cart / Search / Profile / Admin / API / etc.]
   - Type: [Authentication / Financial / E-commerce / Social / Content Management]
   - Domain: [Banking / Healthcare / E-commerce / SaaS / etc.]

2. Do functional tests exist?
   - [ ] YES: Reference test_[module].py for locators and flows
   - [ ] NO: Create functional tests FIRST, then security tests

3. Application information:
   - BASE_URL: [target website]
   - Authentication required: [YES/NO]
   - Test credentials available: [YES/NO]
   - Environment: [Demo / Staging / Authorized Test Environment]
```

### B. Security Scope Definition

```
4. Which attack vectors should we test?
   [ ] Business Logic Exploitation (negative values, race conditions, etc.)
   [ ] Injection Attacks (SQL, XSS, Command Injection, LDAP, etc.)
   [ ] Authentication Attacks (brute force, session fixation, etc.)
   [ ] Authorization Attacks (IDOR, privilege escalation, etc.)
   [ ] Bot Protection / Rate Limiting
   [ ] PCI-DSS Compliance (if payment-related)
   [ ] CSRF Protection
   [ ] Session Management
   [ ] Data Exposure (client-side storage, logs, errors)
   [ ] Access Control
   [ ] Cryptographic Implementation
   [ ] File Upload Security
   [ ] API Security

5. Priority vulnerabilities for this module?
   Critical: [List 3-5 most critical for this specific module]
   High: [List 5-8 high priority]
   Medium: [List any medium priority]
```

### C. Ethical & Legal Confirmation

```
6. Authorization checklist:
   ✅ Testing authorized environment only
   ✅ Demo/staging site, NOT production
   ✅ No real customer data will be affected
   ✅ Permission documented (if required)
   ✅ Responsible disclosure plan in place
   ✅ Scope of testing agreed upon

7. Exploitation boundaries:
   ✅ Will not cause service disruption
   ✅ Will not modify/delete real data
   ✅ Will not expose actual user information
   ✅ Will stop upon discovering vulnerability
   ✅ Will document all findings properly
```

### D. Technical Setup

```
8. Testing environment:
   - Browsers: [ ] Chrome [ ] Firefox [ ] Edge [ ] All
   - Tools needed: [ ] Selenium [ ] Requests [ ] BurpSuite [ ] OWASP ZAP
   - Concurrent testing: [YES/NO - for race conditions]
   - Network access: [Required for API calls]

9. Expected deliverables:
   [ ] test_[module]_security.py (exploitation tests)
   [ ] README_[module]_security.md (detailed documentation)
   [ ] Security findings report (if vulnerabilities found)
   [ ] Remediation recommendations
```

---

<a name="research"></a>
## 5. RESEARCH PHASE BY MODULE TYPE

Before coding, research the specific standards and vulnerabilities relevant to your module type.

### Research Matrix

Use this table to identify which standards to research based on module type:

| Module Type | Primary Standards | Critical Vulnerabilities | Specific Tests Needed |
|-------------|------------------|-------------------------|----------------------|
| **Login/Authentication** | OWASP ASVS v5.0 Ch 2<br>NIST SP 800-63B<br>ISO 27001 A.9.4 | SQL Injection in username/password<br>Brute force attacks<br>Session fixation<br>Weak password policy | Credential stuffing<br>Password strength<br>MFA bypass<br>Session handling |
| **Payment/Checkout** | PCI-DSS 4.0.1 (Req 3.2, 4.2, 6.5, 11.6.1)<br>OWASP Top 10 - A02<br>ISO 25010 | Card data client storage<br>CVV storage<br>TLS < 1.2<br>Price manipulation | Client-side storage check<br>CVV prohibition<br>TLS version<br>Business logic |
| **Shopping Cart** | OWASP WSTG-BUSL<br>ISO 25010<br>OWASP Top 10 - A04 | Negative quantity<br>Price tampering<br>Race conditions<br>Coupon stacking | Quantity manipulation<br>Price override<br>Concurrent adds<br>Discount abuse |
| **Search/Filter** | OWASP Top 10 - A03<br>OWASP ASVS v5.0 Ch 1<br>CWE-89, CWE-79 | SQL Injection<br>XSS<br>LDAP Injection<br>NoSQL Injection | Parametrized injection<br>Stored XSS<br>Reflected XSS<br>Advanced queries |
| **User Profile** | OWASP Top 10 - A01<br>OWASP ASVS v5.0 Ch 4<br>GDPR/Privacy | IDOR<br>Mass assignment<br>XSS in profile fields<br>PII exposure | Access control<br>Field tampering<br>Profile picture XSS<br>Data leakage |
| **Admin Panel** | OWASP Top 10 - A01<br>OWASP ASVS v5.0 Ch 4<br>ISO 27001 | Privilege escalation<br>IDOR on admin functions<br>CSRF on actions<br>Missing authorization | Role bypass<br>Direct URL access<br>CSRF tokens<br>Audit logging |
| **File Upload** | OWASP ASVS v5.0 Ch 12<br>CWE-434<br>OWASP Testing Guide | Unrestricted upload<br>Path traversal<br>RCE via file<br>XXE | File type validation<br>Extension bypass<br>Content-type check<br>Size limits |
| **API Endpoints** | OWASP API Security Top 10<br>OWASP ASVS v5.0 Ch 13<br>ISO 25010 | No rate limiting<br>Broken authentication<br>Excessive data exposure<br>Mass assignment | API enumeration<br>Token handling<br>Response filtering<br>Rate limits |
| **Contact Forms** | OWASP OAT<br>Anti-automation | Spam/bot abuse<br>No CAPTCHA<br>No rate limiting<br>XSS in messages | Automated submission<br>CAPTCHA presence<br>Rate limiting<br>Input sanitization |
| **Session Management** | OWASP Top 10 - A07<br>OWASP ASVS v5.0 Ch 3<br>ISO 27001 A.9.4.2 | Session fixation<br>Predictable tokens<br>No timeout<br>Insecure cookies | Token regeneration<br>Entropy testing<br>Timeout checks<br>Cookie flags |
| **Password Reset** | NIST 800-63B<br>OWASP ASVS v5.0 Ch 2<br>CWE-640 | Token prediction<br>No expiration<br>Account enumeration<br>IDOR on reset | Token randomness<br>Expiry testing<br>Username probing<br>Reset abuse |
| **Registration** | OWASP ASVS v5.0 Ch 2<br>Anti-automation<br>GDPR | Account farming<br>No email verification<br>XSS in username<br>Weak password | Bot detection<br>Email validation<br>Input sanitization<br>Password policy |

### How to Use This Matrix

**Step 1:** Identify your module type
```
Example: "I'm testing a Payment module"
```

**Step 2:** Find it in the table
```
Payment/Checkout row → Lists required standards
```

**Step 3:** Research those specific standards
```
- Read PCI-DSS 4.0.1 Requirements 3.2, 4.2, 6.5, 11.6.1
- Review OWASP Top 10 - A02 (Cryptographic Failures)
- Check ISO 25010 data integrity requirements
```

**Step 4:** Focus on critical vulnerabilities
```
- Card data client storage
- CVV storage prohibition
- TLS version validation
- Price manipulation
```

**Step 5:** Plan specific tests
```
- test_card_data_storage_PCI_001
- test_cvv_prohibition_PCI_002
- test_tls_version_PCI_003
- test_price_manipulation_BL_001
```

### Additional Resources by Standard

**OWASP ASVS v5.0 Chapters:**
- Chapter 1: Architecture, Design and Threat Modeling
- Chapter 2: Authentication
- Chapter 3: Session Management
- Chapter 4: Access Control
- Chapter 5: Validation, Sanitization and Encoding
- Chapter 6: Stored Cryptography
- Chapter 7: Error Handling and Logging
- Chapter 8: Data Protection
- Chapter 9: Communication
- Chapter 10: Malicious Code
- Chapter 11: Business Logic
- Chapter 12: Files and Resources
- Chapter 13: API and Web Service
- Chapter 14: Configuration

**PCI-DSS 4.0.1 Key Requirements:**
- Requirement 3: Protect stored account data
- Requirement 4: Encrypt transmission of cardholder data
- Requirement 6: Develop and maintain secure systems
- Requirement 8: Identify and authenticate access
- Requirement 11: Test security systems and processes regularly

**OWASP Top 10 2021:**
1. A01:2021 – Broken Access Control
2. A02:2021 – Cryptographic Failures
3. A03:2021 – Injection
4. A04:2021 – Insecure Design
5. A05:2021 – Security Misconfiguration
6. A06:2021 – Vulnerable and Outdated Components
7. A07:2021 – Identification and Authentication Failures
8. A08:2021 – Software and Data Integrity Failures
9. A09:2021 – Security Logging and Monitoring Failures
10. A10:2021 – Server-Side Request Forgery (SSRF)

---

<a name="checklist"></a>
## 6. BEFORE WRITING CODE CHECKLIST

Stop! Before writing exploitation code, complete this checklist:

### Understanding Checklist

```
☐ 1. I understand what vulnerability I'm testing for
     Specific vulnerability: _________________________

☐ 2. I know which standard/requirement it violates
     Standard: _________________________
     Requirement number: _________________________

☐ 3. I know how an attacker would exploit this
     Attack technique: _________________________
     Payload example: _________________________

☐ 4. I understand what "DISCOVERY" means for this test
     How will I discover if vulnerable: _________________________
     What response indicates vulnerability: _________________________
     What response indicates security: _________________________

☐ 5. I have researched the exploitation technique
     Reviewed: [ ] OWASP [ ] CWE [ ] Real-world examples
```

### Design Checklist

```
☐ 6. My test will DISCOVER, not ASSUME
     Test will: [ ] Execute exploit [ ] Observe response [ ] Decide objectively
     Test will NOT: [ ] Hardcode assumptions [ ] Assume site behavior

☐ 7. My test is reusable on different sites
     Only need to change: [ ] BASE_URL [ ] LOCATORS
     Logic is generic: [ ] YES

☐ 8. My test has proper severity classification
     CVSS score determined: [ ] YES
     Severity level: [ ] CRITICAL [ ] HIGH [ ] MEDIUM [ ] LOW

☐ 9. My test references specific standards
     Standards cited: _________________________
     Version numbers included: [ ] YES
```

### Safety Checklist

```
☐ 10. Testing authorized environment only
      Environment: [ ] Demo [ ] Staging [ ] Authorized test
      NOT testing: [ ] Production [ ] Live systems

☐ 11. Exploitation will not cause harm
      Won't: [ ] Delete data [ ] Disrupt service [ ] Expose real users

☐ 12. Logging is properly configured
      Sensitive data excluded: [ ] YES
      Exploit attempts logged: [ ] YES
```

### Quality Checklist

```
☐ 13. Code follows template structure
      Sections: [ ] Config [ ] Locators [ ] Helpers [ ] Tests

☐ 14. No emojis in code or comments
      Verified: [ ] YES

☐ 15. Professional docstrings with standards
      Format: Test ID, Severity, CVSS, Standard, Description

☐ 16. Parametrized tests where applicable
      Multiple payloads tested: [ ] YES (if applicable)
```

### Final Validation

```
☐ 17. I can explain this test to a security auditor
      Can explain: [ ] What it tests [ ] Why it matters [ ] How it discovers

☐ 18. This test will work on sites I haven't seen yet
      Generic enough: [ ] YES
      Not site-specific: [ ] YES

☐ 19. Ready to write code
      All above checkboxes completed: [ ] YES
```

**If any checkbox is unchecked, STOP and research more before coding.**

---

<a name="code-structure"></a>
## 7. CODE STRUCTURE TEMPLATE

Before writing exploitation code, gather this information:

### A. Module Information
```
- Module name: [Login/Payment/Cart/Search/Profile/etc.]
- Existing functional tests: [YES: reference / NO: create first]
- Existing README: [YES: upload / NO: create new]
```

### B. Security Scope Definition
```
Files needed:
[ ] test_[module]_security.py (exploitation tests)
[ ] README_[module]_security.md

Attack vectors to test:
[ ] Business Logic Exploitation
[ ] Injection Attacks (SQL, XSS, Command)
[ ] Bot Protection / Rate Limiting
[ ] Authentication / Authorization
[ ] PCI-DSS Compliance (if payment-related)
[ ] CSRF Protection
[ ] Session Management
[ ] Data Exposure
[ ] Access Control
```

### C. Ethical Testing Confirmation
```
Confirm:
✅ Testing authorized environment only
✅ Demo/staging site, NOT production
✅ No real customer data affected
✅ Responsible disclosure planned
✅ Documentation of all exploits
```

---

## 2. Security Research Phase

### Standards to Research (based on attack vectors):

**Business Logic Exploitation:**
- OWASP WSTG-BUSL (Business Logic Testing)
- ISO 25010 (Data Integrity, Security)

**Injection Attacks:**
- OWASP Top 10 2021 - A03 (Injection)
- OWASP ASVS v5.0 Chapter 1 (Input Validation)
- CWE-89 (SQL Injection)
- CWE-79 (Cross-site Scripting)

**Bot Protection:**
- OWASP API Security Top 10 - API6 (Unrestricted Access)
- OWASP Automated Threats to Web Applications

**Payment Security:**
- PCI-DSS 4.0.1 (Requirements 3.2, 4.2, 6.5, 11.6.1)
- OWASP Top 10 2021 - A02 (Cryptographic Failures)

**Session & Authentication:**
- OWASP Top 10 2021 - A07 (Identification & Authentication Failures)
- OWASP ASVS v5.0 Chapter 2 (Authentication)
- OWASP ASVS v5.0 Chapter 3 (Session Management)

**Access Control:**
- OWASP Top 10 2021 - A01 (Broken Access Control)
- CWE-639 (Authorization Bypass)
- CWE-359 (Exposure of Private Information)

---

## 3. Code Structure Template

### File: `test_[module]_security.py`

```python
"""
Security & Exploitation Test Suite
Module: test_[module]_security.py
Author: Arévalo, Marc

Description:
Active security testing suite that attempts to exploit vulnerabilities in [module].
Tests discover security issues through real exploitation attempts.

Standards Validated:
- OWASP Top 10 2021
- OWASP ASVS v5.0
- PCI-DSS 4.0.1 (if applicable)
- WCAG 2.1 Level AA
- ISO 25010

WARNING: This suite performs ACTIVE EXPLOITATION ATTEMPTS.
Run only in authorized testing environments.

Version: 1.0
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import pytest
import time
import logging
import requests
from concurrent.futures import ThreadPoolExecutor

# Log only errors during exploitation attempts
logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


# ============================================================================
# CONFIGURATION SECTION - Change for different websites
# ============================================================================

BASE_URL = "https://example.com/"
TIMEOUT = 10

# Test credentials (if needed for exploitation)
TEST_USERNAME = "testuser"
TEST_PASSWORD = "TestPass123!"

# Attack configuration
RATE_LIMIT_REQUESTS = 1000  # For rate limiting tests
CONCURRENT_REQUESTS = 10    # For race condition tests


# ============================================================================
# LOCATORS SECTION - Change for different websites
# ============================================================================

# Target elements for exploitation
VULNERABLE_FIELD_1 = (By.ID, "field1")
VULNERABLE_FIELD_2 = (By.NAME, "field2")
SUBMIT_BUTTON = (By.XPATH, "//button[@type='submit']")

# Elements for verification
SUCCESS_INDICATOR = (By.CLASS_NAME, "success")
ERROR_MESSAGE = (By.CLASS_NAME, "error")
PRICE_ELEMENT = (By.ID, "price")
QUANTITY_FIELD = (By.ID, "quantity")


# ============================================================================
# FIXTURES SECTION - Generic setup/teardown
# ============================================================================

@pytest.fixture(scope="function")
def browser(request):
    """Cross-browser fixture for security testing"""
    browser_name = request.config.getoption("--browser", default="chrome").lower()
    driver = None

    if browser_name == "chrome":
        service = Service(ChromeDriverManager().install())
        options = webdriver.ChromeOptions()
        # Add options for automated detection bypass
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        driver = webdriver.Chrome(service=service, options=options)
    else:
        pytest.fail(f"Unsupported browser: {browser_name}")

    driver.maximize_window()
    driver.implicitly_wait(TIMEOUT)

    yield driver

    driver.quit()


@pytest.fixture
def authenticated_session(browser):
    """Setup authenticated session for authorization tests"""
    browser.get(BASE_URL)

    # Perform authentication if needed
    # login(browser, TEST_USERNAME, TEST_PASSWORD)

    return browser


# ============================================================================
# HELPER FUNCTIONS SECTION - Exploitation utilities
# ============================================================================

def inject_payload(browser, locator, payload):
    """Generic payload injection function"""
    try:
        element = WebDriverWait(browser, TIMEOUT).until(
            EC.visibility_of_element_located(locator)
        )
        element.clear()
        element.send_keys(payload)
        return True
    except Exception as e:
        logging.error(f"Injection failed: {e}")
        return False


def check_exploitation_success(browser, success_indicator_text, timeout=5):
    """Check if exploitation succeeded"""
    try:
        WebDriverWait(browser, timeout).until(
            EC.visibility_of_element_located(SUCCESS_INDICATOR)
        )
        return True
    except TimeoutException:
        return False


def execute_javascript_exploit(browser, js_code):
    """Execute JavaScript for client-side exploitation"""
    try:
        return browser.execute_script(js_code)
    except Exception as e:
        logging.error(f"JavaScript exploit failed: {e}")
        return None


def check_client_side_storage(browser):
    """Check for sensitive data in client-side storage"""
    try:
        local_storage = browser.execute_script("return JSON.stringify(localStorage);")
        session_storage = browser.execute_script("return JSON.stringify(sessionStorage);")
        cookies = browser.get_cookies()

        return {
            "localStorage": local_storage,
            "sessionStorage": session_storage,
            "cookies": cookies
        }
    except Exception as e:
        logging.error(f"Storage check failed: {e}")
        return None


def simulate_concurrent_requests(browser, action_function, num_requests=10):
    """Simulate race condition attacks"""
    with ThreadPoolExecutor(max_workers=num_requests) as executor:
        futures = [executor.submit(action_function, browser) for _ in range(num_requests)]
        results = [f.result() for f in futures]
    return results


def log_exploitation_attempt(test_id, vulnerability, payload, result, cvss_score, standard):
    """Structured logging for exploitation attempts"""
    logging.error("=" * 80)
    logging.error(f"EXPLOITATION ATTEMPT: {test_id}")
    logging.error(f"Vulnerability: {vulnerability}")
    logging.error(f"Payload: {payload}")
    logging.error(f"Result: {result}")
    logging.error(f"CVSS Score: {cvss_score}")
    logging.error(f"Standard Violated: {standard}")
    logging.error("=" * 80)


# ============================================================================
# BUSINESS LOGIC EXPLOITATION TESTS
# ============================================================================

@pytest.mark.security
@pytest.mark.business_logic
@pytest.mark.critical
def test_negative_quantity_exploit_BL_001(browser):
    """TC-SEC-[MOD]-BL-001: Negative Quantity Price Manipulation

    Severity: CRITICAL
    CVSS: 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H)
    Standard: OWASP WSTG-BUSL-10 (Business Logic Testing)

    Exploitation Attempt:
    Add items with negative quantities to manipulate cart total
    and obtain discounts through business logic flaw.
    """
    logging.info("TC-SEC-[MOD]-BL-001: Attempting negative quantity exploit")

    browser.get(BASE_URL)

    # Attempt to add item with negative quantity
    # Adapt this to your module's specific functionality
    try:
        browser.find_element(*QUANTITY_FIELD).send_keys("-5")
        browser.find_element(*SUBMIT_BUTTON).click()

        # Check if exploit succeeded
        time.sleep(2)

        # Get price/total (adapt to your module)
        final_price = browser.find_element(*PRICE_ELEMENT).text

        # If negative quantity accepted, exploitation succeeded
        if "-" in final_price or "discount" in final_price.lower():
            log_exploitation_attempt(
                test_id="TC-SEC-[MOD]-BL-001",
                vulnerability="Negative quantity accepted",
                payload="quantity=-5",
                result=f"EXPLOITED - Final price: {final_price}",
                cvss_score="9.1 CRITICAL",
                standard="OWASP WSTG-BUSL-10"
            )
            pytest.fail(f"VULNERABILITY: Negative quantities accepted - Price: {final_price}")

        logging.info("Negative quantity exploit failed (system secure)")
        assert True

    except Exception as e:
        logging.info(f"Exploit blocked: {e}")
        assert True


@pytest.mark.security
@pytest.mark.business_logic
@pytest.mark.critical
def test_price_manipulation_BL_002(browser):
    """TC-SEC-[MOD]-BL-002: Client-Side Price Manipulation

    Severity: CRITICAL
    CVSS: 9.1
    Standard: OWASP Top 10 2021 - A04 (Insecure Design)

    Exploitation Attempt:
    Modify price using JavaScript before submission.
    """
    logging.info("TC-SEC-[MOD]-BL-002: Attempting price manipulation")

    browser.get(BASE_URL)

    # Capture original price
    original_price = browser.find_element(*PRICE_ELEMENT).text

    # Attempt to modify price via JavaScript
    execute_javascript_exploit(browser, """
        document.querySelector('#price').innerText = '$0.01';
        // Adapt selector to your module
    """)

    time.sleep(1)

    # Submit and check if manipulation worked
    browser.find_element(*SUBMIT_BUTTON).click()
    time.sleep(2)

    # Verify if exploit succeeded (adapt verification to your module)
    confirmation = browser.page_source

    if "$0.01" in confirmation or "0.01" in confirmation:
        log_exploitation_attempt(
            test_id="TC-SEC-[MOD]-BL-002",
            vulnerability="Client-side price manipulation",
            payload="JavaScript: price = $0.01",
            result="EXPLOITED - Price changed to $0.01",
            cvss_score="9.1 CRITICAL",
            standard="OWASP Top 10 2021 - A04"
        )
        pytest.fail("VULNERABILITY: Client-side price manipulation successful")

    logging.info("Price manipulation blocked (system secure)")
    assert True


@pytest.mark.security
@pytest.mark.business_logic
@pytest.mark.high
def test_integer_overflow_BL_003(browser):
    """TC-SEC-[MOD]-BL-003: Integer Overflow Attack

    Severity: HIGH
    CVSS: 7.5
    Standard: CWE-190 (Integer Overflow)

    Exploitation Attempt:
    Send extremely large numbers to trigger integer overflow.
    """
    logging.info("TC-SEC-[MOD]-BL-003: Attempting integer overflow")

    browser.get(BASE_URL)

    # Attempt maximum 32-bit integer
    overflow_value = "2147483647"  # Max int32

    inject_payload(browser, QUANTITY_FIELD, overflow_value)
    browser.find_element(*SUBMIT_BUTTON).click()

    time.sleep(2)

    # Check if system handled overflow
    page_source = browser.page_source

    if "error" not in page_source.lower() and check_exploitation_success(browser, "success"):
        log_exploitation_attempt(
            test_id="TC-SEC-[MOD]-BL-003",
            vulnerability="Integer overflow not handled",
            payload=f"quantity={overflow_value}",
            result="EXPLOITED - Large integer accepted",
            cvss_score="7.5 HIGH",
            standard="CWE-190"
        )
        pytest.fail(f"VULNERABILITY: Integer overflow - Accepted {overflow_value}")

    logging.info("Integer overflow handled correctly")
    assert True


@pytest.mark.security
@pytest.mark.business_logic
@pytest.mark.critical
def test_race_condition_BL_004(browser):
    """TC-SEC-[MOD]-BL-004: Race Condition Exploit

    Severity: CRITICAL
    CVSS: 8.1
    Standard: CWE-362 (Race Condition)

    Exploitation Attempt:
    Submit concurrent requests to exploit race conditions.
    """
    logging.info("TC-SEC-[MOD]-BL-004: Attempting race condition exploit")

    def submit_action(driver):
        try:
            driver.find_element(*SUBMIT_BUTTON).click()
            time.sleep(0.1)
            return True
        except:
            return False

    browser.get(BASE_URL)

    # Simulate concurrent submissions
    results = simulate_concurrent_requests(browser, submit_action, CONCURRENT_REQUESTS)

    successful_exploits = sum(results)

    # If multiple submissions succeeded, race condition exists
    if successful_exploits > 1:
        log_exploitation_attempt(
            test_id="TC-SEC-[MOD]-BL-004",
            vulnerability="Race condition in submission handling",
            payload=f"{CONCURRENT_REQUESTS} concurrent requests",
            result=f"EXPLOITED - {successful_exploits} simultaneous submissions succeeded",
            cvss_score="8.1 CRITICAL",
            standard="CWE-362"
        )
        pytest.fail(f"VULNERABILITY: Race condition - {successful_exploits} concurrent operations")

    logging.info("Race condition protected")
    assert True


# ============================================================================
# INJECTION ATTACK TESTS
# ============================================================================

@pytest.mark.security
@pytest.mark.injection
@pytest.mark.critical
@pytest.mark.parametrize("sql_payload", [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "' UNION SELECT NULL--",
    "' DROP TABLE users--",
])
def test_sql_injection_INJ_001(browser, sql_payload):
    """TC-SEC-[MOD]-INJ-001: SQL Injection Vulnerability

    Severity: CRITICAL
    CVSS: 9.8
    Standard: OWASP Top 10 2021 - A03 (Injection)
    Reference: OWASP ASVS v5.0-1.2.5

    Exploitation Attempt:
    Inject SQL payloads to bypass authentication or access database.
    """
    logging.info(f"TC-SEC-[MOD]-INJ-001: Testing SQL injection - Payload: {sql_payload}")

    browser.get(BASE_URL)

    # Inject payload into vulnerable field
    inject_payload(browser, VULNERABLE_FIELD_1, sql_payload)
    inject_payload(browser, VULNERABLE_FIELD_2, "test")

    browser.find_element(*SUBMIT_BUTTON).click()
    time.sleep(2)

    # Check if SQL injection succeeded
    if check_exploitation_success(browser, "success"):
        log_exploitation_attempt(
            test_id="TC-SEC-[MOD]-INJ-001",
            vulnerability="SQL Injection",
            payload=sql_payload,
            result="EXPLOITED - SQL injection successful",
            cvss_score="9.8 CRITICAL",
            standard="OWASP ASVS v5.0-1.2.5"
        )
        pytest.fail(f"VULNERABILITY: SQL Injection successful with payload: {sql_payload}")

    logging.info(f"SQL injection blocked: {sql_payload}")
    assert True


@pytest.mark.security
@pytest.mark.injection
@pytest.mark.critical
@pytest.mark.parametrize("xss_payload", [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src='javascript:alert(1)'>",
])
def test_xss_attack_INJ_002(browser, xss_payload):
    """TC-SEC-[MOD]-INJ-002: Cross-Site Scripting (XSS)

    Severity: CRITICAL
    CVSS: 8.8
    Standard: OWASP Top 10 2021 - A03 (Injection)
    Reference: OWASP ASVS v5.0-1.2.1

    Exploitation Attempt:
    Inject XSS payloads to execute JavaScript in victim's browser.
    """
    logging.info(f"TC-SEC-[MOD]-INJ-002: Testing XSS - Payload: {xss_payload}")

    browser.get(BASE_URL)

    # Inject XSS payload
    inject_payload(browser, VULNERABLE_FIELD_1, xss_payload)
    browser.find_element(*SUBMIT_BUTTON).click()

    time.sleep(2)

    # Check if XSS executed (alert would appear)
    try:
        alert = browser.switch_to.alert
        alert_text = alert.text
        alert.accept()

        if 'XSS' in alert_text:
            log_exploitation_attempt(
                test_id="TC-SEC-[MOD]-INJ-002",
                vulnerability="Cross-Site Scripting (XSS)",
                payload=xss_payload,
                result="EXPLOITED - XSS payload executed",
                cvss_score="8.8 CRITICAL",
                standard="OWASP ASVS v5.0-1.2.1"
            )
            pytest.fail(f"VULNERABILITY: XSS successful with payload: {xss_payload}")
    except:
        pass  # No alert = XSS blocked

    logging.info(f"XSS blocked: {xss_payload}")
    assert True


# ============================================================================
# BOT PROTECTION / RATE LIMITING TESTS
# ============================================================================

@pytest.mark.security
@pytest.mark.bot_protection
@pytest.mark.critical
def test_rate_limiting_BOT_001(browser):
    """TC-SEC-[MOD]-BOT-001: Rate Limiting Protection

    Severity: CRITICAL
    CVSS: 9.1
    Standard: OWASP API Security Top 10 - API6 (Unrestricted Access)

    Exploitation Attempt:
    Send rapid automated requests to verify rate limiting.
    """
    logging.info("TC-SEC-[MOD]-BOT-001: Testing rate limiting")

    browser.get(BASE_URL)

    successful_requests = 0
    blocked_requests = 0

    for i in range(RATE_LIMIT_REQUESTS):
        try:
            browser.find_element(*SUBMIT_BUTTON).click()
            time.sleep(0.001)  # Very fast requests

            if check_exploitation_success(browser, "success", timeout=1):
                successful_requests += 1
            else:
                blocked_requests += 1

            # If blocked, rate limiting works
            if blocked_requests > 0:
                logging.info(f"Rate limit triggered after {successful_requests} requests")
                assert True
                return

        except Exception as e:
            # Exception might indicate rate limiting
            logging.info(f"Rate limit triggered: {e}")
            assert True
            return

    # If ALL requests succeeded, no rate limiting
    if successful_requests >= RATE_LIMIT_REQUESTS:
        log_exploitation_attempt(
            test_id="TC-SEC-[MOD]-BOT-001",
            vulnerability="No rate limiting",
            payload=f"{RATE_LIMIT_REQUESTS} automated requests",
            result=f"EXPLOITED - All {successful_requests} requests succeeded",
            cvss_score="9.1 CRITICAL",
            standard="OWASP API Security - API6"
        )
        pytest.fail(f"VULNERABILITY: No rate limiting - {successful_requests} requests succeeded")


@pytest.mark.security
@pytest.mark.bot_protection
@pytest.mark.high
def test_captcha_presence_BOT_002(browser):
    """TC-SEC-[MOD]-BOT-002: CAPTCHA Protection

    Severity: HIGH
    CVSS: 7.5
    Standard: OWASP Automated Threats OAT-021

    Discovery Test:
    Check if CAPTCHA is present to prevent automated abuse.
    """
    logging.info("TC-SEC-[MOD]-BOT-002: Checking CAPTCHA presence")

    browser.get(BASE_URL)

    # Look for common CAPTCHA implementations
    captcha_indicators = [
        (By.CLASS_NAME, "g-recaptcha"),           # Google reCAPTCHA
        (By.CLASS_NAME, "h-captcha"),             # hCaptcha
        (By.ID, "captcha"),                       # Generic
        (By.XPATH, "//iframe[contains(@src, 'recaptcha')]"),
        (By.XPATH, "//iframe[contains(@src, 'hcaptcha')]"),
    ]

    captcha_found = False
    for locator in captcha_indicators:
        try:
            browser.find_element(*locator)
            captcha_found = True
            logging.info(f"CAPTCHA found: {locator}")
            break
        except:
            continue

    if not captcha_found:
        log_exploitation_attempt(
            test_id="TC-SEC-[MOD]-BOT-002",
            vulnerability="No CAPTCHA protection",
            payload="Automated bot detection check",
            result="VULNERABLE - No CAPTCHA implementation found",
            cvss_score="7.5 HIGH",
            standard="OWASP OAT-021"
        )
        pytest.fail("VULNERABILITY: No CAPTCHA protection found")

    logging.info("CAPTCHA protection present")
    assert True


# ============================================================================
# PCI-DSS COMPLIANCE TESTS (for payment modules)
# ============================================================================

@pytest.mark.security
@pytest.mark.pci_dss
@pytest.mark.critical
def test_card_data_client_storage_PCI_001(browser):
    """TC-SEC-[MOD]-PCI-001: PCI-DSS Card Data Storage

    Severity: CRITICAL
    CVSS: 10.0
    Standard: PCI-DSS 4.0.1 Requirement 3.2

    Compliance Check:
    Verify credit card data NOT stored in client-side storage.
    """
    logging.info("TC-SEC-[MOD]-PCI-001: Checking card data storage")

    browser.get(BASE_URL)

    # Simulate entering card data (adapt to your module)
    test_card = "4111111111111111"
    inject_payload(browser, VULNERABLE_FIELD_1, test_card)
    browser.find_element(*SUBMIT_BUTTON).click()

    time.sleep(2)

    # Check all client-side storage
    storage = check_client_side_storage(browser)

    if storage:
        # Search for card patterns
        sensitive_patterns = [test_card, "4111", "card", "cvv", "creditcard"]

        for pattern in sensitive_patterns:
            if (pattern in storage["localStorage"].lower() or
                pattern in storage["sessionStorage"].lower()):

                log_exploitation_attempt(
                    test_id="TC-SEC-[MOD]-PCI-001",
                    vulnerability="Card data stored client-side",
                    payload=f"Pattern found: {pattern}",
                    result="PCI-DSS VIOLATION - Card data in client storage",
                    cvss_score="10.0 CRITICAL",
                    standard="PCI-DSS 4.0.1 Req 3.2"
                )
                pytest.fail(f"PCI-DSS VIOLATION: Card pattern '{pattern}' found in client storage")

    logging.info("Card data not stored client-side (PCI-DSS compliant)")
    assert True


@pytest.mark.security
@pytest.mark.pci_dss
@pytest.mark.critical
def test_cvv_storage_prohibition_PCI_002(browser):
    """TC-SEC-[MOD]-PCI-002: CVV Storage Prohibition

    Severity: CRITICAL
    CVSS: 10.0
    Standard: PCI-DSS 4.0.1 Requirement 3.2

    Compliance Check:
    Verify CVV is NEVER stored anywhere (absolute prohibition).
    """
    logging.info("TC-SEC-[MOD]-PCI-002: Checking CVV storage prohibition")

    browser.get(BASE_URL)

    # Attempt to inject CVV into storage
    execute_javascript_exploit(browser, """
        document.cookie = 'cvv=123; path=/';
        localStorage.setItem('cvv', '123');
        sessionStorage.setItem('cvv', '123');
    """)

    time.sleep(1)

    # Verify CVV was NOT stored
    storage = check_client_side_storage(browser)

    if storage:
        local_cvv = execute_javascript_exploit(browser, "return localStorage.getItem('cvv');")
        session_cvv = execute_javascript_exploit(browser, "return sessionStorage.getItem('cvv');")

        if local_cvv or session_cvv or any('cvv' in str(c) for c in storage["cookies"]):
            log_exploitation_attempt(
                test_id="TC-SEC-[MOD]-PCI-002",
                vulnerability="CVV stored in violation of PCI-DSS",
                payload="CVV injection test",
                result="PCI-DSS VIOLATION - CVV stored",
                cvss_score="10.0 CRITICAL",
                standard="PCI-DSS 4.0.1 Req 3.2"
            )
            pytest.fail("PCI-DSS VIOLATION: CVV storage detected")

    logging.info("CVV not stored (PCI-DSS compliant)")
    assert True


@pytest.mark.security
@pytest.mark.pci_dss
@pytest.mark.high
def test_tls_version_PCI_003(browser):
    """TC-SEC-[MOD]-PCI-003: TLS Version Requirement

    Severity: HIGH
    CVSS: 8.1
    Standard: PCI-DSS 4.0.1 Requirement 4.2

    Compliance Check:
    Verify TLS 1.2 or higher is enforced.
    """
    logging.info("TC-SEC-[MOD]-PCI-003: Checking TLS version")

    try:
        response = requests.get(BASE_URL, timeout=5)

        if hasattr(response, 'raw') and hasattr(response.raw, 'version'):
            ssl_version = response.raw.version

            # TLS versions: 771 = TLS 1.2, 772 = TLS 1.3
            if ssl_version < 771:
                log_exploitation_attempt(
                    test_id="TC-SEC-[MOD]-PCI-003",
                    vulnerability="Weak TLS version",
                    payload=f"TLS version: {ssl_version}",
                    result="PCI-DSS VIOLATION - TLS < 1.2",
                    cvss_score="8.1 HIGH",
                    standard="PCI-DSS 4.0.1 Req 4.2"
                )
                pytest.fail(f"PCI-DSS VIOLATION: TLS version {ssl_version} < 1.2 (771)")

        logging.info("TLS 1.2+ enforced (PCI-DSS compliant)")
        assert True

    except Exception as e:
        logging.error(f"TLS check failed: {e}")
        pytest.skip("Could not verify TLS version")


# ============================================================================
# SESSION & AUTHENTICATION TESTS
# ============================================================================

@pytest.mark.security
@pytest.mark.authentication
@pytest.mark.high
def test_session_fixation_AUTH_001(browser):
    """TC-SEC-[MOD]-AUTH-001: Session Fixation Attack

    Severity: HIGH
    CVSS: 8.1
    Standard: OWASP Top 10 2021 - A07 (Authentication Failures)
    Reference: OWASP ASVS v5.0-3.2.1

    Exploitation Attempt:
    Check if session ID changes after authentication.
    """
    logging.info("TC-SEC-[MOD]-AUTH-001: Testing session fixation")

    browser.get(BASE_URL)

    # Capture session before authentication
    cookies_before = browser.get_cookies()
    session_before = next((c['value'] for c in cookies_before if 'session' in c['name'].lower()), None)

    # Perform authentication (adapt to your module)
    # login(browser, TEST_USERNAME, TEST_PASSWORD)

    time.sleep(2)

    # Capture session after authentication
    cookies_after = browser.get_cookies()
    session_after = next((c['value'] for c in cookies_after if 'session' in c['name'].lower()), None)

    # Session ID should change after login
    if session_before and session_after and session_before == session_after:
        log_exploitation_attempt(
            test_id="TC-SEC-[MOD]-AUTH-001",
            vulnerability="Session fixation",
            payload="Session ID preserved across authentication",
            result="EXPLOITED - Session ID did not change",
            cvss_score="8.1 HIGH",
            standard="OWASP ASVS v5.0-3.2.1"
        )
        pytest.fail("VULNERABILITY: Session fixation - Session ID unchanged after login")

    logging.info("Session fixation protected (session ID regenerated)")
    assert True


# ============================================================================
# ACCESS CONTROL TESTS
# ============================================================================

@pytest.mark.security
@pytest.mark.authorization
@pytest.mark.critical
def test_idor_vulnerability_AUTHZ_001(browser):
    """TC-SEC-[MOD]-AUTHZ-001: Insecure Direct Object Reference (IDOR)

    Severity: CRITICAL
    CVSS: 9.1
    Standard: OWASP Top 10 2021 - A01 (Broken Access Control)
    Reference: CWE-639

    Exploitation Attempt:
    Access resources by manipulating object IDs.
    """
    logging.info("TC-SEC-[MOD]-AUTHZ-001: Testing IDOR vulnerability")

    # Attempt to access resource with predictable ID
    try:
        # Adapt URL to your module
        browser.get(f"{BASE_URL}/resource/1")
        time.sleep(2)

        # Try to access another user's resource
        browser.get(f"{BASE_URL}/resource/2")
        time.sleep(2)

        # Check if access granted without authorization
        if "error" not in browser.page_source.lower() and "unauthorized" not in browser.page_source.lower():
            log_exploitation_attempt(
                test_id="TC-SEC-[MOD]-AUTHZ-001",
                vulnerability="Insecure Direct Object Reference (IDOR)",
                payload="Direct access to /resource/2",
                result="EXPLOITED - Unauthorized access granted",
                cvss_score="9.1 CRITICAL",
                standard="OWASP Top 10 2021 - A01"
            )
            pytest.fail("VULNERABILITY: IDOR - Unauthorized resource access")

        logging.info("IDOR protected (access denied)")
        assert True

    except Exception as e:
        logging.info(f"IDOR test blocked: {e}")
        assert True


# ============================================================================
# CSRF PROTECTION TEST
# ============================================================================

@pytest.mark.security
@pytest.mark.csrf
@pytest.mark.high
def test_csrf_protection_CSRF_001(browser):
    """TC-SEC-[MOD]-CSRF-001: CSRF Token Validation

    Severity: HIGH
    CVSS: 7.5
    Standard: OWASP Top 10 2021 - A01 (Broken Access Control)

    Discovery Test:
    Check if CSRF tokens are implemented.
    """
    logging.info("TC-SEC-[MOD]-CSRF-001: Checking CSRF protection")

    browser.get(BASE_URL)

    # Look for CSRF tokens
    csrf_indicators = [
        "csrf",
        "token",
        "_token",
        "authenticity_token",
    ]

    page_source = browser.page_source.lower()
    csrf_found = any(indicator in page_source for indicator in csrf_indicators)

    if not csrf_found:
        log_exploitation_attempt(
            test_id="TC-SEC-[MOD]-CSRF-001",
            vulnerability="No CSRF protection",
            payload="CSRF token check",
            result="VULNERABLE - No CSRF tokens found",
            cvss_score="7.5 HIGH",
            standard="OWASP Top 10 2021 - A01"
        )
        pytest.fail("VULNERABILITY: No CSRF protection detected")

    logging.info("CSRF protection present")
    assert True


# ============================================================================
# ACCESSIBILITY TESTS (WCAG 2.1)
# ============================================================================

@pytest.mark.security
@pytest.mark.accessibility
@pytest.mark.medium
def test_keyboard_navigation_ACC_001(browser):
    """TC-SEC-[MOD]-ACC-001: Keyboard Accessibility

    Severity: MEDIUM
    CVSS: 4.3
    Standard: WCAG 2.1 Success Criterion 2.1.1 (Level A)

    Compliance Check:
    Verify all functionality accessible via keyboard.
    """
    logging.info("TC-SEC-[MOD]-ACC-001: Testing keyboard accessibility")

    browser.get(BASE_URL)

    # Test Tab navigation
    from selenium.webdriver.common.keys import Keys

    body = browser.find_element(By.TAG_NAME, "body")

    # Count focusable elements
    focusable_count = 0
    for _ in range(20):  # Try 20 tabs
        body.send_keys(Keys.TAB)
        time.sleep(0.1)

        active_element = browser.switch_to.active_element
        if active_element.tag_name not in ['body', 'html']:
            focusable_count += 1

    if focusable_count < 3:  # At least 3 interactive elements should be focusable
        log_exploitation_attempt(
            test_id="TC-SEC-[MOD]-ACC-001",
            vulnerability="Poor keyboard accessibility",
            payload="Tab navigation test",
            result=f"Only {focusable_count} elements focusable",
            cvss_score="4.3 MEDIUM",
            standard="WCAG 2.1 - 2.1.1"
        )
        pytest.fail(f"WCAG VIOLATION: Only {focusable_count} keyboard-accessible elements")

    logging.info(f"Keyboard accessibility OK ({focusable_count} focusable elements)")
    assert True


# Add more tests following the same pattern:
# - Data exposure tests
# - Cookie security tests
# - HTTP security headers
# - Performance/DoS tests
# etc.


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])
```

---

## 4. Test Naming Convention

### Security Tests:
```
test_[vulnerability]_[CATEGORY]_[number]
Examples:
- test_sql_injection_INJ_001
- test_negative_quantity_BL_001
- test_rate_limiting_BOT_001
- test_card_data_storage_PCI_001
```

### Category Codes:
- **BL** = Business Logic
- **INJ** = Injection
- **BOT** = Bot Protection
- **PCI** = PCI-DSS Compliance
- **AUTH** = Authentication
- **AUTHZ** = Authorization
- **CSRF** = CSRF Protection
- **ACC** = Accessibility
- **PERF** = Performance

---

## 5. Markers Usage

```python
# Severity markers
@pytest.mark.critical   # CVSS 9.0-10.0
@pytest.mark.high       # CVSS 7.0-8.9
@pytest.mark.medium     # CVSS 4.0-6.9
@pytest.mark.low        # CVSS 0.1-3.9

# Category markers
@pytest.mark.security
@pytest.mark.business_logic
@pytest.mark.injection
@pytest.mark.bot_protection
@pytest.mark.pci_dss
@pytest.mark.authentication
@pytest.mark.authorization
@pytest.mark.accessibility

# Parametrized tests
@pytest.mark.parametrize("payload", [list_of_payloads])
```

---

## 6. Execution Commands

```bash
# Run all security tests
pytest test_[module]_security.py -v

# Run by severity
pytest test_[module]_security.py -m critical -v
pytest test_[module]_security.py -m high -v

# Run by category
pytest test_[module]_security.py -m business_logic -v
pytest test_[module]_security.py -m injection -v
pytest test_[module]_security.py -m bot_protection -v
pytest test_[module]_security.py -m pci_dss -v

# Generate security report
pytest test_[module]_security.py --html=security_report.html --self-contained-html -v

# Run with detailed logging
pytest test_[module]_security.py -v -s --log-cli-level=ERROR
```

---

## 7. Expected Test Distribution

**Good balance:**
- 4-6 Business Logic Exploitation tests
- 3-5 Injection tests (SQL, XSS, etc.)
- 2-4 Bot Protection tests
- 2-4 PCI-DSS tests (if payment module)
- 2-3 Authentication/Authorization tests
- 1-2 CSRF tests
- 2-3 Accessibility tests
- Optional: Performance/DoS tests

**Total: 16-28 security tests per module**

---

## 8. Critical Principles

### Active Exploitation Philosophy:
```python
# Security tests ACTIVELY EXPLOIT vulnerabilities

# WRONG - Passive check
def test_security():
    check_if_feature_exists()  # Not enough

# CORRECT - Active exploitation
def test_security():
    inject_malicious_payload()
    verify_if_exploit_succeeded()
    if exploited:
        pytest.fail("VULNERABILITY FOUND")
```

### Discoverable Vulnerabilities:
```python
# Tests DISCOVER vulnerabilities, not assume them

# Execute exploit
result = attempt_exploitation(browser)

# Analyze result objectively
if vulnerability_exists(result):
    log_exploitation_attempt(...)
    pytest.fail("VULNERABILITY")
else:
    assert True  # System is secure
```

### Structured Logging:
```python
# Always log exploitation attempts with details
log_exploitation_attempt(
    test_id="TC-SEC-MOD-XXX-001",
    vulnerability="Specific vulnerability name",
    payload="Actual payload used",
    result="What happened",
    cvss_score="X.X SEVERITY",
    standard="Standard violated"
)
```

---

## 9. CVSS Scoring Quick Reference

### Critical (9.0-10.0):
- SQL Injection with data access
- Authentication bypass
- RCE (Remote Code Execution)
- Full system compromise

### High (7.0-8.9):
- XSS with session theft
- PCI-DSS violations
- IDOR with sensitive data access
- Session fixation

### Medium (4.0-6.9):
- Information disclosure
- CSRF without critical impact
- Accessibility issues
- Missing security headers

### Low (0.1-3.9):
- Minor information leakage
- Non-sensitive data exposure

---

## 10. Pre-Delivery Checklist

Before considering code complete, verify:

```
Code Quality:
✅ No emojis in code or comments
✅ Minimal comments (only docstrings)
✅ Clean, professional formatting
✅ JavaScript exploits clearly documented

Test Quality:
✅ Tests actively exploit (not passive checks)
✅ All tests have CVSS scores
✅ All tests reference standards
✅ Exploitation attempts logged
✅ Parametrized tests for multiple payloads

Safety:
✅ Tests run only on authorized environments
✅ No production systems tested
✅ Ethical testing confirmed
✅ Documentation complete

Standards:
✅ OWASP references correct
✅ PCI-DSS requirements cited (if applicable)
✅ CVSS scores accurate
✅ CWE numbers included where relevant
```

---

## 11. Security Standards Reference

### OWASP Top 10 2021 (Always Include):
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable and Outdated Components
- A07: Identification and Authentication Failures
- A08: Software and Data Integrity Failures
- A09: Security Logging and Monitoring Failures
- A10: Server-Side Request Forgery (SSRF)

### OWASP ASVS v5.0:
- Chapter 1: Input Validation
- Chapter 2: Authentication
- Chapter 3: Session Management
- Chapter 4: Access Control
- Chapter 5: Validation, Sanitization and Encoding
- Chapter 9: Communications

### PCI-DSS 4.0.1 (Payment Modules):
- Requirement 3.2: Cardholder Data Protection
- Requirement 4.2: Strong Cryptography
- Requirement 6.5: Secure Development
- Requirement 11.6.1: Script Integrity

### WCAG 2.1 Level AA:
- Success Criterion 2.1.1: Keyboard
- Success Criterion 1.3.1: Info and Relationships
- Success Criterion 1.4.3: Contrast (Minimum)

### CWE (Common Weakness Enumeration):
- CWE-79: Cross-site Scripting (XSS)
- CWE-89: SQL Injection
- CWE-190: Integer Overflow
- CWE-362: Race Condition
- CWE-639: Authorization Bypass

---

## 12. Exploitation Libraries

### Common Tools Used:
```python
# Selenium - UI automation and JavaScript execution
from selenium import webdriver

# Requests - Direct HTTP requests for API testing
import requests

# Concurrent.futures - Race condition testing
from concurrent.futures import ThreadPoolExecutor

# Time - Strategic delays in exploitation
import time

# Logging - Structured exploitation logging
import logging
```

---

---

## IMPORTANT: CONTINUATION

**This template has a PART 2** with critical sections:
- **Section 18:** Example Future Conversation (how to use this template)
- **Section 19:** Common Vulnerabilities by Module Type (quick reference with discovery patterns)

**See:** TEMPLATE_security_PART2_critical_sections.md

---

## VERSION HISTORY

### Version 2.0 - November 2025 (Current - Universal Edition)

**Major Updates:**
- ✅ Complete DISCOVER vs ASSUME philosophy section with 4 detailed examples
- ✅ Anti-Patterns section (8 common mistakes to avoid)
- ✅ Comprehensive Pre-Development Questions (3 categories, 9 questions)
- ✅ Research Matrix by Module Type (12 module types with specific standards)
- ✅ Before Writing Code Checklist (19 validation points)
- ✅ Example Future Conversations (3 detailed scenarios)
- ✅ Common Vulnerabilities by Module (7 module types with discovery patterns)
- ✅ Universal applicability (not e-commerce specific)
- ✅ Extensive documentation (2300+ lines)

**Philosophy Improvements:**
- Explicit DISCOVER formula: EXECUTE → OBSERVE → DECIDE
- Multiple examples showing right vs wrong approaches
- Clear anti-patterns with corrections
- Research matrix for any module type
- Reusable patterns across all domains

**Coverage:**
- Authentication/Login modules
- Payment/Financial modules
- Shopping Cart modules
- Search/Filter modules
- User Profile modules
- Admin Panel modules
- API Endpoints
- Any web application module

### Version 1.0 - November 2025 (Deprecated)

**Initial Release:**
- Basic security testing template
- E-commerce oriented examples
- 15 example tests
- Basic standards references

---

**End of Security & Exploitation Template - Part 1**

**Related Files:**
- **TEMPLATE_security_PART2_critical_sections.md** (REQUIRED - Contains sections 18-19)
- TEMPLATE_functional_business_rules.md (Companion template)
- README_template.md (Documentation template)

**Author:** Arévalo, Marc
**Version:** 2.0 (Universal Edition)
**Date:** November 2025
**Warning:** Use only in authorized testing environments

**Quick Start:**
1. Read Section 2 (DISCOVER vs ASSUME) - CRITICAL
2. Review Section 3 (Anti-Patterns) - Learn what NOT to do
3. Check Research Matrix (Section 5) for your module type
4. Complete Before Writing Code Checklist (Section 6)
5. Review Example Conversations (Part 2, Section 18)
6. Check Common Vulnerabilities (Part 2, Section 19) for your module
7. Generate code following Section 7 template
8. Validate against Pre-Delivery Checklist

**Remember:** Tests must DISCOVER vulnerabilities, never ASSUME them.
