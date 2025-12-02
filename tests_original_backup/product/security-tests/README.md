# Product Details Security Testing Suite (Exploitation)

**Module:** `test_product_security.py`
**Author:** Arévalo, Marc
**Application Under Test:** DemoBlaze (https://www.demoblaze.com/)
**Current Version:** 1.0
**Test Type:** Security Testing (Penetration Testing / Exploitation)

---

## ⚠️ ETHICAL TESTING NOTICE

This test suite is designed for **authorized security testing only**.

**Legal Requirements:**
- Only test applications you **own** or have **explicit written permission** to test
- Follow responsible disclosure practices
- Comply with local laws and regulations (CFAA, Computer Misuse Act, etc.)
- Document all findings professionally
- Never use these tests for malicious purposes

**Unauthorized testing may be illegal and result in criminal prosecution.**

---

## Table of Contents

1. [Overview](#overview)
2. [Philosophy: DISCOVER Methodology](#philosophy)
3. [Quick Start](#quick-start)
4. [Test Coverage](#coverage)
5. [Vulnerability Catalog](#vulnerabilities)
6. [Attack Payloads](#payloads)
7. [Detailed Test Cases](#details)
8. [Execution Guide](#execution)
9. [Expected Results](#results)
10. [Standards Reference](#standards)
11. [CVSS Scoring Guide](#cvss)
12. [Vulnerability Reporting](#reporting)
13. [Troubleshooting](#troubleshooting)
14. [Best Practices](#practices)
15. [Version History](#version)

---

<a name="overview"></a>
## 1. Overview

### Purpose

This test suite conducts **security exploitation testing** on DemoBlaze's product detail page functionality. Tests follow the DISCOVER methodology, actively attempting to exploit vulnerabilities and reporting findings with CVSS v3.1 scoring.

### Test Methodology

**DISCOVER Philosophy for Security:**
1. **EXECUTE:** Attempt exploitation with various attack payloads
2. **OBSERVE:** Analyze responses for vulnerability indicators
3. **DECIDE:** Determine if vulnerability exists based on security standards

**Critical Principle:** Tests assume NO security controls exist until proven otherwise. Missing security features are reported as CRITICAL vulnerabilities, not excused as "out of scope."

### Scope

**Vulnerability Categories Tested:**
- SQL Injection (CWE-89)
- Cross-Site Scripting - XSS (CWE-79)
- Insecure Direct Object References - IDOR (CWE-639)
- Price Manipulation (CWE-840)
- Path Traversal (CWE-22)
- Session Fixation (CWE-384)
- CSRF (CWE-352)
- Security Headers (CWE-693)
- Information Disclosure (CWE-200, CWE-209)

**Standards Coverage:**
- OWASP ASVS v5.0 - Application Security Verification Standard
- CWE - Common Weakness Enumeration
- CVSS v3.1 - Common Vulnerability Scoring System
- OWASP Top 10 2021
- PCI-DSS v4.0 - Payment Card Industry Standards

### Test Statistics

- **Total Test Functions:** 18
- **Total Test Runs:** 25+ (with parametrization)
- **Critical Tests:** 4
- **High Severity Tests:** 10
- **Medium Severity Tests:** 3
- **Low Severity Tests:** 1
- **Attack Payloads:** 20+ unique payloads
- **Lines of Code:** ~1,200 lines

---

<a name="philosophy"></a>
## 2. Philosophy: DISCOVER Methodology for Security

### The DISCOVER Principle in Security Testing

Security tests follow **DISCOVER** with an exploitation focus:
- **D**iscover vulnerabilities through active exploitation
- **I**nvestigate responses for security weaknesses
- **S**tandards-based validation (OWASP, CWE, CVSS)
- **C**ritical vulnerabilities reported as ERRORS
- **O**bserve without assuming security controls exist
- **V**erify actual security posture
- **E**xploit and evaluate systematically
- **R**eport findings with CVSS scoring

### Security Testing Approach

**❌ INCORRECT Approach (What we DON'T do):**
```python
# Assuming security controls exist without testing
def test_sql_injection():
    # "Application probably uses parameterized queries"
    pytest.skip("Security assumed - out of scope")
```

**✅ CORRECT Approach (What we DO):**
```python
# Actively attempting exploitation
def test_sql_injection_INJ_001(browser, sql_payload):
    """
    CWE-89: SQL Injection
    CVSS Score: 9.8 (CRITICAL)
    """
    url = navigate_to_product_by_id(browser, sql_payload)

    if check_for_sql_error_indicators(browser.page_source):
        logging.error("CRITICAL VULNERABILITY: SQL INJECTION")
        logging.error(f"CVSS Score: 9.8 (CRITICAL)")
        logging.error(f"Payload: {sql_payload}")
        pytest.fail("DISCOVERED: SQL Injection vulnerability")
```

### Why This Matters for Security

1. **Real Vulnerability Discovery:** Tests find actual exploitable vulnerabilities
2. **Objective Assessment:** No assumptions about security controls
3. **Professional Reporting:** CVSS v3.1 scoring for risk assessment
4. **Compliance:** Validates against OWASP ASVS and PCI-DSS
5. **Actionable:** Reports include remediation guidance

---

<a name="quick-start"></a>
## 3. Quick Start

### Prerequisites

```bash
# Python 3.8+
python --version

# Install dependencies
pip install -r requirements.txt

# Required packages:
# - pytest
# - selenium
# - webdriver-manager
# - pytest-html
```

### ⚠️ IMPORTANT: Authorization Required

**Before running these tests:**
1. Ensure you have written authorization to test DemoBlaze
2. Understand that unauthorized testing may violate laws
3. Document your authorization
4. Follow responsible disclosure if vulnerabilities found

### Basic Execution

```bash
# Run all security tests
pytest tests/product_details/security-tests/test_product_security.py -v

# Run with HTML report
pytest test_product_security.py --html=report_security.html --self-contained-html

# Run critical vulnerabilities only
pytest test_product_security.py -m "critical" -v
```

### Quick Test Commands

```bash
# SQL injection tests only
pytest test_product_security.py -k "sql_injection" -v

# XSS tests only
pytest test_product_security.py -k "xss" -v

# IDOR tests only
pytest test_product_security.py -k "idor" -v

# High severity only
pytest test_product_security.py -m "high" -v
```

---

<a name="coverage"></a>
## 4. Test Coverage

### Vulnerability Categories

#### Injection Attacks (8 test runs)

| Test ID | Type | Payloads | CVSS | CWE | Status |
|---------|------|----------|------|-----|--------|
| INJ-001 | SQL Injection | 3 variants | 9.8 CRITICAL | CWE-89 | Parametrized |
| INJ-002 | SQL Error Disclosure | 4 variants | 5.3 MEDIUM | CWE-209 | Multiple |
| INJ-003 | XSS (Reflected) | 3 variants | 7.1 HIGH | CWE-79 | Parametrized |
| INJ-004 | XSS (Stored) | Multiple | 8.7 HIGH | CWE-79 | Single |

**SQL Injection Payloads Tested:**
- `1' OR '1'='1`
- `1' OR '1'='1' --`
- `1' OR '1'='1' /*`
- `' OR 1=1--`
- `admin'--`
- `' UNION SELECT NULL--`

**XSS Payloads Tested:**
- `<script>alert('XSS')</script>`
- `<img src=x onerror=alert('XSS')>`
- `<svg/onload=alert('XSS')>`
- `javascript:alert('XSS')`
- `'><script>alert(String.fromCharCode(88,83,83))</script>`

---

#### Access Control Vulnerabilities (3 tests)

| Test ID | Vulnerability | CVSS | CWE | Impact |
|---------|--------------|------|-----|---------|
| IDOR-001 | Product Enumeration | 5.3 MEDIUM | CWE-639 | Information Disclosure |
| IDOR-002 | Invalid ID Handling | 5.3 MEDIUM | CWE-209 | Error Information Exposure |
| IDOR-003 | Negative ID Access | 7.5 HIGH | CWE-20 | Hidden Product Access |

---

#### Business Logic Vulnerabilities (2 tests)

| Test ID | Type | CVSS | CWE | Impact |
|---------|------|------|-----|---------|
| PRICE-001 | Price Tampering | 8.2 HIGH | CWE-840 | Financial Loss |
| PRICE-002 | Price Consistency | 6.5 MEDIUM | CWE-840 | Data Integrity |

---

#### Path Traversal (3 test runs)

| Test ID | Type | Payloads | CVSS | CWE |
|---------|------|----------|------|-----|
| TRAV-001 | Path Traversal | 3 variants | 7.5 HIGH | CWE-22 |

**Path Traversal Payloads:**
- `../`
- `../../`
- `../../../`
- `..%2F`
- `..%5C`
- `%2e%2e%2f`

---

#### Session & Authentication (2 tests)

| Test ID | Vulnerability | CVSS | CWE |
|---------|--------------|------|-----|
| SESS-001 | Session Fixation | 7.5 HIGH | CWE-384 |
| CSRF-001 | CSRF Protection | 6.5 MEDIUM | CWE-352 |

---

#### Security Controls (2 tests)

| Test ID | Control | CVSS | CWE |
|---------|---------|------|-----|
| HEAD-001 | Security Headers | 5.3 MEDIUM | CWE-693 |
| INFO-001 | Information Disclosure | 3.7 LOW | CWE-200 |

---

### Test Execution Flow

```
START
  │
  ├─ Critical Tests (CVSS 9.0-10.0)
  │   └─ SQL Injection, RCE
  │
  ├─ High Severity Tests (CVSS 7.0-8.9)
  │   ├─ XSS
  │   ├─ IDOR
  │   ├─ Price Manipulation
  │   └─ Path Traversal
  │
  ├─ Medium Severity Tests (CVSS 4.0-6.9)
  │   ├─ Session Security
  │   ├─ CSRF
  │   └─ Information Disclosure
  │
  └─ Low Severity Tests (CVSS 0.1-3.9)
      └─ Information Leakage
END
```

---

<a name="vulnerabilities"></a>
## 5. Vulnerability Catalog

### CRITICAL (CVSS 9.0-10.0)

#### SQL Injection (CWE-89)
- **CVSS:** 9.8 (CRITICAL)
- **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
- **Impact:** Complete database compromise
- **Test:** INJ-001
- **Remediation:**
  - Use parameterized queries
  - Implement input validation
  - Apply principle of least privilege
  - Use ORM frameworks

---

### HIGH (CVSS 7.0-8.9)

#### Cross-Site Scripting - Reflected (CWE-79)
- **CVSS:** 7.1 (HIGH)
- **Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L
- **Impact:** Session hijacking, phishing, keylogging
- **Test:** INJ-003
- **Remediation:**
  - Implement output encoding
  - Use Content Security Policy
  - Validate and sanitize all inputs

#### Cross-Site Scripting - Stored (CWE-79)
- **CVSS:** 8.7 (HIGH)
- **Impact:** Persistent XSS affecting all users
- **Test:** INJ-004
- **Remediation:**
  - Same as reflected XSS
  - Additional server-side validation
  - Input sanitization on storage

#### Price Tampering (CWE-840)
- **CVSS:** 8.2 (HIGH)
- **Impact:** Direct financial loss, revenue manipulation
- **Test:** PRICE-001
- **Remediation:**
  - Never trust client-side pricing
  - Validate prices server-side
  - Use cryptographic signatures
  - Implement business logic validation

#### Path Traversal (CWE-22)
- **CVSS:** 7.5 (HIGH)
- **Impact:** Sensitive file access, configuration disclosure
- **Test:** TRAV-001
- **Remediation:**
  - Validate and sanitize file paths
  - Use allow-lists for file access
  - Implement proper access controls
  - Avoid user-controlled file paths

#### Negative Product ID Access (CWE-20)
- **CVSS:** 7.5 (HIGH)
- **Impact:** Access to hidden/administrative products
- **Test:** IDOR-003
- **Remediation:**
  - Implement proper input validation
  - Whitelist acceptable ID ranges
  - Add authorization checks

#### Session Fixation (CWE-384)
- **CVSS:** 7.5 (HIGH)
- **Impact:** Session hijacking, account takeover
- **Test:** SESS-001
- **Remediation:**
  - Regenerate session IDs after authentication
  - Use secure and httponly flags
  - Implement proper session management

---

### MEDIUM (CVSS 4.0-6.9)

#### CSRF (CWE-352)
- **CVSS:** 6.5 (MEDIUM)
- **Impact:** Forced actions on behalf of users
- **Test:** CSRF-001
- **Remediation:**
  - Implement CSRF tokens
  - Validate Origin/Referer headers
  - Use SameSite cookie attribute

#### Price Consistency (CWE-840)
- **CVSS:** 6.5 (MEDIUM)
- **Impact:** Data integrity issues
- **Test:** PRICE-002
- **Remediation:**
  - Ensure price consistency across views
  - Validate pricing logic

#### Product Enumeration (CWE-639)
- **CVSS:** 5.3 (MEDIUM)
- **Impact:** Information disclosure, competitor intelligence
- **Test:** IDOR-001
- **Remediation:**
  - Use non-sequential UUIDs
  - Implement rate limiting
  - Add authorization checks

#### SQL Error Disclosure (CWE-209)
- **CVSS:** 5.3 (MEDIUM)
- **Impact:** Database structure disclosure
- **Test:** INJ-002
- **Remediation:**
  - Implement generic error messages
  - Log detailed errors server-side only
  - Never expose stack traces

#### Security Headers Missing (CWE-693)
- **CVSS:** 5.3 (MEDIUM)
- **Impact:** Increased XSS risk, clickjacking
- **Test:** HEAD-001
- **Remediation:**
  - Implement CSP
  - Add X-Frame-Options
  - Use X-Content-Type-Options
  - Enable HSTS

---

### LOW (CVSS 0.1-3.9)

#### Information Disclosure (CWE-200)
- **CVSS:** 3.7 (LOW)
- **Impact:** Information aids further attacks
- **Test:** INFO-001
- **Remediation:**
  - Remove debug code from production
  - Sanitize comments
  - Minimize information exposure

---

<a name="payloads"></a>
## 6. Attack Payloads

### SQL Injection Payloads

**Basic Authentication Bypass:**
```sql
1' OR '1'='1
' OR 1=1--
admin'--
```

**Union-Based Injection:**
```sql
' UNION SELECT NULL--
' UNION SELECT username, password FROM users--
```

**Time-Based Blind:**
```sql
1' AND SLEEP(5)--
1' WAITFOR DELAY '0:0:5'--
```

### XSS Payloads

**Basic Script Injection:**
```html
<script>alert('XSS')</script>
<script>document.cookie</script>
```

**Event Handler-Based:**
```html
<img src=x onerror=alert('XSS')>
<body onload=alert('XSS')>
```

**SVG-Based:**
```html
<svg/onload=alert('XSS')>
```

**Obfuscated:**
```javascript
<script>alert(String.fromCharCode(88,83,83))</script>
```

### Path Traversal Payloads

**Directory Traversal:**
```
../../../etc/passwd
..\..\..\..\windows\system32\config\sam
```

**Encoded Traversal:**
```
..%2F..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f
```

### IDOR Payloads

**Sequential ID Enumeration:**
```
?id=1, ?id=2, ?id=3 ... ?id=1000
```

**Negative IDs:**
```
?id=-1, ?id=-10, ?id=-100
```

**Special Values:**
```
?id=0
?id=NULL
?id=undefined
?id=admin
```

---

<a name="details"></a>
## 7. Detailed Test Cases

### TC-PRODUCT-SEC-INJ-001: SQL Injection in Product ID

**Objective:** Discover if product ID parameter is vulnerable to SQL injection

**Attack Vector:**
```
https://www.demoblaze.com/prod.html?idp_=1' OR '1'='1
```

**Test Method:**
1. Navigate to product with SQL injection payload in ID
2. Analyze page source for SQL error messages
3. Check for unusual behavior (all products returned, etc.)
4. Look for keywords: "mysql", "syntax error", "postgresql"

**Indicators of Successful Exploitation:**
- SQL error messages visible in page source
- Database structure disclosed
- Unexpected data returned
- Application behavior changes

**If Vulnerability Discovered:**
```
CRITICAL VULNERABILITY: SQL INJECTION
Standard: OWASP ASVS v5.0 Section 5.3.4
CWE-89: SQL Injection
CVSS Score: 9.8 (CRITICAL)
Impact:
  - Complete database compromise possible
  - Customer data exposure
  - Payment information at risk
  - Administrative access possible
```

**Remediation:**
1. **Immediate:** Disable affected parameter
2. **Short-term:** Implement input validation
3. **Long-term:** Use parameterized queries
4. **Verify:** Re-test after remediation

---

### TC-PRODUCT-SEC-INJ-003: Reflected XSS in Product ID

**Objective:** Discover if product ID parameter reflects unencoded input

**Attack Vector:**
```
https://www.demoblaze.com/prod.html?idp_=<script>alert('XSS')</script>
```

**Test Method:**
1. Inject XSS payload in product ID parameter
2. Check if payload reflected in page without encoding
3. Verify if JavaScript executes
4. Analyze output encoding mechanisms

**Common Reflection Points:**
- Error messages
- URL parameters displayed on page
- Product detail sections
- Debug information

**Impact Assessment:**
- **Session Hijacking:** Steal session cookies via document.cookie
- **Phishing:** Redirect to fake login page
- **Keylogging:** Capture user input
- **Defacement:** Modify page content

**If Vulnerability Discovered:**
```
CRITICAL VULNERABILITY: REFLECTED XSS
CVSS Score: 7.1 (HIGH)
Exploitation: Active (user must click link)
Persistence: No (reflected only)
```

---

### TC-PRODUCT-SEC-PRICE-001: Price Tampering

**Objective:** Discover if product price can be manipulated

**Attack Vector:**
```
Original URL: https://www.demoblaze.com/prod.html?idp_=1
Tampered URL: https://www.demoblaze.com/prod.html?idp_=1&price=1
```

**Test Method:**
1. Navigate to legitimate product, record price
2. Modify URL to include price parameter
3. Check if displayed price changes
4. Attempt to add to cart with tampered price
5. Verify if tampered price persists through checkout

**Business Impact:**
- **Direct Financial Loss:** Products sold at wrong prices
- **Revenue Manipulation:** Inventory value incorrect
- **Fraud:** Malicious users exploit for personal gain

**Real-World Example:**
> In 2019, a major e-commerce site lost $1.2M due to price manipulation vulnerability where users modified product prices in POST requests.

**If Vulnerability Discovered:**
```
CRITICAL VULNERABILITY: PRICE TAMPERING
CVSS Score: 8.2 (HIGH)
Impact: Direct financial loss possible
Recommendation:
  - NEVER trust client-side pricing
  - Validate all prices server-side
  - Use cryptographic signatures for price data
```

---

### TC-PRODUCT-SEC-IDOR-003: Negative Product ID Access

**Objective:** Discover if negative IDs expose hidden products

**Attack Vector:**
```
https://www.demoblaze.com/prod.html?idp_=-1
https://www.demoblaze.com/prod.html?idp_=-100
```

**Test Method:**
1. Attempt to access products with negative IDs
2. Check if hidden/administrative products are accessible
3. Verify if test products are exposed
4. Analyze if pricing is different for hidden products

**Why This Matters:**
- Negative IDs often used for test/admin products
- May have unrealistic prices (0.01, 99999)
- Can expose products not intended for public
- May reveal internal product codes

**If Vulnerability Discovered:**
```
CRITICAL VULNERABILITY: HIDDEN PRODUCTS ACCESSIBLE
CVSS Score: 7.5 (HIGH)
Products with negative IDs accessible without authorization
Potential test/admin products exposed
```

---

### TC-PRODUCT-SEC-CSRF-001: CSRF on Add to Cart

**Objective:** Discover if add to cart action is protected against CSRF

**Attack Scenario:**
1. Attacker creates malicious page with auto-submit form
2. Form targets add-to-cart endpoint
3. Victim visits attacker's page while logged into e-commerce site
4. Product automatically added to victim's cart

**Test Method:**
1. Navigate to product page
2. Inspect add to cart request
3. Check for CSRF token in request
4. Verify token validation on server

**Exploitation Impact:**
- Unwanted items added to cart
- Checkout initiated without consent
- Can be combined with other attacks

**If Vulnerability Discovered:**
```
POTENTIAL VULNERABILITY: NO CSRF PROTECTION
CVSS Score: 6.5 (MEDIUM)
Add to cart action may be vulnerable to CSRF
Further testing required to confirm exploitation
```

---

<a name="execution"></a>
## 8. Execution Guide

### Standard Execution

```bash
# Run all security tests
pytest test_product_security.py -v

# Run with HTML report
pytest test_product_security.py --html=report_security.html --self-contained-html

# Run specific test
pytest test_product_security.py::test_sql_injection_product_id_INJ_001 -v
```

### Selective Execution by Severity

```bash
# Critical vulnerabilities only
pytest test_product_security.py -m "critical" -v

# High and critical
pytest test_product_security.py -m "critical or high" -v

# Medium severity
pytest test_product_security.py -m "medium" -v

# Exclude low severity
pytest test_product_security.py -m "not low" -v
```

### Selective Execution by Vulnerability Type

```bash
# SQL injection tests only
pytest test_product_security.py -k "sql_injection" -v

# All injection tests (SQL + XSS)
pytest test_product_security.py -k "injection" -v

# XSS tests only
pytest test_product_security.py -k "xss" -v

# IDOR tests
pytest test_product_security.py -k "idor" -v

# Price manipulation
pytest test_product_security.py -k "price" -v

# Session security
pytest test_product_security.py -k "session or csrf" -v
```

### Browser Selection

```bash
# Run with Firefox
pytest test_product_security.py --browser=firefox -v

# Run headless (recommended for security testing)
pytest test_product_security.py --headless -v
```

### Advanced Options

```bash
# Stop on first failure
pytest test_product_security.py -x

# Run with detailed output
pytest test_product_security.py -vv -s

# Run specific parametrized test
pytest test_product_security.py::test_sql_injection_product_id_INJ_001[1' OR '1'='1] -v
```

### CI/CD Integration

```bash
# Complete security test in CI/CD
pytest test_product_security.py \
  --browser=chrome \
  --headless \
  -v \
  --html=security_report.html \
  --self-contained-html \
  --junitxml=security_results.xml
```

---

<a name="results"></a>
## 9. Expected Results

### Interpreting Test Results

#### All Tests Pass (No Vulnerabilities Found)

```
======================== test session starts =========================
collected 25 items

test_product_security.py::test_sql_injection_product_id_INJ_001[1' OR '1'='1] PASSED
test_product_security.py::test_xss_product_id_parameter_INJ_003[<script>alert('XSS')</script>] PASSED
...

===================== 25 passed in 240.23s ==========================
```

**Interpretation:** Application passed all security tests. However, this doesn't guarantee security - only that these specific vulnerabilities were not found.

---

#### Test Failure (Vulnerability Discovered)

**SQL Injection Example:**
```
FAILED test_product_security.py::test_sql_injection_product_id_INJ_001
pytest.Failed: DISCOVERED: SQL Injection vulnerability in product ID parameter

CRITICAL VULNERABILITY: SQL INJECTION
Payload: 1' OR '1'='1
URL: https://www.demoblaze.com/prod.html?idp_=1' OR '1'='1
Standard: OWASP ASVS v5.0 Section 5.3.4
CWE-89: SQL Injection
CVSS Score: 9.8 (CRITICAL)
SQL Error Indicators Found: ['mysql', 'syntax error']
```

**Immediate Actions Required:**
1. Document the vulnerability with screenshots
2. Assess business impact
3. Notify security team immediately
4. Create remediation plan
5. Re-test after fix

---

**XSS Example:**
```
FAILED test_product_security.py::test_xss_product_id_parameter_INJ_003
pytest.Failed: DISCOVERED: XSS vulnerability in product ID parameter

CRITICAL VULNERABILITY: REFLECTED XSS
Payload: <script>alert('XSS')</script>
CVSS Score: 7.1 (HIGH)
Impact: Session hijacking, phishing, keylogging
```

**Actions:**
1. Verify scope of vulnerability
2. Check if other parameters affected
3. Implement output encoding
4. Test with different payloads
5. Re-test after remediation

---

**Price Tampering Example:**
```
FAILED test_product_security.py::test_price_tampering_url_parameter_PRICE_001
pytest.Failed: DISCOVERED: Price tampering vulnerability via URL manipulation

CRITICAL VULNERABILITY: PRICE TAMPERING
Original price: $790
Tampered price: $1
CVSS Score: 8.2 (HIGH)
Impact: Direct financial loss possible
```

**Immediate Actions:**
1. **CRITICAL:** Disable affected functionality immediately
2. Audit all recent transactions
3. Implement server-side price validation
4. Review business logic security

---

### Expected Test Failures (Discovery Mode)

These tests are **designed to discover vulnerabilities**. If they fail, they're working correctly:

| Test | Expected Result | Interpretation |
|------|----------------|----------------|
| SQL Injection | LIKELY PASS | Most modern frameworks prevent SQL injection |
| XSS | MAY FAIL | XSS is common, especially reflected XSS |
| IDOR | LIKELY FAIL | Sequential IDs common in e-commerce |
| Price Tampering | MAY FAIL | Business logic vulnerabilities often overlooked |
| CSRF | MAY FAIL | CSRF protection not always implemented |

**If tests FAIL, it means vulnerabilities were DISCOVERED - this is the intended behavior.**

---

<a name="standards"></a>
## 10. Standards Reference

### OWASP ASVS v5.0 - Application Security Verification Standard

**Section 5.3.3: Output Encoding**
- Requirement: All output must be properly encoded
- Tests: INJ-003, INJ-004 (XSS tests)
- Level: 1 (Minimum required for all applications)

**Section 5.3.4: SQL Injection Prevention**
- Requirement: Use parameterized queries for all database access
- Tests: INJ-001, INJ-002
- Level: 1 (Minimum required for all applications)

**Section 4.1.2: Access Control**
- Requirement: Verify authorization for all resources
- Tests: IDOR-001, IDOR-003
- Level: 1

**Section 4.2.1: Business Logic Security**
- Requirement: Validate business logic server-side
- Tests: PRICE-001, PRICE-002
- Level: 1

**Section 4.2.2: CSRF Prevention**
- Requirement: Implement CSRF tokens for state-changing operations
- Tests: CSRF-001
- Level: 1

**Section 7.4.1: Error Handling**
- Requirement: Never expose detailed error messages to users
- Tests: INJ-002, IDOR-002
- Level: 1

**Section 12.3.1: File Execution**
- Requirement: Prevent path traversal attacks
- Tests: TRAV-001
- Level: 1

**Section 14.4.1: HTTP Security Headers**
- Requirement: Implement security headers (CSP, X-Frame-Options, etc.)
- Tests: HEAD-001
- Level: 2

---

### CWE - Common Weakness Enumeration

**CWE-89: SQL Injection**
- Rank: #1 in 2021 CWE Top 25
- Tests: INJ-001, INJ-002
- Description: Improper neutralization of SQL commands

**CWE-79: Cross-site Scripting**
- Rank: #2 in 2021 CWE Top 25
- Tests: INJ-003, INJ-004
- Description: Improper neutralization of input during web page generation

**CWE-22: Path Traversal**
- Rank: #8 in 2021 CWE Top 25
- Tests: TRAV-001
- Description: Improper limitation of pathname to restricted directory

**CWE-352: Cross-Site Request Forgery**
- Rank: #9 in 2021 CWE Top 25
- Tests: CSRF-001
- Description: Lack of proper token validation

**CWE-840: Business Logic Errors**
- Tests: PRICE-001, PRICE-002
- Description: Improper enforcement of business rules

**CWE-639: Authorization Bypass**
- Tests: IDOR-001, IDOR-003
- Description: Access control based on user-controlled key

**CWE-384: Session Fixation**
- Tests: SESS-001
- Description: Session ID not regenerated

**CWE-693: Protection Mechanism Failure**
- Tests: HEAD-001
- Description: Missing security controls

**CWE-200/209: Information Exposure**
- Tests: INFO-001, INJ-002, IDOR-002
- Description: Sensitive information disclosed

---

### OWASP Top 10 2021 Mapping

| OWASP Top 10 Category | Tests Coverage |
|----------------------|----------------|
| A01: Broken Access Control | IDOR-001, IDOR-002, IDOR-003 |
| A02: Cryptographic Failures | SESS-001, HEAD-001 |
| A03: Injection | INJ-001, INJ-002, INJ-003, INJ-004 |
| A04: Insecure Design | PRICE-001, PRICE-002 |
| A05: Security Misconfiguration | HEAD-001, INFO-001 |
| A06: Vulnerable Components | N/A (framework testing) |
| A07: Authentication Failures | SESS-001 |
| A08: Software/Data Integrity | PRICE-001, PRICE-002 |
| A09: Security Logging Failures | N/A (infrastructure) |
| A10: SSRF | N/A (not applicable to product pages) |

---

### PCI-DSS v4.0 Relevance

**Requirement 6.5.1: Injection Flaws**
- Tests: INJ-001, INJ-002, INJ-003, INJ-004, TRAV-001
- Compliance: Must prevent SQL injection and XSS

**Requirement 6.5.9: Improper Access Control**
- Tests: IDOR-001, IDOR-002, IDOR-003
- Compliance: Must implement proper authorization

**Requirement 6.5.10: Broken Authentication**
- Tests: SESS-001
- Compliance: Must implement secure session management

---

<a name="cvss"></a>
## 11. CVSS v3.1 Scoring Guide

### Understanding CVSS Scores

**CVSS v3.1 Vector Example:**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

**Breakdown:**
- **AV:N** - Attack Vector: Network (exploitable remotely)
- **AC:L** - Attack Complexity: Low (no special conditions required)
- **PR:N** - Privileges Required: None (no authentication needed)
- **UI:N** - User Interaction: None (no user action required)
- **S:U** - Scope: Unchanged (affects only vulnerable component)
- **C:H** - Confidentiality Impact: High (total information disclosure)
- **I:H** - Integrity Impact: High (total compromise)
- **A:H** - Availability Impact: High (total denial of service)

### Severity Ratings

| CVSS Score | Severity | Examples in This Suite |
|------------|----------|------------------------|
| 0.0 | None | No vulnerabilities |
| 0.1-3.9 | **LOW** | Information disclosure (INFO-001) |
| 4.0-6.9 | **MEDIUM** | CSRF, Enumeration, Error disclosure |
| 7.0-8.9 | **HIGH** | XSS, IDOR, Price tampering, Path traversal |
| 9.0-10.0 | **CRITICAL** | SQL Injection |

### CVSS Scores by Test

| Test | CVSS | Severity | Justification |
|------|------|----------|---------------|
| INJ-001 | 9.8 | CRITICAL | Network-exploitable SQL injection with no auth required |
| INJ-003 | 7.1 | HIGH | XSS requires user interaction but has cross-site impact |
| INJ-004 | 8.7 | HIGH | Stored XSS affects all users without interaction |
| PRICE-001 | 8.2 | HIGH | Direct financial impact with low complexity |
| TRAV-001 | 7.5 | HIGH | File access with potential for full system compromise |
| IDOR-003 | 7.5 | HIGH | Access to hidden products without authorization |
| SESS-001 | 7.5 | HIGH | Session hijacking leads to account takeover |
| CSRF-001 | 6.5 | MEDIUM | Requires user interaction and limited impact |
| IDOR-001 | 5.3 | MEDIUM | Information disclosure but expected for public catalog |
| HEAD-001 | 5.3 | MEDIUM | Missing security controls increase risk |
| INFO-001 | 3.7 | LOW | Information aids attacks but limited direct impact |

---

<a name="reporting"></a>
## 12. Vulnerability Reporting

### Vulnerability Report Template

```markdown
# SECURITY VULNERABILITY REPORT

**Report ID:** VULN-YYYY-MM-DD-001
**Discovered By:** [Your Name]
**Date Discovered:** YYYY-MM-DD
**Application:** DemoBlaze Product Details
**Environment:** Production

---

## Executive Summary

Brief description of the vulnerability and its impact.

---

## Vulnerability Details

**Type:** [SQL Injection / XSS / IDOR / etc.]
**CWE:** CWE-XXX
**CVSS Score:** X.X (SEVERITY)
**CVSS Vector:** CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X

---

## Location

**URL:** https://www.demoblaze.com/prod.html?idp_=
**Parameter:** idp_
**Method:** GET

---

## Proof of Concept

### Reproduction Steps:
1. Navigate to product detail page
2. Inject payload: [payload here]
3. Observe: [what happens]

### Evidence:
- Screenshot 1: [description]
- Screenshot 2: [description]
- Log output: [relevant logs]

---

## Impact Assessment

**Confidentiality:** [HIGH/MEDIUM/LOW]
- Description of confidentiality impact

**Integrity:** [HIGH/MEDIUM/LOW]
- Description of integrity impact

**Availability:** [HIGH/MEDIUM/LOW]
- Description of availability impact

**Business Impact:**
- Financial risk
- Reputation damage
- Legal/compliance impact

---

## Remediation Recommendations

### Immediate Actions (0-24 hours):
1. [Action 1]
2. [Action 2]

### Short-term Actions (1-7 days):
1. [Action 1]
2. [Action 2]

### Long-term Actions (1-3 months):
1. [Action 1]
2. [Action 2]

---

## References

- OWASP ASVS Section X.X.X
- CWE-XXX: https://cwe.mitre.org/data/definitions/XXX.html
- CVSS Calculator: https://www.first.org/cvss/calculator/3.1

---

## Timeline

- **YYYY-MM-DD:** Vulnerability discovered
- **YYYY-MM-DD:** Vendor notified
- **YYYY-MM-DD:** Vendor acknowledged
- **YYYY-MM-DD:** Fix deployed
- **YYYY-MM-DD:** Re-test confirmed fix
```

---

### Responsible Disclosure Process

1. **Discovery:** Document vulnerability thoroughly
2. **Internal Verification:** Confirm vulnerability is real and reproducible
3. **Vendor Notification:** Contact security team via secure channel
4. **Wait Period:** Give vendor 90 days to fix (industry standard)
5. **Re-test:** Verify fix is effective
6. **Disclosure:** Publish findings after vendor has fixed (if applicable)

**Contact Information for DemoBlaze:**
- Email: [security@demoblaze.com] (if available)
- Bug Bounty: [Check if program exists]
- Responsible Disclosure Policy: [Check vendor policy]

---

<a name="troubleshooting"></a>
## 13. Troubleshooting

### Common Issues

**Issue 1: No SQL Errors Detected But Injection Exists**
```
Test passes but you suspect SQL injection vulnerability exists
```
**Cause:** Application may suppress error messages
**Solution:**
- Try blind SQL injection techniques
- Use time-based payloads
- Monitor application response times
- Check for boolean-based injection

---

**Issue 2: XSS Payload Gets Encoded**
```
XSS payload appears in source but is HTML-encoded
```
**Expected Behavior:** This is CORRECT - application is secure
**Confirmation:**
- Check that `<` is encoded as `&lt;`
- Check that `>` is encoded as `&gt;`
- Verify no script execution possible

---

**Issue 3: IDOR Test Shows All Products Accessible**
```
IDOR-001 reports many products enumerable
```
**Expected:** For public e-commerce, this is normal
**When It's a Problem:**
- Hidden/admin products accessible
- User-specific products accessible without auth
- Test products visible in production

---

**Issue 4: Price Tampering Test Inconclusive**
```
Cannot confirm if price tampering affects checkout
```
**Limitation:** These tests only check display price
**Full Test Requires:**
- Complete purchase flow
- Backend request inspection
- Order confirmation validation

**Solution:** Extend tests to include cart/checkout

---

**Issue 5: CSRF Test Cannot Confirm Vulnerability**
```
CSRF test warns of potential vulnerability but cannot confirm
```
**Reason:** Selenium cannot easily test CSRF
**Manual Testing Required:**
1. Create separate HTML page with form
2. Submit form to add-to-cart endpoint
3. Check if action succeeds without token

---

**Issue 6: Security Headers Check Limited**
```
Cannot detect all security headers via Selenium
```
**Limitation:** Selenium has limited access to HTTP headers
**Solution:**
- Use browser DevTools to inspect
- Use curl/Burp Suite for header inspection
- Implement requests-based tests for headers

---

<a name="practices"></a>
## 14. Best Practices

### Security Testing Best Practices

1. **Always Get Authorization**
   - Written permission required
   - Document scope of testing
   - Understand legal boundaries

2. **Test in Safe Environment**
   - Use staging/test environments when possible
   - Avoid production during business hours
   - Have rollback plan ready

3. **Rate Limit Your Tests**
   - Don't overwhelm application
   - Space out attack attempts
   - Avoid DOS conditions

4. **Document Everything**
   - Screenshot every finding
   - Save request/response logs
   - Maintain detailed notes

5. **Follow Responsible Disclosure**
   - Give vendors time to fix
   - Don't publish details prematurely
   - Work collaboratively with security teams

### Test Maintenance

1. **Update Payloads Regularly**
   - New attack techniques emerge
   - Update payload lists quarterly
   - Follow security research

2. **Review CVSS Scores**
   - CVSS scoring evolves
   - Update scores annually
   - Consider context changes

3. **Monitor for New Vulnerabilities**
   - Follow CVE announcements
   - Track OWASP updates
   - Update tests accordingly

### Extending Test Suite

**Adding New Security Tests:**
```python
@pytest.mark.security
@pytest.mark.critical
def test_new_vulnerability_TYPE_XXX(browser):
    """
    TC-PRODUCT-SEC-TYPE-XXX: [Vulnerability Name]

    Standard: OWASP ASVS v5.0 Section X.X.X
    CWE: CWE-XXX
    CVSS Score: X.X (SEVERITY)
    Vector: CVSS:3.1/...

    Discovers if [description].
    """
    # Test implementation
```

---

<a name="version"></a>
## 15. Version History

### Version 1.0 - November 2025 (Current)

**Initial Release**

**Test Coverage:**
- 18 test functions
- 25+ test runs (with parametrization)
- 9 vulnerability categories

**Vulnerability Categories:**
- SQL Injection (4 tests, 8 runs)
- Cross-Site Scripting (2 tests, 4 runs)
- IDOR (3 tests)
- Price Manipulation (2 tests)
- Path Traversal (1 test, 3 runs)
- Session Security (1 test)
- CSRF (1 test)
- Security Headers (1 test)
- Information Disclosure (1 test)

**Attack Payloads:**
- 6 SQL injection variants
- 5 XSS variants
- 6 path traversal variants
- Multiple IDOR test cases

**Key Features:**
- CVSS v3.1 scoring for all vulnerabilities
- CWE references
- OWASP ASVS compliance mapping
- Comprehensive logging with severity levels
- Evidence collection
- Ethical testing guidelines
- Vulnerability reporting templates

**Code Quality:**
- Professional attack payload library
- Clean helper functions for exploitation
- Parametrized testing for efficiency
- Comprehensive error handling
- No duplicate fixtures (uses conftest.py)

**Documentation:**
- Complete vulnerability catalog
- CVSS scoring guide
- Responsible disclosure guidance
- Remediation recommendations
- Ethical testing guidelines

---

## Related Documents

- **Test Implementation:** [test_product_security.py](test_product_security.py)
- **Functional Tests:** [README_test_product_functionality.md](../functional-tests/README.md)
- **DISCOVER Philosophy:** [DISCOVER_PHILOSOPHY.md](../../discover-philosophy-for-better-tests/DISCOVER_PHILOSOPHY.md)
- **Catalog Security:** [README_test_catalog_security.md](../../catalog/security-tests/README.md)

---

## Ethical and Legal Disclaimer

**This test suite is designed for authorized security testing only.**

- **Obtain written authorization** before testing any application
- **Comply with all laws** including CFAA (US), Computer Misuse Act (UK), and local regulations
- **Follow responsible disclosure** practices for any vulnerabilities discovered
- **Never use these tests** for malicious purposes
- **Document all testing activities** thoroughly
- **Work with security teams** collaboratively

**Unauthorized use of these tests may result in criminal prosecution.**

---

**Author:** Arévalo, Marc
**Version:** 1.0
**Last Updated:** November 2025

---

**End of Documentation**
