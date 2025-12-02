# Catalog & Product Browsing Security Testing Suite

**Module:** `test_catalog_security.py`
**Author:** QA Testing Team
**Application Under Test:** DemoBlaze (https://www.demoblaze.com/)
**Current Version:** 1.0
**Test Type:** Security Exploitation Testing

---

## Table of Contents

1. [Overview](#overview)
2. [CRITICAL: Ethical Testing Guidelines](#ethics)
3. [Philosophy: DISCOVER Methodology](#philosophy)
4. [Quick Start](#quick-start)
5. [Test Coverage](#coverage)
6. [Attack Payloads](#payloads)
7. [Test Inventory](#inventory)
8. [Detailed Test Cases](#details)
9. [Execution Guide](#execution)
10. [Expected Results](#results)
11. [Vulnerability Reporting](#reporting)
12. [CVSS Scoring Reference](#cvss)
13. [Troubleshooting](#troubleshooting)
14. [Standards Reference](#standards)
15. [Version History](#version)

---

<a name="overview"></a>
## 1. Overview

### Purpose

This test suite performs security exploitation testing on the catalog and product browsing functionality. Tests execute real attack payloads, observe system responses, and report vulnerabilities based on OWASP standards and CVSS v3.1 scoring.

### Test Methodology

**DISCOVER Philosophy:**
1. **EXECUTE:** Launch actual attack payload against the system
2. **OBSERVE:** Analyze system response for indicators of compromise
3. **DECIDE:** Determine if vulnerability exists based on OWASP/CWE standards

**Critical Principle:** Security vulnerabilities are reported as CRITICAL ERRORS with full CVSS scoring, never excused as "known limitations" or "demo app issues."

### Scope

**In Scope:**
- SQL Injection attacks (category filters, product IDs)
- Cross-Site Scripting (XSS) in search and filters
- Insecure Direct Object Reference (IDOR) on products
- Path Traversal in file access
- Enumeration attacks (product IDs, catalog)
- Session security (fixation, cookies)
- CSRF protection validation
- Security headers presence
- Rate limiting validation
- Information disclosure via errors

**Out of Scope:**
- Payment processing security (covered in purchase tests)
- Authentication bypass (covered in login tests)
- Physical security
- Social engineering

**Test Statistics:**
- **Total Test Functions:** 19
- **Total Test Runs:** 28+ (with parametrization)
- **Vulnerability Categories:** 9
- **Average Execution Time:** 6-10 minutes

### Standards Validated

| Standard | Version | Coverage |
|----------|---------|----------|
| **OWASP ASVS** | v5.0 | Input Validation, Access Control, Error Handling, Session Management |
| **OWASP Top 10** | 2021 | Injection, XSS, Broken Access Control, Security Misconfiguration |
| **CWE** | Current | Specific weaknesses (89, 79, 22, 352, 384, etc.) |
| **NIST SP 800-63B** | Latest | Digital Identity Guidelines |
| **PCI-DSS** | v4.0 | Payment Card Industry Security Standards |

---

<a name="ethics"></a>
## 2. CRITICAL: Ethical Testing Guidelines

### Authorization Required

**BEFORE RUNNING THESE TESTS, YOU MUST HAVE:**

1. Written authorization to perform security testing
2. Clear scope definition of what can be tested
3. Non-production environment OR explicit production approval
4. Incident response plan if vulnerabilities are discovered

### Legal Considerations

**WARNING:** Unauthorized security testing is illegal in most jurisdictions.

**Legal Risks:**
- Computer Fraud and Abuse Act (CFAA) violations
- Violation of terms of service
- Criminal charges possible
- Civil liability for damages

**Authorized Testing Scenarios:**
- Your own applications
- Client applications with written permission
- Bug bounty programs (follow their rules)
- Educational labs and demo applications designed for testing

### Responsible Disclosure

If you discover vulnerabilities:

1. **DO NOT** exploit them beyond proof-of-concept
2. **DO NOT** publish details publicly before vendor can fix
3. **DO** report to vendor/security team immediately
4. **DO** follow coordinated disclosure timeline (typically 90 days)
5. **DO** document findings professionally

### Test Environment Verification

```python
# ALWAYS verify you're testing the authorized environment
BASE_URL = "https://www.demoblaze.com/"  # VERIFY THIS

# Add safety check for production environments
if "production" in BASE_URL and not PRODUCTION_TESTING_AUTHORIZED:
    raise Exception("Production testing requires explicit authorization!")
```

### Damage Prevention

**Test Limits:**
- Rate limiting tests: Maximum 20-30 requests
- Enumeration tests: Maximum 30 sequential attempts
- DoS tests: NOT included (can cause actual damage)
- Destructive payloads: NOT included

**Data Protection:**
- Never extract real user data
- Never modify production databases
- Never delete or corrupt data
- Stop testing immediately if damage occurs

---

<a name="philosophy"></a>
## 3. Philosophy: DISCOVER Methodology

### Core Principle

Security tests discover vulnerabilities by executing attacks and observing results against industry standards. Security weaknesses are reported as ERRORS, not excused.

### DISCOVER Formula for Security Testing

```
DISCOVER = EXECUTE + OBSERVE + DECIDE

1. EXECUTE: Launch actual attack payload
2. OBSERVE: Analyze response for compromise indicators
3. DECIDE: Determine vulnerability based on OWASP/CWE standards
```

### Example: SQL Injection Test

**WRONG Approach (Assuming):**
```python
def test_sql_injection():
    # Assume demo app has SQL injection
    pytest.skip("Known vulnerability, won't test")  # WRONG
```

**CORRECT Approach (DISCOVER):**
```python
def test_sql_injection_product_id_INJ_002(browser, sql_payload):
    # EXECUTE: Attempt SQL injection
    browser.get(f"{BASE_URL}prod.html?idp_={sql_payload}")

    # OBSERVE: Check for SQL errors
    has_error, indicator = check_for_sql_error_indicators(browser)

    # DECIDE: Based on OWASP ASVS 5.3.4
    if has_error:
        logging.error("CRITICAL VULNERABILITY: SQL INJECTION")
        logging.error("Standard: OWASP ASVS v5.0 Section 5.3.4")
        logging.error("CWE-89: SQL Injection")
        logging.error("CVSS Score: 9.8 (CRITICAL)")
        pytest.fail("DISCOVERED: SQL injection vulnerability")
```

This test objectively **discovers** whether SQL injection exists, not based on prior knowledge.

### Why This Matters

**For Security Professionals:**
- Demonstrates understanding of vulnerability assessment
- Shows knowledge of OWASP standards and CVSS scoring
- Proves ability to execute real security testing

**For Organizations:**
- Vulnerabilities have legal and financial implications
- OWASP Top 10 compliance often required
- PCI-DSS mandates security testing

---

<a name="quick-start"></a>
## 4. Quick Start

### Prerequisites

```bash
# Install required packages
pip install pytest selenium requests

# Verify ChromeDriver
chromedriver --version
```

### Run All Security Tests

```bash
# Complete security suite
pytest test_catalog_security.py -v

# Generate HTML report
pytest test_catalog_security.py --html=report_catalog_security.html --self-contained-html
```

### Run by Severity

```bash
# Critical vulnerabilities only
pytest test_catalog_security.py -m "critical" -v

# High severity
pytest test_catalog_security.py -m "high" -v

# Medium and above
pytest test_catalog_security.py -m "high or medium" -v
```

### Run by Vulnerability Type

```bash
# SQL injection tests only
pytest test_catalog_security.py -k "sql_injection" -v

# XSS tests only
pytest test_catalog_security.py -k "xss" -v

# IDOR tests
pytest test_catalog_security.py -k "idor" -v

# All injection tests
pytest test_catalog_security.py -k "injection" -v
```

### Expected Execution Time

- Full suite: 6-10 minutes
- Critical tests only: 3-4 minutes
- Single vulnerability category: 1-2 minutes

---

<a name="coverage"></a>
## 5. Test Coverage

### Vulnerability Categories

#### Injection Attacks (11 test runs)

| Test ID | Type | Target | Payloads | CVSS | Status |
|---------|------|--------|----------|------|--------|
| INJ-001 | SQL Injection | Category Filter | 6 variants | 9.8 CRITICAL | Parametrized |
| INJ-002 | SQL Injection | Product ID | 3 variants | 9.8 CRITICAL | Parametrized |
| INJ-003 | XSS | Search | 5 variants | 7.1 HIGH | Parametrized |
| INJ-004 | Stored XSS | Reviews | 1 test | 8.7 HIGH | Single |

**SQL Payloads Tested:**
- `' OR '1'='1`
- `1' OR '1'='1`
- `' OR 1=1--`
- `') OR ('1'='1`
- `1' UNION SELECT NULL--`
- `' AND 1=0 UNION ALL SELECT ...`

**XSS Payloads Tested:**
- `<script>alert('XSS')</script>`
- `<img src=x onerror=alert('XSS')>`
- `<svg/onload=alert('XSS')>`
- `javascript:alert('XSS')`
- `'><script>alert(String.fromCharCode(88,83,83))</script>`

#### Access Control (2 tests)

| Test ID | Vulnerability | CVSS | CWE |
|---------|--------------|------|-----|
| IDOR-001 | Product Enumeration | 7.5 HIGH | CWE-669 |
| IDOR-002 | Invalid ID Handling | 5.3 MEDIUM | CWE-209 |

#### Path Traversal (8 test runs)

| Test ID | Target | Payloads | CVSS | Status |
|---------|--------|----------|------|--------|
| TRAV-001 | Image Paths | 8 variants | 7.5 HIGH | Parametrized |

**Traversal Payloads:**
- `../`
- `../../`
- `..\\`
- `..%2F`
- `..%5C`
- `%2e%2e%2f`
- `....//`

#### Enumeration (2 tests)

| Test ID | Type | CVSS | CWE |
|---------|------|------|-----|
| ENUM-001 | Sequential IDs | 5.3 MEDIUM | CWE-200 |
| TIME-001 | Timing Attack | 5.3 MEDIUM | CWE-208 |

#### Session Security (2 tests)

| Test ID | Vulnerability | CVSS | CWE |
|---------|--------------|------|-----|
| SESS-001 | Session Fixation | 7.5 HIGH | CWE-384 |
| COOK-001 | Cookie Flags | 6.5 MEDIUM | CWE-614 |

#### Security Controls (3 tests)

| Test ID | Control | CVSS | CWE |
|---------|---------|------|-----|
| CSRF-001 | CSRF Protection | 6.5 MEDIUM | CWE-352 |
| HEAD-001 | Security Headers | 7.5 HIGH | CWE-693 |
| RATE-001 | Rate Limiting | 5.3 MEDIUM | CWE-307 |

#### Information Disclosure (2 tests)

| Test ID | Type | CVSS | CWE |
|---------|------|------|-----|
| INFO-001 | Verbose Errors | 3.7 LOW | CWE-209 |
| INFO-002 | Directory Listing | 5.3 MEDIUM | CWE-548 |

---

<a name="payloads"></a>
## 6. Attack Payloads

### SQL Injection Payloads

**Purpose:** Bypass authentication, extract data, modify database

**Classic Bypasses:**
```sql
' OR '1'='1
1' OR '1'='1
' OR 1=1--
```

**Union-Based Extraction:**
```sql
') OR ('1'='1
1' UNION SELECT NULL--
' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
```

**Why These Work:**
- Break out of SQL string context
- Inject OR conditions that always evaluate to true
- Use comments to ignore rest of query
- UNION allows data extraction from other tables

### XSS Payloads

**Purpose:** Execute JavaScript in victim's browser

**Script Tags:**
```javascript
<script>alert('XSS')</script>
```

**Event Handlers:**
```html
<img src=x onerror=alert('XSS')>
<svg/onload=alert('XSS')>
```

**Protocol Handlers:**
```javascript
javascript:alert('XSS')
```

**Obfuscation:**
```javascript
'><script>alert(String.fromCharCode(88,83,83))</script>
```

**Why These Work:**
- Inject HTML/JavaScript into page
- Event handlers execute without user interaction
- Bypass basic filters with encoding
- Protocol handlers in href attributes

### Path Traversal Payloads

**Purpose:** Access files outside intended directory

**Basic Traversal:**
```
../
../../
../../../
```

**Windows:**
```
..\\
..\\..\\
```

**URL Encoding:**
```
..%2F
..%5C
%2e%2e%2f
```

**Double Encoding:**
```
....//
..;/
```

**Why These Work:**
- Navigate up directory tree
- Access sensitive system files
- Bypass filters with encoding
- Different OS path separators

---

<a name="inventory"></a>
## 7. Test Inventory

### Critical Severity (CVSS 9.0-10.0)

**TC-CATALOG-SEC-INJ-001: SQL Injection in Category Filter**
- **Standard:** OWASP ASVS v5.0 Section 5.3.4
- **CWE:** CWE-89
- **CVSS:** 9.8 (CRITICAL)
- **Impact:** Complete database compromise
- **Payloads:** 6 SQL injection variants

**TC-CATALOG-SEC-INJ-002: SQL Injection in Product ID**
- **Standard:** OWASP ASVS v5.0 Section 5.3.4
- **CWE:** CWE-89
- **CVSS:** 9.8 (CRITICAL)
- **Impact:** Database compromise via product parameter
- **Payloads:** 3 SQL injection variants

### High Severity (CVSS 7.0-8.9)

**TC-CATALOG-SEC-INJ-003: XSS in Search**
- **Standard:** OWASP ASVS v5.0 Section 5.3.3
- **CWE:** CWE-79
- **CVSS:** 7.1 (HIGH)
- **Impact:** Session hijacking, cookie theft
- **Payloads:** 5 XSS variants

**TC-CATALOG-SEC-INJ-004: Stored XSS**
- **Standard:** OWASP ASVS v5.0 Section 5.3.3
- **CWE:** CWE-79
- **CVSS:** 8.7 (HIGH)
- **Impact:** Persistent XSS affecting all users

**TC-CATALOG-SEC-IDOR-001: Product Access Control**
- **Standard:** OWASP ASVS v5.0 Section 4.1.2
- **CWE:** CWE-669
- **CVSS:** 7.5 (HIGH)
- **Impact:** Product enumeration

**TC-CATALOG-SEC-TRAV-001: Path Traversal**
- **Standard:** OWASP ASVS v5.0 Section 12.3.1
- **CWE:** CWE-22
- **CVSS:** 7.5 (HIGH)
- **Impact:** Sensitive file disclosure

**TC-CATALOG-SEC-SESS-001: Session Fixation**
- **Standard:** OWASP ASVS v5.0 Section 3.2.1
- **CWE:** CWE-384
- **CVSS:** 7.5 (HIGH)
- **Impact:** Session hijacking

**TC-CATALOG-SEC-HEAD-001: Security Headers**
- **Standard:** OWASP ASVS v5.0 Section 14.4
- **CWE:** CWE-693
- **CVSS:** 7.5 (HIGH)
- **Impact:** Increased attack surface

### Medium Severity (CVSS 4.0-6.9)

**TC-CATALOG-SEC-IDOR-002: Invalid ID Handling**
- **Standard:** OWASP ASVS v5.0 Section 7.4.1
- **CWE:** CWE-209
- **CVSS:** 5.3 (MEDIUM)
- **Impact:** Information disclosure

**TC-CATALOG-SEC-ENUM-001: Product Enumeration**
- **Standard:** OWASP ASVS v5.0 Section 2.2.2
- **CWE:** CWE-200
- **CVSS:** 5.3 (MEDIUM)
- **Impact:** Catalog intelligence gathering

**TC-CATALOG-SEC-TIME-001: Timing Attack**
- **Standard:** OWASP ASVS v5.0 Section 2.2.2
- **CWE:** CWE-208
- **CVSS:** 5.3 (MEDIUM)
- **Impact:** Product existence detection

**TC-CATALOG-SEC-COOK-001: Cookie Security**
- **Standard:** OWASP ASVS v5.0 Section 3.4.2
- **CWE:** CWE-614
- **CVSS:** 6.5 (MEDIUM)
- **Impact:** Cookie theft via XSS/MITM

**TC-CATALOG-SEC-CSRF-001: CSRF Protection**
- **Standard:** OWASP ASVS v5.0 Section 4.2.2
- **CWE:** CWE-352
- **CVSS:** 6.5 (MEDIUM)
- **Impact:** Forged requests

**TC-CATALOG-SEC-RATE-001: Rate Limiting**
- **Standard:** OWASP ASVS v5.0 Section 2.2.1
- **CWE:** CWE-307
- **CVSS:** 5.3 (MEDIUM)
- **Impact:** Automated scraping, DoS

**TC-CATALOG-SEC-INFO-002: Directory Listing**
- **Standard:** OWASP ASVS v5.0 Section 12.5.1
- **CWE:** CWE-548
- **CVSS:** 5.3 (MEDIUM)
- **Impact:** File structure disclosure

### Low Severity (CVSS 0.1-3.9)

**TC-CATALOG-SEC-INFO-001: Verbose Errors**
- **Standard:** OWASP ASVS v5.0 Section 7.4.1
- **CWE:** CWE-209
- **CVSS:** 3.7 (LOW)
- **Impact:** Minor information disclosure

---

<a name="details"></a>
## 8. Detailed Test Cases

### SQL Injection Tests

#### TC-CATALOG-SEC-INJ-001: SQL Injection in Category Filter

**Objective:** Discover if category parameter is vulnerable to SQL injection

**Attack Vector:**
```
https://www.demoblaze.com/?cat=' OR '1'='1
```

**Test Method:**
1. Inject SQL payload into category parameter
2. Observe response for SQL errors
3. Check for unusual behavior
4. Analyze page content for error indicators

**Indicators of Successful Exploitation:**
- SQL error messages in page source
- Keywords: "mysql", "postgresql", "syntax error", "unexpected"
- Database structure disclosure
- Unexpected data returned

**Discovered Result:**
If SQL error found, test fails with CVSS 9.8 CRITICAL rating and full vulnerability details.

#### TC-CATALOG-SEC-INJ-002: SQL Injection in Product ID

**Objective:** Discover if product ID parameter is vulnerable

**Attack Vector:**
```
https://www.demoblaze.com/prod.html?idp_=1' OR '1'='1
```

**Test Method:**
1. Inject SQL into product ID parameter
2. Monitor for SQL error disclosure
3. Check for data extraction
4. Verify proper input validation

**Why This Matters:**
Product IDs are common injection points. If compromised:
- Complete database accessible
- Customer data at risk
- Payment information exposed

### XSS Tests

#### TC-CATALOG-SEC-INJ-003: XSS in Search Functionality

**Objective:** Discover if search parameters are vulnerable to XSS

**Attack Vector:**
```
https://www.demoblaze.com/?search=<script>alert('XSS')</script>
```

**Test Method:**
1. Submit XSS payload in search parameter
2. Check if payload reflected unescaped
3. Verify JavaScript execution
4. Analyze output encoding

**Common Reflection Points:**
- Search results page
- Error messages
- URL parameters in page
- Meta tags

**Impact:**
- Session hijacking via cookie theft
- Keylogging attacks
- Phishing attacks
- Defacement

#### TC-CATALOG-SEC-INJ-004: Stored XSS in Reviews

**Objective:** Discover if review/comment functionality stores XSS

**Test Method:**
1. Look for review/comment functionality
2. Submit XSS payload
3. Reload page to check persistence
4. Verify if payload executes for other users

**Higher Severity Because:**
- Affects all users viewing content
- Persists across sessions
- Can be weaponized for targeted attacks

### IDOR Tests

#### TC-CATALOG-SEC-IDOR-001: Product Access Control

**Objective:** Discover if product IDs can be enumerated

**Test Method:**
1. Access products with sequential IDs (1-20)
2. Count successful accesses
3. Calculate enumeration rate
4. Determine if authorization exists

**Expected Behavior:**
- For public e-commerce: Products should be accessible
- For restricted catalogs: Authorization required

**Vulnerability Exists If:**
- Private products accessible without auth
- Hidden products enumerable
- Deleted products still accessible

#### TC-CATALOG-SEC-IDOR-002: Invalid Product ID Handling

**Objective:** Discover how system handles invalid IDs

**Test Method:**
1. Submit various invalid IDs (999999, -1, abc, NULL)
2. Analyze error messages
3. Check for information disclosure

**Indicators of Vulnerability:**
- Stack traces visible
- Database errors displayed
- File paths revealed
- System information disclosed

### Path Traversal Tests

#### TC-CATALOG-SEC-TRAV-001: Path Traversal in Images

**Objective:** Discover if file paths are vulnerable to traversal

**Attack Vectors:**
```
/imgs/../../etc/passwd
/imgs/../../../windows/system32/config/sam
/imgs/..%2F..%2Fetc%2Fpasswd
```

**Test Method:**
1. Attempt to access files outside image directory
2. Check response codes and content
3. Look for sensitive file indicators
4. Verify path validation

**Sensitive Files Targeted:**
- `/etc/passwd` (Unix/Linux)
- `/windows/system32/config/sam` (Windows)
- Configuration files
- Database credentials

**Impact:**
- Source code disclosure
- Configuration file access
- Credential theft
- System compromise

---

<a name="execution"></a>
## 9. Execution Guide

### Basic Execution

```bash
# Run all security tests
pytest test_catalog_security.py -v

# Stop on first failure
pytest test_catalog_security.py -x

# Show detailed output
pytest test_catalog_security.py -vv
```

### By Severity Level

```bash
# Only critical vulnerabilities
pytest test_catalog_security.py -m "critical" -v

# High and critical
pytest test_catalog_security.py -m "critical or high" -v

# Exclude low severity
pytest test_catalog_security.py -m "not low" -v
```

### By Vulnerability Type

```bash
# SQL injection tests
pytest test_catalog_security.py -k "sql_injection" -v

# All injection tests (SQL + XSS)
pytest test_catalog_security.py -k "injection" -v

# XSS tests only
pytest test_catalog_security.py -k "xss" -v

# IDOR tests
pytest test_catalog_security.py -k "idor" -v

# Session security
pytest test_catalog_security.py -k "session or cookie" -v
```

### Reporting

```bash
# HTML report
pytest test_catalog_security.py --html=report_security.html --self-contained-html

# JUnit XML (for CI/CD)
pytest test_catalog_security.py --junitxml=results_security.xml

# Both reports
pytest test_catalog_security.py \
  --html=report.html --self-contained-html \
  --junitxml=results.xml
```

### Debugging

```bash
# Show print statements and logging
pytest test_catalog_security.py -s

# Show local variables on failure
pytest test_catalog_security.py -l

# Enter debugger on failure
pytest test_catalog_security.py --pdb
```

---

<a name="results"></a>
## 10. Expected Results

### Test Outcomes

**PASS:** Security control properly implemented
- SQL payload rejected
- XSS payload sanitized
- IDOR prevented with authorization
- Rate limiting triggered
- Security headers configured

**FAIL:** Vulnerability discovered
- Payload accepted by system
- Attack succeeded
- Security control missing
- Configuration inadequate

### Understanding Failures

When a security test fails, it means a **real vulnerability was discovered**.

**Example Failure:**
```
FAILED test_sql_injection_product_id_INJ_002[1' OR '1'='1]

CRITICAL VULNERABILITY: SQL INJECTION IN PRODUCT ID
Payload: 1' OR '1'='1
Standard: OWASP ASVS v5.0 Section 5.3.4
CWE-89: SQL Injection
CVSS Score: 9.8 (CRITICAL)
Impact: Complete database compromise possible
```

**This failure is CORRECT** - the test successfully discovered a SQL injection vulnerability.

### Expected Failure Rate

For typical web applications without security hardening:

| Vulnerability Type | Expected Failure Rate | Common Issues |
|-------------------|----------------------|---------------|
| SQL Injection | 40-60% | Missing parameterization |
| XSS | 50-70% | Inadequate output encoding |
| IDOR | 60-80% | Missing authorization checks |
| Path Traversal | 30-50% | Weak path validation |
| Security Headers | 80-95% | Default server config |
| Rate Limiting | 85-95% | Not implemented |

**These failures are discoveries, not test defects.**

---

<a name="reporting"></a>
## 11. Vulnerability Reporting

### Report Structure

When vulnerability is discovered, document:

**1. Vulnerability Details**
- Test ID and name
- Affected component/parameter
- Attack payload used
- CWE classification

**2. Risk Assessment**
- CVSS score with vector string
- OWASP ASVS section
- Impact description
- Exploitability assessment

**3. Evidence**
- Screenshots
- Log output
- HTTP requests/responses
- Reproduction steps

**4. Business Impact**
- Data at risk
- Users affected
- Compliance violations
- Financial exposure

**5. Remediation**
- Specific fix recommendations
- Code examples
- References to secure coding guides

### Sample Report

```
VULNERABILITY REPORT

ID: VULN-CAT-2025-001
Discovered: 2025-11-20
Severity: CRITICAL

Title: SQL Injection in Product ID Parameter

Description:
The product detail page is vulnerable to SQL injection attacks via the
'idp_' URL parameter. Testing with payload "1' OR '1'='1" resulted in
SQL error disclosure, confirming the vulnerability.

CVSS Score: 9.8 (CRITICAL)
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

CWE: CWE-89 (SQL Injection)
OWASP ASVS: Section 5.3.4 (SQL Injection Prevention)
OWASP Top 10: A03:2021 - Injection

Evidence:
- Test: TC-CATALOG-SEC-INJ-002
- Payload: 1' OR '1'='1
- Result: SQL error message displayed
- Log file: security_test_20251120.log
- Screenshot: sql_injection_evidence.png

Impact:
Attackers can:
- Extract entire database contents
- Modify or delete data
- Bypass authentication
- Gain administrative access
- Access customer payment information

Business Risk:
- HIGH: PCI-DSS compliance violation
- CRITICAL: Customer data breach risk
- HIGH: Reputational damage
- MEDIUM: Legal liability

Remediation:
1. Use parameterized queries (prepared statements)
2. Implement input validation and sanitization
3. Apply principle of least privilege to database accounts
4. Add WAF rules to block SQL injection patterns
5. Implement database activity monitoring

Code Example - FIX:
# WRONG (Vulnerable)
query = f"SELECT * FROM products WHERE id = '{product_id}'"

# CORRECT (Secure)
query = "SELECT * FROM products WHERE id = ?"
cursor.execute(query, (product_id,))

References:
- OWASP SQL Injection Prevention Cheat Sheet
- CWE-89: SQL Injection
- NIST SP 800-53: SI-10 (Information Input Validation)

Timeline:
- Discovery: 2025-11-20
- Reported: 2025-11-20
- Fix Deadline: 2025-11-27 (7 days - CRITICAL)
```

---

<a name="cvss"></a>
## 12. CVSS Scoring Reference

### Severity Ratings

| CVSS Score | Rating | Response Time |
|------------|--------|---------------|
| 9.0 - 10.0 | CRITICAL | Fix immediately (<24h) |
| 7.0 - 8.9 | HIGH | Fix within 7 days |
| 4.0 - 6.9 | MEDIUM | Fix within 30 days |
| 0.1 - 3.9 | LOW | Fix within 90 days |

### CVSS v3.1 Metrics

**Base Metrics:**

**Attack Vector (AV):**
- **N (Network):** Exploitable remotely
- **A (Adjacent):** Requires local network access
- **L (Local):** Requires local access
- **P (Physical):** Requires physical access

**Attack Complexity (AC):**
- **L (Low):** No special conditions required
- **H (High):** Special conditions required

**Privileges Required (PR):**
- **N (None):** No authentication required
- **L (Low):** Basic user privileges
- **H (High):** Administrator privileges

**User Interaction (UI):**
- **N (None):** No user interaction required
- **R (Required):** User must take action

**Scope (S):**
- **U (Unchanged):** Impacts only the vulnerable component
- **C (Changed):** Impacts beyond vulnerable component

**Confidentiality/Integrity/Availability (C/I/A):**
- **N (None):** No impact
- **L (Low):** Limited impact
- **H (High):** Total compromise

### Example Calculations

**SQL Injection (CVSS 9.8):**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

Breakdown:
- AV:N - Network accessible (remotely exploitable)
- AC:L - Simple to exploit
- PR:N - No authentication required
- UI:N - No user interaction needed
- S:U - Scope unchanged
- C:H - Complete confidentiality breach (database access)
- I:H - Complete integrity breach (data modification)
- A:H - Complete availability breach (data deletion)
```

**XSS (CVSS 7.1):**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L

Breakdown:
- AV:N - Network accessible
- AC:L - Easy to exploit
- PR:N - No privileges needed
- UI:R - Requires user to click link
- S:C - Scope changed (affects other users)
- C:L - Limited confidentiality impact (session cookies)
- I:L - Limited integrity impact (page defacement)
- A:L - Limited availability impact
```

**IDOR (CVSS 7.5):**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

Breakdown:
- AV:N - Network accessible
- AC:L - Simple enumeration
- PR:N - No authentication
- UI:N - No user interaction
- S:U - Scope unchanged
- C:H - High confidentiality impact (data access)
- I:N - No integrity impact
- A:N - No availability impact
```

---

<a name="troubleshooting"></a>
## 13. Troubleshooting

### Common Issues

#### Issue 1: False Positives on SQL Injection

**Symptom:** Test reports SQL injection but manual verification shows it's safe

**Possible Causes:**
- Generic error messages containing "error" keyword
- JavaScript errors mistaken for SQL errors
- Overly sensitive detection

**Solution:**
```python
# Refine detection logic
def check_for_sql_error_indicators(browser):
    page_source = browser.page_source.lower()

    # Be more specific
    specific_indicators = [
        "you have an error in your sql syntax",
        "mysql_fetch",
        "unclosed quotation mark",
        "sqlstate"
    ]

    for indicator in specific_indicators:
        if indicator in page_source:
            return True, indicator

    return False, None
```

#### Issue 2: XSS Tests Not Detecting Stored XSS

**Symptom:** Stored XSS test passes but payload is actually stored

**Possible Causes:**
- Payload stored but not immediately reflected
- Requires page refresh
- Different user context needed

**Solution:**
```python
# Add page refresh and re-check
browser.refresh()
time.sleep(2)

# Check multiple times
for _ in range(3):
    if check_for_xss_execution(browser, payload):
        return True
    browser.refresh()
    time.sleep(1)
```

#### Issue 3: Path Traversal Tests Fail to Connect

**Symptom:** Requests timeout or connection refused

**Possible Causes:**
- Server blocking unusual requests
- WAF blocking attack patterns
- Network issues

**Solution:**
```python
# Add retry logic and better error handling
for attempt in range(3):
    try:
        response = requests.get(test_url, timeout=10)
        break
    except requests.Timeout:
        if attempt == 2:
            pytest.skip("Server not responding")
        time.sleep(2)
```

#### Issue 4: Rate Limiting Test Inconsistent

**Symptom:** Sometimes detects rate limiting, sometimes doesn't

**Possible Causes:**
- Shared IP affecting results
- CDN caching
- Time-based rate limits

**Solution:**
```python
# Test at consistent intervals
for i in range(attempts):
    time.sleep(0.5)  # Consistent delay
    # ... test code

# Or increase attempts to get reliable average
attempts = 30  # More attempts = more reliable
```

#### Issue 5: Cookie Security Test False Negatives

**Symptom:** Test passes but cookies are actually insecure

**Possible Causes:**
- Checking wrong cookies
- HTTPS affects Secure flag
- Browser quirks

**Solution:**
```python
# Test both HTTP and HTTPS
for protocol in ["http://", "https://"]:
    browser.get(f"{protocol}www.demoblaze.com")
    cookies = browser.get_cookies()

    # Check all cookies, not just session
    for cookie in cookies:
        check_security_flags(cookie)
```

---

<a name="standards"></a>
## 14. Standards Reference

### OWASP ASVS v5.0

**Section 5.3.4: SQL Injection Prevention**
- Use parameterized queries
- Input validation and sanitization
- Least privilege database accounts

**Section 5.3.3: Output Encoding**
- Context-appropriate encoding
- HTML entity encoding for HTML context
- JavaScript encoding for JS context

**Section 4.1.2: Access Control**
- Deny by default
- Enforce authorization on every request
- Fail securely

**Section 12.3.1: File Execution**
- Validate all file paths
- Use whitelist of allowed paths
- Prevent directory traversal

**Section 3.2.1: Session Generation**
- Generate new session on authentication
- Use cryptographically random session IDs
- Invalidate session on logout

**Section 3.4.2: Cookie Security**
- Set Secure flag for HTTPS
- Set HttpOnly to prevent JS access
- Use SameSite attribute

**Section 4.2.2: CSRF Prevention**
- Use anti-CSRF tokens
- Verify token on state-changing operations
- Double-submit cookie pattern

**Section 14.4: HTTP Security Headers**
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY/SAMEORIGIN
- Strict-Transport-Security
- Content-Security-Policy

**Section 2.2.1: Anti-automation**
- Rate limiting on sensitive operations
- CAPTCHA for repeated failures
- Account lockout mechanisms

**Section 7.4.1: Error Handling**
- Generic error messages to users
- Detailed errors only in logs
- No stack traces in production

### CWE References

- **CWE-89:** SQL Injection
- **CWE-79:** Cross-site Scripting
- **CWE-22:** Path Traversal
- **CWE-352:** Cross-Site Request Forgery
- **CWE-384:** Session Fixation
- **CWE-614:** Sensitive Cookie Without Secure Flag
- **CWE-669:** Incorrect Resource Transfer (IDOR)
- **CWE-200:** Information Exposure
- **CWE-208:** Observable Timing Discrepancy
- **CWE-209:** Information Exposure Through Error Message
- **CWE-307:** Improper Restriction of Excessive Authentication Attempts
- **CWE-548:** Directory Listing
- **CWE-693:** Protection Mechanism Failure

### Additional Resources

**OWASP:**
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- ASVS Standard: https://owasp.org/www-project-application-security-verification-standard/
- Testing Guide: https://owasp.org/www-project-web-security-testing-guide/

**NIST:**
- SP 800-53: Security Controls
- SP 800-63B: Digital Identity Guidelines

**PCI-DSS:**
- Payment Card Industry Security Standards
- https://www.pcisecuritystandards.org/

---

<a name="version"></a>
## 15. Version History

### Version 1.0 - November 2025 (Current)

**Initial Release:**

**Test Coverage:**
- 19 test functions
- 28+ test runs with parametrization
- 9 vulnerability categories
- Complete OWASP Top 10 coverage

**Security Tests:**
- SQL Injection (9 parametrized tests)
- XSS (6 parametrized tests)
- Path Traversal (8 parametrized tests)
- IDOR (2 tests)
- Enumeration (2 tests)
- Session Security (2 tests)
- CSRF (1 test)
- Security Headers (1 test)
- Rate Limiting (1 test)
- Information Disclosure (2 tests)

**Key Features:**
- CVSS v3.1 scoring for all vulnerabilities
- CWE references for each test
- OWASP ASVS compliance mapping
- Comprehensive logging with severity levels
- Evidence collection
- Ethical testing guidelines
- Attack payload library

**Code Quality:**
- Professional attack payloads
- Helper functions for detection
- Parametrized testing for efficiency
- Comprehensive error handling
- Request timeout management

**Documentation:**
- Complete test methodology
- Ethical guidelines with legal considerations
- CVSS reference guide
- Vulnerability reporting templates
- Standards mapping with sections
- Troubleshooting guide

---

**End of Documentation**

**Related Documents:**
- [test_catalog_functionality.py](test_catalog_functionality.py) - Functional tests
- [README_test_catalog_functionality.md](README_test_catalog_functionality.md) - Functional tests documentation
- [OWASP_ASVS_GUIDE.md](OWASP_ASVS_GUIDE.md) - ASVS standard reference
- [CVSS_SCORING_GUIDE.md](CVSS_SCORING_GUIDE.md) - CVSS calculation guide

**For Ethical Testing Questions:**
Consult your organization's security policies and legal team before conducting security testing.

**For Technical Questions:**
Refer to OWASP Testing Guide and security testing best practices documentation.

**For Responsible Disclosure:**
Follow coordinated vulnerability disclosure practices. Report findings to vendor security teams with appropriate timelines for remediation.
