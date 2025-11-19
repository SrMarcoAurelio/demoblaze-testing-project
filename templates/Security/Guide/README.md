# SECURITY TEMPLATE PACKAGE - COMPLETE GUIDE

**Author:** Arévalo, Marc  
**Date:** November 2025  
**Version:** 2.0 Universal Edition

---

##  WHAT YOU'VE RECEIVED

I've created a **comprehensive, universal security testing template** split into 2 files:

### File 1: TEMPLATE_security_exploitation.md (Main Template)
**Size:** 2,350+ lines  
**Sections:** 1-17

**Contains:**
1. ✅ **Philosophy & Core Principles** - Why security testing is different
2. ✅ **DISCOVER vs ASSUME - THE FOUNDATION** - 4 detailed examples (SQL injection, negative quantity, rate limiting, price manipulation)
3. ✅ **Anti-Patterns** - 8 common mistakes with corrections
4. ✅ **Pre-Development Questions** - What to ask before coding
5. ✅ **Research Phase by Module Type** - Complete matrix for 12 module types
6. ✅ **Before Writing Code Checklist** - 19 validation points
7. ✅ **Code Structure Template** - Universal Python code template
8. ✅ **Test Categories & Examples** - All exploitation types
9. ✅ **Test Naming Convention** - Standardized naming
10. ✅ **Markers Usage** - Pytest markers for security tests
11. ✅ **Execution Commands** - How to run tests
12. ✅ **Expected Test Distribution** - How many tests per module
13. ✅ **Critical Principles** - Key concepts to remember
14. ✅ **CVSS Scoring Guide** - Severity classification
15. ✅ **Pre-Delivery Checklist** - Final validation
16. ✅ **Security Standards Reference** - Complete standards list
17. ✅ **Exploitation Tools & Libraries** - Required imports

### File 2: TEMPLATE_security_PART2_critical_sections.md (Critical Additions)
**Size:** 1,000+ lines  
**Sections:** 18-19

**Contains:**
18. ✅ **Example Future Conversation** - 3 complete scenarios showing how you'll use this:
    - Login module example
    - Payment module example
    - API endpoints example
    
19. ✅ **Common Vulnerabilities by Module** - Quick reference for 7 module types:
    - Authentication/Login (5 critical vulns + discovery patterns)
    - Payment/Checkout (5 critical vulns + discovery patterns)
    - Shopping Cart (5 critical vulns + discovery patterns)
    - Search/Filter (5 critical vulns + discovery patterns)
    - User Profile (5 critical vulns + discovery patterns)
    - Admin Panel (5 critical vulns + discovery patterns)
    - API Endpoints (5 critical vulns + discovery patterns)

---

##  THE PHILOSOPHY (CORE CONCEPT)

### The Golden Rule You MUST Understand

> **Tests DISCOVER vulnerabilities by EXECUTING exploits and OBSERVING results.**  
> **Tests NEVER ASSUME the application's behavior.**

### What This Means in Practice

#### ❌ WRONG (Assuming):
```python
def test_sql_injection():
    # "I know DemoBlaze is vulnerable"
    inject_sql()
    assert False  # Assumes it will fail
```

#### ✅ CORRECT (Discovering):
```python
def test_sql_injection():
    # "Let me discover if this site is vulnerable"
    inject_sql("' OR '1'='1")
    result = observe_response()
    
    if result.shows_exploitation():
        pytest.fail("DISCOVERED: SQL Injection vulnerability")
    else:
        assert True  # DISCOVERED: System is secure
```

### The DISCOVER Formula

```
DISCOVER = EXECUTE + OBSERVE + DECIDE

1. EXECUTE: Run the actual exploit attempt
2. OBSERVE: Capture the real system response  
3. DECIDE: Compare against secure behavior objectively
```

---

##  HOW TO USE THIS TEMPLATE IN THE FUTURE

### Scenario 1: You Want to Test a Login Module

**YOU SAY:**
> "Quiero crear test_login_security.py para una app de banking"

**I WILL:**
1. ✅ Confirm module type (Login/Authentication)
2. ✅ Check Research Matrix (Section 5) → Identify standards: OWASP ASVS Ch 2, NIST 800-63B, ISO 27001
3. ✅ List critical vulnerabilities for Login: SQL injection, brute force, session fixation, account enumeration
4. ✅ Ask you for: URL, credentials, environment confirmation
5. ✅ Generate 16-24 tests following DISCOVER philosophy
6. ✅ Create test_login_security.py + README_login_security.md
7. ✅ All tests DISCOVER behavior (never assume)

### Scenario 2: You Want to Test Payment

**YOU SAY:**
> "Genera test_payment_security.py"

**I WILL:**
1. ✅ Check Research Matrix → Payment requires PCI-DSS 4.0.1
2. ✅ Identify CRITICAL tests: Card data storage, CVV prohibition, TLS version, price manipulation
3. ✅ Generate 20-28 tests with PCI-DSS compliance + business logic
4. ✅ Every test DISCOVERS if vulnerable (doesn't assume)

### Scenario 3: You Want to Test an API

**YOU SAY:**
> "Security tests para /api/users endpoint"

**I WILL:**
1. ✅ Check Research Matrix → API Security needs OWASP API Top 10
2. ✅ List tests: Rate limiting, IDOR, authentication, data exposure, mass assignment
3. ✅ Generate API-specific exploitation tests
4. ✅ All tests DISCOVER via actual API calls

---

##  WHAT MAKES THIS TEMPLATE UNIVERSAL

### Works Across Any Domain:

✅ **E-commerce** (DemoBlaze, Amazon, etc.)  
✅ **Banking** (Online banking, fintech)  
✅ **Healthcare** (Patient portals, medical records)  
✅ **Social Networks** (Facebook, Twitter style apps)  
✅ **SaaS** (B2B applications, dashboards)  
✅ **Government** (Public services, portals)  
✅ **Education** (LMS, student systems)  
✅ **ANY web application**

### How It's Universal:

1. **Generic Code Structure:**
   ```python
   # Change these for different sites:
   BASE_URL = "..."
   LOCATORS = {...}
   
   # Keep this logic (works everywhere):
   def test_vulnerability():
       execute_exploit()
       result = observe_response()
       decide_if_vulnerable(result)
   ```

2. **Research Matrix Covers 12 Module Types:**
   - Login/Authentication
   - Payment/Financial
   - Shopping Cart
   - Search/Filter
   - User Profile
   - Admin Panel
   - File Upload
   - API Endpoints
   - Contact Forms
   - Session Management
   - Password Reset
   - Registration

3. **Standards for Any Industry:**
   - OWASP (universal web security)
   - PCI-DSS (payment processing)
   - NIST (government/authentication)
   - ISO 27001 (international security)
   - WCAG (accessibility)
   - GDPR (privacy)

---

##  KEY SECTIONS YOU MUST READ

### CRITICAL (Read First):
1. **Section 2: DISCOVER vs ASSUME** ⭐⭐⭐⭐⭐
   - This is THE MOST IMPORTANT section
   - 4 detailed examples showing right vs wrong
   - Master this = master the philosophy

2. **Section 3: Anti-Patterns** ⭐⭐⭐⭐⭐
   - Learn what NOT to do
   - Common mistakes with corrections
   - Will save you hours of wrong code

3. **Part 2, Section 18: Example Future Conversation** ⭐⭐⭐⭐⭐
   - Shows exactly how you'll use this template
   - 3 complete scenarios
   - Understand the workflow

### IMPORTANT (Read Second):
4. **Section 5: Research Matrix** ⭐⭐⭐⭐
   - Quick reference for what to test per module
   - Standards to research
   - Critical vulnerabilities list

5. **Section 6: Before Writing Code Checklist** ⭐⭐⭐⭐
   - 19 validation points
   - Prevents common mistakes
   - Ensures quality before coding

6. **Part 2, Section 19: Common Vulnerabilities** ⭐⭐⭐⭐
   - 7 module types with specific vulns
   - Discovery patterns for each
   - Quick reference guide

### REFERENCE (Use When Needed):
- Section 7: Code Structure Template (when generating code)
- Section 14: CVSS Scoring (for severity classification)
- Section 15: Pre-Delivery Checklist (before submitting code)
- Section 16: Standards Reference (for citations)

---

##  LEARNING PATH

### If You're New to Security Testing:

**Week 1: Understand Philosophy**
- [ ] Read Section 1 (Philosophy)
- [ ] Read Section 2 (DISCOVER vs ASSUME) - Study all 4 examples
- [ ] Read Section 3 (Anti-Patterns)
- [ ] Read Part 2, Section 18 (Example Conversations)

**Week 2: Learn the Process**
- [ ] Read Section 4 (Pre-Development Questions)
- [ ] Study Section 5 (Research Matrix)
- [ ] Complete Section 6 (Checklist) for practice module
- [ ] Read Part 2, Section 19 (Vulnerabilities by Module)

**Week 3: Practice**
- [ ] Pick a module type (start with Login)
- [ ] Follow Section 5 to identify standards
- [ ] Use Section 7 code template
- [ ] Generate actual tests
- [ ] Validate with Section 15 checklist

### If You're Experienced:

**Quick Start:**
1. Skim Section 2 (DISCOVER examples) - 10 min
2. Check Section 3 (Anti-Patterns) - 5 min
3. Use Section 5 (Research Matrix) as reference
4. Jump to Section 7 (Code Template)
5. Reference Part 2, Section 19 for vulnerabilities

---

##  CRITICAL RULES TO REMEMBER

### The Non-Negotiables:

1. **ALWAYS DISCOVER, NEVER ASSUME**
   ```python
   # Execute → Observe → Decide
   # NEVER hardcode assumptions
   ```

2. **Tests Must Work on Unknown Sites**
   ```python
   # Change BASE_URL + LOCATORS = works anywhere
   # Logic must be generic
   ```

3. **Every Test Has:**
   - CVSS Score
   - Standard Reference
   - Clear Docstring
   - Structured Logging
   - Discovery Logic

4. **No Emojis, Professional Code**
   ```python
   # ❌ def test_fun_exploit(): 😄
   # ✅ def test_sql_injection_INJ_001():
   ```

5. **Ethical Testing Only**
   - Authorized environments
   - Never production without permission
   - Document all findings
   - Responsible disclosure

---

## 📊 WHAT YOU'LL GENERATE

When you ask me to create security tests, I'll generate:

### test_[module]_security.py
```
Typical size: 16-28 tests
Categories:
- Business Logic Exploitation (4-6 tests)
- Injection Attacks (3-5 tests)
- Bot Protection (2-4 tests)
- Authentication/Authorization (2-3 tests)
- PCI-DSS Compliance (2-4 tests if payment)
- Additional security tests (3-5 tests)

All tests follow DISCOVER philosophy
All tests have CVSS scores and standards
All tests are reusable on different sites
```

### README_[module]_security.md
```
Typical size: 30-50 pages
Sections:
1. Overview
2. Test cases summary
3. Code architecture
4. Detailed test explanations
5. Execution guide
6. Expected results
7. Understanding failures
8. Standards reference
9. Troubleshooting
10. Best practices
```

---

##  EXAMPLES OF USAGE

### Example 1: Basic Request

**YOU:**
> "Crea test_login_security.py"

**I GENERATE:**
- test_login_security.py (20 tests)
- README_login_security.md
- All tests DISCOVER behavior
- OWASP ASVS v5.0 + NIST 800-63B compliance

### Example 2: Specific Focus

**YOU:**
> "Security tests para payment pero solo PCI-DSS compliance"

**I GENERATE:**
- test_payment_security.py (8 PCI-DSS specific tests)
- Focus on Req 3.2, 4.2, 6.5, 11.6.1
- README with PCI-DSS explanations

### Example 3: Multiple Modules

**YOU:**
> "Necesito security para login, cart y payment"

**I GENERATE:**
- test_login_security.py (20 tests)
- test_cart_security.py (18 tests)
- test_payment_security.py (24 tests)
- 3 separate READMEs
- All following same philosophy

---

##  HOW TO VERIFY QUALITY

### Before Accepting Generated Code, Check:

**Philosophy:**
- [ ] Tests DISCOVER (execute → observe → decide)
- [ ] No hardcoded assumptions
- [ ] Works on unknown sites

**Code Quality:**
- [ ] No emojis
- [ ] Professional formatting
- [ ] Minimal comments
- [ ] Clear docstrings

**Standards:**
- [ ] Every test has CVSS score
- [ ] Standard references present (OWASP, PCI-DSS, etc.)
- [ ] Version numbers included
- [ ] Severity levels correct

**Reusability:**
- [ ] Configuration section clearly marked
- [ ] Locators section clearly marked
- [ ] Helper functions generic
- [ ] Can work on different sites by changing config

**Documentation:**
- [ ] README generated
- [ ] Test explanations clear
- [ ] Execution guide present
- [ ] Standards referenced

---

##  NEXT STEPS

### To Use This Template:

1. **Read the critical sections** (Sections 2, 3, and Part 2 Section 18)
2. **Identify your module type** (Login, Payment, Cart, etc.)
3. **Ask me to generate:** "Crea test_[module]_security.py"
4. **I will follow the workflow** from Example Conversations
5. **Review generated code** using quality checklist above
6. **Run tests** in authorized environment
7. **Document findings** if vulnerabilities discovered

### Remember:

> **This template is your REFERENCE for HOW I should generate security tests.**  
> **You don't use it directly - you use it to TELL ME what you want.**  
> **I use it to ensure I generate code with the right PHILOSOPHY.**

---

##  QUALITY GUARANTEES

When I generate code using this template, you get:

1. ✅ **Tests that DISCOVER** (not assume)
2. ✅ **Universal applicability** (works on any site)
3. ✅ **Professional quality** (no emojis, clean code)
4. ✅ **Standards-based** (OWASP, PCI-DSS, NIST, etc.)
5. ✅ **Well-documented** (README included)
6. ✅ **Reusable** (change config = works elsewhere)
7. ✅ **Ethical** (authorized testing only)
8. ✅ **Complete** (16-28 tests per module)

---

**Questions? Just ask me and reference this guide!**


**Remember:** The philosophy is DISCOVER, not ASSUME. Master that and everything else follows.
