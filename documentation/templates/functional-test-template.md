# FUNCTIONAL TEMPLATE PACKAGE - COMPLETE GUIDE

**Author:** Arévalo, Marc
**Date:** November 2025
**Version:** 2.0 Universal Edition

---

##  WHAT YOU'VE RECEIVED

I've created a **comprehensive, universal functional testing template** split into 2 files + guide:

### File 1: TEMPLATE_functional_business_rules_v2.md (Main Template)
**Size:** 2,500+ lines
**Sections:** 1-17

**Contains:**
1. ✅ **Philosophy & Core Principles** - Why functional testing matters
2. ✅ **DISCOVER vs ASSUME - THE FOUNDATION** - 4 detailed examples (empty form, password strength, input length, form submission)
3. ✅ **Anti-Patterns** - 8 common mistakes with corrections
4. ✅ **Pre-Development Questions** - What to ask before coding
5. ✅ **Research Phase by Module Type** - Complete matrix for 8 module types
6. ✅ **Before Writing Code Checklist** - 15 validation points
7. ✅ **Code Structure Template** - Universal Python code template
8. ✅ **Test Categories & Distribution** - Functional vs Business Rules
9. ✅ **Test Naming Convention** - Standardized naming
10. ✅ **Markers Usage** - Pytest markers
11. ✅ **Execution Commands** - How to run tests
12. ✅ **Expected Test Distribution** - How many tests per module
13. ✅ **Critical Principles** - Key concepts
14. ✅ **Standards Classification** - All relevant standards
15. ✅ **Pre-Delivery Checklist** - Final validation
16. ✅ **Standards Reference Quick Guide** - Standards by module
17. ✅ **Testing Tools & Libraries** - Required tools

### File 2: TEMPLATE_functional_PART2.md (Critical Additions)
**Size:** 1,200+ lines
**Sections:** 18-20

**Contains:**
18. ✅ **Example Future Conversations** - 3 complete scenarios:
    - Login module (functional + business rules)
    - Payment module (functional only)
    - Cart module (complete suite)

19. ✅ **Common Patterns by Module** - 6 module types with code:
    - Login/Authentication (6 functional + 12 business rules examples)
    - Payment/Checkout (8 functional + 15 business rules examples)
    - Shopping Cart (8 functional + 12 business rules examples)
    - Search/Filter (6 functional + 10 business rules examples)
    - Contact Form (4 functional + 8 business rules examples)
    - User Profile (6 functional + 10 business rules examples)

20. ✅ **Version History**

### File 3: This Guide
**Purpose:** Explains how to use the template package

---

##  THE PHILOSOPHY (CORE CONCEPT)

### The Golden Rule

> **Tests DISCOVER behavior by EXECUTING actions and OBSERVING results.**
> **Tests NEVER ASSUME how the application will behave.**

### Two Types of Tests

#### **1. Functional Tests (Happy Path)**
```python
def test_valid_operation():
    """Discovers if feature works with valid inputs"""
    # EXECUTE
    submit_form(valid_data)

    # OBSERVE
    result = check_success()

    # DECIDE
    if result.success:
        assert True  # DISCOVERED: Works
    else:
        pytest.fail("DISCOVERED: Broken")
```

#### **2. Business Rules Tests (Standards Compliance)**
```python
def test_password_policy():
    """NIST 800-63B: Minimum 8 characters

    Discovers if system enforces password policy.
    """
    # EXECUTE
    signup("user", "123")

    # OBSERVE
    response = get_response()

    # DECIDE (based on NIST standard)
    if password_rejected():
        assert True  # DISCOVERED: Complies
    else:
        log_violation(...)
        pytest.fail("DISCOVERED: Violates NIST")
```

---

##  HOW TO USE THIS TEMPLATE IN THE FUTURE

### Scenario 1: You Want to Test Login

**YOU SAY:**
> "Crea test_login.py con funcionales y business rules"

**I WILL:**
1. ✅ Check Research Matrix → Login needs: OWASP ASVS Ch 2, NIST 800-63B, ISO 27001
2. ✅ Plan 6 functional tests (valid login, invalid login, empty fields, etc.)
3. ✅ Plan 12 business rules tests (password policy, SQL injection, XSS, etc.)
4. ✅ Ask for: URL, credentials, environment
5. ✅ Generate 18 tests total following DISCOVER philosophy
6. ✅ Create test_login.py + README_login.md
7. ✅ All tests DISCOVER behavior (never assume)

### Scenario 2: You Want Only Functional Tests

**YOU SAY:**
> "Solo tests funcionales de payment, sin business rules"

**I WILL:**
1. ✅ Create 8 functional tests only
2. ✅ Valid card works, form submission, confirmation, etc.
3. ✅ No business rules tests
4. ✅ Generate test_payment.py + README_payment.md

### Scenario 3: You Want Complete Suite

**YOU SAY:**
> "Suite completa para cart: todo"

**I WILL:**
1. ✅ 8 functional tests (add, remove, update, total calculation, etc.)
2. ✅ 12 business rules tests (quantity validation, price integrity, XSS prevention, etc.)
3. ✅ 20 tests total
4. ✅ Complete documentation

---

##  WHAT MAKES THIS TEMPLATE UNIVERSAL

### Works Across Any Domain:

✅ **E-commerce** (Your Application, Amazon, Shopify)
✅ **Banking** (Online banking, fintech apps)
✅ **Healthcare** (Patient portals, EHR systems)
✅ **Social Networks** (Twitter/LinkedIn style)
✅ **SaaS** (CRM, ERP, dashboards)
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
   def test_feature():
       execute_action()
       result = observe_response()
       decide_if_correct(result)
   ```

2. **Research Matrix Covers 8 Module Types:**
   - Login/Authentication
   - Payment/Checkout
   - Shopping Cart
   - Search/Filter
   - User Profile
   - Registration
   - Contact Forms
   - File Upload

3. **Standards for Any Industry:**
   - OWASP (universal web security)
   - ISO 25010 (software quality)
   - WCAG (accessibility)
   - NIST (authentication)
   - PCI-DSS (payment)

---

##  KEY SECTIONS YOU MUST READ

### CRITICAL (Read First):

1. **Section 2: DISCOVER vs ASSUME** ⭐⭐⭐⭐⭐
   - THE MOST IMPORTANT SECTION
   - 4 detailed examples showing right vs wrong
   - Master this = master everything

2. **Section 3: Anti-Patterns** ⭐⭐⭐⭐⭐
   - Learn what NOT to do
   - 8 common mistakes with corrections

3. **Part 2, Section 18: Example Conversations** ⭐⭐⭐⭐⭐
   - Shows exactly how you'll use this
   - 3 complete scenarios
   - Understand the workflow

### IMPORTANT (Read Second):

4. **Section 5: Research Matrix** ⭐⭐⭐⭐
   - What standards for each module type
   - Functional vs business rules breakdown

5. **Section 6: Before Writing Code Checklist** ⭐⭐⭐⭐
   - 15 validation points
   - Prevents common mistakes

6. **Part 2, Section 19: Common Patterns** ⭐⭐⭐⭐
   - 6 module types with code examples
   - Functional + business rules for each

---

##  QUALITY GUARANTEES

When I generate code using this template:

1. ✅ **Tests DISCOVER** (not assume)
2. ✅ **Universal** (works on any site)
3. ✅ **Professional** (no emojis, clean code)
4. ✅ **Standards-based** (OWASP, ISO, NIST, WCAG)
5. ✅ **Well-documented** (README included)
6. ✅ **Reusable** (change config = works elsewhere)
7. ✅ **Complete** (functional + business rules)
8. ✅ **Balanced** (30-40% functional, 60-70% business rules)

---

##  COMPARISON: SECURITY vs FUNCTIONAL TEMPLATES

### Similarities (Both Templates):

| Feature | Security | Functional |
|---------|----------|------------|
| DISCOVER philosophy | ✅ Yes | ✅ Yes |
| Anti-Patterns section | ✅ Yes | ✅ Yes |
| Example Conversations | ✅ Yes | ✅ Yes |
| Common Patterns | ✅ Yes | ✅ Yes |
| Research Matrix | ✅ Yes | ✅ Yes |
| Universal applicability | ✅ Yes | ✅ Yes |
| Before Code Checklist | ✅ Yes | ✅ Yes |
| No emojis, professional | ✅ Yes | ✅ Yes |
| Standards references | ✅ Yes | ✅ Yes |
| Size | 3,500+ lines | 2,500+ lines |

### Differences (Purpose & Focus):

| Aspect | Security Template | Functional Template |
|--------|------------------|---------------------|
| **Purpose** | Find vulnerabilities | Validate functionality |
| **Test Type** | Exploitation attempts | Feature verification |
| **Expected Outcome** | Most tests FAIL (discover vulnerabilities) | Functional tests PASS, Business rules discover compliance |
| **Focus** | Breaking the system | Verifying it works + meets standards |
| **Examples** | SQL injection, XSS, IDOR, race conditions | Valid login, form submission, calculation accuracy |
| **Standards** | OWASP Top 10, PCI-DSS, CWE | OWASP ASVS, ISO 25010, WCAG, NIST |
| **CVSS Scores** | Yes (9.8 CRITICAL, etc.) | Severity (HIGH, MEDIUM, LOW) |
| **Business Rules** | Security compliance only | Security + Quality + Accessibility + Data integrity |

---

##  LEARNING PATH

### If You're New to QA Testing:

**Week 1: Understand Philosophy**
- [ ] Read Section 1 (Philosophy)
- [ ] Read Section 2 (DISCOVER vs ASSUME) - Study all 4 examples
- [ ] Read Section 3 (Anti-Patterns)
- [ ] Read Part 2, Section 18 (Example Conversations)

**Week 2: Learn the Process**
- [ ] Read Section 4 (Pre-Development Questions)
- [ ] Study Section 5 (Research Matrix)
- [ ] Complete Section 6 (Checklist) for practice
- [ ] Read Part 2, Section 19 (Common Patterns)

**Week 3: Practice**
- [ ] Pick a module (start with Contact Form - simplest)
- [ ] Follow Research Matrix to identify standards
- [ ] Use Section 7 code template
- [ ] Generate actual tests
- [ ] Validate with Section 15 checklist

### If You're Experienced:

**Quick Start:**
1. Skim Section 2 (DISCOVER examples) - 10 min
2. Check Section 3 (Anti-Patterns) - 5 min
3. Use Section 5 (Research Matrix) as reference
4. Jump to Section 7 (Code Template)
5. Reference Part 2, Section 19 for patterns

---

##  CRITICAL RULES TO REMEMBER

### The Non-Negotiables:

1. **ALWAYS DISCOVER, NEVER ASSUME**
   ```python
   # Execute → Observe → Decide
   # NEVER hardcode expectations
   ```

2. **Two Test Types Are Different**
   ```python
   # Functional: "Does it work?"
   @pytest.mark.functional

   # Business Rules: "Does it meet standards?"
   @pytest.mark.business_rules
   ```

3. **Tests Must Work on Unknown Sites**
   ```python
   # Change BASE_URL + LOCATORS = works anywhere
   # Logic must be generic
   ```

4. **Every Business Rule Has Standard Reference**
   ```python
   """
   Standard: NIST 800-63B Section 5.1.1
   Requirement: Minimum 8 characters for passwords
   """
   ```

5. **No Emojis, Professional Code**
   ```python
   # ❌ def test_cool_feature(): 😄
   # ✅ def test_input_validation_BR_001():
   ```

---

##  WHAT YOU'LL GENERATE

### test_[module].py
```
Typical size: 15-25 tests

Distribution:
- Functional Tests: 30-40% (5-10 tests)
  - Happy path validation
  - Core feature verification
  - Integration flows

- Business Rules Tests: 60-70% (10-15 tests)
  - Input validation standards
  - Security requirements
  - Accessibility compliance
  - Data quality standards

All tests follow DISCOVER philosophy
All business rules cite specific standards
All tests reusable on different sites
```

### README_[module].md
```
Typical size: 25-40 pages

Sections:
1. Overview
2. Test cases summary (table)
3. Code architecture
4. Configuration & locators
5. Fixtures explained
6. Helper functions
7. Detailed test explanations
8. Execution guide
9. Expected results
10. Troubleshooting
11. Related bugs/issues
12. Best practices
13. Version history
```

---

##  EXAMPLES OF USAGE

### Example 1: Basic Request

**YOU:**
> "Crea test_login.py"

**I GENERATE:**
- test_login.py (18 tests: 6 functional + 12 business rules)
- README_login.md
- All tests DISCOVER behavior
- OWASP ASVS v5.0 + NIST 800-63B + ISO 27001 compliance

### Example 2: Functional Only

**YOU:**
> "Test_payment.py solo funcionales, no business rules"

**I GENERATE:**
- test_payment.py (8 functional tests only)
- Happy path validation
- No business rules tests
- README_payment.md

### Example 3: Complete Suite

**YOU:**
> "Suite completa para shopping cart"

**I GENERATE:**
- test_cart.py (20 tests: 8 functional + 12 business rules)
- Complete coverage
- README_cart.md

---

##  HOW TO VERIFY QUALITY

### Before Accepting Generated Code:

**Philosophy:**
- [ ] Tests DISCOVER (execute → observe → decide)
- [ ] No hardcoded assumptions
- [ ] Works on unknown sites

**Code Quality:**
- [ ] No emojis
- [ ] Professional formatting
- [ ] Minimal comments
- [ ] Clear docstrings
- [ ] Proper markers (@pytest.mark.functional / @pytest.mark.business_rules)

**Standards:**
- [ ] Functional tests clearly marked
- [ ] Business rules cite standards (with versions)
- [ ] Severity levels for violations
- [ ] Business impact documented

**Reusability:**
- [ ] Configuration section clear
- [ ] Locators section clear
- [ ] Helper functions generic
- [ ] Can work on different sites

**Documentation:**
- [ ] README generated
- [ ] Test explanations clear
- [ ] Execution guide present

---

##  NEXT STEPS

### To Use This Template:

1. **Read the critical sections** (Sections 2, 3, and Part 2 Section 18)
2. **Identify your module type** (Login, Payment, Cart, etc.)
3. **Decide test types:** Functional only? Business rules only? Both?
4. **Ask me to generate:** "Crea test_[module].py con funcionales y business rules"
5. **I follow the workflow** from Example Conversations
6. **Review generated code** using quality checklist
7. **Run tests** in authorized environment
8. **Document findings** if violations discovered

---

##  WHEN TO USE WHICH TEMPLATE

### Use FUNCTIONAL Template When:
- ✅ Validating features work correctly
- ✅ Testing happy path scenarios
- ✅ Verifying standards compliance (non-security)
- ✅ Checking input validation
- ✅ Testing accessibility (WCAG)
- ✅ Data quality validation

### Use SECURITY Template When:
- ✅ Looking for vulnerabilities
- ✅ Attempting exploitation
- ✅ Testing attack vectors
- ✅ Bot protection testing
- ✅ Rate limiting validation
- ✅ PCI-DSS compliance (payment security)
- ✅ Penetration testing

### Use BOTH When:
- ✅ Complete QA coverage needed
- ✅ Production-ready validation
- ✅ Comprehensive quality assurance
- ✅ Security + functionality + standards

**Typical Workflow:**
1. Start with **FUNCTIONAL** template (validate it works)
2. Then use **SECURITY** template (validate it's secure)
3. Combined coverage = Production ready

---

## 📋 QUICK REFERENCE CARD

### FUNCTIONAL Template Essentials:

```
PURPOSE: Validate functionality + standards compliance
PHILOSOPHY: DISCOVER behavior, never assume
TEST TYPES: Functional (30-40%) + Business Rules (60-70%)

STRUCTURE:
- Functional tests → @pytest.mark.functional
- Business rules → @pytest.mark.business_rules

STANDARDS:
- OWASP ASVS v5.0 (Security)
- ISO 25010 (Quality)
- WCAG 2.1 (Accessibility)
- NIST 800-63B (Authentication)
- Module-specific standards

FORMULA:
Execute → Observe → Decide
```

---

**Remember:** The philosophy is DISCOVER, not ASSUME. Master that and everything else follows.


**Questions? Reference this guide and the template files!**
