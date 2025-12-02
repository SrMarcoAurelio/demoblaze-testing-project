# [MODULE_NAME] Functional Tests - README Template

> **Template Version:** 1.0
> **Last Updated:** November 2025
> **Purpose:** Standard structure for documenting functional test suites

---

## 📋 Instructions for Using This Template

1. **Copy this entire file** to your test directory
2. **Rename** to `README_test_[module]_functionality.md`
3. **Replace ALL PLACEHOLDERS** in [BRACKETS] with actual values
4. **Delete this instructions section** when done
5. **Follow DISCOVER philosophy** - see DISCOVER_PHILOSOPHY.md

**Placeholders to replace:**
- `[MODULE_NAME]` - Name of the module (e.g., "Login", "Cart", "Checkout")
- `[DESCRIPTION]` - Brief description of what the module does
- `[BASE_URL]` - The base URL being tested
- `[TEST_CREDENTIALS]` - Actual test credentials used
- `[NUMBER]` - Actual numbers (test counts, etc.)
- `[LOCATOR_VALUE]` - Actual locator values
- `[STANDARD_SECTION]` - Actual standard reference (e.g., "OWASP ASVS 2.2.1")

---

# [MODULE_NAME] Functional Testing Suite

## 📋 Table of Contents

1. [Overview](#overview)
2. [Philosophy: DISCOVER Methodology](#philosophy)
3. [Test Coverage](#coverage)
4. [Quick Start](#quick-start)
5. [Configuration](#configuration)
6. [Locators](#locators)
7. [Helper Functions](#helpers)
8. [Test Inventory](#inventory)
9. [Test Details](#details)
10. [Execution Guide](#execution)
11. [Expected Results](#expected)
12. [Understanding Test Failures](#understanding)
13. [Troubleshooting](#troubleshooting)
14. [Standards Reference](#standards)
15. [Future Expansion](#future)
16. [Version History](#version)

---

<a name="overview"></a>
## 1. Overview

### Purpose

This test suite validates the **[MODULE_NAME] functionality** of the web application following the **DISCOVER methodology**. Tests execute actions, observe system responses, and make decisions based on objective industry standards.

**Module Description:** [DESCRIPTION]

### Test File

- **Filename:** `test_[module]_functionality.py`
- **Test Framework:** pytest
- **Language:** Python 3.x
- **Dependencies:** Selenium WebDriver, pytest

### Scope

This suite covers:

1. **Functional Tests** ([NUMBER] tests)
   - [Feature 1] validation
   - [Feature 2] validation
   - [Feature 3] validation
   - Error handling and edge cases

2. **Business Rules Tests** ([NUMBER] tests)
   - Input validation
   - Security validation (SQL Injection, XSS)
   - Performance validation
   - Accessibility compliance

### Key Metrics

- **Total Test Functions:** [NUMBER]
- **Total Test Runs:** [NUMBER] (includes parametrized tests)
- **Standards Validated:** OWASP ASVS v5.0, NIST 800-63B, ISO 27001, WCAG 2.1
- **Test Execution Time:** ~[NUMBER] seconds

---

<a name="philosophy"></a>
## 2. Philosophy: DISCOVER Methodology

### Core Principle

> **Tests DISCOVER behavior by EXECUTING actions and OBSERVING results.**
> **Tests NEVER ASSUME how the application will behave.**

### The DISCOVER Formula

```
DISCOVER = EXECUTE + OBSERVE + DECIDE

1. EXECUTE: Run the actual action ([action description])
2. OBSERVE: Capture the real system response
3. DECIDE: Compare against objective standards (OWASP, NIST, ISO, WCAG)
```

### Example: How DISCOVER Works in This Module

#### ❌ WRONG (Assuming):
```python
def test_[feature]():
    # "I know [APPLICATION] doesn't have [FEATURE]"
    pytest.skip("[APPLICATION] doesn't implement [FEATURE]")  # WRONG!
```

#### ✅ CORRECT (Discovering):
```python
def test_[feature]_enforcement_BR_XXX():
    """
    [STANDARD_SECTION]: [Feature] should be implemented

    Discovers if system has [feature].
    """
    # EXECUTE: Perform [action]
    perform_[action](browser, params)

    # OBSERVE: Check if [feature] exists
    feature_exists = check_for_[feature](browser)

    # DECIDE: According to [STANDARD], [feature] should exist
    if not feature_exists:
        logging.critical("VIOLATION: NO [FEATURE]")
        logging.critical("Standard: [STANDARD_SECTION]")
        logging.critical("CVSS Score: [SCORE]")
        pytest.fail("DISCOVERED: NO [FEATURE] - Violates [STANDARD]")
    else:
        assert True  # DISCOVERED: [Feature] implemented
```

### Why This Matters

**Code is universal:**
- Change `BASE_URL` + `LOCATORS` = works on ANY application
- Tests discover actual behavior objectively
- Same tests work on different implementations

**Tests are honest:**
- Don't hide missing features
- Report violations against industry standards
- Provide clear evidence for security/compliance assessments

---

<a name="coverage"></a>
## 3. Test Coverage

### 3.1 Functional Tests

| Test ID | Test Name | Description | Expected Result |
|---------|-----------|-------------|-----------------|
| FT-001 | `test_[feature]_[scenario]` | [Description] | ✅ PASS - [Expected behavior] |
| FT-002 | `test_[feature]_[scenario]` | [Description] | ✅ PASS - [Expected behavior] |
| FT-003 | `test_[feature]_[scenario]` | [Description] | ✅ PASS - [Expected behavior] |

### 3.2 Business Rules Tests

| Test ID | Test Name | Standard | Expected Result |
|---------|-----------|----------|-----------------|
| BR-001 | `test_[validation]_BR_001` | [STANDARD_SECTION] | ✅ PASS - [Expected behavior] |
| BR-002 | `test_[validation]_BR_002` | [STANDARD_SECTION] | ✅ PASS - [Expected behavior] |
| BR-003 | `test_[security]_BR_003` | OWASP ASVS 5.x.x | ✅ PASS - [Expected behavior] |

### 3.3 Expected Test Failures

These tests DISCOVER missing features and report them as violations:

| Test ID | Feature Tested | Standard | Expected Result for [APPLICATION] |
|---------|----------------|----------|-----------------------------------|
| BR-XXX | [Feature Name] | [STANDARD_SECTION] | ❌ FAIL - [Feature] not detected |
| BR-XXX | [Feature Name] | [STANDARD_SECTION] | ❌ FAIL - [Feature] not detected |
| BR-XXX | [Feature Name] | [STANDARD_SECTION] | ❌ FAIL - [Feature] not detected |

**Important:** These failures are NOT bugs in the tests - they are DISCOVERIES of missing controls that violate industry standards. This is the correct behavior of DISCOVER tests.

---

<a name="quick-start"></a>
## 4. Quick Start

### 4.1 Prerequisites

```bash
pip install pytest selenium webdriver-manager
```

### 4.2 Run All Tests

```bash
pytest test_[module]_functionality.py -v
```

### 4.3 Run Specific Test Categories

```bash
# Functional tests only
pytest test_[module]_functionality.py -v -k "test_[module]"

# Business rules only
pytest test_[module]_functionality.py -v -k "BR_"

# Specific test
pytest test_[module]_functionality.py::test_[specific]_BR_001 -v
```

### 4.4 Generate HTML Report

```bash
pytest test_[module]_functionality.py --html=report.html --self-contained-html
```

---

<a name="configuration"></a>
## 5. Configuration

### 5.1 Global Configuration

```python
BASE_URL = "[BASE_URL]"
TEST_USERNAME = "[TEST_USERNAME]"
TEST_PASSWORD = "[TEST_PASSWORD]"
```

**To test a different application:**
1. Update `BASE_URL`
2. Update `LOCATORS` dictionary
3. Update test credentials
4. Run tests

### 5.2 Timeout Configuration

```python
TIMEOUT_ELEMENT = 10  # Standard element wait
TIMEOUT_PAGE_LOAD = 15  # Page load timeout
TIMEOUT_MODAL = 5  # Modal appearance timeout
```

**Rationale:** Standardized timeouts ensure consistent behavior across different system speeds while accommodating network latency and browser rendering variations.

### 5.3 Cross-Platform Compatibility

```python
# Platform-specific delays (JUSTIFIED)
time.sleep(0.5)  # After modal interactions - prevents race conditions
```

**Note:** Minimal sleep statements are used only where necessary for cross-platform stability. Explicit waits are preferred.

---

<a name="locators"></a>
## 6. Locators

### 6.1 Primary Locators (USED)

```python
LOCATORS = {
    "[element_name]": ("ID", "[locator_value]"),
    "[element_name]": ("XPATH", "[locator_value]"),
    "[element_name]": ("CSS_SELECTOR", "[locator_value]"),
}
```

### 6.2 Alternative Locators (UNUSED - Available for Other Applications)

```python
ALTERNATIVE_LOCATORS = {
    "[element_name]": ("NAME", "[locator_value]"),
    "[element_name]": ("CLASS_NAME", "[locator_value]"),
}
```

**Usage:** If testing a different application that uses different HTML structures, these alternative locators can be activated.

---

<a name="helpers"></a>
## 7. Helper Functions

### 7.1 Core Helpers

```python
def wait_for_element(browser, locator, timeout=TIMEOUT_ELEMENT)
def click_element(browser, locator)
def send_keys_to_element(browser, locator, text)
def get_element_text(browser, locator)
```

**Purpose:** Provide reliable, reusable operations that handle common scenarios (stale elements, timing issues, cross-browser differences).

### 7.2 Module-Specific Helpers

```python
def perform_[action](browser, param1, param2)
def verify_[state](browser)
def check_for_[element](browser)
```

**Purpose:** Encapsulate module-specific workflows for reusability and maintainability.

---

<a name="inventory"></a>
## 8. Test Inventory

### 8.1 Functional Tests

#### FT-001: `test_[feature]_[scenario]()`
- **Purpose:** [Description]
- **Steps:**
  1. [Step 1]
  2. [Step 2]
  3. [Step 3]
- **Validation:** [What is checked]
- **Standard:** [STANDARD_SECTION]

#### FT-002: `test_[feature]_[scenario]()`
- **Purpose:** [Description]
- **Steps:**
  1. [Step 1]
  2. [Step 2]
- **Validation:** [What is checked]
- **Standard:** [STANDARD_SECTION]

### 8.2 Business Rules Tests

#### BR-001: `test_[validation]_BR_001()`
- **Purpose:** [Description]
- **Standard:** [STANDARD_SECTION]
- **Expected:** [Expected behavior]
- **Discovery:** If [condition], reports violation

#### BR-002: `test_[validation]_BR_002()`
- **Purpose:** [Description]
- **Standard:** [STANDARD_SECTION]
- **Parametrized:** Yes ([NUMBER] variants)
- **Test Data:**
  - [Data 1]: [Expected result]
  - [Data 2]: [Expected result]

---

<a name="details"></a>
## 9. Test Details

### 9.1 Functional Tests Details

#### Test: `test_[feature]_[scenario]()`

**Standard Reference:** [STANDARD_SECTION]

**Test Logic:**
```python
# EXECUTE
[action_description]

# OBSERVE
[observation_description]

# DECIDE
[decision_logic]
```

**Assertions:**
- [Assertion 1 description]
- [Assertion 2 description]

**Why This Test Matters:**
[Explanation of importance]

---

### 9.2 Business Rules Tests Details

#### Test: `test_[validation]_BR_XXX()`

**Standard Reference:** [STANDARD_SECTION] - [Standard name]

**Requirements:**
> [Quote from standard]

**Test Logic:**
```python
# EXECUTE: [Action description]
# OBSERVE: [What is observed]
# DECIDE: [Decision criteria based on standard]
```

**Expected Outcomes:**
- **If [condition]:** Test PASSES - [Explanation]
- **If [condition]:** Test FAILS - Reports "[VIOLATION]" with CVSS score

**Violation Reporting:**
```python
logging.critical("=" * 80)
logging.critical("VIOLATION DISCOVERED")
logging.critical("=" * 80)
logging.critical("Issue: [Issue description]")
logging.critical("Standard: [STANDARD_SECTION]")
logging.critical("Severity: [SEVERITY]")
logging.critical("CVSS Score: [SCORE]")
logging.critical("Evidence: [Evidence description]")
logging.critical("Impact: [Impact description]")
logging.critical("Recommendation: [Recommendation]")
logging.critical("=" * 80)
```

---

<a name="execution"></a>
## 10. Execution Guide

### 10.1 Command Reference

```bash
# Run all tests with verbose output
pytest test_[module]_functionality.py -v

# Run with detailed logging
pytest test_[module]_functionality.py -v --log-cli-level=INFO

# Run and generate HTML report
pytest test_[module]_functionality.py --html=report.html --self-contained-html

# Run specific test
pytest test_[module]_functionality.py::test_[specific] -v

# Run tests matching pattern
pytest test_[module]_functionality.py -v -k "[pattern]"

# Run with coverage
pytest test_[module]_functionality.py --cov=. --cov-report=html
```

### 10.2 Execution Flags

- `-v` / `--verbose`: Show detailed test output
- `-s`: Show print statements and logging
- `--tb=short`: Shorter traceback format
- `-x`: Stop at first failure
- `--maxfail=N`: Stop after N failures
- `-k EXPRESSION`: Run tests matching expression

### 10.3 Browser Options

Tests run in **headless mode** by default for CI/CD compatibility.

To run with visible browser:
```python
# Edit test file, change:
options.add_argument('--headless')
# To:
# options.add_argument('--headless')  # Commented out
```

---

<a name="expected"></a>
## 11. Expected Results

### 11.1 Functional Tests Results

| Test Category | Expected Passes | Expected Failures | Reason for Failures |
|---------------|-----------------|-------------------|---------------------|
| [Category 1] | [NUMBER] | 0 | N/A |
| [Category 2] | [NUMBER] | 0 | N/A |

**Total Functional:** [NUMBER] PASS / [NUMBER] FAIL

### 11.2 Business Rules Results

| Test Category | Expected Passes | Expected Failures | Reason for Failures |
|---------------|-----------------|-------------------|---------------------|
| Input Validation | [NUMBER] | 0 | N/A |
| Security | [NUMBER] | 0 | Application blocks attacks correctly |
| Advanced Security | 0 | [NUMBER] | Missing features (2FA, rate limiting, etc.) |

**Total Business Rules:** [NUMBER] PASS / [NUMBER] FAIL

### 11.3 Overall Summary

- **Total Tests:** [NUMBER]
- **Expected PASS:** [NUMBER]
- **Expected FAIL:** [NUMBER]
- **Pass Rate:** [PERCENTAGE]%

---

<a name="understanding"></a>
## 12. Understanding Test Failures

### 12.1 Types of Failures

#### ✅ Expected Failures (Discoveries)

Tests that discover missing features as designed:

```
FAILED test_[feature]_BR_XXX - DISCOVERED: NO [FEATURE] - Violates [STANDARD]
```

**This is CORRECT behavior:**
- Test discovered a missing security/compliance feature
- Violation is reported with standard reference
- Provides evidence for security assessments

**Action:** Document finding, recommend implementation

#### ❌ Unexpected Failures (Bugs)

Tests that should pass but fail:

```
FAILED test_[feature] - AssertionError: [unexpected error]
```

**This indicates a problem:**
- Could be application bug
- Could be changed UI/behavior
- Could be test environment issue

**Action:** Investigate and fix

### 12.2 Reading Test Output

**Successful Discovery:**
```
CRITICAL:root:==================================================
CRITICAL:root:VIOLATION DISCOVERED
CRITICAL:root:==================================================
CRITICAL:root:Issue: NO [FEATURE]
CRITICAL:root:Standard: [STANDARD_SECTION]
CRITICAL:root:Severity: HIGH
CRITICAL:root:CVSS Score: 7.5
CRITICAL:root:==================================================
FAILED - DISCOVERED: NO [FEATURE] - Violates [STANDARD]
```

**Interpretation:** Test is working correctly, discovered a violation.

---

<a name="troubleshooting"></a>
## 13. Troubleshooting

### 13.1 Common Issues

#### Issue: Tests time out
**Symptoms:** `TimeoutException` errors

**Solutions:**
1. Increase timeout values if testing slow network/system
2. Check internet connection stability
3. Verify application is accessible

#### Issue: Elements not found
**Symptoms:** `NoSuchElementException`

**Solutions:**
1. Verify application UI hasn't changed
2. Check if testing different application - update LOCATORS
3. Increase TIMEOUT_ELEMENT if system is slow

#### Issue: All tests fail immediately
**Symptoms:** Setup failures

**Solutions:**
1. Verify WebDriver is installed: `pip install webdriver-manager`
2. Check BASE_URL is accessible
3. Verify test credentials are valid

### 13.2 Debug Mode

Run with maximum verbosity:
```bash
pytest test_[module]_functionality.py -v -s --log-cli-level=DEBUG --tb=long
```

---

<a name="standards"></a>
## 14. Standards Reference

### 14.1 OWASP ASVS v5.0

**Sections Validated:**
- **2.x:** Authentication
- **3.x:** Session Management
- **5.x:** Validation, Sanitization
- **[X.x]:** [Additional sections]

**Reference:** https://owasp.org/www-project-application-security-verification-standard/

### 14.2 NIST SP 800-63B

**Sections Validated:**
- **5.1.1.x:** Password Requirements
- **5.2.x:** Multi-Factor Authentication
- **[X.x]:** [Additional sections]

**Reference:** https://pages.nist.gov/800-63-3/sp800-63b.html

### 14.3 ISO 27001:2022

**Controls Validated:**
- **A.9:** Access Control
- **A.10:** Cryptography
- **[A.X]:** [Additional controls]

**Reference:** https://www.iso.org/standard/27001

### 14.4 WCAG 2.1

**Success Criteria Validated:**
- **1.x:** Perceivable
- **2.x:** Operable
- **3.x:** Understandable
- **[X.x]:** [Additional criteria]

**Reference:** https://www.w3.org/WAI/WCAG21/quickref/

---

<a name="future"></a>
## 15. Future Expansion

### 15.1 Additional Tests for Production Applications

When testing production systems (not demos like [APPLICATION]), consider adding:

1. **[Feature Category]**
   - [Test description]
   - Standard: [STANDARD_SECTION]
   - Implementation: [Brief code example]

2. **[Feature Category]**
   - [Test description]
   - Standard: [STANDARD_SECTION]
   - Implementation: [Brief code example]

### 15.2 Unused Locators Available

The following locators are defined but not currently used. They can be activated when testing applications with these features:

```python
UNUSED_LOCATORS = {
    "[feature_element]": "[locator]",  # For [feature description]
}
```

### 15.3 Extensibility

This test suite is designed to be easily extended:

**To add new tests:**
1. Follow DISCOVER formula (EXECUTE + OBSERVE + DECIDE)
2. Reference appropriate standard
3. Log violations with CRITICAL level
4. Update this README

**To adapt for new application:**
1. Update BASE_URL
2. Update LOCATORS dictionary
3. Update test credentials
4. Run and adjust as needed

---

<a name="version"></a>
## 16. Version History

### Version 1.0 - [MONTH YEAR] (Current)

**Initial Release:**

**Test Coverage:**
- [NUMBER] functional tests
- [NUMBER] business rules tests
- Total: [NUMBER] functions, [NUMBER] test runs

**Key Features:**
- Complete [module] workflow validation
- Input validation ([details])
- Security testing ([details])
- Accessibility testing
- DISCOVER philosophy implementation
- Standards-based validation

**Code Quality:**
- No unnecessary imports
- Standardized timeout strategy
- Minimal time.sleep() (justified)
- Clean helper functions
- Professional logging

**Documentation:**
- Comprehensive README
- Future expansion section
- Unused locators documented
- Standards references

---

**End of Documentation**

**Related Documents:**
- [DISCOVER_PHILOSOPHY.md](DISCOVER_PHILOSOPHY.md)
- [Security Tests Documentation](README_test_[module]_security.md)
- [Project Test Plan](../../docs/test-plan.md)

**For questions or clarifications, refer to DISCOVER_PHILOSOPHY.md**
