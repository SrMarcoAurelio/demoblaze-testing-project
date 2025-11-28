# Product Details Functionality Testing Suite

**Module:** `test_product_functionality.py`  
**Author:** Arévalo, Marc  
**Application Under Test:** DemoBlaze (https://www.demoblaze.com/)  
**Current Version:** 1.0  
**Test Type:** Functional and Business Rules Testing

---

## Table of Contents

1. [Overview](#overview)
2. [Philosophy: DISCOVER Methodology](#philosophy)
3. [Quick Start](#quick-start)
4. [Test Coverage](#coverage)
5. [Configuration](#configuration)
6. [Test Inventory](#inventory)
7. [Detailed Test Cases](#details)
8. [Execution Guide](#execution)
9. [Expected Results](#results)
10. [Standards Reference](#standards)
11. [Troubleshooting](#troubleshooting)
12. [Best Practices](#practices)
13. [Version History](#version)

---

<a name="overview"></a>
## 1. Overview

### Purpose

This test suite validates the product detail page functionality of DemoBlaze's e-commerce platform. Tests follow the DISCOVER methodology, executing actions against international standards and reporting violations as errors, not excuses.

### Test Methodology

**DISCOVER Philosophy:**
1. **EXECUTE:** Perform actions on product detail pages
2. **OBSERVE:** Capture actual system behavior and product data
3. **DECIDE:** Validate against international standards (ISO 25010, WCAG 2.1, OWASP ASVS, ISO 9241-110)

**Critical Principle:** Standards are requirements. If the system violates a standard, the test fails and reports an error with full context, CVSS scoring, and impact analysis.

### Scope

**In Scope:**
- Product detail page navigation and display
- Product information completeness (name, price, description, image)
- Add to cart functionality from product page
- Navigation flows (catalog → product → catalog)
- Data consistency across views
- Performance testing (page load times)
- Accessibility compliance (WCAG 2.1 Level A)
- Usability validation (ISO 9241-110)

**Standards Coverage:**
- ISO 25010:2011 - Software Quality Model
- WCAG 2.1 - Web Content Accessibility Guidelines (Level A and AA)
- OWASP ASVS v5.0 - Application Security Verification Standard
- ISO 9241-110 - Ergonomics of human-system interaction
- NIST SP 800-63B - Digital Identity Guidelines

### Test Statistics

- **Total Test Functions:** 20
- **Total Test Runs:** 23+ (with parametrization)
- **Functional Tests:** 10
- **Business Rules Tests:** 10 (with 1 parametrized)
- **Standards Validated:** 5 international standards
- **Lines of Code:** ~1,000 lines

---

<a name="philosophy"></a>
## 2. Philosophy: DISCOVER Methodology

### The DISCOVER Principle

Tests in this suite follow the **DISCOVER** methodology:
- **D**iscover actual behavior
- **I**nvestigate objectively
- **S**tandards-based validation
- **C**ritical violations reported as errors
- **O**bserve without assumptions
- **V**erify against requirements
- **E**xecute and evaluate
- **R**eport findings accurately

### Examples

**❌ INCORRECT Approach (What we DON'T do):**
```python
# Assuming DemoBlaze is just a demo and excusing missing features
def test_product_has_reviews():
    # Product doesn't have reviews, but it's just a demo app
    pytest.skip("Reviews not implemented - out of scope")
```

**✅ CORRECT Approach (What we DO):**
```python
# Discovering violations and reporting them
def test_product_data_completeness_BR_003():
    """
    Standard: ISO 25010 Section 5.3 (Completeness)
    CVSS Score: 3.7 (LOW) if violated
    """
    if not product_has_description:
        logging.error("DATA COMPLETENESS VIOLATION")
        logging.error("Standard: ISO 25010 Section 5.3")
        logging.error("CVSS Score: 3.7 (LOW)")
        pytest.fail("DISCOVERED: Product lacks description")
```

### Why This Matters

1. **Objective Testing:** Tests discover what IS, not what we assume
2. **Standards Compliance:** Validates against recognized industry standards
3. **Professional Reporting:** Violations include CVSS scores and impact analysis
4. **Real-World Value:** Tests work on ANY e-commerce application
5. **Legal Compliance:** WCAG violations are reported as mandatory requirements

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
# - requests
```

### Basic Execution

```bash
# Run all tests
pytest tests/product_details/functional-tests/test_product_functionality.py -v

# Run with HTML report
pytest tests/product_details/functional-tests/test_product_functionality.py --html=report.html --self-contained-html

# Run specific test
pytest tests/product_details/functional-tests/test_product_functionality.py::test_navigate_to_product_from_catalog_FUNC_001 -v
```

### Quick Test Commands

```bash
# Functional tests only
pytest test_product_functionality.py -m "functional" -v

# Business rules only
pytest test_product_functionality.py -m "business_rules" -v

# Run with different browser
pytest test_product_functionality.py --browser=firefox -v

# Headless mode (CI/CD)
pytest test_product_functionality.py --headless -v
```

---

<a name="coverage"></a>
## 4. Test Coverage

### Functional Tests (10 tests)

| Test ID | Test Name | Description | Priority |
|---------|-----------|-------------|----------|
| FUNC-001 | Navigate to Product from Catalog | Verifies navigation flow from catalog to product detail | HIGH |
| FUNC-002 | Product Name Displays | Validates product name is visible | HIGH |
| FUNC-003 | Product Price Displays | Validates product price is visible | HIGH |
| FUNC-004 | Product Description Displays | Validates product description is visible | MEDIUM |
| FUNC-005 | Product Image Displays | Validates product image loads | HIGH |
| FUNC-006 | Add to Cart Button Present | Validates add to cart button exists | HIGH |
| FUNC-007 | Add to Cart from Product Page | Verifies add to cart functionality works | HIGH |
| FUNC-008 | Back to Catalog Navigation | Verifies user can return to catalog | MEDIUM |
| FUNC-009 | Browser Back Button | Validates browser back button works | MEDIUM |
| FUNC-010 | Multiple Product Navigation | Verifies navigation between products | MEDIUM |

### Business Rules Tests (13 test runs)

| Test ID | Test Name | Standard | CVSS | Runs |
|---------|-----------|----------|------|------|
| BR-001 | All Products Have Name | ISO 25010 Section 5.3 | 5.3 MEDIUM | 1 |
| BR-002 | All Products Have Price | ISO 25010 Section 5.3 | 7.5 HIGH | 1 |
| BR-003 | All Products Have Description | ISO 25010 Section 5.3 | 3.7 LOW | 1 |
| BR-004 | Product Images Load Successfully | ISO 25010 Section 5.4 | 5.3 MEDIUM | 1 |
| BR-005 | Price Format Consistency | ISO 25010 Section 5.2 | 3.7 LOW | 1 |
| BR-006 | Product Load Time < 3s | ISO 25010 Section 5.5 | 5.3 MEDIUM | 1 |
| BR-007 | Add to Cart Button Visibility | ISO 9241-110 Section 5.3 | 5.3 MEDIUM | 1 |
| BR-008 | Images Have Alt Text | WCAG 2.1 SC 1.1.1 Level A | 7.5 HIGH | 1 |
| BR-009 | Keyboard Navigation | WCAG 2.1 SC 2.1.1 Level A | 7.5 HIGH | 1 |
| BR-010 | Data Consistency Across Views | ISO 25010 Section 5.2 | 5.3 MEDIUM | 3 (parametrized) |

### Test Execution Flow

```
START
  │
  ├─ Functional Tests (Basic Validation)
  │   ├─ Navigation tests
  │   ├─ Display tests
  │   └─ Interaction tests
  │
  └─ Business Rules Tests (Standards Validation)
      ├─ Data completeness (ISO 25010)
      ├─ Performance (ISO 25010)
      ├─ Usability (ISO 9241-110)
      └─ Accessibility (WCAG 2.1)
END
```

---

<a name="configuration"></a>
## 5. Configuration

### Global Configuration

```python
BASE_URL = "https://www.demoblaze.com/"
TIMEOUT = 10              # Standard timeout for element waits
TIMEOUT_SHORT = 5         # Short timeout for quick checks
TIMEOUT_MEDIUM = 15       # Medium timeout for slower operations
```

### Locators

**Catalog/Home:**
```python
PRODUCT_LINKS = (By.CSS_SELECTOR, ".hrefch")
PRODUCT_CARDS = (By.CSS_SELECTOR, ".card")
```

**Product Details Page:**
```python
PRODUCT_NAME = (By.CSS_SELECTOR, "h2.name")
PRODUCT_PRICE = (By.CSS_SELECTOR, "h3.price-container")
PRODUCT_DESCRIPTION = (By.CSS_SELECTOR, "#more")
PRODUCT_IMAGE = (By.CSS_SELECTOR, ".item.active img")
ADD_TO_CART_BUTTON = (By.CSS_SELECTOR, "a.btn.btn-success.btn-lg")
```

**Navigation:**
```python
HOME_LINK = (By.CSS_SELECTOR, "a.nav-link[href='index.html']")
CART_LINK = (By.ID, "cartur")
```

### Helper Functions

**wait_for_page_load(browser, timeout=TIMEOUT)**
- Waits for page to fully load using document.readyState
- Returns: True if loaded, False if timeout

**navigate_to_first_product(browser)**
- Navigates from home to first product detail page
- Returns: (success: bool, product_name: str)

**get_product_details(browser)**
- Extracts all product details from current page
- Returns: Dictionary with name, price, description, image_src, add_to_cart_present

**check_image_loads_successfully(image_url)**
- Verifies image URL returns HTTP 200 OK
- Returns: True if image loads, False otherwise

---

<a name="inventory"></a>
## 6. Test Inventory

### Critical Path Tests (Must Pass)

**TC-PRODUCT-FUNC-001: Navigate to Product from Catalog**
- **Purpose:** Validates core navigation flow
- **User Flow:** Home → Click Product → Product Detail Page
- **Expected:** URL contains "prod.html", product details visible
- **Failure Impact:** Users cannot view products (CRITICAL)

**TC-PRODUCT-FUNC-002: Product Name Displays**
- **Purpose:** Validates essential product information
- **Expected:** Product name visible and non-empty
- **Failure Impact:** Users don't know what product they're viewing (HIGH)

**TC-PRODUCT-FUNC-003: Product Price Displays**
- **Purpose:** Validates critical purchase information
- **Expected:** Price visible, contains "$" symbol
- **Failure Impact:** Users cannot determine cost (CRITICAL)

**TC-PRODUCT-FUNC-007: Add to Cart from Product Page**
- **Purpose:** Validates core e-commerce functionality
- **Expected:** Click button → Alert appears → Product added
- **Failure Impact:** Users cannot purchase (CRITICAL)

### Data Quality Tests (Standards Compliance)

**TC-PRODUCT-BR-001: All Products Have Name**
- **Standard:** ISO 25010 Section 5.3 (Completeness)
- **Method:** Navigate to 10 products, verify name present
- **Violation:** CVSS 5.3 (MEDIUM) if any product lacks name
- **Impact:** Poor UX, missing critical information

**TC-PRODUCT-BR-002: All Products Have Price**
- **Standard:** ISO 25010 Section 5.3 (Completeness)
- **Method:** Navigate to 10 products, verify price present
- **Violation:** CVSS 7.5 (HIGH) if any product lacks price
- **Impact:** Cannot complete purchase, broken business logic

**TC-PRODUCT-BR-004: Product Images Load Successfully**
- **Standard:** ISO 25010 Section 5.4 (Availability)
- **Method:** Navigate to 10 products, HTTP HEAD request to verify 200 OK
- **Violation:** CVSS 5.3 (MEDIUM) if images return 404/error
- **Impact:** Users cannot see products, poor UX

### Performance Tests

**TC-PRODUCT-BR-006: Product Load Time < 3 seconds**
- **Standard:** ISO 25010 Section 5.5 (Performance Efficiency)
- **Method:** Measure time from click to page loaded
- **Threshold:** 3 seconds maximum
- **Violation:** CVSS 5.3 (MEDIUM) if exceeds 3s
- **Impact:** Poor UX, increased bounce rate

### Accessibility Tests (MANDATORY)

**TC-PRODUCT-BR-008: Images Have Alt Text**
- **Standard:** WCAG 2.1 SC 1.1.1 Level A (MANDATORY)
- **Method:** Check alt attribute on product images
- **Violation:** CVSS 7.5 (HIGH) - ADA compliance failure
- **Legal:** This is a MANDATORY accessibility requirement
- **Impact:** Screen readers cannot describe images, legal liability

**TC-PRODUCT-BR-009: Keyboard Navigation**
- **Standard:** WCAG 2.1 SC 2.1.1 Level A (MANDATORY)
- **Method:** Tab key navigation to add to cart button
- **Violation:** CVSS 7.5 (HIGH) - ADA compliance failure
- **Legal:** This is a MANDATORY accessibility requirement
- **Impact:** Keyboard-only users cannot purchase

---

<a name="details"></a>
## 7. Detailed Test Cases

### TC-PRODUCT-FUNC-001: Navigate to Product from Catalog

**Objective:** Verify user can navigate from catalog to product detail page

**Prerequisites:**
- Browser initialized
- Base URL accessible

**Test Steps:**
1. Navigate to BASE_URL
2. Wait for products to load
3. Click on first product link
4. Wait for product detail page to load

**Expected Results:**
- URL contains "prod.html"
- Product detail elements visible (name, price, description)
- No errors in browser console

**Validation:**
```python
assert "prod.html" in browser.current_url
assert product_name_element.is_displayed()
```

**Failure Conditions:**
- Timeout waiting for products
- Product link not clickable
- Product page doesn't load
- URL doesn't change

---

### TC-PRODUCT-BR-002: All Products Have Price

**Objective:** Discover if any products lack price information

**Standard:** ISO 25010 Section 5.3 (Completeness)

**Test Steps:**
1. Load catalog page
2. For first 10 products:
   - Navigate to product detail page
   - Check for price element
   - Verify price contains "$"
   - Record any missing prices

**Expected Results:**
- All products have visible price
- Price format includes "$" symbol
- No products without pricing

**If Violation Discovered:**
```
CRITICAL: PRODUCTS WITHOUT PRICE INFORMATION
Standard: ISO 25010 Section 5.3 (Completeness)
CVSS Score: 7.5 (HIGH)
Impact: Cannot complete purchase, broken business logic
Recommendation: Add price to all products
```

**Why This Test Matters:**
- Price is critical business data
- Users cannot make purchase decisions without price
- Missing prices indicate data integrity issues

---

### TC-PRODUCT-BR-006: Product Load Time < 3 seconds

**Objective:** Discover if product pages load within acceptable time

**Standard:** ISO 25010 Section 5.5 (Performance Efficiency)

**Test Steps:**
1. Load catalog page
2. For first 5 products:
   - Record start time
   - Click product link
   - Wait for page loaded
   - Wait for product name visible
   - Calculate elapsed time
   - Record if > 3 seconds

**Performance Thresholds:**
- **Excellent:** < 1 second
- **Acceptable:** 1-3 seconds
- **Poor:** > 3 seconds (VIOLATION)

**If Violation Discovered:**
```
PERFORMANCE VIOLATION: SLOW PRODUCT LOAD TIMES
Standard: ISO 25010 Section 5.5 (Performance Efficiency)
CVSS Score: 5.3 (MEDIUM)
Impact: Poor user experience, increased bounce rate
Requirement: Page load should be < 3 seconds
```

**Optimization Recommendations:**
- Optimize images (lazy loading, compression)
- Minimize JavaScript/CSS
- Implement caching
- Use CDN for static assets

---

### TC-PRODUCT-BR-008: Images Have Alt Text

**Objective:** Discover if product images have proper alt text for accessibility

**Standard:** WCAG 2.1 Success Criterion 1.1.1 Level A (MANDATORY)

**Legal Context:**
- This is a MANDATORY accessibility requirement under ADA
- Failure can result in lawsuits
- Level A is the minimum legal requirement

**Test Steps:**
1. Load catalog page
2. For first 5 products:
   - Navigate to product page
   - Find product image element
   - Check alt attribute
   - Verify alt text is non-empty

**Expected Results:**
- All images have alt attribute
- Alt text describes the image
- Alt text is non-empty (not just "")

**If Violation Discovered:**
```
ACCESSIBILITY VIOLATION: IMAGES WITHOUT ALT TEXT
Standard: WCAG 2.1 SC 1.1.1 Level A (MANDATORY)
CVSS Score: 7.5 (HIGH)
Impact:
  - Screen readers cannot describe images
  - ADA compliance failure
  - Legal liability (lawsuits)
  - SEO impact
Legal: This is a MANDATORY accessibility requirement
```

**Remediation:**
```html
<!-- ❌ WRONG -->
<img src="product.jpg">

<!-- ✅ CORRECT -->
<img src="product.jpg" alt="Samsung Galaxy S9 smartphone in midnight black">
```

---

### TC-PRODUCT-BR-010: Data Consistency Across Views

**Objective:** Discover if product data is consistent between catalog and detail page

**Standard:** ISO 25010 Section 5.2 (Consistency)

**Test Steps:**
1. Load catalog page
2. Record product name from catalog
3. Click product link
4. Record product name from detail page
5. Compare names (case-insensitive)

**Expected Results:**
- Product name in catalog matches detail page
- Data consistency maintained across views

**Why This Test Matters:**
- Inconsistent data creates user confusion
- May indicate database synchronization issues
- Affects user trust in the platform

**Parametrization:**
- Test runs 3 times with product indices [0, 1, 2]
- Validates consistency across multiple products

---

<a name="execution"></a>
## 8. Execution Guide

### Standard Execution

```bash
# Run all tests with verbose output
pytest test_product_functionality.py -v

# Run with HTML report
pytest test_product_functionality.py --html=report_product.html --self-contained-html

# Run specific test
pytest test_product_functionality.py::test_navigate_to_product_from_catalog_FUNC_001 -v
```

### Selective Execution

```bash
# Functional tests only
pytest test_product_functionality.py -m "functional" -v

# Business rules only
pytest test_product_functionality.py -m "business_rules" -v

# Run first 5 tests only
pytest test_product_functionality.py -v -k "FUNC_00"
```

### Browser Selection

```bash
# Run with Firefox
pytest test_product_functionality.py --browser=firefox -v

# Run with Edge
pytest test_product_functionality.py --browser=edge -v

# Run headless (CI/CD)
pytest test_product_functionality.py --headless -v
```

### Advanced Options

```bash
# Stop on first failure
pytest test_product_functionality.py -x

# Run with detailed output
pytest test_product_functionality.py -vv

# Show print statements
pytest test_product_functionality.py -s

# Run specific parametrized test
pytest test_product_functionality.py::test_product_data_consistency_across_views_BR_010[0] -v
```

### Parallel Execution

```bash
# Install pytest-xdist
pip install pytest-xdist

# Run tests in parallel (4 workers)
pytest test_product_functionality.py -n 4
```

### CI/CD Integration

```bash
# Complete CI/CD command
pytest test_product_functionality.py \
  --browser=chrome \
  --headless \
  -v \
  --html=report.html \
  --self-contained-html \
  --junitxml=results.xml
```

---

<a name="results"></a>
## 9. Expected Results

### All Tests Pass (Ideal Scenario)

```
======================== test session starts =========================
collected 23 items

test_product_functionality.py::test_navigate_to_product_from_catalog_FUNC_001 PASSED
test_product_functionality.py::test_product_name_displays_FUNC_002 PASSED
test_product_functionality.py::test_product_price_displays_FUNC_003 PASSED
...
test_product_functionality.py::test_product_data_consistency_across_views_BR_010[2] PASSED

===================== 23 passed in 180.45s ==========================
```

### Interpreting Failures

**FUNCTIONAL TEST FAILURE:**
- Indicates core product page functionality broken
- Requires immediate attention
- May block user purchases

**Example:**
```
FAILED test_product_functionality.py::test_add_to_cart_from_product_page_FUNC_007
AssertionError: FAILED: Add to cart button not found
```
**Action:** Check if add to cart button selector changed, verify element exists

---

**BUSINESS RULES FAILURE (Standards Violation):**
- Indicates violation of industry standard
- CVSS score indicates severity
- May have legal implications (accessibility)

**Example:**
```
FAILED test_product_functionality.py::test_product_image_has_alt_text_BR_008
pytest.Failed: DISCOVERED: 3 products lack image alt text (WCAG 2.1 Level A violation)

ACCESSIBILITY VIOLATION: IMAGES WITHOUT ALT TEXT
Standard: WCAG 2.1 SC 1.1.1 Level A (MANDATORY)
CVSS Score: 7.5 (HIGH)
Legal: This is a MANDATORY accessibility requirement
```
**Action:** Add alt text to all product images immediately (legal requirement)

---

**PERFORMANCE FAILURE:**
```
FAILED test_product_functionality.py::test_product_detail_load_time_BR_006
pytest.Failed: DISCOVERED: 2 products exceed 3s load time

PERFORMANCE VIOLATION: SLOW PRODUCT LOAD TIMES
Product 2: 3.45s
Product 4: 4.12s
```
**Action:** Investigate slow-loading products, optimize images/scripts

---

### Expected Test Failures (Discovery Mode)

These tests are DESIGNED to discover violations:

| Test | Expected to Fail? | Why |
|------|------------------|-----|
| BR-002 (Price) | Unlikely | Most e-commerce sites have prices |
| BR-006 (Performance) | Possible | DemoBlaze may have slow pages |
| BR-008 (Alt Text) | **LIKELY** | Many sites lack proper alt text |
| BR-009 (Keyboard) | Possible | Keyboard nav often overlooked |

**If these tests FAIL, it's CORRECT behavior - they're discovering real violations.**

---

<a name="standards"></a>
## 10. Standards Reference

### ISO 25010:2011 - Software Quality Model

**Section 5.2: Consistency**
- Definition: Degree to which product behavior is consistent across features
- Tests: BR-005 (Price Format), BR-010 (Data Consistency)

**Section 5.3: Completeness**
- Definition: Degree to which product has all required features and data
- Tests: BR-001 (Name), BR-002 (Price), BR-003 (Description)

**Section 5.4: Availability**
- Definition: Degree to which system is operational and accessible
- Tests: BR-004 (Image Loading)

**Section 5.5: Performance Efficiency**
- Definition: Performance relative to resources used under stated conditions
- Tests: BR-006 (Load Time < 3s)

---

### WCAG 2.1 - Web Content Accessibility Guidelines

**Success Criterion 1.1.1: Non-text Content (Level A - MANDATORY)**
- Requirement: All non-text content has text alternative
- Test: BR-008 (Image Alt Text)
- Legal: ADA compliance required
- Penalty: Lawsuits, fines, reputation damage

**Success Criterion 2.1.1: Keyboard (Level A - MANDATORY)**
- Requirement: All functionality available via keyboard
- Test: BR-009 (Keyboard Navigation)
- Legal: ADA compliance required
- Impact: Excludes users with motor disabilities

**Level A vs Level AA:**
- Level A: Minimum legal requirement (MANDATORY)
- Level AA: Enhanced accessibility (RECOMMENDED)
- Level AAA: Maximum accessibility (OPTIONAL)

---

### OWASP ASVS v5.0 - Application Security Verification Standard

While this is a functional test suite, OWASP ASVS principles inform our testing:

**V1.14: Configuration**
- Verify security headers present
- Related: Future security test suite

**V14: Configuration**
- Verify error messages don't leak sensitive info
- Related: Future security test suite

---

### ISO 9241-110 - Ergonomics of Human-System Interaction

**Section 5.3: Suitability for Learning**
- Principle: System should support learning
- Test: BR-007 (Button Visibility)

**Section 5.7: Suitability for Individualization**
- Principle: Users can customize interaction
- Related: Future usability tests

---

<a name="troubleshooting"></a>
## 11. Troubleshooting

### Common Issues

**Issue 1: Timeout Waiting for Products**
```
TimeoutException: Message: Element not found: .hrefch
```
**Cause:** Products not loading on homepage  
**Solution:**
- Increase TIMEOUT value
- Check internet connection
- Verify BASE_URL is correct
- Check if DemoBlaze is accessible

---

**Issue 2: Stale Element Reference**
```
StaleElementReferenceException: stale element reference: element is not attached to page
```
**Cause:** Page changed after element was found  
**Solution:**
- Re-locate element after page change
- Use WebDriverWait for dynamic content
- Avoid storing references to elements

**Code Fix:**
```python
# ❌ WRONG - Element may become stale
product_link = browser.find_element(*PRODUCT_LINKS)
time.sleep(5)
product_link.click()  # May throw StaleElementReferenceException

# ✅ CORRECT - Re-locate element
browser.find_element(*PRODUCT_LINKS).click()
```

---

**Issue 3: Tests Pass Locally but Fail in CI/CD**
```
All tests pass on local machine but fail in GitHub Actions
```
**Causes:**
- Headless browser behaves differently
- Timing issues (slower CI environment)
- Network latency

**Solutions:**
- Run locally with `--headless` flag to reproduce
- Increase timeouts for CI environment
- Add explicit waits before critical actions
- Use `time.sleep(2)` after page loads in CI

---

**Issue 4: Image Check Fails (BR-004)**
```
requests.exceptions.ConnectionError: Max retries exceeded
```
**Cause:** Network issue checking image URLs  
**Solution:**
- Check firewall settings
- Verify `requests` library installed
- Increase timeout in `check_image_loads_successfully()`

---

**Issue 5: Keyboard Navigation Test Fails (BR-009)**
```
Keyboard test fails - button not reachable via Tab
```
**Cause:** Tab order may vary by browser  
**Solution:**
- Increase Tab press count (currently 10)
- Verify button has proper `tabindex`
- Test manually to confirm keyboard accessibility

---

**Issue 6: Parametrized Test Skipped**
```
test_product_data_consistency_across_views_BR_010[2] SKIPPED
```
**Cause:** Not enough products (product index 2 unavailable)  
**Expected:** Normal behavior if catalog has < 3 products  
**Action:** None required - test correctly skips when product unavailable

---

<a name="practices"></a>
## 12. Best Practices

### Test Execution

1. **Run Full Suite Regularly**
   - Execute complete test suite daily
   - Catch regressions early

2. **Use HTML Reports**
   - Generate reports for stakeholders
   - Include screenshots on failures

3. **CI/CD Integration**
   - Run tests on every commit
   - Block deployment if critical tests fail

### Test Maintenance

1. **Update Locators When UI Changes**
   - Monitor for ElementNotFound errors
   - Update LOCATORS section when elements change

2. **Review CVSS Scores Annually**
   - CVSS scoring may change with new standards
   - Update severity levels accordingly

3. **Keep Standards References Current**
   - WCAG, OWASP, ISO standards are updated
   - Review and update test documentation

### Extending Test Suite

**Adding New Tests:**
1. Follow naming convention: `test_<name>_<TYPE>_<ID>`
2. Add appropriate markers (`@pytest.mark.functional` or `@pytest.mark.business_rules`)
3. Include docstring with standard reference and CVSS score
4. Update README test coverage table

**Example:**
```python
@pytest.mark.business_rules
def test_product_has_stock_info_BR_011(browser):
    """
    TC-PRODUCT-BR-011: Products Should Display Stock Information
    
    Standard: ISO 25010 Section 5.3 (Completeness)
    CVSS Score: 3.7 (LOW) if violated
    
    Discovers if products show stock availability.
    """
    # Test implementation
```

---

<a name="version"></a>
## 13. Version History

### Version 1.0 - November 2025 (Current)

**Initial Release**

**Test Coverage:**
- 10 functional tests
- 10 business rules tests (1 parametrized with 3 variants)
- Total: 20 functions, 23 test runs

**Functional Tests:**
- Product navigation from catalog
- Product information display (name, price, description, image)
- Add to cart functionality
- Navigation flows (back button, home link)

**Business Rules Tests:**
- Data completeness validation (ISO 25010)
- Performance validation (load time < 3s)
- Usability validation (button visibility)
- Accessibility compliance (WCAG 2.1 Level A)
- Data consistency validation

**Standards Validated:**
- ISO 25010 (Software Quality)
- WCAG 2.1 Level A and AA (Accessibility)
- OWASP ASVS v5.0 (Security)
- ISO 9241-110 (Ergonomics)

**Key Features:**
- Standards-based testing (no assumptions)
- CVSS scoring for violations
- Comprehensive logging
- Accessibility focus (WCAG 2.1 mandatory requirements)
- Performance thresholds
- Legal compliance awareness

**Code Quality:**
- Professional helper functions
- Clean locator organization
- Standardized timeout strategy
- Comprehensive error handling
- No duplicate fixtures (uses conftest.py)

---

## Related Documents

- **Test Implementation:** [test_product_functionality.py](test_product_functionality.py)
- **DISCOVER Philosophy:** [DISCOVER_PHILOSOPHY.md](../../discover-philosophy-for-better-tests/DISCOVER_PHILOSOPHY.md)
- **Catalog Tests:** [README_test_catalog_functionality.md](../../catalog/functional-tests/README.md)
- **Security Tests:** [README_test_product_security.md](../security-tests/README.md) *(Future)*

---

## Contact & Support

**For Technical Questions:**
- Review troubleshooting section above
- Check test execution logs
- Verify conftest.py configuration

**For Standards Interpretation:**
- Consult official documentation:
  - ISO 25010: https://iso25000.com/index.php/en/iso-25000-standards/iso-25010
  - WCAG 2.1: https://www.w3.org/WAI/WCAG21/quickref/
  - OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/

**For Legal/Compliance Questions:**
- Consult with legal team regarding ADA compliance
- Review accessibility audit requirements
- Understand regional accessibility laws

---

**Author:** Arévalo, Marc  
**Version:** 1.0  
**Last Updated:** November 2025

---

**End of Documentation**
