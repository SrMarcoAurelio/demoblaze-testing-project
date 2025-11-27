# 📱 Product Module - Test Suite Documentation

## 📋 Overview

Complete test coverage for DemoBlaze's **Product Detail Pages** functionality, migrated to **Page Object Model (POM)** architecture following the **DISCOVER philosophy**.

**Philosophy:** EXECUTE → OBSERVE → DECIDE (No assumptions, only real discoveries)

---

## 📊 Test Coverage Summary

| Test File | Tests | Executions | Purpose |
|-----------|-------|------------|---------|
| **test_product_functional.py** | 20 | ~22 | Core functionality, navigation, business rules |
| **test_product_security.py** | 14 | ~25 | Security exploits, IDOR, injection attacks |
| **TOTAL** | **34** | **~47** | **Complete Product coverage** |

---

## 🏗️ Architecture

### Page Object Model

**`pages/product_page.py`** (623 lines)
- Product navigation (catalog→product, by index, by URL)
- Product information retrieval (name, price, description, image)
- Add to cart operations
- Catalog iteration (for validation across all products)
- Validation methods (completeness, format, image loading)
- Accessibility testing (keyboard navigation, alt text)
- Performance measurement (page load time)
- Security testing helpers (SQL error detection, XSS checking, information disclosure)

### Test Organization

```
tests_new/product/
├── __init__.py
├── test_product_functional.py    # Core features + business rules
├── test_product_security.py      # Security exploits
└── README.md                      # This file
```

---

## 📝 Standards Tested

- **OWASP ASVS v5.0** - Application Security Verification
- **OWASP Top 10 2021** - Web Application Security
- **ISO 25010** - Software Quality Standards (Completeness, Consistency, Reliability)
- **WCAG 2.1 Level A & AA** - Web Content Accessibility Guidelines
- **CWE** - Common Weakness Enumeration
- **CVSS 3.1** - Vulnerability Scoring System

---

## 🔬 Test Examples with Code

### 1. FUNCTIONAL TESTS (`test_product_functional.py`)

#### Example 1: Complete Product Navigation Flow

**Test ID:** TC-PRODUCT-FUNC-001

**What this test does:**
1. Starts on the home/catalog page
2. Waits for product links to load
3. Clicks on the first product link
4. Verifies navigation to product detail page
5. Confirms URL contains "prod.html"
6. Validates product name was captured

```python
@pytest.mark.functional
@pytest.mark.critical
def test_navigate_to_product_from_catalog_FUNC_001(browser, base_url):
    """
    TC-PRODUCT-FUNC-001: Navigate to Product from Catalog
    DISCOVER: Can users navigate from catalog to product detail page?
    """
    # EXECUTE: Navigate to product
    product_page = ProductPage(browser)
    success, product_name = product_page.navigate_to_first_product()

    # OBSERVE: Check navigation result
    current_url = browser.current_url

    # DECIDE: Should successfully navigate to product page
    assert success, "Failed to navigate to product"
    assert "prod.html" in current_url, f"Not on product page: {current_url}"
    assert product_name, "Product name not captured during navigation"

    logger.info(f"✓ Successfully navigated to product: {product_name}")
```

#### Example 2: Product Price Display and Validation

**Test ID:** TC-PRODUCT-FUNC-003

**What this test does:**
1. Navigates to a product detail page
2. Extracts the price text (e.g., "$790 *includes tax")
3. Extracts the numeric price value (790)
4. Validates price contains "$" symbol
5. Validates numeric value is positive
6. Discovers if price information is complete and correctly formatted

```python
@pytest.mark.functional
@pytest.mark.critical
def test_product_price_displays_FUNC_003(browser, base_url):
    """
    TC-PRODUCT-FUNC-003: Product Price Displays
    DISCOVER: Is product price visible on product detail page?
    """
    # EXECUTE: Navigate to product
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    # OBSERVE: Get product price
    product_price = product_page.get_product_price()
    price_value = product_page.get_product_price_value()

    # DECIDE: Product price should be present
    assert product_price, "Product price not displayed"
    assert "$" in product_price, f"Price doesn't contain '$': {product_price}"
    assert price_value is not None, "Could not extract numeric price value"
    assert price_value > 0, f"Price value should be positive: {price_value}"

    logger.info(f"✓ Product price displayed: {product_price} (value: ${price_value})")
```

#### Example 3: Add to Cart Functionality with Alert Handling

**Test ID:** TC-PRODUCT-FUNC-007

**What this test does:**
1. Navigates to a product
2. Clicks the "Add to Cart" button
3. Waits for and captures the browser alert
4. Accepts the alert automatically
5. Validates alert message confirms product was added
6. Discovers complete add-to-cart user flow

```python
@pytest.mark.functional
@pytest.mark.critical
def test_add_to_cart_from_product_page_FUNC_007(browser, base_url):
    """
    TC-PRODUCT-FUNC-007: Add to Cart from Product Page
    DISCOVER: Can users add product to cart from product detail page?
    """
    # EXECUTE: Navigate to product and add to cart
    product_page = ProductPage(browser)
    success, product_name = product_page.navigate_to_first_product()

    # EXECUTE: Click Add to Cart
    success, alert_text = product_page.add_to_cart_and_handle_alert()

    # DECIDE: Should successfully add to cart
    assert success, "Failed to add product to cart"
    assert alert_text, "No alert received after adding to cart"
    assert "added" in alert_text.lower() or "cart" in alert_text.lower(), \
        f"Unexpected alert text: {alert_text}"

    logger.info(f"✓ Product added to cart: {product_name}, Alert: {alert_text}")
```

#### Example 4: Business Rule - All Products Have Complete Information

**Test ID:** TC-PRODUCT-BR-001

**What this test does:**
1. Uses generator to iterate through all products in catalog (limited to first 5 for performance)
2. For each product: navigates to detail page
3. Checks if product name is present
4. Tracks products missing required information
5. Fails test if any product lacks a name
6. Discovers information completeness across entire catalog

**This is a powerful pattern**: one test validates ALL products, not just one!

```python
@pytest.mark.business_rules
@pytest.mark.high
def test_all_products_have_name_BR_001(browser, base_url):
    """
    TC-PRODUCT-BR-001: All Products Have Name
    Standard: ISO 25010 (Software Quality - Information Completeness)
    DISCOVER: Do ALL products in catalog have visible names?
    """
    # EXECUTE: Iterate through all products (limit to first 5 for performance)
    product_page = ProductPage(browser)
    products_without_name = []

    for index, product_name, details in product_page.iterate_all_products(max_products=5):
        # OBSERVE: Check if name is present
        if not details['name']:
            products_without_name.append(f"Product {index}")
            logger.error(f"✗ Product {index} has no name")

    # DECIDE: All products should have names
    if products_without_name:
        pytest.fail(f"DISCOVERED: {len(products_without_name)} products without names: {products_without_name}")

    logger.info("✓ All checked products have names")
```

#### Example 5: Image Loading Validation Across All Products

**Test ID:** TC-PRODUCT-BR-004

**What this test does:**
1. Iterates through all products (first 5)
2. For each product: extracts image URL
3. Makes HTTP HEAD request to image URL
4. Checks if HTTP status code is 200 (success)
5. Tracks which products have broken images
6. Discovers image reliability issues

**Real HTTP validation**, not just checking if `<img>` tag exists!

```python
@pytest.mark.business_rules
@pytest.mark.medium
def test_all_product_images_load_successfully_BR_004(browser, base_url):
    """
    TC-PRODUCT-BR-004: All Product Images Load Successfully
    Standard: ISO 25010 (Software Quality - Reliability)
    DISCOVER: Do all product images load with HTTP 200?
    """
    # EXECUTE: Iterate through products and check image loading
    product_page = ProductPage(browser)
    images_failed = []

    for index, product_name, details in product_page.iterate_all_products(max_products=5):
        # OBSERVE: Verify image loads
        loads, status_code, image_url = product_page.verify_image_loads()

        if not loads:
            images_failed.append(f"Product {index}: {product_name} (Status: {status_code})")
            logger.error(f"✗ Product {index} image failed: {status_code}")

    # DECIDE: All images should load successfully
    if images_failed:
        pytest.fail(f"DISCOVERED: {len(images_failed)} images failed to load: {images_failed}")

    logger.info("✓ All checked product images load successfully")
```

---

### 2. SECURITY TESTS (`test_product_security.py`)

#### Example 1: SQL Injection in Product ID (Parametrized)

**Test ID:** TC-PRODUCT-INJ-001

**What this test does:**
1. Uses `@pytest.mark.parametrize` to test 6 different SQL injection payloads
2. For each payload: navigates to product URL with malicious ID
3. Checks TWO things:
   - SQL error disclosure (error messages in page source)
   - Injection success (multiple products returned unexpectedly)
4. Fails if EITHER vulnerability is discovered
5. Real exploitation attempt, not theoretical

**Payloads tested:**
- `1' OR '1'='1` - Classic authentication bypass
- `1' OR '1'='1' --` - Comment-based injection
- `1' OR '1'='1' /*` - Multi-line comment injection
- `' OR 1=1--` - Numeric comparison injection
- `admin'--` - Admin account targeting
- `' UNION SELECT NULL--` - Union-based injection

```python
@pytest.mark.security
@pytest.mark.critical
@pytest.mark.injection
@pytest.mark.parametrize("sql_payload", [
    "1' OR '1'='1",
    "1' OR '1'='1' --",
    "1' OR '1'='1' /*",
    "' OR 1=1--",
    "admin'--",
    "' UNION SELECT NULL--",
])
def test_sql_injection_product_id_INJ_001(browser, base_url, sql_payload):
    """
    TC-PRODUCT-INJ-001: SQL Injection in Product ID Parameter
    CWE: CWE-89 (SQL Injection)
    CVSS Score: 9.8 CRITICAL
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    DISCOVER: Is product ID parameter vulnerable to SQL injection?
    """
    # EXECUTE: Navigate to product with SQL injection payload
    product_page = ProductPage(browser)
    product_page.navigate_to_product_by_url(sql_payload)

    # OBSERVE: Check for SQL error disclosure
    has_error, error_indicators = product_page.check_for_sql_error_indicators()

    # OBSERVE: Check if page behaves unexpectedly
    page_source = browser.page_source.lower()
    products_listed = page_source.count("hrefch")  # Product link class

    # DECIDE: SQL injection should be prevented
    if has_error:
        logger.critical(f"✗ CRITICAL: SQL error disclosure detected: {error_indicators}")
        pytest.fail(f"DISCOVERED: SQL error disclosure with payload '{sql_payload}': {error_indicators}")

    if products_listed > 10:
        logger.critical(f"✗ CRITICAL: Possible SQL injection - multiple products returned")
        pytest.fail(f"DISCOVERED: SQL injection may have bypassed product ID filter")

    logger.info(f"✓ SQL injection prevented: {sql_payload}")
```

#### Example 2: XSS (Cross-Site Scripting) in Product ID

**Test ID:** TC-PRODUCT-INJ-003

**What this test does:**
1. Tests 5 different XSS attack vectors via parametrization
2. For each payload: injects XSS code into product ID parameter
3. Checks if payload is reflected unescaped in HTML
4. Checks if JavaScript actually executes (alert appears)
5. Discovers both reflected XSS and XSS execution

**XSS vectors tested:**
- `<script>alert('XSS')</script>` - Basic script injection
- `<img src=x onerror=alert('XSS')>` - Image-based XSS
- `<svg/onload=alert('XSS')>` - SVG-based XSS
- `javascript:alert('XSS')` - JavaScript protocol
- `'><script>alert(String.fromCharCode(88,83,83))</script>` - Encoded XSS

```python
@pytest.mark.security
@pytest.mark.critical
@pytest.mark.injection
@pytest.mark.parametrize("xss_payload", [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "'><script>alert(String.fromCharCode(88,83,83))</script>",
])
def test_xss_product_id_parameter_INJ_003(browser, base_url, xss_payload):
    """
    TC-PRODUCT-INJ-003: XSS in Product ID Parameter
    CWE: CWE-79 (Cross-site Scripting)
    CVSS Score: 8.2 HIGH
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N

    DISCOVER: Is product ID parameter vulnerable to reflected XSS?
    """
    # EXECUTE: Navigate to product with XSS payload
    product_page = ProductPage(browser)
    product_page.navigate_to_product_by_url(xss_payload)

    # OBSERVE: Check for XSS execution
    is_vulnerable, evidence = product_page.check_for_xss_execution(xss_payload)

    # DECIDE: XSS should be prevented
    if is_vulnerable:
        logger.critical(f"✗ CRITICAL: XSS vulnerability detected!")
        pytest.fail(f"DISCOVERED: XSS vulnerability with payload '{xss_payload}': {evidence}")

    logger.info(f"✓ XSS prevented: {xss_payload}")
```

#### Example 3: IDOR (Insecure Direct Object Reference) - Product Enumeration

**Test ID:** TC-PRODUCT-IDOR-001

**What this test does:**
1. Attempts to access products with sequential IDs (1-20)
2. For each ID: navigates directly via URL manipulation
3. Checks if product loads successfully
4. Counts how many products are accessible
5. Discovers if predictable IDs allow enumeration

**Note:** Product enumeration is expected for **public catalogs** but would be a vulnerability for **private resources**!

```python
@pytest.mark.security
@pytest.mark.high
@pytest.mark.idor
def test_idor_product_enumeration_IDOR_001(browser, base_url):
    """
    TC-PRODUCT-IDOR-001: Product ID Enumeration
    CWE: CWE-639 (Authorization Bypass Through User-Controlled Key)
    CVSS Score: 7.5 HIGH
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

    DISCOVER: Can attackers enumerate products by guessing IDs?
    """
    # EXECUTE: Try accessing products with sequential IDs
    product_page = ProductPage(browser)
    accessible_products = []

    # Try IDs 1-20
    for product_id in range(1, 21):
        product_page.navigate_to_product_by_url(product_id)

        # OBSERVE: Check if product loads successfully
        product_name = product_page.get_product_name(timeout=3)

        if product_name:
            accessible_products.append((product_id, product_name))

    # DECIDE: Enumeration is possible (expected for public catalog)
    logger.info(f"✓ Product enumeration check: {len(accessible_products)} products accessible")
    logger.info(f"  Note: Product enumeration is expected for public catalogs")
```

#### Example 4: Price Tampering via URL Manipulation

**Test ID:** TC-PRODUCT-PRICE-001

**What this test does:**
1. Navigates to a product normally
2. Records the legitimate price
3. Constructs malicious URL with `&price=1` parameter
4. Navigates to manipulated URL
5. Checks if displayed price changed
6. Discovers if client-side price can affect server-side logic

**Business logic exploit**, not just technical vulnerability!

```python
@pytest.mark.security
@pytest.mark.critical
@pytest.mark.business_logic
def test_price_tampering_url_parameter_PRICE_001(browser, base_url):
    """
    TC-PRODUCT-PRICE-001: Price Tampering via URL Parameter
    CWE: CWE-602 (Client-Side Enforcement of Server-Side Security)
    CVSS Score: 8.6 HIGH
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L

    DISCOVER: Can prices be manipulated via URL parameters?
    """
    # EXECUTE: Navigate to product normally
    product_page = ProductPage(browser)
    product_page.navigate_to_first_product()

    # OBSERVE: Get legitimate price
    legitimate_price = product_page.get_product_price_value()
    product_id = product_page.get_current_product_id_from_url()

    logger.info(f"Legitimate price: ${legitimate_price}, Product ID: {product_id}")

    # EXECUTE: Try to manipulate price via URL
    manipulated_url = f"{base_url}prod.html?idp_={product_id}&price=1"
    browser.get(manipulated_url)
    product_page.wait_for_page_load()

    # OBSERVE: Check if price changed
    manipulated_price = product_page.get_product_price_value()

    # DECIDE: Price should not be manipulatable via URL
    if manipulated_price and manipulated_price != legitimate_price:
        logger.critical(f"✗ CRITICAL: Price manipulation succeeded!")
        pytest.fail(f"DISCOVERED: Price changed from ${legitimate_price} to ${manipulated_price}")

    logger.info("✓ Price tampering via URL prevented")
```

#### Example 5: Path Traversal in Product ID

**Test ID:** TC-PRODUCT-TRAV-001

**What this test does:**
1. Tests 4 different path traversal payloads
2. For each payload: injects into product ID parameter
3. Looks for file system disclosure indicators:
   - `root:` (Unix /etc/passwd file)
   - `[boot loader]` (Windows .ini files)
   - `file not found` errors
   - Directory listings
4. Discovers if product ID allows file system access

**Real path traversal attempts:**
- `../` - One level up
- `../../` - Two levels up
- `../../../etc/passwd` - Unix password file
- `..\\..\\windows\\system32` - Windows system directory

```python
@pytest.mark.security
@pytest.mark.high
@pytest.mark.injection
@pytest.mark.parametrize("traversal_payload", [
    "../",
    "../../",
    "../../../etc/passwd",
    "..\\..\\windows\\system32",
])
def test_path_traversal_product_id_TRAV_001(browser, base_url, traversal_payload):
    """
    TC-PRODUCT-TRAV-001: Path Traversal in Product ID
    CWE: CWE-22 (Path Traversal)
    CVSS Score: 7.5 HIGH
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

    DISCOVER: Is product ID parameter vulnerable to path traversal?
    """
    # EXECUTE: Navigate with path traversal payload
    product_page = ProductPage(browser)
    product_page.navigate_to_product_by_url(traversal_payload)

    # OBSERVE: Check for file system disclosure
    page_source = browser.page_source.lower()

    disclosure_indicators = [
        'root:',  # Unix passwd file
        '[boot loader]',  # Windows ini files
        'file not found',
        'directory',
        'access denied'
    ]

    violations = []

    for indicator in disclosure_indicators:
        if indicator in page_source:
            violations.append(indicator)
            logger.critical(f"✗ Path traversal disclosure: {indicator}")

    # DECIDE: Path traversal should be prevented
    if violations:
        pytest.fail(f"DISCOVERED: Path traversal vulnerability - {violations}")

    logger.info(f"✓ Path traversal prevented: {traversal_payload}")
```

---

## 🚀 Running the Tests

### Run All Product Tests
```bash
pytest tests_new/product/ -v
```

### Run by File
```bash
# Functional tests only
pytest tests_new/product/test_product_functional.py -v

# Security tests only
pytest tests_new/product/test_product_security.py -v
```

### Run by Priority
```bash
# Critical tests only
pytest tests_new/product/ -m critical -v

# High priority tests
pytest tests_new/product/ -m high -v
```

### Run by Type
```bash
# All security tests
pytest tests_new/product/ -m security -v

# Business rules tests
pytest tests_new/product/ -m business_rules -v

# Injection attack tests
pytest tests_new/product/ -m injection -v

# IDOR tests
pytest tests_new/product/ -m idor -v

# Accessibility tests
pytest tests_new/product/ -m accessibility -v
```

### Run Specific Test Patterns
```bash
# SQL injection tests only
pytest tests_new/product/ -k "sql_injection" -v

# XSS tests only
pytest tests_new/product/ -k "xss" -v

# All "BR" (Business Rules) tests
pytest tests_new/product/ -k "BR_" -v

# IDOR tests
pytest tests_new/product/ -k "IDOR" -v
```

---

## 📈 Test Execution Matrix

### Expected Results (DISCOVER Philosophy)

Tests are designed to DISCOVER actual behavior, not assume it:

| Category | Tests | Expected Pass % | Notes |
|----------|-------|----------------|-------|
| Functional | 20 | ~100% | Core features should work |
| Security | 14 | ~60-80% | Discovers vulnerabilities |
| **TOTAL** | **34** | **~85%** | Discovery-focused testing |

**Note:** Lower pass rates in security tests indicate successful vulnerability discovery, not test failure.

---

## 🎯 Key Test Markers

```python
@pytest.mark.functional         # Core functionality tests
@pytest.mark.business_rules     # Standards compliance tests
@pytest.mark.security           # Security exploitation tests
@pytest.mark.critical           # Critical priority (must pass)
@pytest.mark.high               # High priority
@pytest.mark.medium             # Medium priority
@pytest.mark.low                # Low priority
@pytest.mark.injection          # Injection attack tests (SQL, XSS)
@pytest.mark.idor               # IDOR/authorization tests
@pytest.mark.business_logic     # Business logic exploit tests
@pytest.mark.csrf               # CSRF protection tests
@pytest.mark.session            # Session security tests
@pytest.mark.headers            # Security headers tests
@pytest.mark.information_disclosure  # Information leak tests
@pytest.mark.accessibility      # WCAG compliance tests
```

---

## 🔍 Vulnerability Discovery Metrics

### High-Risk Vulnerabilities Tested

1. **SQL Injection** (CVSS 9.8 CRITICAL) - Product ID parameter
2. **XSS Attacks** (CVSS 8.2 HIGH) - Reflected and stored
3. **Price Tampering** (CVSS 8.6 HIGH) - URL manipulation
4. **Path Traversal** (CVSS 7.5 HIGH) - File system access
5. **IDOR** (CVSS 7.5 HIGH) - Product enumeration
6. **CSRF** (CVSS 6.5 MEDIUM) - Add to cart protection
7. **Information Disclosure** (CVSS 5.3 MEDIUM) - Sensitive data exposure

---

## 📚 Related Documentation

- **OWASP ASVS v5.0:** https://owasp.org/www-project-application-security-verification-standard/
- **OWASP Top 10 2021:** https://owasp.org/Top10/
- **WCAG 2.1:** https://www.w3.org/WAI/WCAG21/quickref/
- **CWE:** https://cwe.mitre.org/
- **CVSS 3.1:** https://www.first.org/cvss/

---

## 👨‍💻 Author

**Marc Arévalo**
Version: 1.0
Date: 2025

**Philosophy:** DISCOVER (EXECUTE → OBSERVE → DECIDE)
*"Tests should discover reality, not assume it."*

---

## 📝 Changelog

### Version 1.0 (Initial Release)
- ✅ 34 tests migrated to POM architecture
- ✅ 100% parity with original test suite
- ✅ DISCOVER philosophy implemented
- ✅ Comprehensive standards coverage (OWASP, ISO, WCAG, CWE, CVSS)
- ✅ Real exploitation attempts (no mocking)
- ✅ Single ProductPage POM (623 lines)
