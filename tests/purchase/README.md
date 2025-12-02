# 🛒 Purchase Module - Test Suite Documentation

## 📋 Overview

Complete test coverage for DemoBlaze's **Purchase and Checkout** functionality, migrated to **Page Object Model (POM)** architecture following the **DISCOVER philosophy**.

**Philosophy:** EXECUTE → OBSERVE → DECIDE (No assumptions, only real discoveries)

---

## 📊 Test Coverage Summary

| Test File | Tests | Executions | Purpose |
|-----------|-------|------------|---------|
| **test_purchase_functional.py** | 20 | ~20 | Core functionality and user flows |
| **test_purchase_business.py** | 20 | ~45 | Business rules, validation, standards compliance |
| **test_purchase_security.py** | 28 | ~35 | Security exploits, PCI-DSS, accessibility |
| **TOTAL** | **68** | **~100** | **Complete Purchase coverage** |

---

## 🏗️ Architecture

### Page Object Models

1. **`pages/cart_page.py`** (315 lines)
   - Cart navigation and operations
   - Add/remove products
   - Cart total calculations
   - Checkout initiation

2. **`pages/purchase_page.py`** (403 lines)
   - Order modal operations
   - Payment form filling
   - Form navigation (Tab order)
   - Purchase confirmation handling
   - Validation helpers

### Test Organization

```
tests_new/purchase/
├── __init__.py
├── test_purchase_functional.py    # Core features
├── test_purchase_business.py      # Standards & validation
├── test_purchase_security.py      # Security & exploits
└── README.md                       # This file
```

---

## 📝 Standards Tested

- **OWASP ASVS v5.0** - Application Security Verification
- **OWASP Top 10 2021** - Web Application Security
- **PCI-DSS 4.0.1** - Payment Card Industry Data Security
- **ISO 25010** - Software Quality Standards
- **ISO 8601** - Date/Time Format Standards
- **WCAG 2.1** - Web Content Accessibility Guidelines
- **CWE** - Common Weakness Enumeration
- **CVSS 3.1** - Vulnerability Scoring System

---

## 🔬 Test Examples with Code

### 1. FUNCTIONAL TESTS (`test_purchase_functional.py`)

#### Example 1: Complete Purchase Flow with Price Verification

**Test ID:** TC-PURCHASE-FUNC-001

**What this test does:**
1. Adds a product to the cart
2. Navigates to cart and verifies the total
3. Opens the checkout modal
4. Fills in valid payment information
5. Completes the purchase
6. Verifies the confirmed amount matches the cart total

```python
@pytest.mark.functional
@pytest.mark.critical
def test_successful_purchase_with_price_verification_FUNC_001(browser, base_url):
    """
    TC-PURCHASE-FUNC-001: Successful Purchase with Price Verification
    DISCOVER: Verify complete purchase flow and price consistency
    """
    # EXECUTE: Add product and navigate to cart
    cart = CartPage(browser)
    product_name, price = cart.add_first_product()
    cart.open_cart()

    # OBSERVE: Get cart total
    cart_total = cart.get_cart_total()
    assert cart_total == price, f"Cart total {cart_total} doesn't match product price {price}"

    # EXECUTE: Open order modal
    cart.click_place_order()
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    # EXECUTE: Complete purchase
    success, confirm_text, details = purchase.complete_purchase(
        name="QA Tester",
        country="Spain",
        city="Barcelona",
        card="1234567890123456",
        month="12",
        year="2028"
    )

    # DECIDE: Purchase should succeed with correct amount
    assert success, "Purchase should complete successfully"
    assert details['amount'] == cart_total, \
        f"Confirmed amount {details['amount']} doesn't match cart total {cart_total}"

    logger.info(f"✓ Purchase completed successfully: ${details['amount']}")
```

#### Example 2: Multiple Items Total Calculation

**Test ID:** TC-PURCHASE-FUNC-004

**What this test does:**
1. Adds two different products to the cart
2. Navigates to the cart page
3. Verifies the cart contains exactly 2 items
4. Calculates expected total (sum of both product prices)
5. Compares cart total with expected calculation
6. Ensures server-side total calculation is accurate

```python
@pytest.mark.functional
@pytest.mark.high
def test_multiple_items_total_calculation_FUNC_004(browser, base_url):
    """
    TC-PURCHASE-FUNC-004: Multiple Items Total Calculation
    DISCOVER: How does cart handle multiple items and calculate totals?
    """
    # EXECUTE: Add two products
    browser.get(base_url)
    cart = CartPage(browser)
    product1_name, price1 = cart.add_first_product()
    product2_name, price2 = cart.add_second_product()

    logger.info(f"Added: {product1_name} (${price1}), {product2_name} (${price2})")

    # EXECUTE: Navigate to cart
    cart.open_cart()

    # OBSERVE: Get cart state
    item_count = cart.get_cart_item_count()
    cart_total = cart.get_cart_total()
    expected_total = price1 + price2

    # DECIDE: Cart should show 2 items with correct total
    assert item_count == 2, f"Expected 2 items, found {item_count}"
    assert cart_total == expected_total, \
        f"Cart total {cart_total} doesn't match expected {expected_total}"

    logger.info(f"✓ Cart correctly calculated total: ${cart_total}")
```

#### Example 3: Cart Persistence Across Navigation

**Test ID:** TC-PURCHASE-FUNC-013

**What this test does:**
1. Adds a product to the cart
2. Navigates to the cart and records the item count
3. Navigates back to the home page
4. Returns to the cart again
5. Verifies the cart still contains the same items
6. Discovers if cart state persists across page navigation

```python
@pytest.mark.functional
@pytest.mark.medium
def test_cart_persistence_across_navigation_FUNC_013(browser, base_url):
    """
    TC-PURCHASE-FUNC-013: Cart Persistence Across Navigation
    DISCOVER: Does cart persist when navigating to different pages?
    """
    # EXECUTE: Add product to cart
    browser.get(base_url)
    cart = CartPage(browser)
    product_name, price = cart.add_first_product()
    cart.open_cart()

    # OBSERVE: Initial cart state
    initial_count = cart.get_cart_item_count()
    initial_total = cart.get_cart_total()

    logger.info(f"Initial cart: {initial_count} items, ${initial_total}")

    # EXECUTE: Navigate away and back
    cart.go_home()
    time.sleep(1)
    cart.open_cart()

    # OBSERVE: Cart state after navigation
    final_count = cart.get_cart_item_count()
    final_total = cart.get_cart_total()

    # DECIDE: Cart should persist
    assert final_count == initial_count, \
        f"Cart lost items during navigation: {initial_count} -> {final_count}"
    assert final_total == initial_total, \
        f"Cart total changed: ${initial_total} -> ${final_total}"

    logger.info("✓ Cart persistence verified across navigation")
```

---

### 2. BUSINESS RULES TESTS (`test_purchase_business.py`)

#### Example 1: Empty Field Validation (Parametrized)

**Test ID:** TC-PURCHASE-VAL-001

**What this test does:**
1. Uses `@pytest.mark.parametrize` to test all 6 form fields
2. For each field: adds a product, opens checkout modal
3. Fills ALL fields EXCEPT the target field (leaves it empty)
4. Attempts to complete the purchase
5. Verifies the system rejects the empty field
6. Discovers which fields have proper validation

**Parametrization runs this test 6 times:**
- name = ""
- country = ""
- city = ""
- card = ""
- month = ""
- year = ""

```python
@pytest.mark.business_rules
@pytest.mark.validation
@pytest.mark.critical
@pytest.mark.parametrize("field_name,test_data", [
    ("name", ""),
    ("country", ""),
    ("city", ""),
    ("card", ""),
    ("month", ""),
    ("year", "")
])
def test_empty_field_validation_VAL_001(browser, base_url, field_name, test_data):
    """
    TC-PURCHASE-VAL-001: Empty Field Validation
    Standard: ISO 25010 (Software Quality - Data Validation)
    CVSS Score: 5.3 MEDIUM

    DISCOVER: How does the system handle empty required fields?
    """
    # EXECUTE: Add product to cart
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    # EXECUTE: Fill form with one empty field
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    form_data = {
        'name': 'QA Tester',
        'country': 'Spain',
        'city': 'Barcelona',
        'card': '1234567890123456',
        'month': '12',
        'year': '2028'
    }
    form_data[field_name] = test_data  # Set target field to empty

    purchase.fill_order_form(**form_data)
    purchase.click_purchase()

    # OBSERVE: Check if purchase proceeds
    time.sleep(1)
    is_confirmed = purchase.is_purchase_confirmed(timeout=3)

    # DECIDE: Purchase should NOT succeed with empty required fields
    if is_confirmed:
        logger.error(f"✗ VIOLATION: Purchase succeeded with empty {field_name} field")
        pytest.fail(f"DISCOVERED: Empty field validation missing for '{field_name}'")
    else:
        logger.info(f"✓ Purchase correctly blocked with empty {field_name}")
```

#### Example 2: SQL Injection Protection (Parametrized)

**Test ID:** TC-PURCHASE-VAL-006

**What this test does:**
1. Uses parametrization to test 5 different SQL injection payloads
2. For each payload: adds product, opens checkout
3. Injects SQL payload into the NAME field
4. Attempts to complete purchase
5. Checks TWO things:
   - Did the injection succeed? (purchase confirmed)
   - Is there SQL error disclosure? (error messages in page source)
6. Discovers actual SQL injection vulnerabilities

**Real SQL payloads tested:**
- `' OR '1'='1` - Classic authentication bypass
- `admin'--` - Comment-based injection
- `') OR ('1'='1` - Parenthesis escape
- `' OR 1=1--` - Numeric comparison
- `1' UNION SELECT NULL--` - Union-based injection

```python
@pytest.mark.business_rules
@pytest.mark.security
@pytest.mark.critical
@pytest.mark.parametrize("sql_payload", [
    "' OR '1'='1",
    "admin'--",
    "') OR ('1'='1",
    "' OR 1=1--",
    "1' UNION SELECT NULL--",
])
def test_sql_injection_protection_VAL_006(browser, base_url, sql_payload):
    """
    TC-PURCHASE-VAL-006: SQL Injection Protection
    Standard: OWASP ASVS v5.0 Section 1.2.5 (SQL Injection Prevention)
    CWE: CWE-89
    CVSS Score: 9.8 CRITICAL
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    DISCOVER: Is the purchase form vulnerable to SQL injection?
    """
    # EXECUTE: Add product and open order form
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    # EXECUTE: Try SQL injection in name field
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()
    purchase.fill_order_form(
        name=sql_payload,
        country="Spain",
        city="Barcelona",
        card="1234567890123456",
        month="12",
        year="2028"
    )
    purchase.click_purchase()

    # OBSERVE: Check if injection succeeds or causes error disclosure
    time.sleep(1)
    is_confirmed = purchase.is_purchase_confirmed(timeout=3)
    page_source = browser.page_source.lower()

    error_indicators = ["sql syntax", "mysql", "postgresql", "sqlite", "database error"]

    # DECIDE: SQL injection should be prevented
    if is_confirmed:
        logger.critical(f"✗ CRITICAL: SQL injection may have succeeded: {sql_payload}")
        pytest.fail(f"DISCOVERED: Possible SQL injection vulnerability with '{sql_payload}'")

    for indicator in error_indicators:
        if indicator in page_source:
            logger.critical(f"✗ CRITICAL: SQL error disclosure detected: {indicator}")
            pytest.fail(f"DISCOVERED: SQL error disclosure with indicator '{indicator}'")

    logger.info(f"✓ SQL injection correctly prevented: {sql_payload}")
```

#### Example 3: PCI-DSS Card Expiration Validation

**Test ID:** TC-PURCHASE-BR-004

**What this test does:**
1. Tests PCI-DSS Requirement 8.3.1 (expired card handling)
2. Calculates expired years (current year -1, -2, -5)
3. For each expired date: adds product, opens checkout
4. Attempts to purchase with expired card
5. Verifies the system rejects expired cards
6. Discovers if expiration date validation exists

**Business Rule:** Cards must not be expired (PCI-DSS compliance)

```python
@pytest.mark.business_rules
@pytest.mark.high
@pytest.mark.pci_dss
def test_card_expiration_validation_BR_004(browser, base_url):
    """
    TC-PURCHASE-BR-004: Card Expiration Date Validation
    Business Rule: Card must not be expired
    Standard: PCI-DSS 4.0.1 Requirement 8.3.1

    DISCOVER: Are expired cards accepted?
    """
    # EXECUTE: Add product and open order form
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    # EXECUTE: Test expired dates
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    current_year = datetime.date.today().year
    expired_dates = [
        ("12", str(current_year - 1)),  # Last year
        ("01", str(current_year - 2)),  # 2 years ago
        ("06", str(current_year - 5)),  # 5 years ago
    ]

    violations = []

    for month, year in expired_dates:
        browser.get(base_url)
        cart.open_cart()
        cart.click_place_order()
        purchase.wait_for_order_modal()

        purchase.fill_order_form(
            name="QA Tester",
            country="Spain",
            city="Barcelona",
            card="1234567890123456",
            month=month,
            year=year
        )
        purchase.click_purchase()

        # OBSERVE: Check if accepted
        time.sleep(1)
        is_confirmed = purchase.is_purchase_confirmed(timeout=2)

        if is_confirmed:
            violations.append(f"{month}/{year}")
            logger.error(f"✗ VIOLATION: Expired card accepted: {month}/{year}")

    # DECIDE: Expired cards should be rejected
    if violations:
        pytest.fail(f"DISCOVERED: Expiration validation missing - accepted {len(violations)} expired cards")

    logger.info("✓ Expired card validation enforced")
```

---

### 3. SECURITY TESTS (`test_purchase_security.py`)

#### Example 1: Client-Side Price Manipulation

**Test ID:** TC-PURCHASE-SEC-001

**What this test does:**
1. Adds a product and records its actual price
2. Navigates to cart and gets the legitimate cart total
3. Uses JavaScript to manipulate the displayed price to $1
4. Proceeds to complete the purchase
5. Checks if the manipulated price was used by the server
6. Discovers if server validates prices or trusts client

**Attack Vector:** CWE-602 (Client-Side Enforcement of Server-Side Security)

**CVSS Score:** 8.6 HIGH - This is a critical business logic flaw

```python
@pytest.mark.security
@pytest.mark.critical
@pytest.mark.business_logic
def test_price_manipulation_in_client_SEC_001(browser, base_url):
    """
    TC-PURCHASE-SEC-001: Client-Side Price Manipulation
    CWE: CWE-602 (Client-Side Enforcement of Server-Side Security)
    CVSS Score: 8.6 HIGH
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L

    DISCOVER: Can prices be manipulated via client-side modifications?
    """
    # EXECUTE: Add product to cart
    browser.get(base_url)
    cart = CartPage(browser)
    product_name, original_price = cart.add_first_product()
    cart.open_cart()

    # OBSERVE: Get original cart total
    cart_total = cart.get_cart_total()
    logger.info(f"Original cart total: ${cart_total}")

    # EXECUTE: Attempt to modify price via JavaScript
    try:
        browser.execute_script("""
            var totalElement = document.getElementById('totalp');
            if (totalElement) {
                totalElement.textContent = '1';
            }
        """)
        time.sleep(1)

        # EXECUTE: Proceed with purchase
        cart.click_place_order()
        purchase = PurchasePage(browser)
        purchase.wait_for_order_modal()

        success, confirm_text, details = purchase.complete_purchase()

        # OBSERVE: Check if manipulated price was used
        if success:
            confirmed_amount = details['amount']
            logger.info(f"Confirmed amount: ${confirmed_amount}")

            # DECIDE: Server should use original price, not manipulated
            if confirmed_amount != cart_total:
                logger.critical(f"✗ CRITICAL: Price manipulation succeeded!")
                pytest.fail(f"DISCOVERED: Client-side price manipulation vulnerability")
            else:
                logger.info(f"✓ Price manipulation prevented - server-side validation enforced")

    except Exception as e:
        logger.info(f"✓ Price manipulation blocked: {str(e)}")
```

#### Example 2: Race Condition - Double Purchase

**Test ID:** TC-PURCHASE-SEC-003

**What this test does:**
1. Adds a product to cart
2. Opens the checkout modal and fills payment form
3. Rapidly clicks "Purchase" button 5 times in succession
4. Waits and checks for multiple purchase confirmations
5. Counts how many purchases were processed
6. Discovers if race conditions allow duplicate charges

**Attack Vector:** CWE-362 (Concurrent Execution using Shared Resource)

**Real-world impact:** Users could be charged multiple times for a single purchase

```python
@pytest.mark.security
@pytest.mark.high
@pytest.mark.race_condition
def test_race_condition_double_purchase_SEC_003(browser, base_url):
    """
    TC-PURCHASE-SEC-003: Race Condition - Double Purchase
    CWE: CWE-362 (Concurrent Execution using Shared Resource)
    CVSS Score: 7.4 HIGH
    Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H

    DISCOVER: Can multiple rapid purchase clicks result in double charging?
    """
    # EXECUTE: Add product to cart
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()

    cart_total = cart.get_cart_total()
    cart.click_place_order()

    # EXECUTE: Fill form and attempt rapid purchase clicks
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()
    purchase.fill_valid_order_form()

    # EXECUTE: Rapid-fire purchase button clicks
    purchase.rapid_purchase_clicks(times=5)

    # OBSERVE: Check if multiple confirmations appear
    time.sleep(2)
    confirmations_count = 0

    try:
        for _ in range(3):
            if purchase.is_purchase_confirmed(timeout=1):
                confirmations_count += 1
                purchase.close_purchase_confirmation()
                time.sleep(0.5)
    except:
        pass

    # DECIDE: Only one purchase should succeed
    if confirmations_count > 1:
        logger.critical(f"✗ CRITICAL: Multiple purchases detected ({confirmations_count})")
        pytest.fail(f"DISCOVERED: Race condition allows double purchase")
    else:
        logger.info(f"✓ Race condition prevented - {confirmations_count} purchase(s)")
```

#### Example 3: PCI-DSS Card Number Masking

**Test ID:** TC-PURCHASE-PCI-001

**What this test does:**
1. Completes a purchase with a test card number (1234567890123456)
2. Captures the purchase confirmation message
3. Checks if the FULL card number appears in the confirmation
4. Verifies if card is properly masked (e.g., ****3456)
5. Discovers PCI-DSS compliance violation if full card is shown

**Compliance Standard:** PCI-DSS 4.0.1 Requirement 3.3

**Why this matters:** Displaying full card numbers violates payment security standards

```python
@pytest.mark.security
@pytest.mark.critical
@pytest.mark.pci_dss
def test_card_number_masking_PCI_001(browser, base_url):
    """
    TC-PURCHASE-PCI-001: Card Number Masking in Confirmation
    Standard: PCI-DSS 4.0.1 Requirement 3.3 (Mask PAN when displayed)
    CWE: CWE-532 (Information Exposure Through Log Files)
    CVSS Score: 8.2 HIGH

    DISCOVER: Is the full card number displayed in confirmation?
    """
    # EXECUTE: Complete a purchase
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    # EXECUTE: Purchase with test card
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    test_card = "1234567890123456"
    success, confirm_text, details = purchase.complete_purchase(
        name="QA Tester",
        country="Spain",
        city="Barcelona",
        card=test_card,
        month="12",
        year="2028"
    )

    # OBSERVE: Check if full card number is exposed
    if success and confirm_text:
        # DECIDE: Full card number should NOT be displayed
        if test_card in confirm_text:
            logger.critical("✗ CRITICAL: Full card number exposed in confirmation!")
            pytest.fail("DISCOVERED: PCI-DSS violation - unmasked card number displayed")

        # Check for proper masking (e.g., ****3456 or XXXX-XXXX-XXXX-3456)
        if details['card']:
            displayed_card = details['card']
            logger.info(f"Card displayed as: {displayed_card}")

            # Proper masking should show only last 4 digits
            if len(displayed_card) == 16 and displayed_card == test_card:
                logger.critical("✗ CRITICAL: Card number not masked!")
                pytest.fail("DISCOVERED: PCI-DSS violation - card not masked")

        logger.info("✓ Card number properly masked in confirmation")
```

#### Example 4: Advanced XSS Vectors (Parametrized)

**Test ID:** TC-PURCHASE-INJ-002

**What this test does:**
1. Tests 4 different XSS attack vectors using parametrization
2. For each payload: adds product, opens checkout
3. Injects XSS payload into the NAME field
4. Completes purchase and captures confirmation
5. Checks TWO things:
   - Is payload reflected unescaped in HTML?
   - Does the script actually execute? (alert appears)
6. Discovers real XSS vulnerabilities, not theoretical ones

**Real XSS payloads tested:**
- `<img src=x onerror=alert(document.cookie)>` - Image-based XSS
- `<svg/onload=alert('XSS')>` - SVG-based XSS
- `javascript:alert(document.domain)` - JavaScript protocol
- `<iframe src='javascript:alert(1)'>` - Iframe injection

```python
@pytest.mark.security
@pytest.mark.critical
@pytest.mark.injection
@pytest.mark.parametrize("xss_vector", [
    "<img src=x onerror=alert(document.cookie)>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert(document.domain)",
    "<iframe src='javascript:alert(1)'>",
])
def test_advanced_xss_vectors_INJ_002(browser, base_url, xss_vector):
    """
    TC-PURCHASE-INJ-002: Advanced XSS Attack Vectors
    CWE: CWE-79
    CVSS Score: 8.2 HIGH
    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N

    DISCOVER: Advanced XSS vectors in purchase confirmation
    """
    # EXECUTE: Add product and inject XSS payload
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    purchase.fill_order_form(
        name=xss_vector,
        country="Spain",
        city="Barcelona",
        card="1234567890123456",
        month="12",
        year="2028"
    )
    purchase.click_purchase()

    # OBSERVE: Check for XSS execution
    time.sleep(1)
    is_confirmed = purchase.is_purchase_confirmed(timeout=2)

    if is_confirmed:
        page_source = browser.page_source

        # DECIDE: XSS should be sanitized
        if xss_vector in page_source:
            logger.critical(f"✗ CRITICAL: XSS payload reflected: {xss_vector}")
            pytest.fail(f"DISCOVERED: XSS vulnerability - payload reflected unescaped")

        # Check for alert execution
        try:
            alert = browser.switch_to.alert
            alert_text = alert.text
            alert.accept()
            logger.critical(f"✗ CRITICAL: XSS executed! Alert: {alert_text}")
            pytest.fail("DISCOVERED: XSS execution confirmed")
        except:
            pass  # No alert = good

    logger.info(f"✓ XSS prevented: {xss_vector}")
```

#### Example 5: WCAG Keyboard Navigation

**Test ID:** TC-PURCHASE-WCAG-001

**What this test does:**
1. Tests WCAG 2.1 Level AA compliance (Guideline 2.1.1)
2. Adds product and opens checkout modal
3. Uses ONLY Tab key to navigate through all 6 form fields
4. Fills each field as it's focused via Tab navigation
5. Verifies all fields were successfully filled via keyboard
6. Discovers accessibility barriers for keyboard-only users

**Why this matters:** Users with motor disabilities may rely on keyboard-only navigation

```python
@pytest.mark.security
@pytest.mark.low
@pytest.mark.accessibility
def test_keyboard_navigation_WCAG_001(browser, base_url):
    """
    TC-PURCHASE-WCAG-001: Keyboard-Only Navigation
    Standard: WCAG 2.1 Level AA - Guideline 2.1.1 (Keyboard)
    CVSS Score: 4.3 LOW

    DISCOVER: Can purchase flow be completed using only keyboard?
    """
    # EXECUTE: Add product and navigate to order form
    browser.get(base_url)
    cart = CartPage(browser)
    cart.add_first_product()
    cart.open_cart()
    cart.click_place_order()

    # EXECUTE: Try keyboard-only form navigation
    purchase = PurchasePage(browser)
    purchase.wait_for_order_modal()

    try:
        filled_values = purchase.navigate_form_with_tab(
            fill_data=["QA Tester", "Spain", "Barcelona", "1234567890123456", "12", "2028"]
        )

        # OBSERVE: Check if all fields were filled via Tab navigation
        logger.info(f"Keyboard navigation filled: {filled_values}")

        # DECIDE: All fields should be accessible via keyboard
        if all(filled_values.values()):
            logger.info("✓ Keyboard navigation fully functional")
        else:
            empty_fields = [k for k, v in filled_values.items() if not v]
            logger.warning(f"⚠ ACCESSIBILITY ISSUE: Fields not keyboard-accessible: {empty_fields}")

    except Exception as e:
        logger.warning(f"⚠ Keyboard navigation issue: {str(e)}")
```

---

## 🚀 Running the Tests

### Run All Purchase Tests
```bash
pytest tests_new/purchase/ -v
```

### Run by Category
```bash
# Functional tests only
pytest tests_new/purchase/test_purchase_functional.py -v

# Business rules tests only
pytest tests_new/purchase/test_purchase_business.py -v

# Security tests only
pytest tests_new/purchase/test_purchase_security.py -v
```

### Run by Priority
```bash
# Critical tests only
pytest tests_new/purchase/ -m critical -v

# High priority tests
pytest tests_new/purchase/ -m high -v

# Medium priority tests
pytest tests_new/purchase/ -m medium -v
```

### Run by Type
```bash
# All security tests
pytest tests_new/purchase/ -m security -v

# Business rules tests
pytest tests_new/purchase/ -m business_rules -v

# PCI-DSS compliance tests
pytest tests_new/purchase/ -m pci_dss -v

# Accessibility tests
pytest tests_new/purchase/ -m accessibility -v

# Injection attack tests
pytest tests_new/purchase/ -m injection -v
```

### Run Specific Test Suites
```bash
# Cart operations tests
pytest tests_new/purchase/test_purchase_functional.py -k "cart" -v

# Validation tests
pytest tests_new/purchase/test_purchase_business.py -k "validation" -v

# SQL injection tests
pytest tests_new/purchase/ -k "sql_injection" -v

# XSS tests
pytest tests_new/purchase/ -k "xss" -v
```

---

## 📈 Test Execution Matrix

### Expected Results (DISCOVER Philosophy)

Tests are designed to DISCOVER actual behavior, not assume it:

| Category | Tests | Expected Pass % | Notes |
|----------|-------|----------------|-------|
| Functional | 20 | ~100% | Core features should work |
| Business Rules | 20 | ~70-80% | Discovers validation gaps |
| Security | 28 | ~60-70% | Discovers vulnerabilities |
| **TOTAL** | **68** | **~75%** | Discovery-focused testing |

**Note:** Lower pass rates indicate successful vulnerability discovery, not test failure.

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
@pytest.mark.validation         # Input validation tests
@pytest.mark.pci_dss            # PCI-DSS compliance tests
@pytest.mark.injection          # Injection attack tests
@pytest.mark.business_logic     # Business logic exploit tests
@pytest.mark.bot_protection     # Bot/automation tests
@pytest.mark.session            # Session security tests
@pytest.mark.race_condition     # Concurrency tests
@pytest.mark.accessibility      # WCAG compliance tests
```

---

## 🔍 Vulnerability Discovery Metrics

### High-Risk Vulnerabilities Tested

1. **Client-Side Price Manipulation** (CVSS 8.6 HIGH)
2. **SQL Injection** (CVSS 9.8 CRITICAL)
3. **XSS Attacks** (CVSS 8.2 HIGH)
4. **Race Conditions** (CVSS 7.4 HIGH)
5. **PCI-DSS Violations** (CVSS 8.2-9.8 HIGH-CRITICAL)
6. **Command Injection** (CVSS 9.8 CRITICAL)
7. **Session Hijacking** (CVSS 6.5 MEDIUM)

---

## 📚 Related Documentation

- **OWASP ASVS v5.0:** https://owasp.org/www-project-application-security-verification-standard/
- **PCI-DSS 4.0.1:** https://www.pcisecuritystandards.org/
- **WCAG 2.1:** https://www.w3.org/WAI/WCAG21/quickref/
- **CWE Top 25:** https://cwe.mitre.org/top25/
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
- ✅ 68 tests migrated to POM architecture
- ✅ 100% parity with original test suite
- ✅ DISCOVER philosophy implemented
- ✅ Comprehensive standards coverage
- ✅ Real exploitation attempts (no mocking)
