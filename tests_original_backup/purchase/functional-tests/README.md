# Test Suite: Purchase & Cart Functionality

**Module:** `test_purchase.py`
**Author:** Arévalo, Marc
**Application Under Test:** DemoBlaze (https://www.demoblaze.com/)
**Current Version:** 4.0

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Test Cases Summary](#test-cases-summary)
4. [Code Architecture](#architecture)
5. [Configuration & Locators](#configuration)
6. [Fixtures](#fixtures)
7. [Helper Functions](#helpers)
8. [Test Cases Details](#test-details)
9. [Execution Guide](#execution)
10. [Expected Results](#results)
11. [Troubleshooting](#troubleshooting)
12. [Related Bugs](#bugs)
13. [Best Practices](#practices)
14. [Version History](#version-history)

---

<a name="overview"></a>
## 1. Overview

### Purpose

This test suite validates DemoBlaze's purchase and cart functionality with focus on:
- Complete purchase workflow (add to cart → checkout → payment → confirmation)
- Cart operations (add, delete, price calculations)
- Order form validation (required fields, data types)
- Business rules validation (empty cart prevention, input constraints)
- Security testing (SQL injection, XSS, malicious inputs)
- User scenarios (guest vs logged-in purchases)

### Scope

**In Scope:**
- Product addition to cart
- Cart total calculations (single/multiple items)
- Item deletion from cart
- Price verification throughout flow
- Order form validation and robustness
- Complete purchase with confirmation
- Guest and authenticated user purchases
- Empty cart handling
- Order modal interactions
- Security validation (SQL injection, XSS, special characters, null bytes)
- Accessibility features (keyboard navigation, screen readers, color contrast)
- Performance testing (concurrent operations, load capacity)

**Out of Scope:**
- Product catalog browsing
- Product search/filtering
- Quantity selection (DemoBlaze limitation)
- Coupon/discount codes
- Multiple shipping addresses
- Real payment gateway integration

---

<a name="quick-start"></a>
## 2. Quick Start

### Prerequisites

```bash
pip install -r requirements.txt
```

**Required packages:**
- pytest
- selenium
- webdriver-manager
- pytest-html

### Run All Tests

```bash
pytest test_purchase.py -v
```

### Run Specific Categories

```bash
# Functional tests only
pytest test_purchase.py -m functional -v

# Business rules tests
pytest test_purchase.py -m business_rules -v

# Parametrized validation tests
pytest test_purchase.py -k "validation" -v
```

### Generate HTML Report

```bash
pytest test_purchase.py --html=report.html --self-contained-html
```

---

<a name="test-cases-summary"></a>
## 3. Test Cases Summary

### Test Distribution

| Category | Count | Type | Status |
|----------|-------|------|--------|
| Functional - Purchase Flow | 11 | Positive | ✅ Pass |
| Functional - Cart Operations | 10 | Positive | ✅ Pass |
| Functional - UI/Navigation | 8 | Functional | ✅ Pass |
| Functional - Misc | 3 | Edge Cases | ✅ Pass |
| Business Rules | 10 | Validation | ⚠️ Expected Fail |
| Parametrized Validation | 12 scenarios | Security/Robustness | ⚠️ Mixed |
| **TOTAL TESTS** | **40 functions** | **52 test runs** | **Mixed** |

### Critical Test Cases

**Must Pass:**
- TC-PURCH-001: Successful purchase with price verification
- TC-PURCH-002: Multiple items total calculation
- TC-PURCH-003: Delete item from cart
- TC-PURCH-017: Cart empty after purchase

**Expected to Fail (Business Rules):**
- TC-PURCH-BR-001: Empty cart purchase prevention
- TC-PURCH-BR-002: Credit card format validation
- TC-PURCH-BR-003: Card length validation
- TC-PURCH-BR-004: Expired card rejection
- TC-PURCH-BR-006: SQL injection protection
- TC-PURCH-BR-007: XSS protection

---

<a name="architecture"></a>
## 4. Code Architecture

### File Structure

```
project_root/
├── tests/
│   └── purchase/
│       ├── test_purchase.py (functional tests)
│       ├── test_purchase_security.py (exploitation tests)
│       ├── README_purchase.md (this file)
│       └── README_security.md (security tests doc)
├── conftest.py
└── requirements.txt
```

### Code Organization

**test_purchase.py structure:**

1. **Module Documentation** - Purpose and standards
2. **Imports** - Required libraries
3. **Configuration** - URLs, timeouts, test data
4. **Locators** - Page element identifiers
5. **Helper Functions** - Reusable utilities
6. **Fixtures** - Test setup/teardown
7. **Test Functions** - Actual test cases

### Standards Validated

- **OWASP Top 10 2021** - SQL Injection (A03), XSS (A03)
- **PCI-DSS 4.0.1** - Card validation, format requirements
- **ISO 25010** - Functional suitability, usability
- **WCAG 2.1** - Keyboard navigation, screen readers

---

<a name="configuration"></a>
## 5. Configuration & Locators

### Base Configuration

```python
BASE_URL = "https://www.demoblaze.com/"
TIMEOUT = 10
EXPLICIT_WAIT = 5
```

### Test Credentials

```python
TEST_USERNAME = "testuser_qa_2024"
TEST_PASSWORD = "SecurePass123!"
```

Used for authenticated user purchase tests.

### Locator Strategy

Locators organized by functionality:

**Product Locators:**
- `FIRST_PRODUCT_LINK` - First product on homepage
- `SECOND_PRODUCT_LINK` - Second product
- `PRODUCT_PRICE_HEADER` - Price display on detail page
- `ADD_TO_CART_BUTTON` - Add to cart action

**Navigation:**
- `HOME_NAV_LINK` - Return to homepage
- `CART_NAV_LINK` - Navigate to cart
- `CONTACT_NAV_LINK` - Contact form
- `ABOUT_US_NAV_LINK` - About us modal

**Cart Page:**
- `PLACE_ORDER_BUTTON` - Initiate checkout
- `DELETE_ITEM_LINK` - Remove cart item
- `CART_TOTAL_PRICE` - Total price display
- `FIRST_ITEM_IN_CART_NAME` - First item name

**Order Modal:**
- `ORDER_NAME_FIELD` - Customer name input
- `ORDER_COUNTRY_FIELD` - Country input
- `ORDER_CITY_FIELD` - City input
- `ORDER_CARD_FIELD` - Credit card number
- `ORDER_MONTH_FIELD` - Expiration month
- `ORDER_YEAR_FIELD` - Expiration year
- `PURCHASE_BUTTON` - Submit purchase
- `CLOSE_ORDER_MODAL_BUTTON` - Cancel checkout

**Confirmation:**
- `PURCHASE_CONFIRM_MODAL` - Success modal
- `PURCHASE_CONFIRM_MSG` - Thank you message
- `CONFIRM_OK_BUTTON` - Close confirmation

**Contact Form:**
- `CONTACT_EMAIL_FIELD` - Email input
- `CONTACT_NAME_FIELD` - Name input
- `CONTACT_MESSAGE_FIELD` - Message textarea
- `CONTACT_SEND_BUTTON` - Submit message

---

<a name="fixtures"></a>
## 6. Fixtures

### `browser` (from conftest.py)

**Scope:** Function-level
**Purpose:** Provides browser instance with cross-browser support

**Configuration:**
- Chrome (default)
- Firefox
- Edge
- Headless options

**Usage:**
```python
def test_example(browser):
    browser.get(BASE_URL)
```

### `cart_page`

**Purpose:** Navigate to cart with one product already added

**Flow:**
1. Navigate to homepage
2. Add first product to cart
3. Navigate to cart page
4. Wait for "Place Order" button
5. Return browser

**Dependencies:** `browser` fixture

**Usage:**
```python
def test_delete_item(cart_page):
    cart_page.find_element(*DELETE_ITEM_LINK).click()
```

**Why useful:**
- Many tests start with item in cart
- Eliminates repetitive setup
- Ensures consistent state

### `order_modal_page`

**Purpose:** Open order form with cart ready

**Flow:**
1. Use `cart_page` fixture
2. Click "Place Order"
3. Wait for form to appear
4. Return browser

**Dependencies:** `cart_page` fixture (composition)

**Usage:**
```python
def test_purchase(order_modal_page):
    fill_order_form(order_modal_page, ...)
    order_modal_page.find_element(*PURCHASE_BUTTON).click()
```

**Why useful:**
- Skip navigation steps
- Test focuses on purchase logic
- Consistent starting point

---

<a name="helpers"></a>
## 7. Helper Functions

### `wait_for_alert_and_get_text(browser, timeout=5)`

**Purpose:** Handle JavaScript alerts gracefully

**Returns:** Alert text or None

**Usage:**
```python
alert_text = wait_for_alert_and_get_text(browser)
if alert_text:
    assert alert_text == "Product added."
```

**Why needed:**
- DemoBlaze uses alerts for feedback
- Alerts must be accepted to continue
- Centralized error handling

---

### `parse_price(price_str)`

**Purpose:** Extract numeric price from string

**Examples:**
```python
parse_price("$790")                 # Returns 790
parse_price("790 *includes tax")    # Returns 790
parse_price("Amount: 790 USD")      # Returns 790
```

**Implementation:**
```python
match = re.search(r'\d+', price_str)
return int(match.group(0)) if match else 0
```

**Why needed:**
- Prices displayed in various formats
- Need consistent numeric comparison
- Single source of truth for parsing

---

### `add_product_to_cart(browser, product_locator)`

**Purpose:** Complete product addition flow and return price

**Flow:**
1. Click product link
2. Capture product price
3. Click "Add to cart"
4. Accept confirmation alert
5. Return to homepage
6. Return price (integer)

**Returns:** Product price as integer

**Usage:**
```python
price1 = add_product_to_cart(browser, FIRST_PRODUCT_LINK)
price2 = add_product_to_cart(browser, SECOND_PRODUCT_LINK)
expected_total = price1 + price2
```

**Why returns price:**
- Tests need price for assertions
- Capture at time of adding
- Avoid re-reading from cart

---

### `fill_order_form(browser, name, country, city, card, month, year)`

**Purpose:** Fill all order form fields

**Parameters:** All optional (default to empty strings)

**Usage:**
```python
fill_order_form(browser,
    name="John Doe",
    country="USA",
    city="NYC",
    card="4111111111111111",
    month="12",
    year="2025"
)
```

**Why needed:**
- Order form has 6 fields
- Without helper: 6 lines per test
- With helper: 1 line per test
- Consistent field population

---

### `perform_login(browser, username, password)`

**Purpose:** Login helper for authenticated tests

**Flow:**
1. Click login button
2. Wait for modal
3. Enter credentials
4. Submit form
5. Wait for welcome message

**Usage:**
```python
perform_login(browser, TEST_USERNAME, TEST_PASSWORD)
```

---

### `wait_for_cart_total_update(browser, timeout=10)`

**Purpose:** Wait for asynchronous cart total calculation

**Why needed:**
- DemoBlaze calculates total via JavaScript
- Total element exists immediately but empty
- Must wait for JavaScript to populate

**Flow:**
1. Wait for total element visibility
2. Wait for text to be non-empty
3. Parse and return total

**Usage:**
```python
browser.find_element(*CART_NAV_LINK).click()
total = wait_for_cart_total_update(browser)
assert total == expected_total
```

**Replaces:**
```python
# Bad (old approach)
time.sleep(2)
total = browser.find_element(*CART_TOTAL_PRICE).text
```

---

<a name="test-details"></a>
## 8. Test Cases Details

### Functional Tests - Purchase Flow

#### TC-PURCH-001: Successful Purchase with Price Verification

**Priority:** Critical
**Type:** End-to-End Positive Test

**Purpose:**
Validates complete purchase flow with price integrity throughout.

**Test Steps:**
1. Add product to cart (fixture)
2. Navigate to cart
3. Click "Place Order"
4. Capture cart total
5. Fill valid order data
6. Submit purchase
7. Verify confirmation modal
8. Extract amount from confirmation
9. Compare with cart total

**Key Assertions:**
```python
assert "Thank you for your purchase!" in confirm_msg.text
assert confirmed_price == expected_price
```

**Why Critical:**
- Validates entire purchase workflow
- Ensures price accuracy
- Financial integrity check
- Customer trust verification

**Expected Result:** ✅ Pass

---

#### TC-PURCH-002: Multiple Items Total Calculation

**Priority:** High
**Type:** Calculation Validation

**Purpose:**
Verify cart correctly sums multiple product prices.

**Test Steps:**
1. Add first product → capture price1
2. Add second product → capture price2
3. Navigate to cart
4. Wait for total calculation
5. Verify total = price1 + price2

**Key Wait:**
```python
total_price = wait_for_cart_total_update(browser)
```

**Why Important:**
- Cart math must be accurate
- Multiple items common scenario
- Asynchronous calculation test

**Expected Result:** ✅ Pass

---

#### TC-PURCH-012: Purchase as Logged-In User

**Priority:** Medium
**Type:** User Scenario Test

**Purpose:**
Verify authenticated users can complete purchase.

**Test Steps:**
1. Login with test credentials
2. Add product to cart
3. Open order modal
4. Verify form NOT auto-filled (DemoBlaze limitation)
5. Fill form manually
6. Complete purchase
7. Verify confirmation

**Key Assertion:**
```python
assert name_field.get_attribute("value") == ""
```

**Documents:** DemoBlaze doesn't store/auto-fill user data

**Expected Result:** ✅ Pass

---

### Functional Tests - Cart Operations

#### TC-PURCH-003: Delete Item from Cart

**Priority:** High
**Type:** Basic Cart Operation

**Test Steps:**
1. Add item to cart (fixture)
2. Verify item visible
3. Click "Delete"
4. Wait for removal
5. Verify item gone

**Key Wait:**
```python
WebDriverWait(browser, TIMEOUT).until(
    EC.invisibility_of_element_located(FIRST_ITEM_IN_CART_NAME)
)
```

**Expected Result:** ✅ Pass

---

#### TC-PURCH-003B: Delete Item and Recalculate Total

**Priority:** High
**Type:** Dynamic Calculation Test

**Purpose:**
Verify cart total recalculates after deletion.

**Test Steps:**
1. Add two products
2. Verify initial total correct
3. Delete first item
4. Wait for DOM update
5. Wait for total recalculation
6. Verify new total = remaining item price

**Why Two Waits:**
```python
# Wait 1: Item removed from DOM
WebDriverWait(browser, TIMEOUT).until(
    EC.invisibility_of_element_located(FIRST_ITEM_IN_CART_NAME)
)

# Wait 2: Total recalculated (async)
total_after = wait_for_cart_total_update(browser)
```

**Expected Result:** ✅ Pass

---

#### TC-PURCH-015: Add Same Product Multiple Times

**Priority:** High
**Type:** Quantity Handling Test

**Purpose:**
Verify system handles duplicate product additions.

**Test Steps:**
1. Add product → get price
2. Add same product again
3. Navigate to cart
4. Count items
5. Verify 2 separate items
6. Verify total = price × 2

**Note:**
DemoBlaze has no quantity selector - creates duplicate cart entries.

**Expected Result:** ✅ Pass

---

#### TC-PURCH-017: Cart Empty After Purchase

**Priority:** High
**Type:** Session Management Test

**Purpose:**
Ensure cart clears after successful purchase.

**Test Steps:**
1. Add product
2. Complete purchase
3. Navigate to cart
4. Verify 0 items

**Why Important:**
- Proper session cleanup
- Prevents confusion
- Clean state for next purchase

**Expected Result:** ✅ Pass

---

#### TC-PURCH-018: Add Many Products to Cart

**Priority:** Medium
**Type:** Boundary Test

**Purpose:**
Validate cart handles multiple items (10 products).

**Test Steps:**
1. Add 10 products
2. Navigate to cart
3. Verify 10 items present
4. Verify total = price × 10

**Why 10 not 100:**
- Realistic boundary
- Reasonable execution time
- Validates bulk operations

**Expected Result:** ✅ Pass

---

#### TC-PURCH-019: Delete All Items From Cart

**Priority:** Medium
**Type:** Bulk Operation Test

**Purpose:**
Verify all items can be removed sequentially.

**Test Steps:**
1. Add 2 products
2. Delete first item
3. Delete second item
4. Verify cart empty

**Expected Result:** ✅ Pass

---

### Functional Tests - UI/Navigation

#### TC-PURCH-013: Order Modal Close Button

**Priority:** Low
**Type:** UI Interaction Test

**Test Steps:**
1. Open order modal
2. Click "Close"
3. Verify modal closes
4. Verify returned to cart

**Expected Result:** ✅ Pass

---

#### TC-PURCH-016: Navigation After Purchase

**Priority:** Medium
**Type:** Navigation Test

**Purpose:**
Verify no unexpected redirects after purchase.

**Test Steps:**
1. Complete purchase
2. Click OK
3. Check current URL
4. Verify still on DemoBlaze

**Expected Result:** ✅ Pass

---

#### TC-PURCH-020: Open/Close Modal Multiple Times

**Priority:** Low
**Type:** Robustness Test

**Purpose:**
Ensure modal can be toggled without issues.

**Test Steps:**
1. Open modal
2. Close modal
3. Repeat 3 times
4. Verify no errors

**Expected Result:** ✅ Pass

---

#### TC-PURCH-021: Access Empty Cart

**Priority:** Medium
**Type:** Edge Case Test

**Purpose:**
Verify empty cart page accessible.

**Test Steps:**
1. Navigate to cart (no products added)
2. Verify page loads
3. Verify "Place Order" visible (Bug #13)

**Documents:** Bug #13 - "Place Order" always visible

**Expected Result:** ✅ Pass

---

#### TC-PURCH-026: Cart Persistence Across Navigation

**Priority:** High
**Type:** Session Management

**Purpose:**
Verify cart contents persist during navigation.

**Test Steps:**
1. Add product
2. Navigate away from cart
3. Browse product details
4. Return to cart
5. Verify item still present
6. Verify price unchanged

**Expected Result:** ✅ Pass

---

#### TC-PURCH-031: Close Modal with ESC Key

**Priority:** Low
**Type:** Keyboard Navigation

**Purpose:**
Test ESC key functionality on modal.

**Test Steps:**
1. Open order modal
2. Press ESC key
3. Observe if modal closes

**Note:**
May not work (DemoBlaze limitation) - test documents behavior.

**Expected Result:** ✅ Pass (documents actual behavior)

---

#### TC-PURCH-032: Browser Refresh on Modal

**Priority:** Medium
**Type:** State Management

**Purpose:**
Verify modal state after browser refresh.

**Test Steps:**
1. Open order modal
2. Browser.refresh()
3. Verify page state

**Expected Result:** ✅ Pass

---

#### TC-PURCH-039: Homepage Pagination

**Priority:** Medium
**Type:** Navigation

**Purpose:**
Verify pagination next/previous buttons work.

**Test Steps:**
1. Capture first product name
2. Click Next
3. Verify different products
4. Click Previous
5. Verify original products

**Expected Result:** ✅ Pass

---

### Functional Tests - Additional Features

#### TC-PURCH-027: Rapid Add to Cart Clicks

**Priority:** Medium
**Type:** Race Condition Test

**Purpose:**
Test rapid clicking "Add to cart".

**Test Steps:**
1. Navigate to product
2. Click "Add to cart" 3 times rapidly
3. Check cart count
4. Verify 1-3 items added

**Expected Result:** ✅ Pass (handles gracefully)

---

#### TC-PURCH-033: Cart After Logout

**Priority:** Medium
**Type:** Session Test

**Purpose:**
Verify cart behavior after logout.

**Test Steps:**
1. Login
2. Add product
3. Logout
4. Check cart

**Documents:** Whether cart persists or clears

**Expected Result:** ✅ Pass (documents behavior)

---

#### TC-PURCH-038: Add Product from Category

**Priority:** Medium
**Type:** Navigation Flow

**Purpose:**
Verify adding product from category page.

**Test Steps:**
1. Click "Laptops" category
2. Select product
3. Add to cart
4. Verify in cart

**Expected Result:** ✅ Pass

---

### Business Rules Tests

#### TC-PURCH-BR-001: Empty Cart Purchase Prevention

**Priority:** CRITICAL
**Standard:** ISO 25010
**Status:** ⚠️ Expected Fail (Bug #13)

**Business Rule:**
E-commerce systems must prevent checkout with empty cart.

**Test Steps:**
1. Navigate to cart (no products)
2. Click "Place Order" (should be blocked)
3. Fill form
4. Submit

**Current Behavior (BUG):**
Purchase completes with $0 total

**Expected Behavior:**
- "Place Order" button disabled
- OR alert: "Cart is empty"

**Impact:**
- Invalid orders
- Wasted resources
- Poor UX

**Expected Result:** ❌ Fail (until fixed)

---

#### TC-PURCH-BR-002: Credit Card Format Validation

**Priority:** CRITICAL
**Standard:** PCI-DSS 3.2.1

**Business Rule:**
Credit cards must be numeric only.

**Test:** Input "ABCD-1234" as card number

**Expected:** Rejection or validation error

**Current:** Accepts any input

**Impact:** PCI-DSS compliance violation

**Expected Result:** ❌ Fail

---

#### TC-PURCH-BR-003: Card Length Validation

**Priority:** CRITICAL
**Standard:** PCI-DSS

**Business Rule:**
Credit cards must be 16 digits.

**Test:** Input "123" as card

**Expected:** "Invalid card length"

**Current:** Accepts

**Expected Result:** ❌ Fail

---

#### TC-PURCH-BR-004: Expired Card Rejection

**Priority:** CRITICAL
**Standard:** PCI-DSS

**Business Rule:**
System must reject expired cards.

**Test:** Input last year as expiration

**Expected:** "Card expired"

**Current:** Accepts

**Expected Result:** ❌ Fail

---

#### TC-PURCH-BR-005: Month Range Validation

**Priority:** HIGH
**Standard:** ISO 8601

**Business Rule:**
Month must be 01-12.

**Test:** Input "13" as month

**Expected:** "Invalid month"

**Current:** Accepts

**Expected Result:** ❌ Fail

---

#### TC-PURCH-BR-006: SQL Injection Protection

**Priority:** CRITICAL
**Standard:** OWASP A03:2021

**Business Rule:**
System must sanitize SQL injection attempts.

**Test:** Input `' OR '1'='1` in name field

**Expected:** Sanitized or blocked

**Current:** Likely vulnerable

**Impact:** Database compromise

**Expected Result:** ❌ Fail

---

#### TC-PURCH-BR-007: XSS Protection

**Priority:** CRITICAL
**Standard:** OWASP A03:2021

**Business Rule:**
System must prevent XSS attacks.

**Test:** Input `<script>alert('XSS')</script>` in city

**Expected:** Sanitized

**Current:** Likely vulnerable

**Impact:** Session hijacking

**Expected Result:** ❌ Fail

---

#### TC-PURCH-BR-008: Name Maximum Length

**Priority:** MEDIUM
**Standard:** OWASP - Input Validation

**Business Rule:**
Name should have reasonable length limit.

**Test:** Input 200 characters

**Expected:** Rejection or truncation

**Current:** Accepts

**Expected Result:** ❌ Fail

---

#### TC-PURCH-BR-009: Whitespace-Only Input

**Priority:** MEDIUM
**Standard:** ISO 25010 - Data Quality

**Business Rule:**
Fields should reject whitespace-only input.

**Test:** Input "     " as name

**Expected:** Rejection

**Current:** Accepts

**Expected Result:** ❌ Fail

---

#### TC-PURCH-BR-010: Contact Form Validation

**Priority:** MEDIUM
**Standard:** ISO 25010 - Usability

**Business Rule:**
Contact form requires all fields.

**Test:** Submit empty contact form

**Expected:** Validation error

**Current:** Likely no validation

**Expected Result:** ❌ Fail

---

### Parametrized Validation Tests

#### TC-PURCH-004 to TC-PURCH-VAL-004 (12 scenarios)

**Test Data Matrix:**

| ID | Name | Card | Month | Year | Expected |
|----|------|------|-------|------|----------|
| 004 | "" | "" | "" | "" | Alert: Fill required |
| 005 | "QA" | "" | "" | "" | Alert: Fill required |
| 006 | "" | "1234" | "" | "" | Alert: Fill required |
| 007 | "Test" | "abc" | "12" | "28" | No validation |
| 008 | "Test" | "1234" | "abc" | "def" | No validation |
| 009 | "a"×200 | "1234" | "12" | "28" | No validation |
| 010 | "' OR 1=1" | "1234" | "12" | "28" | SQL test |
| 011 | "Test" | "1234" | "12" | `<script>` | XSS test |
| VAL-001 | "   " | "1234" | "12" | "28" | Whitespace |
| VAL-002 | "Test" | "1234" | "12" | "2023" | Expired |
| VAL-003 | "Test" | "123" | "12" | "28" | Short card |
| VAL-004 | "Test" | "1234" | "13" | "28" | Invalid month |

**Purpose:**
Test various input scenarios with single parametrized function.

**Expected Results:** Mixed (some alert, some no validation)

---

<a name="execution"></a>
## 9. Execution Guide

### Run All Tests

```bash
pytest test_purchase.py -v
```

### Run by Browser

```bash
pytest test_purchase.py --browser=chrome -v
pytest test_purchase.py --browser=firefox -v
pytest test_purchase.py --browser=edge -v
```

### Run by Category

```bash
# Functional tests only
pytest test_purchase.py -m functional -v

# Business rules tests
pytest test_purchase.py -m business_rules -v

# Security tests
pytest test_purchase.py -m security -v
```

### Run Specific Test

```bash
pytest test_purchase.py::test_successful_purchase_and_price_verification -v
```

### Generate HTML Report

```bash
pytest test_purchase.py --html=report.html --self-contained-html -v
```

### Show Print Statements

```bash
pytest test_purchase.py -s -v
```

### Stop on First Failure

```bash
pytest test_purchase.py -x
```

---

<a name="results"></a>
## 10. Expected Results

### Test Execution Summary

| Category | Tests | Pass | Fail | Expected |
|----------|-------|------|------|----------|
| Functional | 32 | 32 | 0 | ✅ All pass |
| Business Rules | 10 | 0 | 10 | ❌ All fail |
| Parametrized | 12 | ~8 | ~4 | ⚠️ Mixed |
| **TOTAL** | **54** | **40** | **14** | **Mixed** |

### Performance Benchmarks

**Expected execution times:**
- Simple tests: 8-12 seconds
- Multi-item tests: 15-20 seconds
- Parametrized tests: 5-8 seconds per scenario
- **Total suite: ~4-5 minutes**

### Success Criteria

Test suite PASSES if:
- ✅ 32 functional tests pass
- ✅ 10 business rules fail as expected
- ✅ No unexpected failures
- ✅ Execution time < 6 minutes

---

<a name="troubleshooting"></a>
## 11. Troubleshooting

### Cart total shows 0

**Cause:** Reading total before JavaScript calculates

**Solution:**
```python
total = wait_for_cart_total_update(browser)
```

---

### Element not found after deletion

**Cause:** Not waiting for DOM update

**Solution:**
```python
WebDriverWait(browser, TIMEOUT).until(
    EC.invisibility_of_element_located(ELEMENT)
)
```

---

### Test hangs on cart page

**Cause:** JavaScript not loading

**Solution:**
- Check browser console for errors
- Verify network connectivity
- Increase timeout if needed

---

### Alert not found

**Cause:** Alert appeared and disappeared

**Solution:**
```python
alert_text = wait_for_alert_and_get_text(browser, timeout=2)
```

---

### Price mismatch

**Cause:** Async calculation not complete

**Solution:** Use `wait_for_cart_total_update()` everywhere

---

<a name="bugs"></a>
## 12. Related Bugs

### Bug #13: Empty Cart Purchase

**Severity:** HIGH
**Test Case:** TC-PURCH-BR-001
**Status:** OPEN

**Description:**
System allows purchasing with empty cart.

**Current Behavior:**
- "Place Order" always visible
- Can submit empty cart purchase
- Confirmation shows $0 USD

**Expected Behavior:**
- "Place Order" disabled when cart empty
- OR alert: "Your cart is empty"

**Impact:**
- Invalid orders in database
- Wasted resources
- Poor user experience
- Potential abuse

**Recommendation:**
Add client-side validation before allowing checkout.

---

<a name="practices"></a>
## 13. Best Practices Applied

### Code Quality

**DRY Principle:**
- Reusable helper functions
- Fixtures for common setup
- No code duplication

**Clean Code:**
- Minimal comments
- Clear function names
- Logging for feedback
- Descriptive docstrings

### Testing Best Practices

**Explicit Waits:**
- No `time.sleep()` in production
- `wait_for_cart_total_update()` for async
- `EC.invisibility_of_element_located()` for deletions

**Price Verification:**
- Capture at source
- Compare at every step
- Financial accuracy critical

**Parametrization:**
- 12 scenarios in 1 function
- Clean data separation
- Efficient execution

### Selenium Best Practices

**Wait Strategy:**
- Wait for clickable before clicking
- Wait for visibility before reading
- Custom waits for async operations

**Locator Strategy:**
- ID preferred (fastest)
- XPath for dynamic content
- Consistent naming

---

<a name="version-history"></a>
## 14. Version History

### Version 4.0 - November 2025 (Current)

**Major Updates:**
- Merged functional and business rules tests
- Added 10 business rules validation tests
- Removed xfail markers (tests fail naturally to show gaps)
- Added comprehensive security testing
- Added accessibility tests (WCAG 2.1)
- Added performance tests
- Reorganized documentation structure
- Enhanced logging throughout
- Total: 52 test runs (40 functions)

**Files:**
- `test_purchase.py` - Functional + business rules (52 tests)
- `test_purchase_security.py` - Exploitation tests (28 tests)
- `README_purchase.md` - This file
- `README_security.md` - Security tests documentation

---

### Version 3.0 - November 2025

**Changes:**
- Split into two test files (functional vs business rules)
- Added xfail markers for known failures
- Enhanced business rules documentation
- Added standards references (OWASP, PCI-DSS, ISO 25010)
- Total: 53 tests (36 functional + 17 business rules)

---

### Version 2.0 - November 2025

**Changes:**
- Enhanced logging for real-time feedback
- Eliminated `time.sleep()` in favor of explicit waits
- Added `wait_for_cart_total_update()` helper
- Improved wait strategies
- Clean code (removed excessive comments)
- Comprehensive docstrings
- Total: ~41 test runs (28 functions)

---

### Version 1.0 - November 2025

**Initial Release:**
- Basic purchase flow tests
- Cart operations
- Order form validation
- Parametrized security tests
- Total: ~38 test runs

---

**End of Documentation**

**Related Documents:**
- [Security Tests Documentation](README_security.md)
- [Test Plan](../../docs/test-plan.md)
- [Test Summary Report](../../docs/Test_Summary_Report.md)
- [DemoBlaze Test Cases](../../docs/DemoBlaze_Test_Cases.xlsx)
