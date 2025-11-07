# Test Suite: Purchase & Cart Functionality

**Module:** `test_purchase.py`  
**Author:** Arévalo, Marc  
**Created:** November 2025  
**Version:** 2.0 - Enhanced logging, improved waits, clean code  
**Application Under Test:** DemoBlaze (https://www.demoblaze.com/)

---

## Table of Contents

1. [Overview](#overview)
2. [Test Cases Covered](#test-cases)
3. [Related Bugs](#bugs)
4. [Code Architecture](#architecture)
5. [Imports Explanation](#imports)
6. [Configuration Variables](#configuration)
7. [Fixtures Deep Dive](#fixtures)
8. [Helper Functions](#helpers)
9. [Test Functions Breakdown](#tests)
10. [Execution Guide](#execution)
11. [Expected Results](#results)
12. [Troubleshooting](#troubleshooting)
13. [Best Practices Applied](#practices)

---

<a name="overview"></a>
## 1. Overview

### Purpose

This test suite automates comprehensive validation of DemoBlaze's purchase and cart functionality, including:
- Complete purchase flow (add to cart, checkout, payment)
- Cart operations (add, delete, update quantities)
- Price calculations and verification
- Order form validation
- Security testing (SQL injection, XSS in order form)
- Purchase scenarios (guest vs logged-in user)

### Scope

**In Scope:**
- Adding products to cart
- Cart total calculation (single and multiple items)
- Deleting items from cart
- Price verification throughout purchase flow
- Order form validation (required fields)
- Complete purchase flow with confirmation
- Purchase as guest user
- Purchase as logged-in user
- Empty cart validation
- Order modal interaction (open/close)
- SQL Injection attempts in order form
- Cross-Site Scripting (XSS) in order form
- Boundary tests (very long inputs in order form)
- Non-numeric input validation (card, month, year)

**Out of Scope:**
- Product catalog browsing (separate module)
- Product search functionality
- Product filtering/sorting
- Quantity selection (DemoBlaze doesn't implement this)
- Coupon/discount codes
- Multiple shipping addresses
- Payment gateway integration (DemoBlaze uses mock payment)

### Version History

**v2.0 (Current):**
- Enhanced logging for real-time feedback
- Eliminated `time.sleep()` in favor of explicit waits
- Added `wait_for_cart_total_update()` helper
- Improved wait strategies for cart recalculation
- Clean code (no excessive comments)
- Comprehensive docstrings moved to README

**v1.0:**
- Initial release with basic purchase tests

---

<a name="test-cases"></a>
## 2. Test Cases Covered

### Functional Tests - Purchase Flow

#### TC-PURCH-001: Successful Purchase with Price Verification
**Priority:** Critical  
**Type:** Positive Test  

**Test Steps:**
1. Add product to cart (via fixture)
2. Navigate to cart
3. Click "Place Order"
4. Get cart total before purchase
5. Fill order form with valid data
6. Submit purchase
7. Verify confirmation modal appears
8. Extract "Amount" from confirmation
9. Compare with cart total

**Expected Result:**
- Purchase completes successfully
- Confirmation shows "Thank you for your purchase!"
- Amount in confirmation matches cart total exactly
- No price discrepancies

**Why This Test Matters:**
Critical for e-commerce - price integrity throughout checkout ensures:
- Customer trust
- Financial accuracy
- No revenue loss

---

#### TC-PURCH-002: Multiple Items Total Calculation
**Priority:** High  
**Type:** Positive Test  

**Test Steps:**
1. Navigate to home
2. Add first product (capture price1)
3. Return to home
4. Add second product (capture price2)
5. Navigate to cart
6. Wait for total to calculate
7. Verify total = price1 + price2

**Expected Result:**
- Cart total equals sum of individual prices
- Calculation is accurate

**Note:**
DemoBlaze calculates cart total asynchronously via JavaScript. Test uses `wait_for_cart_total_update()` to ensure total is calculated before assertion.

---

### Functional Tests - Cart Operations

#### TC-PURCH-003: Delete Item from Cart
**Priority:** High  
**Type:** Positive Test  

**Test Steps:**
1. Add item to cart (via fixture)
2. Navigate to cart
3. Verify item is visible
4. Click "Delete" link
5. Wait for item removal
6. Verify item no longer in cart

**Expected Result:**
- Item successfully removed from DOM
- NoSuchElementException when trying to find deleted item

---

#### TC-PURCH-003B: Delete Item and Recalculate Total
**Priority:** High  
**Type:** Positive Test  

**Test Steps:**
1. Add two products (price1, price2)
2. Navigate to cart
3. Verify total = price1 + price2
4. Delete first item
5. Wait for total recalculation
6. Verify new total = price2

**Expected Result:**
- Initial total correct
- After deletion, total recalculates correctly
- Shows only remaining item's price

**Why This Test Matters:**
Ensures cart totals dynamically update when items removed - critical for UX and preventing checkout errors.

---

#### TC-PURCH-015: Add Same Product Multiple Times
**Priority:** High  
**Type:** Positive Test  

**Test Steps:**
1. Navigate to home
2. Add first product to cart
3. Return to home
4. Add same product again
5. Navigate to cart
6. Count items in cart
7. Verify total = price × 2

**Expected Result:**
- Product appears twice as separate items (DemoBlaze has no quantity selector)
- Cart shows 2 items
- Total = price × 2

**Note:**
DemoBlaze does NOT implement quantity selection. Adding same product multiple times creates duplicate cart entries.

---

#### TC-PURCH-018: Add Many Products to Cart
**Priority:** Medium  
**Type:** Boundary Test  

**Test Steps:**
1. Add 10 products to cart (same product)
2. Navigate to cart
3. Verify 10 items present
4. Verify total = price × 10

**Expected Result:**
- System handles 10 items without issues
- Total calculates correctly
- No performance degradation

**Why 10 and not 100:**
- Realistic boundary test
- Avoids excessive test execution time
- Still validates cart can handle multiple items

---

#### TC-PURCH-019: Delete All Items From Cart
**Priority:** Medium  
**Type:** Positive Test  

**Test Steps:**
1. Add 2 products
2. Navigate to cart
3. Delete first item
4. Wait for removal
5. Delete second item
6. Verify cart is empty

**Expected Result:**
- Both items deleted successfully
- Cart shows 0 items
- No errors during deletion loop

---

#### TC-PURCH-017: Cart Empty After Successful Purchase
**Priority:** High  
**Type:** Positive Test  

**Test Steps:**
1. Add product to cart (via fixture)
2. Complete purchase successfully
3. Click OK on confirmation
4. Navigate to cart
5. Verify cart is empty

**Expected Result:**
- Cart cleared after successful purchase
- User can start new shopping session
- No orphaned items

**Why This Test Matters:**
Ensures proper session management - prevents confusion and ensures clean state for next purchase.

---

### Functional Tests - User Scenarios

#### TC-PURCH-012: Purchase as Logged-In User
**Priority:** Medium  
**Type:** Positive Test  

**Test Steps:**
1. Login with test credentials
2. Add product to cart
3. Navigate to cart
4. Click "Place Order"
5. Verify order form fields are empty (no auto-fill)
6. Fill form manually
7. Complete purchase
8. Verify confirmation with correct price

**Expected Result:**
- Logged-in user can purchase successfully
- Order form does NOT auto-fill (DemoBlaze limitation)
- Purchase confirmation correct

**Note:**
DemoBlaze does NOT implement user profile data storage. Even when logged in, users must manually fill shipping/payment info. This test verifies this behavior.

---

### UI Interaction Tests

#### TC-PURCH-013: Order Modal Close Button
**Priority:** Low  
**Type:** Functional Test  

**Test Steps:**
1. Add item to cart (via fixture)
2. Click "Place Order"
3. Verify modal opens
4. Click "Close" button
5. Verify modal closes
6. Verify returned to cart page

**Expected Result:**
- Modal closes without errors
- User returns to cart page
- Cart contents preserved

---

#### TC-PURCH-016: Navigation After Purchase
**Priority:** Medium  
**Type:** Positive Test  

**Test Steps:**
1. Complete purchase successfully
2. Click OK on confirmation modal
3. Observe current URL
4. Verify still on DemoBlaze site

**Expected Result:**
- User remains on DemoBlaze
- No redirect to external site
- URL contains BASE_URL

**Note:**
This test verifies basic navigation - actual destination page may vary (home, cart, etc.)

---

#### TC-PURCH-020: Open and Close Order Modal Multiple Times
**Priority:** Low  
**Type:** Robustness Test  

**Test Steps:**
1. Add item to cart (via fixture)
2. Click "Place Order" → modal opens
3. Click "Close" → modal closes
4. Repeat steps 2-3 two more times (3 iterations total)
5. Verify no errors or state issues

**Expected Result:**
- Modal opens/closes reliably each time
- No memory leaks or DOM issues
- Cart contents preserved throughout

**Why This Test Matters:**
Users may open/close modal multiple times while deciding. System must handle this gracefully.

---

#### TC-PURCH-021: Access Cart Without Adding Products
**Priority:** Medium  
**Type:** Edge Case Test  

**Test Steps:**
1. Navigate to home
2. Click cart link (without adding products)
3. Verify cart page loads
4. Verify cart is empty
5. Verify "Place Order" button still visible

**Expected Result:**
- Empty cart accessible
- No errors
- "Place Order" button visible (related to Bug #13)

**Note:**
This test documents that "Place Order" button is always visible, even for empty cart (Bug #13).

---

### Known Vulnerability Tests (xfail)

#### TC-PURCH-014: Purchase with Empty Cart
**Priority:** Critical  
**Type:** Security/UX Test  
**Status:** Expected to fail (Bug #13)

**Test Steps:**
1. Navigate to cart WITHOUT adding products
2. Click "Place Order" (should be disabled but isn't)
3. Fill order form with valid data
4. Submit purchase
5. Observe confirmation appears

**Current Behavior (BUG):**
- System allows purchase with empty cart
- Confirmation shows "Amount: 0 USD"
- No validation prevents this

**Expected Behavior (Post-Fix):**
- "Place Order" button disabled for empty cart
- OR alert: "Your cart is empty"
- Prevent meaningless transactions

**Security/Business Impact:**
- Creates invalid orders in database
- Wastes server resources
- Poor user experience
- Potential for abuse

**Test Status:** Marked as `xfail` until Bug #13 is resolved

---

### Validation Tests - Order Form

#### TC-PURCH-004: Empty Form Validation
**Priority:** High  
**Type:** Negative Test (Parametrized)  

**Test Data:**
All fields empty

**Expected Result:**
- Alert: "Please fill out Name and Creditcard."
- Purchase not submitted

---

#### TC-PURCH-005: Name Only (Missing Card)
**Priority:** High  
**Type:** Negative Test (Parametrized)  

**Test Data:**
- Name: "QA Tester"
- Card: (empty)

**Expected Result:**
- Alert: "Please fill out Name and Creditcard."

---

#### TC-PURCH-006: Card Only (Missing Name)
**Priority:** High  
**Type:** Negative Test (Parametrized)  

**Test Data:**
- Name: (empty)
- Card: "1234567890"

**Expected Result:**
- Alert: "Please fill out Name and Creditcard."

---

### Robustness Tests - Order Form

#### TC-PURCH-007: Non-Numeric Card Number
**Priority:** Medium  
**Type:** Robustness Test (Parametrized)  

**Test Data:**
- Card: "abcdefg"

**Expected Result:**
- System handles gracefully
- Purchase completes or shows appropriate error
- No crash

**Note:**
DemoBlaze does NOT validate card format - accepts any input. This tests system robustness.

---

#### TC-PURCH-008: Non-Numeric Month/Year
**Priority:** Medium  
**Type:** Robustness Test (Parametrized)  

**Test Data:**
- Month: "abc"
- Year: "def"

**Expected Result:**
- System handles without crashing
- Purchase may complete (no validation)

---

#### TC-PURCH-009: Very Long Name (1000 chars)
**Priority:** Medium  
**Type:** Boundary Test (Parametrized)  

**Test Data:**
- Name: "a" * 1000

**Expected Result:**
- System handles large input
- No buffer overflow
- No crash

---

### Security Tests - Order Form

#### TC-PURCH-010: SQL Injection in Name Field
**Priority:** Critical  
**Type:** Security Test (Parametrized)  

**Payload:**
```
' OR '1'='1
```

**Expected Result:**
- SQL injection blocked or sanitized
- Purchase completes safely
- No database manipulation

---

#### TC-PURCH-011: XSS in City Field
**Priority:** Critical  
**Type:** Security Test (Parametrized)  

**Payload:**
```html
<script>alert(1)</script>
```

**Expected Result:**
- XSS payload sanitized
- No script execution
- Purchase completes safely

---

### Security Tests - Order Form (Comprehensive)

#### TC-PURCH-022: SQL Injection in All Order Form Fields
**Priority:** Critical  
**Type:** Security Test (Parametrized - 5 iterations)  

**Fields tested:**
- Name field
- Country field
- City field
- Card field

**Payloads:**
- `' OR '1'='1`
- `admin'--`

**Expected Result:**
- SQL payloads blocked or sanitized
- No database manipulation
- Purchase completes safely or fails gracefully

**Test runs:** 5 (4 fields × multiple payloads)

---

#### TC-PURCH-023: XSS in All Order Form Fields
**Priority:** Critical  
**Type:** Security Test (Parametrized - 4 iterations)  

**Fields tested:**
- Name field
- Country field
- City field  
- Card field

**Payloads:**
- `<script>alert('XSS')</script>`
- `<img src=x onerror=alert('XSS')>`
- `<svg/onload=alert('XSS')>`
- `javascript:alert('XSS')`

**Expected Result:**
- XSS payloads sanitized
- No script execution
- Purchase completes safely

**Critical check:**
If alert appears with 'XSS' text → VULNERABILITY DETECTED → Test fails

**Test runs:** 4 (one payload per field)

---

#### TC-PURCH-024: Special Characters in All Order Form Fields
**Priority:** Medium  
**Type:** Robustness Test (Parametrized - 4 iterations)  

**Fields tested:**
- Name: `Test@#$%^&*()`
- Country: `España™®©`
- City: `Test<>?:|\\`
- Card: `1234-5678-9012-3456`

**Expected Result:**
- Special characters handled gracefully
- No crashes
- Purchase completes successfully

**Test runs:** 4 (one per field)

---

#### TC-PURCH-025: Null Bytes in Order Form
**Priority:** High  
**Type:** Security Test (Parametrized - 3 iterations)  

**Test inputs:**
- `Test\x00User` (null byte in middle)
- `\x00Test` (null byte at start)
- `Test\x00` (null byte at end)

**Expected Result:**
- Null bytes handled safely
- No string truncation exploits
- Purchase blocks or completes safely

**Test runs:** 3

---

## 3. Related Bugs

| Bug ID | Severity | Title | Test Case | Status |
|--------|----------|-------|-----------|--------|
| #13 | High | System allows purchasing with empty cart | TC-PURCH-014 | Open |

**Bug #13 Details:**
- **Impact:** Creates invalid orders, wastes resources
- **Recommendation:** Add cart validation before checkout
- **Expected Fix:** Disable "Place Order" button when cart empty

---

<a name="architecture"></a>
## 4. Code Architecture

### File Structure

```
project_root/
├── tests/
│   ├── login/
│   │   └── ...
│   └── purchase/
│       ├── __init__.py
│       ├── test_purchase.py
│       └── README.md (this file)
├── test_results/
│   └── purchase/
│       └── report_chrome_YYYY-MM-DD_HH-MM-SS.html
├── conftest.py
└── requirements.txt
```

### Code Organization

The Python file is organized into 5 sections:

1. **HEADER** - Module documentation
2. **IMPORTS** - External libraries
3. **CONFIGURATION** - Constants and locators
4. **HELPERS & FIXTURES** - Reusable functions and setup
5. **TEST CASES** - Actual test functions

---

<a name="imports"></a>
## 5. Imports Explanation

### Core Selenium Imports

Same as login module:
- `webdriver` - Browser control
- `By` - Locator strategies
- `WebDriverWait` & `expected_conditions` - Explicit waits
- `TimeoutException`, `NoSuchElementException` - Error handling

### Additional Imports

```python
import re
```
**Purpose:** Parse prices from strings

DemoBlaze displays prices in various formats:
- "$790"
- "790 *includes tax"
- "Amount: 790 USD"

The `parse_price()` function uses regex to extract numeric value:
```python
match = re.search(r'\d+', price_str)
```

---

<a name="configuration"></a>
## 6. Configuration Variables

### Base Configuration

```python
BASE_URL = "https://www.demoblaze.com/"
TIMEOUT = 10
EXPLICIT_WAIT = 5
```

Same as login module.

### Test Credentials

```python
TEST_USERNAME = "testuser_qa_2024"
TEST_PASSWORD = "SecurePass123!"
```

Used in TC-PURCH-012 (logged-in user purchase).

### Locators Organization

Locators grouped by functionality:

**Product Locators:**
- `FIRST_PRODUCT_LINK` - First product on home page
- `SECOND_PRODUCT_LINK` - Second product
- `PRODUCT_PRICE_HEADER` - Price on product detail page
- `ADD_TO_CART_BUTTON` - Add to cart button

**Navigation Locators:**
- `HOME_NAV_LINK` - Home link in navbar
- `CART_NAV_LINK` - Cart link in navbar

**Cart Locators:**
- `PLACE_ORDER_BUTTON` - Checkout button
- `DELETE_ITEM_LINK` - Delete button for first item
- `CART_TOTAL_PRICE` - Total price display
- `FIRST_ITEM_IN_CART_NAME` - First item name in cart table

**Order Modal Locators:**
- `ORDER_NAME_FIELD` - Name input
- `ORDER_COUNTRY_FIELD` - Country input
- `ORDER_CITY_FIELD` - City input
- `ORDER_CARD_FIELD` - Credit card input
- `ORDER_MONTH_FIELD` - Expiration month
- `ORDER_YEAR_FIELD` - Expiration year
- `PURCHASE_BUTTON` - Final purchase button
- `CLOSE_ORDER_MODAL_BUTTON` - Close modal button

**Confirmation Locators:**
- `PURCHASE_CONFIRM_MODAL` - Success modal
- `PURCHASE_CONFIRM_MSG` - "Thank you" message
- `CONFIRM_OK_BUTTON` - OK button to close confirmation

### How Locators Were Obtained

Same process as login module (see login README section 10).

**Example - Cart Total:**

1. Add product to cart
2. Navigate to cart page
3. Right-click total price → Inspect
4. HTML:
   ```html
   <h3 id="totalp">790</h3>
   ```
5. Extract: `(By.ID, "totalp")`

---

<a name="fixtures"></a>
## 7. Fixtures Deep Dive

### Fixture: `browser`

Defined in root `conftest.py`. Provides cross-browser support. See login README for details.

---

### Fixture: `cart_page`

**Purpose:** Navigates to cart with one product already added

**What it does:**
1. Navigate to home page
2. Add first product to cart (using `add_product_to_cart()`)
3. Navigate to cart page
4. Wait for "Place Order" button to appear
5. Return browser instance

**Why useful:**
- Many tests start with item in cart
- Avoids repeating setup code
- Ensures consistent starting state

**Usage:**
```python
def test_delete_item_from_cart(cart_page):
    # Cart already has one item
    cart_page.find_element(*DELETE_ITEM_LINK).click()
```

---

### Fixture: `order_modal_page`

**Purpose:** Opens order modal with item in cart

**Dependencies:**
- Requires `cart_page` fixture (composition)

**What it does:**
1. Receive browser from `cart_page` fixture
2. Click "Place Order" button
3. Wait for order form to appear
4. Return browser instance

**Usage:**
```python
def test_successful_purchase(order_modal_page):
    # Order modal already open
    fill_order_form(order_modal_page, ...)
```

---

<a name="helpers"></a>
## 8. Helper Functions

### `wait_for_alert_and_get_text(browser, timeout)`

Same as login module - handles JavaScript alerts.

**Usage in purchase module:**
- Capture "Product added" confirmation
- Capture form validation alerts

---

### `fill_order_form(browser, name, country, city, card, month, year)`

**Purpose:** Fills all order form fields

**Parameters:** All strings, all optional (defaults to empty)

**What it does:**
1. Wait for name field to appear
2. Send keys to each field
3. Log what was entered
4. Raise exception if error occurs

**Why needed:**
- Order form has 6 fields
- Without helper: 6 lines per test
- With helper: 1 line per test

**Usage:**
```python
fill_order_form(browser, "John Doe", "USA", "NYC", "4111111111111111", "12", "2025")
```

---

### `parse_price(price_str)`

**Purpose:** Extract numeric price from string

**How it works:**
```python
match = re.search(r'\d+', price_str)  # Find first number
if match:
    return int(match.group(0))        # Return as integer
return 0                               # Default to 0
```

**Examples:**
```python
parse_price("$790")                 # Returns 790
parse_price("790 *includes tax")    # Returns 790
parse_price("Amount: 790 USD")      # Returns 790
parse_price("No price")             # Returns 0
```

**Why needed:**
- Prices displayed in different formats
- Need consistent numeric comparison
- Centralized parsing logic

---

### `add_product_to_cart(browser, product_locator)`

**Purpose:** Complete flow to add product and return price

**What it does:**
1. Click product link (wait until clickable)
2. Get product price from detail page
3. Parse price to integer
4. Click "Add to cart" button (wait until clickable)
5. Accept confirmation alert
6. Click Home link
7. Wait for home page to load
8. Return price

**Why it returns price:**
- Tests need to verify cart totals
- Capture price at time of adding
- Use for later assertions

**Usage:**
```python
price1 = add_product_to_cart(browser, FIRST_PRODUCT_LINK)
price2 = add_product_to_cart(browser, SECOND_PRODUCT_LINK)
expected_total = price1 + price2
```

---

### `perform_login(browser, username, password)`

**Purpose:** Login helper for TC-PURCH-012

Same logic as login module but duplicated here for independence.

---

### `wait_for_cart_total_update(browser, timeout)`

**Purpose:** Wait for asynchronous cart total calculation

**Why needed:**
DemoBlaze calculates cart total via JavaScript after page load:
- Total element exists immediately (displays empty)
- JavaScript populates it after ~1 second
- Direct read may get empty string or "0"

**What it does:**
1. Wait for total element to be visible
2. Wait until text is not empty
3. Parse and return total

**Usage:**
```python
browser.find_element(*CART_NAV_LINK).click()
total = wait_for_cart_total_update(browser)
assert total == expected_total
```

**Replaces:**
```python
# Bad approach (old code)
time.sleep(2)  # Arbitrary wait
total = parse_price(browser.find_element(*CART_TOTAL_PRICE).text)
```

---

<a name="tests"></a>
## 9. Test Functions Breakdown

### `test_successful_purchase_and_price_verification(order_modal_page)`

**Flow:**
1. Get cart total before purchase
2. Verify total is not 0
3. Fill order form with valid data
4. Click "Purchase"
5. Wait for confirmation modal
6. Verify "Thank you" message
7. Extract "Amount: X USD" from confirmation
8. Verify amount matches cart total
9. Click OK to close modal

**Key Assertions:**
- `assert "Thank you for your purchase!" in confirm_text`
- `assert confirmed_price == expected_price`

**Why price verification matters:**
- Ensures no price manipulation
- Confirms accurate checkout
- Critical for financial integrity

---

### `test_multiple_items_total(browser)`

**Flow:**
1. Add first product → capture price1
2. Add second product → capture price2
3. Navigate to cart
4. Wait for total calculation
5. Verify total = price1 + price2

**Key Wait:**
```python
total_price = wait_for_cart_total_update(browser)
```

Without this, test may read total before JavaScript calculates it.

---

### `test_delete_item_from_cart(cart_page)`

**Flow:**
1. Verify item is visible in cart
2. Click "Delete"
3. Wait for element to disappear
4. Try to find element again
5. Expect NoSuchElementException

**Key Wait:**
```python
WebDriverWait(browser, TIMEOUT).until(
    EC.invisibility_of_element_located(FIRST_ITEM_IN_CART_NAME)
)
```

Ensures item actually removed before assertion.

---

### `test_delete_item_and_recalculate_total(browser)`

**Flow:**
1. Add two products
2. Verify initial total correct
3. Delete first item
4. Wait for DOM update
5. Wait for total recalculation
6. Verify new total = second product price

**Why two waits:**
```python
# Wait 1: Item removed from DOM
WebDriverWait(browser, TIMEOUT).until(
    EC.invisibility_of_element_located(FIRST_ITEM_IN_CART_NAME)
)

# Wait 2: Total recalculated
total_after = wait_for_cart_total_update(browser)
```

DemoBlaze updates DOM first, then recalculates total asynchronously.

---

### `test_add_same_product_multiple_times(browser)`

**Flow:**
1. Add first product → get price
2. Add same product again
3. Navigate to cart
4. Count items in cart
5. Verify 2 items present
6. Verify total = price × 2

**Key check:**
```python
cart_items = browser.find_elements(By.XPATH, "//tbody[@id='tbodyid']/tr")
assert len(cart_items) == 2
```

DemoBlaze creates duplicate entries (no quantity field).

---

### `test_navigation_after_purchase(order_modal_page)`

**Flow:**
1. Complete purchase
2. Click OK on confirmation
3. Get current URL
4. Verify still on DemoBlaze domain

**Purpose:**
Ensures no unexpected redirects to external sites after purchase.

---

### `test_cart_empty_after_purchase(order_modal_page)`

**Flow:**
1. Complete purchase (cart has 1 item)
2. Click OK
3. Navigate to cart
4. Count items
5. Verify 0 items

**Why important:**
Confirms proper session management - cart clears after successful purchase.

---

### `test_add_many_products_to_cart(browser)`

**Flow:**
1. Loop 10 times:
   - Add product
   - Accumulate expected total
2. Navigate to cart
3. Verify 10 items present
4. Verify total matches expected

**Why 10 not 100:**
- Realistic boundary test
- Reasonable execution time
- Still validates cart handles multiple items

---

### `test_delete_all_items_from_cart(browser)`

**Flow:**
1. Add 2 products
2. Navigate to cart
3. Loop to delete both items:
   - Click delete
   - Wait for item removal
4. Verify cart empty

**Key loop:**
```python
for i in range(initial_count):
    browser.find_element(*DELETE_ITEM_LINK).click()
    # Wait for count to decrease
    WebDriverWait(browser, TIMEOUT).until(
        lambda d: len(d.find_elements(...)) == initial_count - (i + 1)
    )
```

---

### `test_open_close_order_modal_multiple_times(cart_page)`

**Flow:**
1. Repeat 3 times:
   - Click "Place Order"
   - Verify modal opens
   - Click "Close"
   - Verify modal closes
   - Verify back on cart

**Purpose:**
Ensures modal can be opened/closed multiple times without issues.

---

### `test_access_empty_cart(browser)`

**Flow:**
1. Navigate to home
2. Go directly to cart (no products added)
3. Verify cart is empty
4. Verify "Place Order" button still visible

**Documents Bug #13:**
"Place Order" button visible even for empty cart.

---

### `test_sql_injection_all_order_fields(...)` **(Parametrized)**

**Runs 5 times** - tests SQL injection in each field:

| Field | Payload |
|-------|---------|
| Name | `' OR '1'='1` |
| Name | `admin'--` |
| Country | `' OR '1'='1` |
| City | `' OR '1'='1` |
| Card | `' OR '1'='1` |

**Logic:**
1. Fill all fields with valid data
2. Replace target field with SQL payload
3. Submit purchase
4. Verify purchase completes safely or blocks appropriately

---

### `test_xss_all_order_fields(...)` **(Parametrized)**

**Runs 4 times** - tests XSS in each field:

| Field | Payload |
|-------|---------|
| Name | `<script>alert('XSS')</script>` |
| Country | `<img src=x onerror=alert('XSS')>` |
| City | `<svg/onload=alert('XSS')>` |
| Card | `javascript:alert('XSS')` |

**Critical check:**
```python
if alert_text and 'XSS' in alert_text:
    logging.critical("🚨 XSS VULNERABILITY DETECTED 🚨")
    pytest.fail(f"XSS vulnerability in {field_name} field")
```

If XSS executes → test fails with security warning.

---

### `test_special_characters_all_order_fields(...)` **(Parametrized)**

**Runs 4 times** - tests special characters:

Tests various special characters in each field to ensure robustness.

---

### `test_null_bytes_order_form(...)` **(Parametrized)**

**Runs 3 times** - tests null byte injection:

Ensures null bytes don't cause string truncation exploits.

---

### `test_purchase_as_logged_in_user(browser)`

**Flow:**
1. Login
2. Add product
3. Navigate to cart
4. Open order modal
5. Verify name field is empty (DemoBlaze doesn't auto-fill)
6. Fill form manually
7. Complete purchase
8. Verify confirmation

**Key Assertion:**
```python
assert name_field.get_attribute("value") == "", \
    "Name field should NOT auto-fill"
```

Documents DemoBlaze limitation.

---

### `test_order_modal_close_button(order_modal_page)`

**Flow:**
1. Verify modal visible
2. Click "Close"
3. Wait for modal to disappear
4. Verify back on cart page

**Why test UI buttons:**
- Ensures users can cancel checkout
- Verifies modal behavior correct
- Cart contents preserved

---

### `test_purchase_empty_cart(browser)` **(xfail)**

**Flow:**
1. Navigate to cart without adding products
2. Click "Place Order" (shouldn't be possible but is)
3. Fill form
4. Submit
5. Observe confirmation appears (BUG)
6. Verify "Amount: 0 USD"
7. Fail with message about Bug #13

**Marked xfail:**
```python
@pytest.mark.xfail(reason="Bug #13: System allows purchasing with empty cart")
```

Test will fail as expected until bug fixed.

---

### `test_order_form_validation_robustness_security(...)` **(Parametrized)**

**Runs 8 times** with different data:

| Test ID | Data | Expected Result |
|---------|------|-----------------|
| TC-PURCH-004 | All empty | Alert |
| TC-PURCH-005 | Name only | Alert |
| TC-PURCH-006 | Card only | Alert |
| TC-PURCH-007 | Letters in card | Purchase completes |
| TC-PURCH-008 | Letters in month/year | Purchase completes |
| TC-PURCH-009 | 1000 char name | Purchase completes |
| TC-PURCH-010 | SQL injection | Purchase completes safely |
| TC-PURCH-011 | XSS payload | Purchase completes safely |

**Logic:**
```python
if expected_alert:
    # Validation tests
    alert_text = wait_for_alert_and_get_text(browser)
    assert alert_text == expected_alert
else:
    # Robustness/security tests
    assert no unexpected alert
    assert purchase completes or fails gracefully
```

---

## 10. Execution Guide

**Flow:**
1. Login
2. Add product
3. Navigate to cart
4. Open order modal
5. Verify name field is empty (DemoBlaze doesn't auto-fill)
6. Fill form manually
7. Complete purchase
8. Verify confirmation

**Key Assertion:**
```python
assert name_field.get_attribute("value") == "", \
    "Name field should NOT auto-fill"
```

Documents DemoBlaze limitation.

---

### `test_order_modal_close_button(order_modal_page)`

**Flow:**
1. Verify modal visible
2. Click "Close"
3. Wait for modal to disappear
4. Verify back on cart page

**Why test UI buttons:**
- Ensures users can cancel checkout
- Verifies modal behavior correct
- Cart contents preserved

---

### `test_purchase_empty_cart(browser)` **(xfail)**

**Flow:**
1. Navigate to cart without adding products
2. Click "Place Order" (shouldn't be possible but is)
3. Fill form
4. Submit
5. Observe confirmation appears (BUG)
6. Verify "Amount: 0 USD"
7. Fail with message about Bug #13

**Marked xfail:**
```python
@pytest.mark.xfail(reason="Bug #13: System allows purchasing with empty cart")
```

Test will fail as expected until bug fixed.

---

### `test_order_form_validation_robustness_security(...)` **(Parametrized)**

**Runs 8 times** with different data:

| Test ID | Data | Expected Result |
|---------|------|-----------------|
| TC-PURCH-004 | All empty | Alert |
| TC-PURCH-005 | Name only | Alert |
| TC-PURCH-006 | Card only | Alert |
| TC-PURCH-007 | Letters in card | Purchase completes |
| TC-PURCH-008 | Letters in month/year | Purchase completes |
| TC-PURCH-009 | 1000 char name | Purchase completes |
| TC-PURCH-010 | SQL injection | Purchase completes safely |
| TC-PURCH-011 | XSS payload | Purchase completes safely |

**Logic:**
```python
if expected_alert:
    # Validation tests
    alert_text = wait_for_alert_and_get_text(browser)
    assert alert_text == expected_alert
else:
    # Robustness/security tests
    assert no unexpected alert
    assert purchase completes or fails gracefully
```

---

<a name="execution"></a>
## 10. Execution Guide

### Prerequisites

```bash
# Install dependencies
pip install -r requirements.txt
```

### Running Tests

**Run all purchase tests:**
```bash
pytest tests/purchase/
```

**Run with specific browser:**
```bash
pytest tests/purchase/ --browser=chrome
pytest tests/purchase/ --browser=firefox
pytest tests/purchase/ --browser=edge
```

**Run specific test:**
```bash
pytest tests/purchase/test_purchase.py::test_successful_purchase_and_price_verification
```

**Run with verbose output:**
```bash
pytest tests/purchase/ -v
```

**Run with logging output:**
```bash
pytest tests/purchase/ -s
```

**Run excluding xfail tests:**
```bash
pytest tests/purchase/ -m "not xfail"
```

### HTML Reports

Reports generated automatically in:
```
test_results/purchase/report_[browser]_[timestamp].html
```

Example:
```
test_results/purchase/report_chrome_2025-11-07_15-30-45.html
```

---

<a name="results"></a>
## 11. Expected Results

### Test Execution Summary

| Test Category | Tests | Pass | Xfail | Total |
|--------------|-------|------|-------|-------|
| Purchase Flow | 1 | 1 | 0 | 1 |
| Cart Operations | 7 | 7 | 0 | 7 |
| User Scenarios | 1 | 1 | 0 | 1 |
| UI Interaction | 4 | 4 | 0 | 4 |
| Validation | 8 | 8 | 0 | 8 |
| Security - SQL Injection | 5 | 5 | 0 | 5 |
| Security - XSS | 4 | 4 | 0 | 4 |
| Security - Special Chars | 4 | 4 | 0 | 4 |
| Security - Null Bytes | 3 | 3 | 0 | 3 |
| Known Bugs | 1 | 0 | 1 | 1 |
| **TOTAL TESTS** | **28** | **27** | **1** | **28** |
| **TOTAL RUNS** | **~41** | **~40** | **1** | **~41** |

**Note:** Some tests are parametrized, resulting in more test runs than test functions.

### Success Criteria

Test suite PASSED if:
- 27 stable tests pass
- 1 xfail test fails as expected (Bug #13)
- No unexpected failures
- Execution time under 5 minutes

### Performance Benchmarks

**Expected execution times:**
- Simple tests: 8-12 seconds each
- Multi-item tests: 15-20 seconds
- Parametrized tests: 5-8 seconds per iteration
- Total suite: ~4-5 minutes (varies by number of products added)

---

<a name="troubleshooting"></a>
## 12. Troubleshooting

### Issue: Cart total shows 0

**Cause:** Reading total before JavaScript calculates it

**Solution:** Use `wait_for_cart_total_update()` instead of direct read

---

### Issue: Element not found after deletion

**Cause:** Not waiting for DOM update

**Solution:**
```python
WebDriverWait(browser, TIMEOUT).until(
    EC.invisibility_of_element_located(LOCATOR)
)
```

---

### Issue: Alert not found

**Cause:** Alert appeared and disappeared before test checked

**Solution:** Reduce timeout or check immediately after action

---

### Issue: Test hangs on cart page

**Cause:** Cart total never populates (DemoBlaze bug or network issue)

**Solution:** Check browser console for JavaScript errors

---

<a name="practices"></a>
## 13. Best Practices Applied

### Code Quality

**DRY Principle:**
- `add_product_to_cart()` used in multiple tests
- `fill_order_form()` eliminates repetition
- Fixtures provide consistent setup

**Clean Code:**
- No excessive comments
- Logging for runtime feedback
- Clear function names

### Testing Best Practices

**Explicit Waits:**
- `wait_for_cart_total_update()` for async operations
- `EC.invisibility_of_element_located()` for deletions
- No `time.sleep()` in production code

**Price Verification:**
- Capture prices at source
- Compare at every step
- Ensures financial accuracy

**Parametrization:**
- 8 test cases in 1 function
- Clean test data separation
- Efficient execution

### Selenium Best Practices

**Wait Strategy:**
- Wait for element clickable before clicking
- Wait for visibility before reading text
- Custom waits for async operations

**Locator Strategy:**
- ID when available (fastest)
- XPath for dynamic content
- Consistent naming

---

## 14. Maintenance Guide

### When to Update Tests

**Site Redesign:**
- Update locators
- Verify cart calculation logic still async
- Test on all browsers

**Bug Fixes:**
- Remove `@pytest.mark.xfail` from TC-PURCH-014 when Bug #13 fixed
- Update expected behavior
- Re-verify test passes

**New Features:**
- Add quantity selection tests if implemented
- Add discount code tests if implemented
- Maintain same structure

---

## 15. Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.0 | Nov 2025 | Enhanced logging, improved waits, clean code |
| 1.0 | Nov 2025 | Initial release with basic tests |

---

## 16. Related Documents

- [Test Plan](../../docs/test-plan.md)
- [Test Summary Report](../../docs/Test_Summary_Report.md)
- [User Flows](../../docs/users-flow.md)
- [DemoBlaze Test Cases](../../docs/DemoBlaze_Test_Cases.xlsx)
- [Login Module README](../login/README.md)
- Bug #13: Empty Cart Purchase (documented in Test Summary Report)

---

**End of Documentation**
