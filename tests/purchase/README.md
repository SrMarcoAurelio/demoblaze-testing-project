# Test Suite: Login & Authentication

**Module:** `test_dem_login.py`  
**Author:** Arévalo, Marc  
**Created:** November 2025  
**Version:** 1.0  
**Application Under Test:** DemoBlaze (https://www.demoblaze.com/)

---

## 📑 Table of Contents

1. [Overview](#overview)
2. [Test Cases Covered](#test-cases)
3. [Related Bugs](#bugs)
4. [Code Architecture](#architecture)
5. [Imports Explanation](#imports)
6. [Configuration Variables](#configuration)
7. [Fixtures Deep Dive](#fixtures)
8. [Helper Functions](#helpers)
9. [Test Functions Breakdown](#tests)
10. [How to Obtain Locators](#locators)
11. [Execution Guide](#execution)
12. [Expected Results](#results)
13. [Troubleshooting](#troubleshooting)
14. [Best Practices Applied](#practices)

---

<a name="overview"></a>
## 1. Overview

### Purpose

This test suite automates the validation of DemoBlaze's authentication system, including login, registration, and session management functionalities. The primary goal is to verify both positive scenarios (successful login) and negative scenarios (failed login attempts, security vulnerabilities).

### Scope

**In Scope:**
- Valid login with correct credentials
- Invalid login scenarios (wrong password, non-existent user, empty fields)
- Weak password acceptance (security vulnerability)
- Username enumeration vulnerability
- Session state verification

**Out of Scope:**
- Password recovery functionality
- Remember me checkbox
- Social login integrations
- Multi-factor authentication (not implemented in DemoBlaze)

### Why This Module First?

Authentication is the foundation of any web application. Without proper login functionality:
- Users cannot access protected features
- E-commerce transactions cannot be completed
- Security vulnerabilities expose user data

Testing login first ensures:
1. Base functionality works before testing dependent modules
2. Critical security flaws are identified early
3. Other test suites can reuse login functions

---

<a name="test-cases"></a>
## 2. Test Cases Covered

### TC-LOGIN-001: Valid Login
**Objective:** Verify successful login with valid credentials  
**Priority:** Critical  
**Type:** Positive Test  
**Automation Status:** ✅ Automated

**Test Steps:**
1. Navigate to DemoBlaze homepage
2. Click "Log in" button in navigation bar
3. Enter valid username
4. Enter valid password
5. Click "Log in" submit button

**Expected Result:**
- User successfully authenticated
- "Log out" button appears in navbar
- Username displayed as "Welcome [username]"
- Modal closes automatically

---

### TC-LOGIN-002: Invalid Password
**Objective:** Verify error handling for incorrect password  
**Priority:** High  
**Type:** Negative Test  
**Automation Status:** ✅ Automated

**Test Steps:**
1. Navigate to login modal
2. Enter valid username (existing user)
3. Enter incorrect password
4. Click submit

**Expected Result:**
- Login rejected
- JavaScript alert displays: "Wrong password."
- User remains logged out
- Modal remains open

---

### TC-LOGIN-003: Non-existent User
**Objective:** Verify error for username that doesn't exist  
**Priority:** High  
**Type:** Negative Test  
**Automation Status:** ✅ Automated

**Test Steps:**
1. Navigate to login modal
2. Enter non-existent username
3. Enter any password
4. Click submit

**Expected Result:**
- Login rejected
- JavaScript alert displays: "User does not exist."
- User remains logged out

---

### TC-LOGIN-004: Empty Fields Validation
**Objective:** Verify client-side validation for empty fields  
**Priority:** Medium  
**Type:** Negative Test  
**Automation Status:** ✅ Automated

**Test Steps:**
1. Navigate to login modal
2. Leave username field empty
3. Leave password field empty
4. Click submit

**Expected Result:**
- Form submission prevented
- JavaScript alert displays: "Please fill out Username and Password."
- No server request sent

---

### TC-LOGIN-005: Weak Password Vulnerability
**Objective:** Document security flaw - system accepts weak passwords  
**Priority:** Critical  
**Type:** Security Test  
**Automation Status:** ✅ Automated (xfail)  
**Related Bug:** #11

**Test Steps:**
1. Register new user with password "123"
2. Attempt login with that weak password

**Current Behavior (BUG):**
- System accepts "123" as valid password
- No password complexity requirements enforced

**Expected Behavior (Post-Fix):**
- System should reject weak passwords
- Minimum requirements should include:
  - 8+ characters
  - At least 1 uppercase letter
  - At least 1 lowercase letter
  - At least 1 number
  - At least 1 special character

**Test Status:** Marked as `xfail` (expected to fail) until bug is resolved

---

### TC-LOGIN-006: Username Enumeration Vulnerability
**Objective:** Document security flaw - different error messages reveal valid usernames  
**Priority:** Critical  
**Type:** Security Test  
**Automation Status:** ✅ Automated (xfail)  
**Related Bug:** #10

**Test Steps:**
1. Attempt login with existing username + wrong password
2. Note error message: "Wrong password."
3. Attempt login with non-existent username + any password
4. Note error message: "User does not exist."
5. Compare messages

**Current Behavior (BUG):**
- Different error messages reveal whether username exists
- Attacker can enumerate valid usernames

**Expected Behavior (Post-Fix):**
- Generic error message for all failed login attempts
- Example: "Invalid username or password."
- Prevents username enumeration attacks

**Security Impact:**
- Attackers can build list of valid usernames
- Targeted password attacks become easier
- OWASP Top 10 vulnerability

**Test Status:** Marked as `xfail` until bug is resolved

---

<a name="bugs"></a>
## 3. Related Bugs

| Bug ID | Severity | Title | Test Case | Status |
|--------|----------|-------|-----------|--------|
| #10 | High | Username enumeration vulnerability | TC-LOGIN-006 | Open |
| #11 | High | System accepts weak passwords | TC-LOGIN-005 | Open |
| #12 | High | No rate limiting on login attempts | Not automated yet | Open |

**Note on Bug #12:**
Rate limiting tests require multiple rapid login attempts (100+ requests). This is not included in current test suite to avoid:
- Overloading demo server
- Extended test execution time
- Potential IP blocking

Recommendation: Test rate limiting manually or in dedicated security testing suite.

---

<a name="architecture"></a>
## 4. Code Architecture

### File Structure

```
tests/
├── test_dem_login.py          # Executable test code
└── test_dem_login.md          # This documentation
```

### Code Organization

The Python file is organized into 6 sections:

1. **IMPORTS** - External libraries and dependencies
2. **CONFIGURATION** - Constants and test data
3. **FIXTURES** - Setup/teardown automation
4. **HELPER FUNCTIONS** - Reusable utility functions
5. **TEST CASES** - Actual test functions
6. **EXECUTION BLOCK** - Optional direct execution

### Design Pattern: Page Object Model (Simplified)

While not a full POM implementation, the code follows POM principles:
- Locators centralized in CONFIGURATION section
- Business logic separated from test logic
- Helper functions encapsulate page interactions
- Tests focus on "what to test" not "how to test"

**Why Simplified POM?**
- Single page/modal being tested
- Reduces complexity for portfolio project
- Easier to understand for learning purposes
- Can be extended to full POM if needed

---

<a name="imports"></a>
## 5. Imports Explanation

### Why Each Library is Needed

#### `from selenium import webdriver`
**Purpose:** Core Selenium library - controls browser automation  
**What it does:**
- Opens and closes browsers
- Provides WebDriver interface
- Manages browser sessions

**Usage in code:**
```python
driver = webdriver.Chrome()  # Opens Chrome browser
```

---

#### `from selenium.webdriver.common.by import By`
**Purpose:** Locator strategy enum  
**What it does:**
- Defines how to find elements (ID, XPath, CSS, etc.)
- Replaces deprecated methods like `find_element_by_id()`

**Modern vs Deprecated:**
```python
# Modern (correct)
element = driver.find_element(By.ID, "login2")

# Deprecated (old way)
element = driver.find_element_by_id("login2")
```

**Why modern is better:**
- More flexible
- Better error messages
- Future-proof

---

#### `from selenium.webdriver.support.ui import WebDriverWait`
**Purpose:** Explicit waits for dynamic content  
**What it does:**
- Waits for specific conditions before proceeding
- Prevents "element not found" errors
- More reliable than `time.sleep()`

**Usage example:**
```python
WebDriverWait(driver, 10).until(
    EC.presence_of_element_located((By.ID, "login2"))
)
```
Translation: "Wait up to 10 seconds until element with ID 'login2' appears"

---

#### `from selenium.webdriver.support import expected_conditions as EC`
**Purpose:** Pre-built wait conditions  
**What it does:**
- Provides common waiting scenarios
- Works with WebDriverWait

**Common conditions:**
- `presence_of_element_located` - Element exists in DOM
- `visibility_of_element_located` - Element is visible
- `element_to_be_clickable` - Element can be clicked
- `alert_is_present` - JavaScript alert appeared

---

#### `from selenium.common.exceptions import TimeoutException`
**Purpose:** Handle timeout errors gracefully  
**What it does:**
- Catches when WebDriverWait times out
- Allows custom error handling

**Usage:**
```python
try:
    WebDriverWait(driver, 10).until(EC.alert_is_present())
except TimeoutException:
    return None  # No alert appeared
```

---

#### `from webdriver_manager.chrome import ChromeDriverManager`
**Purpose:** Automatic ChromeDriver management  
**What it does:**
- Downloads correct ChromeDriver version automatically
- Matches Chrome browser version
- Eliminates manual driver setup

**Without WebDriver Manager:**
1. Check Chrome version
2. Download matching ChromeDriver
3. Add to PATH or specify location
4. Update when Chrome updates

**With WebDriver Manager:**
```python
service = Service(ChromeDriverManager().install())
driver = webdriver.Chrome(service=service)
```
Done. Automatic.

---

#### `from selenium.webdriver.chrome.service import Service`
**Purpose:** Manage ChromeDriver service  
**What it does:**
- Interfaces with ChromeDriver process
- Required for WebDriver Manager integration

---

#### `import pytest`
**Purpose:** Testing framework  
**What it does:**
- Discovers and runs tests
- Provides fixtures
- Generates reports
- Manages test lifecycle

**Key features used:**
- `@pytest.fixture` - Setup/teardown
- `@pytest.mark.xfail` - Expected failures
- `pytest.main()` - Programmatic execution
- Assertions - Test validations

---

#### `import time`
**Purpose:** Time-related utilities  
**What it does:**
- Generate timestamps for unique usernames
- Add small delays when needed (sparingly)

**Usage in code:**
```python
timestamp = str(int(time.time()))  # "1699123456"
unique_username = f"testuser_{timestamp}"
```

**Why unique usernames?**
- Tests can be run multiple times
- Avoid "username already exists" errors
- Each test run is independent

---

<a name="configuration"></a>
## 6. Configuration Variables

### How These Values Were Determined

#### `BASE_URL = "https://www.demoblaze.com/"`
**Source:** Manual - Known URL of application under test  
**Type:** String constant  
**Purpose:** Central point for site URL

**Why constant?**
- If site moves to different domain, change once
- Easy to switch between environments:
  ```python
  # Development
  BASE_URL = "https://dev.demoblaze.com/"
  
  # Production
  BASE_URL = "https://www.demoblaze.com/"
  ```

---

#### `TIMEOUT = 10`
**Source:** Industry best practice  
**Type:** Integer (seconds)  
**Purpose:** Maximum wait time for elements

**Why 10 seconds?**
- Standard in automation testing
- Sufficient for slow networks
- Not too long (tests don't hang forever)
- Balances reliability vs speed

**Used in:**
- WebDriverWait calls
- Implicit waits
- Alert waiting

---

#### `TEST_USERNAME = "testuser_qa_2024"`
**Source:** Manually created test account  
**Type:** String  
**Purpose:** Valid username for positive tests

**Prerequisites:**
- Account must be pre-registered in DemoBlaze
- Use strong password (for Bug #11 testing contrast)

**Best Practice:**
- Use descriptive username (includes "test" and year)
- Easy to identify as test account
- Can be filtered in production data

---

#### `TEST_PASSWORD = "SecurePass123!"`
**Source:** Manually defined  
**Type:** String  
**Purpose:** Strong password for valid login tests

**Why this password?**
- Demonstrates contrast with weak passwords
- Meets security best practices:
  - 8+ characters ✅
  - Uppercase ✅
  - Lowercase ✅
  - Numbers ✅
  - Special character ✅

---

### Locators - How They Were Found

#### `LOGIN_BUTTON_NAV = "login2"`
**Element:** "Log in" button in navigation bar  
**Type:** ID locator  
**How obtained:**

1. Navigate to https://www.demoblaze.com/
2. Right-click "Log in" button
3. Select "Inspect" or press F12
4. HTML revealed:
   ```html
   <a id="login2" data-toggle="modal" data-target="#logInModal">Log in</a>
   ```
5. Extract ID: `login2`

**Why use ID?**
- Fastest locator strategy
- Most reliable (IDs should be unique)
- Less likely to break with UI changes

---

#### `LOGIN_USERNAME_FIELD = "loginusername"`
**Element:** Username input field in login modal  
**Type:** ID locator  
**How obtained:**

1. Click "Log in" button to open modal
2. Right-click username field
3. Inspect element
4. HTML:
   ```html
   <input type="text" class="form-control" id="loginusername" placeholder="Username">
   ```
5. Extract ID: `loginusername`

---

#### `LOGIN_PASSWORD_FIELD = "loginpassword"`
**Element:** Password input field in login modal  
**Type:** ID locator  
**How obtained:**

1. Same modal as username field
2. Inspect password field
3. HTML:
   ```html
   <input type="password" class="form-control" id="loginpassword" placeholder="Password">
   ```
4. Extract ID: `loginpassword`

---

#### `LOGIN_SUBMIT_BUTTON = "//button[text()='Log in']"`
**Element:** Submit button inside login modal  
**Type:** XPath locator  
**How obtained:**

1. Inspect submit button
2. HTML:
   ```html
   <button type="button" class="btn btn-primary" onclick="logIn()">Log in</button>
   ```
3. No unique ID present
4. Create XPath based on button text:
   ```xpath
   //button[text()='Log in']
   ```

**Why XPath here?**
- No unique ID available
- Text is distinctive
- Multiple "Log in" elements exist, but only one is a button

**XPath breakdown:**
- `//` - Search anywhere in document
- `button` - Element type
- `[text()='Log in']` - Condition: text equals "Log in"

**Alternative locators (not used):**
```python
# By onclick attribute
"//button[@onclick='logIn()']"

# By classes (fragile)
"button.btn.btn-primary"
```

**Why text-based XPath is better:**
- More readable
- Less likely to break if CSS classes change
- Self-documenting

---

#### `LOGOUT_BUTTON = "logout2"`
**Element:** "Log out" button in navbar  
**Type:** ID locator  
**How obtained:**

1. Login first to make element visible
2. Inspect "Log out" button
3. HTML:
   ```html
   <a id="logout2" onclick="logOut()">Log out</a>
   ```
4. Extract ID: `logout2`

**Usage:** Verify user is logged in by checking if this element exists

---

#### `WELCOME_USER_TEXT = "nameofuser"`
**Element:** Welcome message showing username  
**Type:** ID locator  
**How obtained:**

1. Login to make element visible
2. Inspect welcome text (e.g., "Welcome testuser_qa_2024")
3. HTML:
   ```html
   <a id="nameofuser">Welcome testuser_qa_2024</a>
   ```
4. Extract ID: `nameofuser`

**Usage:** Verify correct username is displayed after login

---

<a name="fixtures"></a>
## 7. Fixtures Deep Dive

### What Are Fixtures?

Fixtures are pytest's mechanism for setup and teardown code that runs before and after tests.

**Analogy:**
Think of fixtures like a restaurant table setup:
- **Setup:** Clean table, place silverware, napkins (before customer arrives)
- **Test:** Customer eats meal
- **Teardown:** Clear table, clean (after customer leaves)

### Fixture: `browser`

**Purpose:** Provides fresh browser instance for each test

**Code structure:**
```python
@pytest.fixture
def browser():
    # SETUP (before test)
    driver = webdriver.Chrome()
    
    # HANDOFF (give to test)
    yield driver
    
    # TEARDOWN (after test)
    driver.quit()
```

**What happens:**

1. **Before test runs:**
   ```python
   service = Service(ChromeDriverManager().install())
   driver = webdriver.Chrome(service=service)
   driver.maximize_window()
   driver.implicitly_wait(TIMEOUT)
   ```
   - Downloads/verifies ChromeDriver
   - Opens Chrome browser
   - Maximizes window (better for element visibility)
   - Sets implicit wait (backup if explicit waits not used)

2. **During test:**
   - Test receives `driver` object
   - Test uses it to interact with browser

3. **After test completes:**
   ```python
   driver.quit()
   ```
   - Closes browser
   - Cleans up resources
   - Happens even if test fails

**Why `yield` instead of `return`?**

```python
# With return (doesn't work for teardown)
def browser():
    driver = webdriver.Chrome()
    return driver
    # Code here never runs

# With yield (proper teardown)
def browser():
    driver = webdriver.Chrome()
    yield driver
    driver.quit()  # This WILL run
```

**Test isolation benefit:**
Each test gets a fresh browser:
- No cookies from previous tests
- No cached data
- Clean state
- Tests don't affect each other

---

### Fixture: `login_page`

**Purpose:** Opens browser AND navigates to login modal

**Why separate fixture?**
- Many tests start at login modal
- Avoid repeating navigation code in every test

**Dependencies:**
```python
def login_page(browser):  # Requires browser fixture
```
This fixture uses the `browser` fixture. Pytest handles the dependency automatically.

**What it does:**

1. **Navigate to homepage:**
   ```python
   browser.get(BASE_URL)
   ```

2. **Wait for page to load:**
   ```python
   WebDriverWait(browser, TIMEOUT).until(
       EC.presence_of_element_located((By.ID, LOGIN_BUTTON_NAV))
   )
   ```
   Translation: "Don't proceed until 'Log in' button appears"

3. **Click login button:**
   ```python
   login_btn = browser.find_element(By.ID, LOGIN_BUTTON_NAV)
   login_btn.click()
   ```

4. **Wait for modal to open:**
   ```python
   WebDriverWait(browser, TIMEOUT).until(
       EC.visibility_of_element_located((By.ID, LOGIN_USERNAME_FIELD))
   )
   ```
   Translation: "Don't proceed until username field is visible"

5. **Return browser:**
   ```python
   return browser
   ```
   Test now has browser with login modal open and ready

**Usage in tests:**
```python
def test_login_valid_credentials(login_page):
    # login_page is browser with modal already open
    # No need to navigate or click "Log in"
    perform_login(login_page, username, password)
```

**Why this is efficient:**
- 5 lines of setup code → 0 lines in test
- Test focuses on what's being tested, not navigation
- Consistent starting point for all login tests

---

<a name="helpers"></a>
## 8. Helper Functions

### Function: `perform_login(browser, username, password)`

**Purpose:** Encapsulates the login action

**Why it exists:**
- Login is needed in almost every test
- Without helper:
  ```python
  # Repeated in EVERY test (bad)
  def test_something():
      browser.find_element(By.ID, "loginusername").send_keys(username)
      browser.find_element(By.ID, "loginpassword").send_keys(password)
      browser.find_element(By.XPATH, "//button[text()='Log in']").click()
  ```
- With helper:
  ```python
  # Clean and reusable (good)
  def test_something():
      perform_login(browser, username, password)
  ```

**What it does:**

1. **Find username field and enter text:**
   ```python
   username_field = browser.find_element(By.ID, LOGIN_USERNAME_FIELD)
   username_field.clear()  # Clear any existing text
   username_field.send_keys(username)
   ```

2. **Find password field and enter text:**
   ```python
   password_field = browser.find_element(By.ID, LOGIN_PASSWORD_FIELD)
   password_field.clear()
   password_field.send_keys(password)
   ```

3. **Click submit button:**
   ```python
   submit_btn = browser.find_element(By.XPATH, LOGIN_SUBMIT_BUTTON)
   submit_btn.click()
   ```

**Parameters explained:**
- `browser` - WebDriver instance to use
- `username` - String to enter in username field
- `password` - String to enter in password field

**Return value:** None (performs action, doesn't return data)

**Design decision:**
- Generic function (not specific to valid/invalid login)
- Caller decides what credentials to pass
- Flexible for positive and negative tests

---

### Function: `wait_for_alert_and_get_text(browser, timeout=TIMEOUT)`

**Purpose:** Handle JavaScript alerts (error messages in DemoBlaze)

**Why it exists:**
DemoBlaze uses JavaScript alerts for feedback:
- "Wrong password."
- "User does not exist."
- "Please fill out Username and Password."

**Problem without this function:**
```python
# Breaks if no alert appears
alert = browser.switch_to.alert
text = alert.text  # Error: no alert present
```

**Solution: Safe alert handling**

**What it does:**

1. **Wait for alert to appear:**
   ```python
   try:
       WebDriverWait(browser, timeout).until(EC.alert_is_present())
   ```
   - Waits up to `timeout` seconds
   - Returns when alert detected
   - Raises `TimeoutException` if no alert

2. **Switch to alert context:**
   ```python
   alert = browser.switch_to.alert
   ```
   Browser focus moves from page to alert popup

3. **Get alert text:**
   ```python
   alert_text = alert.text
   ```
   Extracts message like "Wrong password."

4. **Close alert:**
   ```python
   alert.accept()
   ```
   Clicks "OK" button programmatically

5. **Return text:**
   ```python
   return alert_text
   ```

6. **Handle no alert scenario:**
   ```python
   except TimeoutException:
       return None
   ```
   If no alert appears, return `None` instead of crashing

**Usage in tests:**
```python
perform_login(browser, "wrong", "credentials")
alert_text = wait_for_alert_and_get_text(browser)

if alert_text:
    assert "Wrong password" in alert_text
else:
    # No alert appeared (unexpected)
    pytest.fail("Expected error alert but none appeared")
```

**Why `timeout` is a parameter:**
- Default: Use global `TIMEOUT` (10 seconds)
- Flexibility: Can override if needed
  ```python
  # Wait only 3 seconds for alert
  text = wait_for_alert_and_get_text(browser, timeout=3)
  ```

---

### Function: `is_user_logged_in(browser)`

**Purpose:** Check if user is currently authenticated

**Why it exists:**
- Multiple tests need to verify login state
- Centralized logic for consistency

**How it works:**

**Logic:**
If "Log out" button exists → User is logged in  
If "Log out" button doesn't exist → User is logged out

**Implementation:**
```python
try:
    browser.find_element(By.ID, LOGOUT_BUTTON)
    return True  # Element found = logged in
except:
    return False  # Element not found = logged out
```

**Why this approach?**
- Simple and reliable
- "Log out" button only visible when logged in
- Single source of truth for login state

**Alternative approaches (not used):**
1. Check for "Log in" button absence (opposite logic, confusing)
2. Check for welcome message (more complex)
3. Check cookies (less reliable, more code)

**Usage in tests:**

**Positive test:**
```python
perform_login(browser, valid_user, valid_pass)
assert is_user_logged_in(browser), "User should be logged in"
```

**Negative test:**
```python
perform_login(browser, invalid_user, invalid_pass)
assert not is_user_logged_in(browser), "User should NOT be logged in"
```

**Return type:** Boolean (True/False)

---

<a name="tests"></a>
## 9. Test Functions Breakdown

### Test: `test_login_valid_credentials(login_page)`

**Test ID:** TC-LOGIN-001  
**Type:** Positive test  
**Priority:** Critical

**What it tests:**
Successful login with correct username and password

**Step-by-step flow:**

1. **Arrange (Setup):**
   ```python
   # login_page fixture already opened modal
   # No explicit setup needed
   ```

2. **Act (Perform action):**
   ```python
   perform_login(login_page, TEST_USERNAME, TEST_PASSWORD)
   ```
   - Enters valid credentials
   - Clicks submit

3. **Wait for processing:**
   ```python
   time.sleep(2)
   ```
   - Allows time for login to complete
   - DemoBlaze may take a moment to process

4. **Assert (Verify results):**
   
   **Assertion 1: User is logged in**
   ```python
   assert is_user_logged_in(login_page), "User should be logged in after valid credentials"
   ```
   - Checks if "Log out" button exists
   - Fails if user not logged in

   **Assertion 2: Username displayed**
   ```python
   welcome_element = login_page.find_element(By.ID, WELCOME_USER_TEXT)
   assert TEST_USERNAME in welcome_element.text, f"Welcome message should contain username '{TEST_USERNAME}'"
   ```
   - Finds welcome message element
   - Verifies it contains the username
   - Example: "Welcome testuser_qa_2024"

**Why two assertions?**
- Tests two distinct aspects:
  1. Authentication succeeded (logout button)
  2. Correct user authenticated (username display)
- More thorough validation

**Success criteria:**
- ✅ Both assertions pass
- ✅ No exceptions thrown
- ✅ Test marked as PASSED

---

### Test: `test_login_invalid_password(login_page)`

**Test ID:** TC-LOGIN-002  
**Type:** Negative test  
**Priority:** High

**What it tests:**
Correct error handling when password is wrong

**Step-by-step flow:**

1. **Act:**
   ```python
   perform_login(login_page, TEST_USERNAME, "wrongpassword123")
   ```
   - Valid username (exists in system)
   - Invalid password (incorrect)

2. **Capture error:**
   ```python
   alert_text = wait_for_alert_and_get_text(login_page)
   ```
   - Waits for error alert
   - Gets message text
   - Closes alert

3. **Assert:**
   
   **Assertion 1: Correct error message**
   ```python
   assert alert_text == "Wrong password.", f"Expected 'Wrong password.' but got '{alert_text}'"
   ```
   - Exact match required
   - Case-sensitive
   - Includes period

   **Assertion 2: Login failed**
   ```python
   assert not is_user_logged_in(login_page), "User should NOT be logged in with wrong password"
   ```
   - Verifies "Log out" button absent
   - Confirms authentication rejected

**Why this test matters:**
- Validates error handling
- Ensures system doesn't grant access with wrong password
- Checks user feedback (error message)

**Possible failures:**
- ❌ Wrong error message text
- ❌ User somehow logged in (security issue)
- ❌ No alert appeared (broken error handling)

---

### Test: `test_login_nonexistent_user(login_page)`

**Test ID:** TC-LOGIN-003  
**Type:** Negative test  
**Priority:** High

**What it tests:**
Error handling when username doesn't exist

**Step-by-step flow:**

1. **Act:**
   ```python
   perform_login(login_page, "nonexistent_user_xyz_999", "anypassword")
   ```
   - Username that definitely doesn't exist
   - Random password (doesn't matter)

2. **Capture error:**
   ```python
   alert_text = wait_for_alert_and_get_text(login_page)
   ```

3. **Assert:**
   
   **Assertion 1: Correct error message**
   ```python
   assert alert_text == "User does not exist.", f"Expected 'User does not exist.' but got '{alert_text}'"
   ```

   **Assertion 2: Login failed**
   ```python
   assert not is_user_logged_in(login_page), "User should NOT be logged in with invalid username"
   ```

**Security note:**
This test documents Bug #10 (username enumeration). Different error messages for "wrong password" vs "user doesn't exist" allow attackers to discover valid usernames.

**Expected behavior after bug fix:**
Both scenarios should return generic message:
- "Invalid username or password."

---

### Test: `test_login_empty_fields(login_page)`

**Test ID:** TC-LOGIN-004  
**Type:** Negative test  
**Priority:** Medium

**What it tests:**
Client-side validation when fields are empty

**Step-by-step flow:**

1. **Act:**
   ```python
   perform_login(login_page, "", "")
   ```
   - Both fields empty strings
   - Tests form validation

2. **Capture validation message:**
   ```python
   alert_text = wait_for_alert_and_get_text(login_page)
   ```

3. **Assert:**
   ```python
   assert alert_text == "Please fill out Username and Password.", \
       f"Expected validation message but got '{alert_text}'"
   ```

**Why this test matters:**
- Validates client-side validation exists
- Prevents unnecessary server requests
- Improves user experience (immediate feedback)

**Expected behavior:**
- Form not submitted to server
- JavaScript alert appears
- User remains on page

---

### Test: `test_login_weak_password_vulnerability(browser)`

**Test ID:** TC-LOGIN-005  
**Type:** Security test  
**Priority:** Critical  
**Status:** Expected to fail (Bug #11)

**What it tests:**
Documents that system accepts dangerously weak passwords

**Marked as xfail:**
```python
@pytest.mark.xfail(reason="Bug #11: System accepts weak passwords")
```

**Why xfail?**
- Bug is known and documented
- Test will fail until bug is fixed
- When bug is fixed, test will start passing
- Serves as regression test

**Step-by-step flow:**

1. **Generate unique username:**
   ```python
   timestamp = str(int(time.time()))
   test_user = f"weakpass_test_{timestamp}"
   ```
   - Prevents "username exists" errors
   - Each test run uses different username

2. **Define weak password:**
   ```python
   weak_password = "123"
   ```
   - Obviously insecure
   - Should be rejected

3. **Navigate to registration:**
   ```python
   browser.get(BASE_URL)
   signup_btn = browser.find_element(By.ID, "signin2")
   signup_btn.click()
   ```

4. **Wait for modal:**
   ```python
   WebDriverWait(browser, TIMEOUT).until(
       EC.visibility_of_element_located((By.ID, "sign-username"))
   )
   ```

5. **Register with weak password:**
   ```python
   browser.find_element(By.ID, "sign-username").send_keys(test_user)
   browser.find_element(By.ID, "sign-password").send_keys(weak_password)
   browser.find_element(By.XPATH, "//button[text()='Sign up']").click()
   ```

6. **Check registration result:**
   ```python
   alert_text = wait_for_alert_and_get_text(browser)
   ```

7. **Assert (expected to fail):**
   ```python
   assert "Password too weak" in alert_text or "password requirements" in alert_text.lower(), \
       "System should reject weak passwords (Bug #11)"
   ```

**Current behavior (bug exists):**
- Registration succeeds
- "123" accepted as valid password
- Test fails (as expected)

**Expected behavior (after fix):**
- Registration rejected
- Error message about password requirements
- Test passes

**Security impact:**
- Users can create easily guessed passwords
- Accounts vulnerable to brute force
- Violates security best practices

---

### Test: `test_username_enumeration_vulnerability(login_page)`

**Test ID:** TC-LOGIN-006  
**Type:** Security test  
**Priority:** Critical  
**Status:** Expected to fail (Bug #10)

**What it tests:**
Documents username enumeration vulnerability through different error messages

**Marked as xfail:**
```python
@pytest.mark.xfail(reason="Bug #10: Username enumeration vulnerability")
```

**Step-by-step flow:**

1. **Test existing username with wrong password:**
   ```python
   perform_login(login_page, TEST_USERNAME, "wrong_password_xyz")
   error_msg_existing_user = wait_for_alert_and_get_text(login_page)
   ```
   - Result: "Wrong password."

2. **Reopen login modal:**
   ```python
   login_page.find_element(By.ID, LOGIN_BUTTON_NAV).click()
   time.sleep(1)
   ```
   - Necessary because modal closed after first attempt

3. **Test non-existent username:**
   ```python
   perform_login(login_page, "definitely_not_a_real_user_xyz", "any_password")
   error_msg_nonexistent_user = wait_for_alert_and_get_text(login_page)
   ```
   - Result: "User does not exist."

4. **Compare error messages:**
   ```python
   assert error_msg_existing_user == error_msg_nonexistent_user, \
       f"Error messages should be identical to prevent username enumeration. " \
       f"Got: '{error_msg_existing_user}' vs '{error_msg_nonexistent_user}' (Bug #10)"
   ```

**Current behavior (bug exists):**
- Different messages reveal username validity
- Test fails (as expected)

**Attack scenario:**
1. Attacker tries login with username "admin"
2. Sees "Wrong password." → "admin" exists!
3. Attacker tries login with username "randomuser123"
4. Sees "User does not exist." → Not a valid username
5. Attacker builds list of valid usernames
6. Launches targeted password attacks

**Expected behavior (after fix):**
- Same generic message for all failed logins
- Example: "Invalid credentials."
- Test passes

**OWASP reference:**
This vulnerability appears in OWASP Top 10 under "Broken Authentication"

---

<a name="locators"></a>
## 10. How to Obtain Locators

### Tools Needed

**Browser DevTools (F12 or Right-click → Inspect)**
- Chrome: Best for web automation testing
- Firefox: Good alternative
- Edge: Also works well

---

### Method 1: Using Browser Inspector

**Step-by-step for "Log in" button:**

1. **Navigate to page:**
   - Open https://www.demoblaze.com/

2. **Open DevTools:**
   - Press F12, or
   - Right-click anywhere → Inspect

3. **Select element picker:**
   - Click the cursor icon (top-left of DevTools)
   - Or press Ctrl+Shift+C

4. **Click the element:**
   - Hover over "Log in" button
   - Click it

5. **Read HTML:**
   ```html
   <a id="login2" data-toggle="modal" data-target="#logInModal">Log in</a>
   ```

6. **Extract locator:**
   - See `id="login2"`
   - Use: `By.ID, "login2"`

---

### Method 2: Manual Search in HTML

**When to use:**
- Element is hidden
- Element appears after interaction
- Need to find multiple similar elements

**Steps:**

1. **Open DevTools (F12)**

2. **Go to Elements/Inspector tab**

3. **Use search (Ctrl+F in DevTools)**
   - Search for text: "Log in"
   - Search for attribute: `id="login`
   - Search for class: `class="form-control"`

4. **Navigate HTML tree:**
   - Expand/collapse elements
   - Find target element

5. **Copy locator:**
   - Right-click element in HTML
   - Copy → Copy selector (CSS)
   - Copy → Copy XPath

---

### Locator Strategy Decision Tree

**Question 1: Does element have a unique ID?**
- ✅ Yes → Use ID (fastest, most reliable)
  ```python
  By.ID, "loginusername"
  ```
- ❌ No → Go to Question 2

**Question 2: Does element have unique name attribute?**
- ✅ Yes → Use NAME
  ```python
  By.NAME, "username"
  ```
- ❌ No → Go to Question 3

**Question 3: Is element easily identified by class?**
- ✅ Yes → Use CSS Selector
  ```python
  By.CSS_SELECTOR, ".login-button"
  ```
- ❌ No → Go to Question 4

**Question 4: Does element have unique text?**
- ✅ Yes → Use XPath with text
  ```python
  By.XPATH, "//button[text()='Log in']"
  ```
- ❌ No → Use complex XPath

---

### Locator Examples from This Project

#### Example 1: Login Button (ID)
**HTML:**
```html
<a id="login2">Log in</a>
```

**Locator options:**
```python
# Best (ID)
By.ID, "login2"

# Also works (CSS)
By.CSS_SELECTOR, "#login2"

# Also works (XPath)
By.XPATH, "//a[@id='login2']"
```

**Chosen:** ID (simplest and fastest)

---

#### Example 2: Username Field (ID)
**HTML:**
```html
<input type="text" id="loginusername" class="form-control" placeholder="Username">
```

**Locator options:**
```python
# Best (ID)
By.ID, "loginusername"

# Works (CSS with attribute)
By.CSS_SELECTOR, "input[placeholder='Username']"

# Works (XPath)
By.XPATH, "//input[@type='text' and @id='loginusername']"
```

**Chosen:** ID

---

#### Example 3: Submit Button (XPath with text)
**HTML:**
```html
<button type="button" class="btn btn-primary" onclick="logIn()">Log in</button>
```

**Why not ID?** No unique ID attribute

**Locator options:**
```python
# Good (XPath text)
By.XPATH, "//button[text()='Log in']"

# Works (CSS with onclick)
By.CSS_SELECTOR, "button[onclick='logIn()']"

# Fragile (classes can change)
By.CSS_SELECTOR, "button.btn.btn-primary"
```

**Chosen:** XPath with text (readable and distinctive)

---

### Testing Your Locators

**In Python console:**
```python
from selenium import webdriver
from selenium.webdriver.common.by import By

driver = webdriver.Chrome()
driver.get("https://www.demoblaze.com/")

# Test your locator
element = driver.find_element(By.ID, "login2")
print(element.text)  # Should print "Log in"

driver.quit()
```

**In Browser DevTools Console:**
```javascript
// Test CSS Selector
document.querySelector("#login2")

// Test XPath
$x("//button[text()='Log in']")
```

If element is found, locator works!

---

<a name="execution"></a>
## 11. Execution Guide

### Prerequisites Check

Before running tests, verify:

```bash
# Python version (should be 3.8+)
python --version

# pip version
pip --version

# Selenium installed
pip show selenium

# pytest installed
pip show pytest
```

---

### Running Tests

#### Run all tests in file:
```bash
pytest tests/test_dem_login.py
```

**Output example:**
```
collected 6 items

test_dem_login.py::test_login_valid_credentials PASSED           [ 16%]
test_dem_login.py::test_login_invalid_password PASSED            [ 33%]
test_dem_login.py::test_login_nonexistent_user PASSED            [ 50%]
test_dem_login.py::test_login_empty_fields PASSED                [ 66%]
test_dem_login.py::test_login_weak_password_vulnerability XFAIL  [ 83%]
test_dem_login.py::test_username_enumeration_vulnerability XFAIL [100%]

====================== 4 passed, 2 xfailed in 45.23s =======================
```

---

#### Run specific test:
```bash
pytest tests/test_dem_login.py::test_login_valid_credentials
```

---

#### Run with verbose output:
```bash
pytest tests/test_dem_login.py -v
```

**Shows:**
- Detailed test names
- Docstring summaries
- Progress indicators

---

#### Run with HTML report:
```bash
pytest tests/test_dem_login.py --html=reports/login_report.html --self-contained-html
```

**Generates:**
- Professional HTML report
- Test results summary
- Failure details
- Execution time

**View report:**
```bash
# Open in browser
reports/login_report.html
```

---

#### Run with custom markers:
```bash
# Run only xfail tests (security bugs)
pytest tests/test_dem_login.py -m xfail

# Skip xfail tests (run only stable tests)
pytest tests/test_dem_login.py -m "not xfail"
```

---

#### Run with print statements (for debugging):
```bash
pytest tests/test_dem_login.py -s
```

**Shows:**
- `print()` output
- Useful for debugging

---

#### Run with last failed:
```bash
# Run only tests that failed last time
pytest tests/test_dem_login.py --lf
```

**Use case:**
- Fixed a bug
- Re-run only failed tests
- Faster iteration

---

### Continuous Integration (CI) Command

**For GitHub Actions / Jenkins / etc:**
```bash
pytest tests/test_dem_login.py --html=reports/report.html --self-contained-html --maxfail=1 -v
```

**Flags explained:**
- `--html=...` - Generate report
- `--self-contained-html` - Single file (no dependencies)
- `--maxfail=1` - Stop after first failure (fail fast)
- `-v` - Verbose output for CI logs

---

<a name="results"></a>
## 12. Expected Results

### Test Execution Summary

| Test Case | ID | Expected Result | Status |
|-----------|----|--------------------|--------|
| Valid Login | TC-LOGIN-001 | ✅ PASS | Stable |
| Invalid Password | TC-LOGIN-002 | ✅ PASS | Stable |
| Non-existent User | TC-LOGIN-003 | ✅ PASS | Stable |
| Empty Fields | TC-LOGIN-004 | ✅ PASS | Stable |
| Weak Password | TC-LOGIN-005 | ❌ XFAIL | Bug #11 |
| Username Enumeration | TC-LOGIN-006 | ❌ XFAIL | Bug #10 |

---

### Success Criteria

**Test suite is considered PASSED if:**
1. ✅ 4 stable tests pass (TC-LOGIN-001 through 004)
2. ✅ 2 xfail tests fail as expected (TC-LOGIN-005, 006)
3. ✅ No unexpected failures
4. ✅ No exceptions/errors in stable tests
5. ✅ Execution time under 2 minutes

---

### Failure Investigation

**If test fails unexpectedly:**

1. **Check error message:**
   ```bash
   pytest tests/test_dem_login.py -v
   ```

2. **Read traceback:**
   - Which line failed?
   - What was the assertion?

3. **Common issues:**

   **Timeout errors:**
   - Site is slow
   - Element locator changed
   - Internet connection issue
   
   **Element not found:**
   - Locator changed (site updated)
   - Element takes longer to appear
   - Wrong environment (dev vs prod)
   
   **Assertion failures:**
   - Expected vs actual mismatch
   - Logic error in test
   - Application bug

4. **Debug with print statements:**
   ```python
   # Add to test
   print(f"Alert text: {alert_text}")
   print(f"Logged in: {is_user_logged_in(browser)}")
   ```
   
   Run with:
   ```bash
   pytest tests/test_dem_login.py -s
   ```

---

### Performance Benchmarks

**Expected execution times:**

| Test | Avg Time | Max Acceptable |
|------|----------|----------------|
| test_login_valid_credentials | 8s | 15s |
| test_login_invalid_password | 6s | 12s |
| test_login_nonexistent_user | 6s | 12s |
| test_login_empty_fields | 5s | 10s |
| test_login_weak_password_vulnerability | 12s | 20s |
| test_username_enumeration_vulnerability | 10s | 18s |
| **Total Suite** | **47s** | **90s** |

**If tests are slower:**
- Reduce `TIMEOUT` (if site is fast)
- Check internet connection
- Site may be experiencing issues

---

<a name="troubleshooting"></a>
## 13. Troubleshooting

### Common Issues and Solutions

#### Issue 1: ChromeDriver version mismatch

**Error:**
```
selenium.common.exceptions.SessionNotCreatedException: 
Message: session not created: This version of ChromeDriver only supports Chrome version 118
```

**Solution:**
```bash
# Reinstall webdriver-manager
pip uninstall webdriver-manager
pip install webdriver-manager

# Clear cache
rm -rf ~/.wdm
```

**Why it happens:**
- Chrome auto-updates
- ChromeDriver doesn't match

---

#### Issue 2: Element not found

**Error:**
```
selenium.common.exceptions.NoSuchElementException: 
Message: no such element: Unable to locate element: {"method":"css selector","selector":"#login2"}
```

**Possible causes:**
1. Page not loaded yet
2. Locator changed
3. Element inside iframe

**Solution 1: Add wait**
```python
WebDriverWait(browser, 10).until(
    EC.presence_of_element_located((By.ID, "login2"))
)
```

**Solution 2: Verify locator**
- Inspect element manually
- Check if ID still exists
- Try alternative locator

**Solution 3: Check for iframe**
```python
# Switch to iframe if element is inside one
browser.switch_to.frame("iframe_name")
element = browser.find_element(By.ID, "login2")
```

---

#### Issue 3: Test hangs indefinitely

**Symptom:**
- Test runs but never completes
- No error message

**Causes:**
- Alert not handled
- Infinite wait
- Modal not closed

**Solution:**
```bash
# Kill test with Ctrl+C

# Add timeout to problematic operation
# Example:
WebDriverWait(browser, 5).until(...)  # Reduce timeout
```

---

#### Issue 4: Tests pass locally but fail in CI

**Possible causes:**
1. Different environment
2. Timing issues (CI is slower)
3. Browser/driver version mismatch

**Solutions:**

**Increase timeouts for CI:**
```python
# In conftest.py or similar
import os

if os.getenv('CI'):
    TIMEOUT = 20  # Double timeout in CI
else:
    TIMEOUT = 10
```

**Headless mode for CI:**
```python
options = webdriver.ChromeOptions()
options.add_argument('--headless')
driver = webdriver.Chrome(options=options)
```

---

#### Issue 5: Weak password test passes (should be xfail)

**What it means:**
- Bug #11 was fixed!
- System now rejects weak passwords

**What to do:**
1. Remove `@pytest.mark.xfail` decorator
2. Update test to expect password rejection
3. Update bug status to "Fixed"

---

<a name="practices"></a>
## 14. Best Practices Applied

### Code Quality

#### ✅ DRY (Don't Repeat Yourself)
**Applied in:**
- Helper functions (`perform_login`, `wait_for_alert_and_get_text`)
- Fixtures (browser setup/teardown)
- Configuration constants

**Benefit:** Change once, apply everywhere

---

#### ✅ Single Responsibility Principle
**Applied in:**
- Each function does one thing
- `perform_login()` only performs login
- `is_user_logged_in()` only checks state

**Benefit:** Easy to understand and maintain

---

#### ✅ Explicit is Better Than Implicit
**Applied in:**
- Named constants instead of magic strings
- Clear function names
- Descriptive variable names

**Example:**
```python
# ✅ Good
LOGIN_BUTTON_NAV = "login2"
browser.find_element(By.ID, LOGIN_BUTTON_NAV)

# ❌ Bad
browser.find_element(By.ID, "login2")  # What is login2?
```

---

### Testing Best Practices

#### ✅ Test Isolation
**Implementation:**
- Each test gets fresh browser
- No shared state between tests
- Tests can run in any order

**Benefit:** Reliable, reproducible results

---

#### ✅ AAA Pattern (Arrange-Act-Assert)
**Applied in all tests:**
```python
def test_example():
    # Arrange
    username = "test"
    
    # Act
    perform_login(browser, username, password)
    
    # Assert
    assert is_user_logged_in(browser)
```

**Benefit:** Clear test structure

---

#### ✅ Meaningful Test Names
**Convention:**
```
test_[module]_[action]_[context]
```

**Examples:**
- `test_login_valid_credentials` ✅
- `test_login_invalid_password` ✅
- `test1` ❌

**Benefit:** Self-documenting code

---

#### ✅ Expected Failures (xfail)
**For known bugs:**
```python
@pytest.mark.xfail(reason="Bug #11: Weak passwords")
def test_weak_password_vulnerability():
    # Tests known bug
```

**Benefits:**
- Documents bugs in code
- Regression testing ready
- Clear distinction between expected/unexpected failures

---

### Documentation Best Practices

#### ✅ Separate Documentation File
**This file (test_dem_login.md) provides:**
- Comprehensive explanation
- Clean code (no comment clutter)
- Easy to read
- Can be versioned separately

---

#### ✅ Traceability
**Links between:**
- Test cases (TC-LOGIN-001)
- Bug reports (Bug #10, #11)
- Test functions
- Documentation sections

**Benefit:** Easy to navigate between artifacts

---

#### ✅ How-To Sections
**Includes:**
- How to obtain locators
- How to run tests
- Troubleshooting guide

**Benefit:** Self-service for other team members

---

### Selenium Best Practices

#### ✅ Explicit Waits
**Used instead of:**
```python
# ❌ Bad
time.sleep(5)  # Arbitrary wait

# ✅ Good
WebDriverWait(browser, 10).until(
    EC.visibility_of_element_located((By.ID, "element"))
)
```

**Benefits:**
- Faster tests (wait only as needed)
- More reliable
- Better error messages

---

#### ✅ WebDriver Manager
**Auto-manages drivers:**
```python
ChromeDriverManager().install()
```

**Benefits:**
- No manual driver downloads
- Always correct version
- Cross-platform compatible

---

#### ✅ Locator Strategy Hierarchy
**Priority:**
1. ID (fastest, most reliable)
2. Name
3. CSS Selector
4. XPath (last resort)

**Applied:** Used IDs where available, XPath only when necessary

---

## 15. Maintenance Guide

### When to Update Tests

**Trigger 1: Site Redesign**
- Locators may change
- Update `CONFIGURATION` section
- Re-verify all element IDs

**Trigger 2: Bug Fixes**
- Remove `@pytest.mark.xfail` when bug resolved
- Update expected behavior
- Change assertions if needed

**Trigger 3: New Features**
- Add new test cases
- Update documentation
- Maintain same structure

---

### How to Add New Tests

1. **Add to documentation first:**
   - New test case in section 2
   - Expected results in section 12

2. **Write test function:**
   ```python
   def test_login_[new_scenario](login_page):
       # Follow AAA pattern
       pass
   ```

3. **Update this file:**
   - Add to Table of Contents
   - Add to Test Cases section
   - Add to Expected Results

---

### Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | Nov 2025 | Arévalo, Marc | Initial documentation |

---

## 16. Related Documents

- [Test Plan](../docs/test-plan.md)
- [Test Summary Report](../docs/Test_Summary_Report.md)
- [Bug #10: Username Enumeration](../docs/bugs/bug-010-username-enumeration.md)
- [Bug #11: Weak Passwords](../docs/bugs/bug-011-weak-passwords.md)
- [Bug #12: No Rate Limiting](../docs/bugs/bug-012-no-rate-limiting.md)

---

## 17. Contact & Support

**Test Suite Author:**  
Marc Arévalo  
GitHub: [Your GitHub Username]

**Questions?**
- Review this documentation first
- Check Troubleshooting section
- Examine test code
- Open GitHub issue if problem persists

---

**End of Documentation**
