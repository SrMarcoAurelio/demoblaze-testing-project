# Migration Guide: Robot Framework → Universal Test Framework

**Comprehensive guide for migrating from Robot Framework to this Python pytest-based framework**

---

## 📋 Overview

This guide helps teams migrate from Robot Framework's keyword-driven approach to this modern Python pytest framework with Page Object Model.

**Migration Time**: 6-12 hours for typical test suite (50-100 test cases)

**Why Migrate?**
- ✅ Full Python power (not keyword-limited)
- ✅ Better IDE support (autocomplete, refactoring)
- ✅ Type safety with type hints
- ✅ More flexible test logic
- ✅ Native Python debugging
- ✅ Better integration with Python ecosystems
- ✅ Faster test execution (60-80% with optimizations)
- ✅ Modern development practices (pre-commit, mypy, black)

**When NOT to Migrate:**
- ❌ Non-technical team members write tests
- ❌ Business users need to read/modify tests directly
- ❌ Heavy investment in Robot Framework ecosystem
- ❌ Keyword-driven approach is core requirement

---

## Table of Contents

1. [Quick Comparison](#quick-comparison)
2. [Concept Mapping](#concept-mapping)
3. [Keyword to Python Translation](#keyword-to-python-translation)
4. [Step-by-Step Migration](#step-by-step-migration)
5. [Code Examples](#code-examples)
6. [Migration Patterns](#migration-patterns)
7. [Troubleshooting](#troubleshooting)

---

## Quick Comparison

| Feature | Robot Framework | This Framework (pytest) |
|---------|----------------|------------------------|
| **Language** | Keyword-driven (DSL) | Pure Python |
| **Test Format** | `.robot` files | `.py` files |
| **Syntax** | Space/tab separated | Python syntax |
| **Libraries** | SeleniumLibrary | Selenium + pytest |
| **Page Objects** | Keywords/Resources | Python classes |
| **Variables** | `${variable}` | Python variables |
| **Loops** | `FOR` keyword | `for` loop |
| **Conditions** | `Run Keyword If` | `if/elif/else` |
| **Setup/Teardown** | Test Setup/Teardown | `@pytest.fixture` |
| **Assertions** | `Should Be Equal` | `assert` |
| **Parametrization** | Test Template | `@pytest.mark.parametrize` |
| **Reports** | HTML (Robot) | HTML, Allure, custom |
| **IDE Support** | Limited | Full (VSCode, PyCharm) |
| **Debugging** | Limited | Full Python debugging |
| **Type Safety** | No | Yes (type hints) |

---

## Concept Mapping

### Test Case Structure

**Robot Framework:**
```robot
*** Test Cases ***
Valid Login Test
    [Documentation]    Test successful login with valid credentials
    [Tags]    smoke    functional
    [Setup]    Open Browser    ${URL}    chrome

    Input Text    id=username    testuser
    Input Text    id=password    testpass123
    Click Button    id=login-btn
    Page Should Contain    Welcome

    [Teardown]    Close Browser
```

**This Framework:**
```python
import pytest

@pytest.mark.smoke
@pytest.mark.functional
def test_valid_login(browser, base_url, login_page):
    """Test successful login with valid credentials"""
    browser.get(base_url)

    login_page.login("testuser", "testpass123")

    assert login_page.is_logged_in()
    assert "Welcome" in login_page.get_welcome_message()
```

### Variables

**Robot Framework:**
```robot
*** Variables ***
${USERNAME}       testuser
${PASSWORD}       testpass123
${URL}            https://example.com
```

**This Framework:**
```python
# In .env file
TEST_USERNAME=testuser
TEST_PASSWORD=testpass123
BASE_URL=https://example.com

# Or in Python
USERNAME = "testuser"
PASSWORD = "testpass123"
URL = "https://example.com"
```

### Keywords (Functions)

**Robot Framework:**
```robot
*** Keywords ***
Login With Credentials
    [Arguments]    ${username}    ${password}
    Input Text    id=username    ${username}
    Input Text    id=password    ${password}
    Click Button    id=login-btn
```

**This Framework:**
```python
# In page object
class LoginPage:
    def login(self, username: str, password: str) -> None:
        """Login with given credentials"""
        self.interactor.type_text(self.USERNAME_FIELD, username)
        self.interactor.type_text(self.PASSWORD_FIELD, password)
        self.interactor.click(self.LOGIN_BUTTON)
```

### Loops

**Robot Framework:**
```robot
*** Test Cases ***
Test Multiple Users
    FOR    ${user}    IN    @{USERS}
        Login With Credentials    ${user.username}    ${user.password}
        Verify Login Success
        Logout
    END
```

**This Framework:**
```python
@pytest.mark.parametrize("user", USERS)
def test_user_login(login_page, user):
    """Test login with multiple users"""
    login_page.login(user['username'], user['password'])
    assert login_page.is_logged_in()
    login_page.logout()
```

### Conditions

**Robot Framework:**
```robot
*** Test Cases ***
Conditional Test
    ${status}=    Get Element Attribute    id=status    value
    Run Keyword If    '${status}' == 'active'    Click Button    id=activate-btn
    ...    ELSE    Click Button    id=deactivate-btn
```

**This Framework:**
```python
def test_conditional_action(browser):
    """Test conditional button click"""
    status = browser.find_element(By.ID, "status").get_attribute("value")

    if status == "active":
        browser.find_element(By.ID, "activate-btn").click()
    else:
        browser.find_element(By.ID, "deactivate-btn").click()
```

---

## Keyword to Python Translation

### Common SeleniumLibrary Keywords

| Robot Keyword | Python Equivalent |
|--------------|------------------|
| `Open Browser` | `driver = webdriver.Chrome()` |
| `Go To` | `driver.get(url)` |
| `Click Button` | `driver.find_element(...).click()` |
| `Click Element` | `driver.find_element(...).click()` |
| `Input Text` | `driver.find_element(...).send_keys(text)` |
| `Input Password` | `driver.find_element(...).send_keys(password)` |
| `Select From List` | `Select(element).select_by_visible_text()` |
| `Get Text` | `driver.find_element(...).text` |
| `Get Element Attribute` | `driver.find_element(...).get_attribute(attr)` |
| `Page Should Contain` | `assert text in driver.page_source` |
| `Element Should Be Visible` | `assert element.is_displayed()` |
| `Wait Until Element Is Visible` | `WebDriverWait().until(EC.visibility_of_element_located())` |
| `Close Browser` | `driver.quit()` |

### Common BuiltIn Keywords

| Robot Keyword | Python Equivalent |
|--------------|------------------|
| `Log` | `print()` or `logger.info()` |
| `Should Be Equal` | `assert a == b` |
| `Should Contain` | `assert x in y` |
| `Should Be True` | `assert condition` |
| `Should Not Be Empty` | `assert value` |
| `Set Variable` | `variable = value` |
| `Sleep` | `time.sleep()` (avoid!) |
| `Run Keyword If` | `if condition:` |
| `Run Keywords` | Multiple statements |
| `Create List` | `list = [...]` |
| `Create Dictionary` | `dict = {...}` |

### Framework-Specific Translations

| Robot Concept | This Framework |
|--------------|----------------|
| `Suite Setup` | `@pytest.fixture(scope="session")` |
| `Suite Teardown` | Fixture with `yield` |
| `Test Setup` | `@pytest.fixture(scope="function")` |
| `Test Teardown` | Fixture with `yield` |
| `Test Template` | `@pytest.mark.parametrize` |
| `[Tags]` | `@pytest.mark.tagname` |
| `Resource Files` | Python modules with imports |
| `Variables Files` | Python modules or .env files |

---

## Step-by-Step Migration

### Step 1: Analyze Robot Framework Tests (1-2 hours)

```bash
# Count test cases
grep -r "^\*\*\* Test Cases \*\*\*" . | wc -l

# Count custom keywords
grep -r "^\*\*\* Keywords \*\*\*" . | wc -l

# Identify libraries used
grep -r "^Library" . | sort | uniq

# Find all tags
grep -r "\[Tags\]" . | awk '{for(i=2;i<=NF;i++) print $i}' | sort | uniq
```

Create inventory:
- Number of test suites (.robot files)
- Number of test cases
- Custom keywords per file
- Resource files
- Variable files
- External libraries used

### Step 2: Setup Framework (30 minutes)

```bash
# Clone and setup
git clone <framework-url>
cd test-automation-framework
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure
cp config/examples/.env.development .env
# Edit with your settings
```

### Step 3: Convert Custom Keywords to Page Objects (3-4 hours)

**Robot Framework Keywords:**
```robot
*** Keywords ***
Login With Credentials
    [Arguments]    ${username}    ${password}
    Wait Until Element Is Visible    id=username    10s
    Input Text    id=username    ${username}
    Input Text    id=password    ${password}
    Click Button    id=login-btn
    Wait Until Page Contains    Welcome    10s

Verify Login Success
    Element Should Be Visible    id=user-menu
    Page Should Contain    Welcome

Logout User
    Click Element    id=user-menu
    Click Link    Logout
    Wait Until Page Contains    Login    5s
```

**Convert to Page Object:**
```python
# pages/login_page.py
from selenium.webdriver.common.by import By
from framework.core import ElementFinder, WaitHandler, ElementInteractor

class LoginPage:
    # Locators
    USERNAME_FIELD = (By.ID, "username")
    PASSWORD_FIELD = (By.ID, "password")
    LOGIN_BUTTON = (By.ID, "login-btn")
    USER_MENU = (By.ID, "user-menu")
    LOGOUT_LINK = (By.LINK_TEXT, "Logout")

    def __init__(self, driver):
        self.driver = driver
        self.finder = ElementFinder(driver)
        self.interactor = ElementInteractor(driver)
        self.waiter = WaitHandler(driver)

    def login(self, username: str, password: str) -> None:
        """Login with credentials (was: Login With Credentials)"""
        self.waiter.wait_for_element_visible(self.USERNAME_FIELD)
        self.interactor.type_text(self.USERNAME_FIELD, username)
        self.interactor.type_text(self.PASSWORD_FIELD, password)
        self.interactor.click(self.LOGIN_BUTTON)
        self.waiter.wait_for_page_to_contain_text("Welcome")

    def is_logged_in(self) -> bool:
        """Verify login success (was: Verify Login Success)"""
        return (
            self.finder.is_element_visible(self.USER_MENU)
            and "Welcome" in self.driver.page_source
        )

    def logout(self) -> None:
        """Logout user (was: Logout User)"""
        self.interactor.click(self.USER_MENU)
        self.interactor.click(self.LOGOUT_LINK)
        self.waiter.wait_for_page_to_contain_text("Login")
```

### Step 4: Convert Test Cases (2-4 hours)

**Robot Framework Test:**
```robot
*** Settings ***
Library           SeleniumLibrary
Resource          resources/login_keywords.robot
Test Setup        Open Browser    ${URL}    chrome
Test Teardown     Close Browser

*** Variables ***
${URL}            https://example.com
${VALID_USER}     testuser
${VALID_PASS}     testpass123

*** Test Cases ***
TC001 - Successful Login
    [Documentation]    Verify successful login with valid credentials
    [Tags]    smoke    login    positive
    Login With Credentials    ${VALID_USER}    ${VALID_PASS}
    Verify Login Success

TC002 - Failed Login
    [Documentation]    Verify login failure with invalid credentials
    [Tags]    login    negative
    Login With Credentials    wronguser    wrongpass
    Page Should Contain    Invalid credentials

TC003 - Logout
    [Documentation]    Verify logout functionality
    [Tags]    smoke    login
    Login With Credentials    ${VALID_USER}    ${VALID_PASS}
    Logout User
    Page Should Contain    Login
```

**Convert to pytest:**
```python
# tests/login/test_login_functional.py
import pytest

@pytest.mark.smoke
@pytest.mark.login
@pytest.mark.positive
def test_tc001_successful_login(browser, base_url, login_page, valid_user):
    """TC001 - Verify successful login with valid credentials"""
    browser.get(base_url)

    login_page.login(valid_user['username'], valid_user['password'])

    assert login_page.is_logged_in()

@pytest.mark.login
@pytest.mark.negative
def test_tc002_failed_login(browser, base_url, login_page):
    """TC002 - Verify login failure with invalid credentials"""
    browser.get(base_url)

    login_page.login("wronguser", "wrongpass")

    assert "Invalid credentials" in browser.page_source

@pytest.mark.smoke
@pytest.mark.login
def test_tc003_logout(browser, base_url, login_page, valid_user):
    """TC003 - Verify logout functionality"""
    browser.get(base_url)

    login_page.login(valid_user['username'], valid_user['password'])
    login_page.logout()

    assert "Login" in browser.page_source
```

**With fixtures (cleaner):**
```python
# conftest.py
@pytest.fixture
def login_page(browser, base_url):
    browser.get(base_url)
    from pages.login_page import LoginPage
    return LoginPage(browser)

@pytest.fixture
def valid_user():
    return {
        'username': os.getenv('TEST_USERNAME', 'testuser'),
        'password': os.getenv('TEST_PASSWORD', 'testpass123')
    }

# tests/login/test_login_functional.py (simplified)
@pytest.mark.smoke
def test_successful_login(login_page, valid_user):
    login_page.login(**valid_user)
    assert login_page.is_logged_in()

def test_failed_login(login_page):
    login_page.login("wronguser", "wrongpass")
    assert "Invalid credentials" in login_page.get_error_message()

@pytest.mark.smoke
def test_logout(login_page, valid_user):
    login_page.login(**valid_user)
    login_page.logout()
    assert login_page.is_on_login_page()
```

### Step 5: Convert Data-Driven Tests (1-2 hours)

**Robot Framework (Test Template):**
```robot
*** Test Cases ***
Login With Multiple Invalid Credentials
    [Template]    Login With Invalid Credentials
    ${EMPTY}         password123    Username is required
    testuser         ${EMPTY}       Password is required
    a                password       Username too short
    verylongusername password       Username too long

*** Keywords ***
Login With Invalid Credentials
    [Arguments]    ${username}    ${password}    ${expected_error}
    Input Text    id=username    ${username}
    Input Text    id=password    ${password}
    Click Button  id=login-btn
    Page Should Contain    ${expected_error}
```

**Convert to pytest.mark.parametrize:**
```python
@pytest.mark.parametrize("username,password,expected_error", [
    ("", "password123", "Username is required"),
    ("testuser", "", "Password is required"),
    ("a", "password", "Username too short"),
    ("verylongusername", "password", "Username too long"),
], ids=[
    "empty_username",
    "empty_password",
    "short_username",
    "long_username",
])
def test_login_validation(login_page, username, password, expected_error):
    """Test login validation with invalid credentials"""
    login_page.login(username, password)

    error_message = login_page.get_error_message()
    assert expected_error in error_message
```

---

## Code Examples

### Example 1: Simple Test Conversion

**Robot Framework:**
```robot
*** Test Cases ***
Verify Homepage Title
    [Documentation]    Check homepage has correct title
    [Tags]    smoke
    Open Browser    https://example.com    chrome
    Title Should Be    Example Domain
    Close Browser
```

**Pytest:**
```python
@pytest.mark.smoke
def test_homepage_title(browser, base_url):
    """Check homepage has correct title"""
    browser.get(base_url)
    assert browser.title == "Example Domain"
```

### Example 2: Complex Workflow Conversion

**Robot Framework:**
```robot
*** Test Cases ***
Complete Purchase Flow
    [Documentation]    Test end-to-end purchase
    [Setup]    Open Browser And Login

    Navigate To Products
    Add Product To Cart    Samsung Galaxy S9
    Go To Cart
    Verify Product In Cart    Samsung Galaxy S9
    Proceed To Checkout
    Fill Payment Details    ${CARD_DATA}
    Complete Purchase
    Verify Order Confirmation

    [Teardown]    Close Browser

*** Keywords ***
Open Browser And Login
    Open Browser    ${URL}    chrome
    Login With Credentials    ${USER}    ${PASS}

Navigate To Products
    Click Link    Products
    Wait Until Page Contains    Product Catalog

Add Product To Cart
    [Arguments]    ${product_name}
    Click Element    xpath=//div[contains(text(),'${product_name}')]
    Click Button    Add to cart
    Wait Until Page Contains    Product added
```

**Pytest:**
```python
@pytest.mark.functional
def test_complete_purchase_flow(logged_in_user, catalog_page, cart_page, checkout_page):
    """Test end-to-end purchase (was: Complete Purchase Flow)"""
    # Navigate to products (was: Navigate To Products)
    catalog_page.navigate()

    # Add product to cart (was: Add Product To Cart)
    product = catalog_page.select_product("Samsung Galaxy S9")
    product.add_to_cart()

    # Go to cart and verify (was: Go To Cart + Verify Product In Cart)
    cart_page.navigate()
    assert cart_page.has_product("Samsung Galaxy S9")

    # Checkout (was: Proceed To Checkout)
    checkout_page = cart_page.proceed_to_checkout()

    # Fill payment and complete (was: Fill Payment Details + Complete Purchase)
    checkout_page.fill_payment_details(CARD_DATA)
    order_page = checkout_page.complete_purchase()

    # Verify (was: Verify Order Confirmation)
    assert order_page.has_confirmation()
```

### Example 3: Resource File Conversion

**Robot Framework Resource:**
```robot
*** Settings ***
Library    SeleniumLibrary

*** Variables ***
${TIMEOUT}    10s

*** Keywords ***
Wait And Click
    [Arguments]    ${locator}
    Wait Until Element Is Visible    ${locator}    ${TIMEOUT}
    Click Element    ${locator}

Get Element Text With Wait
    [Arguments]    ${locator}
    Wait Until Element Is Visible    ${locator}    ${TIMEOUT}
    ${text}=    Get Text    ${locator}
    [Return]    ${text}
```

**Python Module:**
```python
# utils/selenium_helpers.py
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

TIMEOUT = 10

def wait_and_click(driver, locator, timeout=TIMEOUT):
    """Wait for element and click (was: Wait And Click)"""
    element = WebDriverWait(driver, timeout).until(
        EC.element_to_be_clickable(locator)
    )
    element.click()
    return element

def get_element_text_with_wait(driver, locator, timeout=TIMEOUT):
    """Get element text after waiting (was: Get Element Text With Wait)"""
    element = WebDriverWait(driver, timeout).until(
        EC.visibility_of_element_located(locator)
    )
    return element.text
```

---

## Migration Patterns

### Pattern 1: Suite Setup → Session Fixture

**Robot:**
```robot
*** Settings ***
Suite Setup    Initialize Test Environment
Suite Teardown    Cleanup Test Environment

*** Keywords ***
Initialize Test Environment
    Create Test Database
    Load Test Data
```

**Pytest:**
```python
@pytest.fixture(scope="session")
def test_environment():
    """Initialize test environment (was: Suite Setup/Teardown)"""
    # Setup
    create_test_database()
    load_test_data()

    yield  # Tests run here

    # Teardown
    cleanup_test_environment()
```

### Pattern 2: Test Tags → Pytest Markers

**Robot:**
```robot
*** Test Cases ***
Test Login
    [Tags]    smoke    critical    authentication
    # test code
```

**Pytest:**
```python
@pytest.mark.smoke
@pytest.mark.critical
@pytest.mark.authentication
def test_login():
    # test code
    pass
```

### Pattern 3: Variables File → Python/Env

**Robot (variables.py for Robot):**
```python
# robot_variables.py
URL = "https://example.com"
USERNAME = "testuser"
PASSWORD = "testpass123"
TIMEOUT = 10
```

**Pytest (.env file):**
```bash
# .env
BASE_URL=https://example.com
TEST_USERNAME=testuser
TEST_PASSWORD=testpass123
TIMEOUT_DEFAULT=10
```

```python
# config.py
import os
from dotenv import load_dotenv

load_dotenv()

URL = os.getenv("BASE_URL")
USERNAME = os.getenv("TEST_USERNAME")
PASSWORD = os.getenv("TEST_PASSWORD")
TIMEOUT = int(os.getenv("TIMEOUT_DEFAULT", "10"))
```

---

## Migration Checklist

### Pre-Migration

- [ ] Audit all .robot files
- [ ] Document custom keywords
- [ ] List all resource files
- [ ] Identify all libraries used
- [ ] Note all variables files
- [ ] Backup Robot Framework tests
- [ ] Create migration branch

### Migration Phase

- [ ] Setup pytest framework
- [ ] Convert variables to .env or Python
- [ ] Convert resource files to Python modules
- [ ] Create page objects from keywords
- [ ] Convert test cases module by module
- [ ] Migrate tags to pytest markers
- [ ] Update CI/CD scripts
- [ ] Create fixtures for setup/teardown

### Post-Migration

- [ ] Run full test suite
- [ ] Compare coverage
- [ ] Verify all tags work
- [ ] Test parallel execution
- [ ] Update team documentation
- [ ] Train team on pytest
- [ ] Keep Robot tests in archive branch

---

## Troubleshooting

### Issue 1: "Keyword not found" equivalent

**Robot:** Uses keywords from libraries
**Solution:** Import Python functions or use page object methods

```python
# Instead of keywords, use methods
from pages.login_page import LoginPage
login_page = LoginPage(driver)
login_page.login(user, pass)
```

### Issue 2: Variables not accessible

**Robot:** Uses `${VARIABLE}` syntax
**Solution:** Use Python variables or environment variables

```python
# Python variable
USERNAME = "testuser"

# Or from .env
import os
USERNAME = os.getenv("TEST_USERNAME")

# Or from fixture
@pytest.fixture
def username():
    return "testuser"
```

### Issue 3: Missing waits

**Robot:** SeleniumLibrary has implicit waits
**Solution:** Use explicit waits

```python
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# Or use framework's WaitHandler
wait_handler.wait_for_element_visible((By.ID, "element"))
```

---

## Performance Comparison

### Execution Speed

**Robot Framework** (100 tests):
- Sequential: ~400 seconds
- Parallel (Pabot): ~200 seconds

**Pytest** (100 tests):
- Sequential: ~300 seconds (faster base execution)
- Parallel (pytest-xdist): ~75 seconds
- With --performance=fast: ~120 seconds
- Combined: **~30 seconds** (10x faster!)

---

## Additional Resources

- [Robot Framework Documentation](https://robotframework.org/)
- [SeleniumLibrary to Selenium Translation](https://robotframework.org/SeleniumLibrary/)
- [Best Practices Guide](best-practices.md)
- [Performance Optimization](performance-optimization.md)

---

**Last Updated**: December 24, 2025
**Framework Version**: 6.0
