# Demoblaze Example - Test Suite Implementation

**⚠️ IMPORTANT: THIS IS AN EXAMPLE ONLY**

This directory contains a **complete test suite implementation** for the Demoblaze
e-commerce platform (https://www.demoblaze.com/).

## 🚫 What This Is NOT

- **NOT a template to copy directly**
- **NOT production code for your project**
- **NOT a starting point for your application**
- **NOT universal or reusable as-is**

## ✅ What This IS

- **EXAMPLE** of how to use the framework
- **REFERENCE** implementation showing all framework features
- **LEARNING RESOURCE** to understand patterns
- **DEMONSTRATION** of complete test coverage

## 📚 Purpose

This example demonstrates:

1. **Page Object Model** - How to structure page objects
2. **Test Organization** - How to categorize tests (functional, security, accessibility)
3. **Framework Usage** - How to use ElementFinder, WaitHandler, DiscoveryEngine
4. **Best Practices** - Patterns for maintainable test automation
5. **Complete Coverage** - Login, cart, catalog, product, purchase flows

## 🎓 How to Use This Example

### **DO:**
✅ **Study the structure** - See how tests are organized
✅ **Learn the patterns** - Understand Page Object Model implementation
✅ **Reference the code** - Look up how to use framework features
✅ **Adapt concepts** - Take ideas and apply to YOUR application

### **DON'T:**
❌ **Copy directly** - These locators won't work for your app
❌ **Use in production** - This is demo code, not production-ready
❌ **Expect it to run** - Requires Demoblaze-specific setup
❌ **Modify for your app** - Create your own files instead

## 🏗️ Structure

```
examples/demoblaze/
├── pages/                  # Page Objects for Demoblaze
│   ├── base_page.py       # Base page with common methods
│   ├── login_page.py      # Login/logout functionality
│   ├── signup_page.py     # User registration
│   ├── cart_page.py       # Shopping cart operations
│   ├── catalog_page.py    # Product catalog and categories
│   ├── product_page.py    # Product detail pages
│   └── purchase_page.py   # Checkout and purchase
│
├── tests/                  # Tests for Demoblaze
│   ├── login/             # Login test suite
│   ├── signup/            # Signup test suite
│   ├── cart/              # Cart test suite
│   ├── catalog/           # Catalog test suite
│   ├── product/           # Product test suite
│   ├── purchase/          # Purchase test suite
│   ├── accessibility/     # WCAG accessibility tests
│   ├── performance/       # Performance baseline tests
│   └── visual/            # Visual regression tests
│
├── conftest.py            # Demoblaze-specific fixtures
├── .env.example           # Environment configuration template
└── README.md             # This file
```

## 🚀 Running the Example

### **Prerequisites**

1. Framework installed (see main README.md)
2. Chrome browser installed
3. Python 3.11+

### **Setup**

```bash
# Navigate to example directory
cd examples/demoblaze/

# Copy environment template
cp .env.example .env

# (Optional) Modify credentials in .env
# Default Demoblaze test user: Apolo2025/apolo2025
```

### **Run Tests**

```bash
# Run all example tests
pytest tests/ -v

# Run specific test suite
pytest tests/login/ -v

# Run with different markers
pytest -m functional -v    # Functional tests only
pytest -m security -v      # Security tests only
pytest -m accessibility -v # Accessibility tests only
```

### **Expected Results**

✅ **Most tests should PASS** against Demoblaze
⚠️ **Some tests may FAIL** - Demoblaze is a demo site, not production
❌ **DO NOT expect 100% pass rate** - This is demo code

## 📖 Learning From This Example

### **Example 1: Page Object Pattern**

**File:** `pages/login_page.py`

Study how:
- Locators are defined as class attributes
- Methods encapsulate page interactions
- Business logic is separated from test logic
- Error handling is implemented

**Then create YOUR version:**
```python
# YOUR_PROJECT/pages/login_page.py
class LoginPage(BasePage):
    # YOUR locators (different from Demoblaze!)
    USERNAME_FIELD = (By.ID, "your-username-field-id")

    def login(self, username, password):
        # YOUR implementation
        pass
```

### **Example 2: Test Organization**

**Directory:** `tests/login/`

Study how:
- Tests are categorized (functional, business, security, accessibility)
- Each test has clear docstring explaining purpose
- Pytest markers are used (@pytest.mark.functional)
- Fixtures are leveraged for setup/teardown

**Then create YOUR tests:**
```python
# YOUR_PROJECT/tests/login/test_login_functional.py
@pytest.mark.functional
def test_valid_login(browser, base_url, test_user):
    # YOUR test implementation for YOUR app
    pass
```

### **Example 3: Framework Usage**

**File:** `pages/base_page.py`

Study how:
- ElementFinder is used for element discovery
- WaitHandler manages intelligent waiting
- ElementInteractor handles click/type/drag
- Methods are composed from framework components

**Then use in YOUR page objects:**
```python
# YOUR_PROJECT/pages/base_page.py
from framework.core import ElementFinder, WaitHandler

class BasePage:
    def __init__(self, driver):
        self.finder = ElementFinder(driver)
        self.waiter = WaitHandler(driver)
        # Use framework components
```

## 🎯 Key Takeaways

1. **Locators are App-Specific**
   - Demoblaze uses specific IDs, classes, XPaths
   - YOUR app will have DIFFERENT locators
   - You MUST find YOUR app's locators

2. **Test Flow is App-Specific**
   - Demoblaze has specific user flows
   - YOUR app may have different workflows
   - Adapt test logic to YOUR business rules

3. **Framework is Universal**
   - ElementFinder, WaitHandler, DiscoveryEngine work anywhere
   - Page Object Model pattern works anywhere
   - Test organization principles work anywhere

4. **Patterns are Transferable**
   - How to structure page objects ✅
   - How to organize tests ✅
   - How to use fixtures ✅
   - How to write assertions ✅

## 🔗 Next Steps

After studying this example:

1. **Return to main project directory**
   ```bash
   cd ../../
   ```

2. **Copy templates to your project**
   ```bash
   cp -r templates/page_objects/* pages/
   cp -r templates/test_files/* tests/
   ```

3. **Adapt templates to YOUR application**
   - Replace ALL locators
   - Modify methods for YOUR workflows
   - Write tests for YOUR business logic

4. **Run YOUR tests**
   ```bash
   pytest tests/ -v
   ```

## ❓ FAQ

**Q: Can I use this code in my project?**
A: No. This code is specific to Demoblaze. Create your own.

**Q: Why are some tests failing?**
A: Demoblaze is a demo site. It may be down, slow, or have issues.

**Q: Can I modify this example for my app?**
A: No. Start fresh with templates. Don't modify this example.

**Q: How do I find locators for my app?**
A: Use browser DevTools (F12), inspect elements, copy selectors.

**Q: This is too complex for my app, can I simplify?**
A: Yes! Use what you need. This example shows ALL features.

**Q: Where are the templates I should use?**
A: In `../../templates/` directory (two levels up).

## 📞 Support

For framework questions: See main project documentation
For Demoblaze issues: This is just an example, no support provided

---

**Remember:** This is a LEARNING RESOURCE, not a PRODUCTION TEMPLATE.

Study it, understand it, then build YOUR OWN test suite for YOUR application.
