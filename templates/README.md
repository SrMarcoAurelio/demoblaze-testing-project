# Universal Test Automation Framework - Templates

This directory contains **universal templates** for creating test automation components.

## Goal: Purpose

These templates are **starting points** for building YOUR test automation suite. They demonstrate best practices and framework usage, but **require adaptation** to YOUR application.

## WARNING: Important

- **DO NOT use templates directly** - They will not work without adaptation
- **DO NOT treat framework examples as YOUR tests** - They demonstrate features, not your application
- **DO adapt templates** to YOUR application's locators, workflows, and business logic

## 📁 Directory Structure

```
templates/
├── page_objects/          # Page Object templates
│   ├── __template_base_page.py
│   └── __template_login_page.py
│
├── test_files/            # Test file templates
│   ├── __template_functional_test.py
│   └── __template_security_test.py
│
└── configuration/         # Configuration templates
    ├── __template_conftest.py
    ├── __template_env.txt
    └── __template_config.py
```

##  How to Use Templates

### Step 1: Copy the Template

```bash
# Example: Copy login page template
cp templates/page_objects/__template_login_page.py pages/login_page.py
```

### Step 2: Find YOUR Application's Locators

1. Open YOUR application in Chrome
2. Press **F12** to open DevTools
3. Click element selector (top-left corner of DevTools)
4. Click on the element you want to locate
5. Right-click highlighted HTML → **Copy** → **Copy selector**
6. Use the copied selector in your page object

Example:
```python
# What you copy from DevTools:
#main > div > form > input#username

# How to use it:
USERNAME_FIELD = (By.CSS_SELECTOR, "#username")
# or
USERNAME_FIELD = (By.ID, "username")
```

### Step 3: Replace ALL Placeholders

Templates contain `YOUR_*` placeholders that **MUST be replaced**:

- `YOUR_APPLICATION_URL` → Your actual application URL
- `YOUR_USERNAME_FIELD_ID` → Your actual field ID/selector
- `YOUR_LOGIN_BUTTON_SELECTOR` → Your actual button selector
- etc.

### Step 4: Remove pytest.skip()

All templates have `pytest.skip()` by default to prevent accidental execution.

**Remove this line** when you've adapted the template:

```python
# REMOVE THIS LINE:
pytest.skip("Template not adapted...", allow_module_level=True)
```

### Step 5: Test and Iterate

Run your tests and refine:

```bash
pytest tests/your_test.py -v
```

## 📖 Template Descriptions

### Page Object Templates

#### `__template_base_page.py`

Base page class with common functionality:
- Element finding (using ElementFinder)
- Element interaction (using ElementInteractor)
- Intelligent waiting (using WaitHandler)
- Common page operations

**Adapt for:**
- YOUR application's common page behavior
- YOUR custom page methods

#### `__template_login_page.py`

Login page object demonstrating:
- Locator definitions
- Page-specific methods
- Error handling
- Success verification

**Adapt for:**
- YOUR login page locators
- YOUR login workflow
- YOUR error messages
- YOUR success indicators

### Test File Templates

#### `__template_functional_test.py`

Functional test template showing:
- Test class structure
- AAA pattern (Arrange-Act-Assert)
- Parametrized tests
- Pytest markers

**Adapt for:**
- YOUR application features
- YOUR test scenarios
- YOUR expected results

#### `__template_security_test.py`

Security test template demonstrating:
- SQL injection testing
- XSS testing
- Authentication testing
- Authorization testing

**Adapt for:**
- YOUR application's security requirements
- YOUR input validation
- YOUR access control

WARNING: **Only test applications you have permission to test!**

### Configuration Templates

#### `__template_conftest.py`

Pytest configuration showing:
- Fixture definitions
- Browser setup
- Test data fixtures
- Pytest hooks

**Adapt for:**
- YOUR application URL
- YOUR test users
- YOUR browser configuration
- YOUR custom fixtures

#### `__template_env.txt`

Environment variables template showing:
- Application configuration
- Test credentials
- Browser settings
- Service configuration

**Adapt for:**
- YOUR application URL
- YOUR test user credentials
- YOUR API endpoints
- YOUR service credentials

**Security:** Never commit `.env` to version control!

## [Yes] Adaptation Checklist

Each template includes a checklist at the bottom:

```python
# ADAPTATION CHECKLIST:
# [ ] Copied to appropriate directory
# [ ] Removed pytest.skip() line
# [ ] Replaced ALL placeholders
# [ ] Found YOUR locators using DevTools
# [ ] Tested with YOUR application
# [ ] Removed this checklist when done
```

Work through the checklist to ensure complete adaptation.

##  Learning Resources

### Study the Framework Examples

The `tests/examples/` directory contains examples demonstrating framework capabilities:

```bash
# View example tests
ls tests/examples/api/          # API testing examples
ls tests/examples/database/     # Database testing examples
cat tests/examples/README.md    # Examples documentation
```

**Remember:** These are examples showing HOW to use framework features, not application-specific tests. Study the patterns, then create tests for YOUR application.

### Framework Documentation

Read the framework documentation to understand:
- ElementFinder usage
- WaitHandler strategies
- ElementInteractor methods
- DiscoveryEngine capabilities

### Best Practices

1. **One page object per page** - Don't mix multiple pages in one class
2. **Locators as constants** - Define at class level, not in methods
3. **Methods represent actions** - login(), add_to_cart(), not click_button()
4. **Explicit waits** - Always wait for elements before interaction
5. **No assertions in page objects** - Keep assertions in tests

##  FAQ

**Q: Can I use templates without modification?**
A: No. Templates have placeholder values that won't work without adaptation.

**Q: Should I copy the framework examples?**
A: No. Those examples demonstrate framework features (API testing, database testing). Study them for patterns, but create your own tests for YOUR application.

**Q: What if my application doesn't have a login page?**
A: Skip that template and adapt the ones you need.

**Q: Can I modify templates?**
A: Yes! Templates are starting points. Adapt them to YOUR needs.

**Q: Do I need all templates?**
A: No. Use only what you need for YOUR application.

**Q: How do I find element locators?**
A: Use browser DevTools (F12), inspect elements, copy selectors.

**Q: What if a template doesn't fit my use case?**
A: Adapt it or create your own. Templates are guides, not requirements.

##  Next Steps

1. **Read** framework documentation (documentation/README.md)
2. **Study** framework examples (tests/examples/)
3. **Copy** templates you need to pages/ and tests/
4. **Find** YOUR application's locators using DevTools (F12)
5. **Replace** all placeholders with YOUR values
6. **Remove** pytest.skip() when adapted
7. **Test** with YOUR application
8. **Iterate** and improve

##  Support

For template questions:
- Check adaptation checklist in each template
- Study framework examples for patterns (tests/examples/)
- Read framework documentation (documentation/README.md)
- Review best practices above

---

**Remember:** Templates are **guides**, not **solutions**. Adapt them to YOUR application!
