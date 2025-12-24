# Universal Web Test Automation Framework

Professional test automation framework built with Python, Selenium, and Pytest for web application testing.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Selenium](https://img.shields.io/badge/selenium-4.25.0-green.svg)](https://www.selenium.dev/)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**Version**: 6.0 (Universal Edition)
**Author**: Marc Arevalo
**License**: MIT

---

## 🚀 5-Minute Quick Start

**Want to try it out? Here's the fastest path:**

```bash
# 1. Clone and install (1 minute)
git clone https://github.com/SrMarcoAurelio/demoblaze-testing-project.git
cd demoblaze-testing-project
python -m venv venv && source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 2. Run example tests (30 seconds)
cd examples/demoblaze
pytest tests/login/ -v  # See the framework in action

# 3. Start building YOUR test suite (3 minutes)
cd ../..
export BASE_URL="https://your-application.com"  # YOUR app URL
cp templates/page_objects/__template_login_page.py pages/login_page.py

# 4. Adapt to YOUR app
# - Open browser DevTools (F12)
# - Find YOUR login button ID
# - Replace "YOUR_LOGIN_BUTTON_ID" in pages/login_page.py
# - Remove pytest.skip() line
# - Run pytest tests/!
```

**That's it!** You've seen the framework in action and started adapting it to YOUR application.

---

## Overview

Universal test automation framework providing reusable components, patterns, and infrastructure for web application testing. Like pytest or selenium, this framework provides the **building blocks** - you provide the application-specific implementation.

### Philosophy

Professional frameworks don't assume your application structure - they provide tools to build upon:

- **Framework provides**: Element discovery, intelligent waits, page object patterns, test infrastructure
- **You provide**: Application URL, locators, page objects, test scenarios
- **Result**: Maintainable, scalable test automation adapted to YOUR application

### Framework Comparison

**How does this compare to alternatives?**

| Feature | This Framework | Selenium + unittest | Robot Framework | Playwright |
|---------|----------------|---------------------|-----------------|------------|
| **Language** | Python | Python | Keyword-driven | Python/JS/Java |
| **Learning Curve** | Medium | Low | Low | Medium-High |
| **Page Objects** | ✅ Built-in templates | ⚠️ Manual implementation | ❌ Not native | ✅ Built-in |
| **Fixtures** | ✅ Pytest (25+) | ⚠️ setUp/tearDown | ⚠️ Test Setup/Teardown | ✅ Built-in |
| **Security Testing** | ✅ UI-level payloads | ❌ Manual | ❌ Manual | ⚠️ Limited |
| **Accessibility** | ✅ axe-core integration | ❌ Manual | ❌ Manual | ✅ Built-in |
| **Performance** | ✅ Built-in metrics | ❌ Manual | ⚠️ Limited | ✅ Built-in tracing |
| **Reports** | ✅ HTML + Allure | ⚠️ unittest basic | ✅ HTML + Logs | ✅ HTML + Trace viewer |
| **Parallel Execution** | ✅ pytest-xdist | ⚠️ Manual | ✅ Built-in | ✅ Built-in |
| **Type Safety** | ✅ Full type hints | ⚠️ Partial | ❌ No | ✅ Full TypeScript |
| **CI/CD Templates** | ✅ GitHub Actions | ❌ Manual | ⚠️ Basic | ✅ Multiple platforms |
| **Browser Support** | Chrome, Firefox, Edge | All | All | Chrome, Firefox, WebKit |
| **Best For** | Python teams, comprehensive testing | Simple scripts | Non-programmers | Modern JS apps, video recording |

### When to Use This Framework

✅ **Perfect fit if you:**
- Work primarily with Python
- Need Page Object Model out-of-the-box
- Want comprehensive test types (functional, security, accessibility, performance)
- Require type safety and IDE autocomplete
- Need CI/CD integration with minimal setup
- Value pytest's powerful fixture system
- Want professional development practices (pre-commit hooks, type checking)

❌ **Consider alternatives if you:**
- **Robot Framework**: Your team prefers keyword-driven testing or includes non-programmers
- **Playwright**: You need video recording, network interception, or test modern JavaScript frameworks
- **Cypress**: You're a pure JavaScript team doing component testing
- **Selenium + unittest**: You want absolute simplicity with minimal structure

### What This Framework Provides

- **Universal Core Components** - Discovery-based element finding, interaction, and waiting
- **Page Object Model Infrastructure** - Base classes and patterns for page objects
- **Comprehensive Fixtures** - 25+ pytest fixtures for browser management, data, and performance
- **Multiple Test Types** - Functional, security, accessibility, performance testing capabilities
- **CI/CD Ready** - Docker support, GitHub Actions, pre-commit hooks
- **Professional Reporting** - HTML reports, performance metrics, failure screenshots
- **Type Safety** - Type hints throughout for better IDE support

### What This Framework Is NOT

- **Not zero-configuration** - Requires adaptation to your application (4-8 hours estimated)
- **Not application-specific** - Provides patterns and tools, not ready-made tests
- **Not a DAST tool** - UI-level testing only, use dedicated security tools for comprehensive security testing
- **Not for beginners** - Requires Selenium, Pytest, and Python knowledge

---

## Quick Start

### Installation

```bash
# Clone repository
git clone <your-fork-url>
cd universal-test-framework

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install pre-commit hooks (optional)
pre-commit install
```

### Configuration

```bash
# REQUIRED: Set your application URL
export BASE_URL="https://your-application.com"

# REQUIRED: Set test credentials
export TEST_USERNAME="your_test_user"
export TEST_PASSWORD="your_test_password"

# Optional browser configuration
export BROWSER="chrome"          # chrome, firefox, or edge
export HEADLESS="false"          # true for headless mode
export TIMEOUT_DEFAULT="10"      # default wait timeout (seconds)
```

### Run Tests

```bash
# Run specific test module (after adaptation)
pytest tests/login/test_login_functional.py -v

# Run with specific browser
pytest --browser=firefox --headless

# Run with HTML report
pytest --html=results/report.html

# Run with coverage
pytest --cov=pages --cov=utils
```

---

## Framework Architecture

### Core Components (`framework/`)

Universal, discovery-based components for any web application:

```
framework/
├── core/
│   ├── element_finder.py      # Element discovery with fallback strategies
│   ├── element_interactor.py  # Reliable element interactions with retry logic
│   ├── wait_handler.py        # Intelligent waits (no sleep() calls)
│   └── discovery_engine.py    # Automatic page structure discovery
│
└── adapters/
    ├── base_adapter.py        # Abstract adapter interface
    └── adapter_template.py    # Template for your application adapter
```

**Key Principle**: Tests should DISCOVER page structure, not ASSUME it.

### Page Objects (`pages/`)

Page Object Model templates for your application:

```
pages/
├── base_page.py      # Base page class with common functionality
├── login_page.py     # Example: Login page template
├── cart_page.py      # Example: Shopping cart template
└── ...               # Add your application's page objects
```

**Adaptation Required**: Modify page objects to match YOUR application's structure.

### Tests (`tests/`)

Test templates organized by type and module:

```
tests/
├── login/            # Login functionality tests
├── cart/             # Shopping cart tests
├── security_real/    # Security testing (OWASP Top 10)
├── accessibility/    # WCAG 2.1 compliance tests
├── performance/      # Performance and load time tests
└── static_test_data.py  # Test data structures
```

**Adaptation Required**: Modify tests to match YOUR application's workflows.

### Utilities (`utils/`)

Testing utilities and helpers:

- **Security**: Payload library, vulnerability scanner (1,265 lines)
- **Accessibility**: WCAG 2.1 validator with axe-core
- **Performance**: Core Web Vitals monitoring
- **API**: REST API testing client
- **Visual**: Screenshot comparison and visual regression

---

## Framework Features

### 1. Discovery-Based Element Finding

Instead of hardcoding selectors, discover elements intelligently:

```python
from framework.core import ElementFinder

def test_login_discovery(browser, element_finder):
    # Find login button by text (tries multiple strategies)
    login_btn = element_finder.find_by_text("Login", tag="button")

    # Find form inputs automatically
    inputs = element_finder.find_input_elements()

    # Fallback strategies if primary locator fails
    element = element_finder.find_element_with_fallback([
        (By.ID, "submit"),
        (By.NAME, "submit-button"),
        (By.XPATH, "//button[@type='submit']")
    ])
```

### 2. Intelligent Waiting (No sleep())

No `time.sleep()` calls - only condition-based waits:

```python
from framework.core import WaitHandler

def test_modal(browser, wait_handler):
    # Wait for element to be visible
    modal = wait_handler.wait_for_element_visible(By.ID, "modal")

    # Wait for element to be clickable
    button = wait_handler.wait_for_element_clickable(By.ID, "submit")

    # Wait for custom condition
    wait_handler.wait_for_condition(lambda d: len(d.find_elements(By.TAG_NAME, "tr")) > 5)
```

### 3. Page Structure Discovery

Automatically discover page structure for adaptive testing:

```python
from framework.core import DiscoveryEngine

def test_discover_forms(browser, discovery_engine):
    # Discover all forms on page
    forms = discovery_engine.discover_forms()

    for form in forms:
        print(f"Form: {form['id']}")
        print(f"Inputs: {len(form['inputs'])}")
        print(f"Buttons: {len(form['buttons'])}")

    # Generate comprehensive page report
    report = discovery_engine.generate_page_report()
```

### 4. Comprehensive Fixtures

25+ pytest fixtures available:

- **Browser**: `browser`, `base_url`, `timeout_config`
- **Data**: `valid_user`, `invalid_user`, `new_user`, `purchase_data`
- **Pages**: `login_page`, `signup_page`, `catalog_page`, `cart_page`, `purchase_page`
- **State**: `logged_in_user` (automatic login/logout)
- **Performance**: `performance_collector`, `performance_timer`
- **Universal Framework**: `element_finder`, `element_interactor`, `wait_handler`, `discovery_engine`

### 5. Multiple Test Types

**Functional Testing**: Core application workflows
**Security Testing**: OWASP Top 10 payloads (SQL injection, XSS, CSRF, etc.)
**Accessibility Testing**: WCAG 2.1 Level AA compliance with axe-core
**Performance Testing**: Page load times, Core Web Vitals
**Business Logic Testing**: Standards compliance (ISO 25010, NIST, PCI-DSS)

### 6. Professional Development Practices

- **Pre-commit Hooks**: 15 automated checks (black, flake8, mypy, etc.)
- **CI/CD Integration**: GitHub Actions with automated testing
- **Docker Support**: Containerized test execution
- **Type Hints**: Throughout codebase for IDE support
- **Code Coverage**: Automated coverage reporting

---

## Adapting This Framework

### Estimated Time: 4-8 Hours

This framework requires adaptation for your specific application:

#### 1. Configuration (30 minutes)

```bash
# Set required environment variables
export BASE_URL="https://your-app.com"
export TEST_USERNAME="your_test_user"
export TEST_PASSWORD="your_test_password"

# Optional: customize config.py for your needs
# - Timeouts
# - Browser preferences
# - Report directories
```

#### 2. Locators (2-4 hours)

Update `config/locators.json` with your application's element selectors:

```json
{
  "login": {
    "username_input": "id=username",
    "password_input": "id=password",
    "login_button": "css=button[type='submit']"
  }
}
```

#### 3. Page Objects (2-3 hours)

Modify page objects in `pages/` to match your application:

```python
class YourLoginPage(BasePage):
    def login(self, username, password):
        # Adapt to YOUR application's login flow
        self.type_text(self.locators["username_input"], username)
        self.type_text(self.locators["password_input"], password)
        self.click(self.locators["login_button"])
```

#### 4. Test Data (30 minutes)

Update `tests/static_test_data.py`:

- Replace `PurchaseData` fields with YOUR checkout form fields
- Add application-specific test data classes

#### 5. Tests (1-2 hours)

Adapt tests in `tests/` to YOUR workflows:

- Modify functional tests to match your application flows
- Update assertions to match your application behavior
- Add/remove test modules as needed

---

## Testing Capabilities

### Functional Testing

Test core application workflows:
- User authentication (login, signup, logout)
- Navigation and routing
- Form submission and validation
- CRUD operations
- State management

### Security Testing (UI Level)

**IMPORTANT**: These tests verify UI-level input validation only. For comprehensive security testing, use dedicated DAST tools like OWASP ZAP or Burp Suite.

- SQL Injection payloads (input validation)
- XSS payloads (output encoding)
- CSRF protection (UI observation)
- Authentication security
- Session management

### Accessibility Testing

- WCAG 2.1 Level AA automated scans (axe-core)
- Color contrast verification
- Keyboard navigation testing
- Screen reader compatibility
- Form label associations

### Performance Testing

- Page load time measurement
- Action duration metrics
- Performance baselines and thresholds
- Core Web Vitals monitoring

---

## Project Structure

```
universal-test-framework/
├── framework/              # Universal framework core
│   ├── core/              # Discovery-based components
│   └── adapters/          # Application adapter pattern
│
├── pages/                 # Page Object Model (adapt to your app)
│   ├── base_page.py      # Base page class
│   └── *.py              # Your page objects
│
├── tests/                 # Test suites (adapt to your app)
│   ├── login/            # Example: Login tests
│   ├── security_real/    # Security testing
│   ├── accessibility/    # WCAG testing
│   └── static_test_data.py  # Test data structures
│
├── utils/                 # Testing utilities
│   ├── security/         # Payload library, scanner
│   ├── accessibility/    # WCAG validator
│   ├── performance/      # Metrics collector
│   └── ...
│
├── config/
│   ├── config.py         # Configuration management
│   └── locators.json     # Element locators (adapt to your app)
│
├── documentation/         # Comprehensive guides
│   ├── getting-started/  # Installation, quick start
│   ├── guides/          # Implementation guides
│   └── api-reference/   # API documentation
│
├── conftest.py           # Pytest fixtures
├── pytest.ini            # Pytest configuration
├── requirements.txt      # Dependencies
└── docker-compose.yml    # Docker setup
```

---

## Running Tests

### Basic Commands

```bash
# Run all tests
pytest

# Run specific module
pytest tests/login/ -v

# Run by marker
pytest -m functional       # Functional tests
pytest -m security        # Security tests
pytest -m accessibility   # Accessibility tests

# Run with coverage
pytest --cov=pages --cov=utils

# Generate HTML report
pytest --html=results/report.html --self-contained-html
```

### Docker Execution

```bash
# Run all tests in Docker
docker-compose up --build

# Run specific module
docker-compose run tests pytest tests/login/ -v

# Run with coverage
docker-compose run tests pytest --cov=pages --cov=utils
```

### Pytest Markers

- `@pytest.mark.smoke` - Critical smoke tests
- `@pytest.mark.functional` - Functional tests
- `@pytest.mark.security` - Security tests
- `@pytest.mark.accessibility` - Accessibility tests
- `@pytest.mark.performance` - Performance tests
- `@pytest.mark.slow` - Long-running tests

---

## Requirements

### System Requirements

- Python 3.11 or higher
- Modern browser (Chrome, Firefox, or Edge)
- 4GB RAM minimum (8GB recommended for parallel execution)
- Unix-like OS or Windows with WSL (for Docker)

### Knowledge Requirements

- Python programming fundamentals
- Selenium WebDriver basics
- Pytest framework understanding
- Page Object Model pattern
- Web technologies (HTML, CSS, JavaScript)

### Not Suitable For

- Complete beginners without Selenium knowledge
- Projects requiring zero-configuration solutions
- Teams without Python/testing experience
- Applications without web UI

---

## Documentation

Complete documentation available in `/documentation`:

### Getting Started

- [Installation Guide](documentation/getting-started/installation.md)
- [Quick Start](documentation/getting-started/quick-start.md)
- [Your First Test](documentation/getting-started/first-test.md)

### Guides

- [Implementation Guide](documentation/guides/implementation-guide.md) - Adapting framework to your app
- [Accessibility Testing](documentation/guides/accessibility-testing.md) - WCAG 2.1 testing
- [Performance Testing](documentation/guides/performance-testing.md) - Performance monitoring
- [Security Testing](documentation/guides/real-security-testing.md) - Security testing guide

### API Reference

- [BasePage API](documentation/api-reference/base-page-api.md)
- [Fixtures API](documentation/api-reference/fixtures-api.md)
- [Locators API](documentation/api-reference/locators-api.md)

### Testing Philosophy

- [Discover vs Assume](documentation/testing-philosophy/discover-vs-assume.md) - Core testing philosophy

---

## Contributing

This is a learning project, but contributions are welcome:

- **Bug Reports**: Open an issue with reproduction steps
- **Feature Requests**: Open a discussion describing the use case
- **Pull Requests**: Fork, implement, and submit PR with tests
- **Documentation**: Improvements always appreciated

Please follow existing code style (black, flake8, mypy) and include tests for new features.

---

## Standards Compliance

This framework references industry standards:

- **ISTQB**: International Software Testing Qualifications Board
- **IEEE 829**: Software Test Documentation
- **ISO/IEC 25010**: Software Quality Model
- **WCAG 2.1**: Web Content Accessibility Guidelines
- **OWASP Top 10**: Web Application Security Risks
- **NIST 800-63B**: Digital Identity Guidelines (password requirements)
- **PCI-DSS**: Payment Card Industry Data Security Standard

---

## Honest Limitations

### 1. Not Truly Zero-Configuration

- Requires 4-8 hours adaptation work
- Page objects need modification for different workflows
- Locators must be updated for your application
- Some test logic is template-based, needs customization

### 2. Security Testing Limitations

- UI-level validation only (not network-level)
- Cannot replace dedicated DAST tools (OWASP ZAP, Burp Suite)
- Requires manual verification of findings
- Does not test API security directly

### 3. Learning Curve

- Requires Selenium knowledge
- Pytest framework understanding needed
- Page Object Model pattern familiarity
- Python programming skills required
- Not suitable for complete beginners

### 4. Maintenance

- Locator updates needed when UI changes
- Test data needs periodic refresh
- CI/CD pipeline may need adjustments for your environment
- Performance thresholds require tuning per application

---

## License

MIT License - Free to use, modify, and distribute with attribution.

---

## Contact

**Author**: Marc Arevalo
**Email**: marcarevalocano@gmail.com
**GitHub**: [@SrMarcoAurelio](https://github.com/SrMarcoAurelio)

Questions, feedback, and collaboration opportunities welcome.

---

## Acknowledgments

---

**Last Updated**: December 2025
**Version**: 6.0 (Universal Edition)
**Status**: Production-ready framework requiring application-specific adaptation

For complete documentation, see [documentation/README.md](documentation/README.md)
