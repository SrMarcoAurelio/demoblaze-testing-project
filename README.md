# Professional QA Automation Framework
### Production-Ready Test Automation Architecture with Python, Selenium & Pytest

[![Tests](https://github.com/SrMarcoAurelio/demoblaze-testing-project/actions/workflows/tests.yml/badge.svg)](https://github.com/SrMarcoAurelio/demoblaze-testing-project/actions/workflows/tests.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Selenium](https://img.shields.io/badge/selenium-4.25.0-green.svg)](https://www.selenium.dev/)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**Author**: Marc Arévalo
**Version**: 4.0 (Template Edition)
**License**: MIT

---

## 🎯 What Is This?

A **professional-grade QA automation framework** built with Python, Selenium, and Pytest. This is an **architecture template** designed to help QA engineers and developers build robust, maintainable test suites for web applications.

### What This Framework Provides:

- ✅ **Clean Architecture**: Page Object Model (POM) with proper separation of concerns
- ✅ **External Configuration**: JSON-based locator management for easier maintenance
- ✅ **Comprehensive Testing**: Functional, business logic, security, accessibility, and performance tests
- ✅ **Type Safety**: Full type hints for better IDE support and error detection
- ✅ **CI/CD Ready**: Docker, GitHub Actions, and pre-commit hooks configured
- ✅ **Professional Reporting**: HTML, Allure, and code coverage reports
- ✅ **Standards-Based**: Tests reference OWASP, ISO 25010, WCAG 2.1, PCI-DSS
- ✅ **Well-Documented**: Extensive guides and inline documentation

### What This Framework Is NOT:

- ❌ **Not a "zero-code" solution** - You'll need to adapt it to your application
- ❌ **Not fully automated** - Security testing requires manual validation
- ❌ **Not a DAST tool** - Selenium tests UI behavior, not application security at the network level
- ❌ **Not production-ready out of the box** - Requires configuration for your specific application

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11 or higher
- Git
- Chrome/Firefox browser
- Docker (optional)

### Installation

```bash
# 1. Clone repository
git clone https://github.com/SrMarcoAurelio/demoblaze-testing-project.git
cd demoblaze-testing-project

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install pre-commit hooks (optional but recommended)
pre-commit install

# 5. Run example tests
pytest tests/login/test_login_functional.py -v
```

### Docker Setup

```bash
# Build and run with Docker Compose
docker-compose up --build

# Run specific tests
docker-compose run tests pytest tests/login/ -v
```

---

## 📁 Project Structure

```
framework/
├── pages/                      # Page Object Model
│   ├── base_page.py           # Base class with common methods
│   ├── login_page.py          # Example: Login page object
│   └── ...
│
├── tests/                      # Test suites
│   ├── login/
│   │   ├── test_login_functional.py
│   │   ├── test_login_business.py
│   │   └── test_login_security.py
│   ├── accessibility/          # WCAG 2.1 accessibility tests
│   ├── performance/            # Performance baseline tests
│   └── test_data.py           # Centralized test data
│
├── utils/                      # Reusable utilities
│   ├── accessibility/          # Axe-core WCAG helper
│   ├── performance/            # Performance metrics system
│   ├── helpers/
│   │   ├── data_generator.py  # Test data generation
│   │   ├── validators.py      # Validation utilities
│   │   └── wait_helpers.py    # Wait strategies
│   └── locators_loader.py     # JSON locator loader
│
├── config/                     # Configuration
│   ├── config.py              # Application settings
│   └── locators.json          # External locators (JSON)
│
├── results/                    # Test results and reports
│   ├── coverage/              # Code coverage reports
│   ├── performance/           # Performance metrics
│   └── accessibility/         # Accessibility reports
│
├── docs/                       # Documentation
│   ├── test-plan.md
│   └── users-flow.md
│
├── .github/workflows/          # CI/CD pipelines
│   └── tests.yml
│
├── conftest.py                 # Pytest configuration & fixtures
├── pytest.ini                  # Pytest settings
├── requirements.txt            # Python dependencies
├── .coveragerc                 # Coverage configuration
├── mypy.ini                    # Type checking configuration
├── .pre-commit-config.yaml     # Pre-commit hooks
└── docker-compose.yml          # Docker setup
```

---

## 🏗️ Architecture Overview

### 1. Page Object Model (POM)

**Pattern**: Encapsulate page interactions in dedicated classes.

```python
# pages/login_page.py
from pages.base_page import BasePage
from utils.locators_loader import load_locator

class LoginPage(BasePage):
    # Load locators from external JSON
    username_field = load_locator("login", "username_field")
    password_field = load_locator("login", "password_field")
    login_button = load_locator("login", "login_button")

    def login(self, username: str, password: str) -> None:
        """Perform login action"""
        self.type(self.username_field, username)
        self.type(self.password_field, password)
        self.click(self.login_button)
```

### 2. External Locator Configuration

**File**: `config/locators.json`

```json
{
  "login": {
    "username_field": {"by": "id", "value": "loginusername"},
    "password_field": {"by": "id", "value": "loginpassword"},
    "login_button": {"by": "xpath", "value": "//button[text()='Log in']"}
  }
}
```

**Benefits**:
- Locators separated from code
- Easier maintenance when UI changes
- No code changes needed to update selectors
- Centralized locator management

### 3. Trinity Test Structure

Tests organized by type:

- **Functional Tests**: Core feature validation (happy path, edge cases)
- **Business Tests**: Standards compliance (ISO 25010, WCAG, PCI-DSS)
- **Security Tests**: Vulnerability scanning (SQL injection, XSS, CSRF)

### 4. Test Data Management

**File**: `tests/test_data.py`

Centralized test data using dataclasses:

```python
from dataclasses import dataclass

@dataclass
class User:
    username: str
    password: str

class Users:
    VALID = User("testuser", "Test@1234")
    INVALID = User("wronguser", "wrongpass")
```

### 5. Pytest Fixtures System

**File**: `conftest.py`

18 fixtures for:
- Browser setup (Chrome, Firefox, Edge)
- Page objects (auto-initialized)
- Test data (valid/invalid users, products, cards)
- State management (logged_in_user, cart_with_products)

---

## ✅ Testing Capabilities

### Functional Testing
- Login/Signup workflows
- Product browsing and selection
- Shopping cart operations
- Purchase/checkout flows
- Form validation
- Navigation testing

### Business Logic Testing
- Standards compliance (ISO 25010)
- Password strength requirements (NIST 800-63B)
- Credit card validation (Luhn algorithm, PCI-DSS)
- Form validation rules
- Business rule enforcement

### Security Testing (UI Level)
- SQL injection payloads (input validation)
- XSS payloads (output encoding)
- CSRF token validation (UI observation)
- Session management (UI behavior)
- Authentication bypass attempts

**Important**: These are **UI-level security tests** that verify input validation and error handling. For comprehensive security testing, use dedicated DAST tools like OWASP ZAP or Burp Suite.

### Accessibility Testing
- WCAG 2.1 Level AA compliance
- Automated accessibility scans (axe-core)
- Color contrast verification
- Keyboard navigation
- Screen reader compatibility

### Performance Testing
- Page load times
- Action duration metrics
- Performance baselines
- Threshold validation
- HTML performance reports

### Code Coverage
- Automated coverage reporting
- Configurable threshold (varies by test type)
- HTML coverage reports
- Branch coverage tracking

---

## 🔧 Adapting This Framework

### Realistic Time Estimate: 4-8 hours

This is not a "plug-and-play" solution. You'll need to:

### 1. Update Configuration (30-60 minutes)

**File**: `config/config.py`

```python
@dataclass
class Config:
    # Update with your application URL
    BASE_URL: str = os.getenv('BASE_URL', 'https://your-app.com/')

    # Adjust timeouts as needed
    IMPLICIT_WAIT: int = int(os.getenv('IMPLICIT_WAIT', '10'))
    EXPLICIT_WAIT: int = int(os.getenv('EXPLICIT_WAIT', '20'))
```

### 2. Map Your UI Elements (2-4 hours)

**File**: `config/locators.json`

Use browser DevTools to:
1. Inspect each UI element you want to test
2. Copy element IDs, names, or XPath
3. Update `locators.json` with your selectors

```json
{
  "your_page": {
    "element_name": {
      "by": "id",        // or "xpath", "css", "name", etc.
      "value": "element-id"
    }
  }
}
```

### 3. Update Page Objects (2-3 hours)

Modify page classes in `pages/` to match your application's workflows:

```python
def your_workflow(self, param: str) -> None:
    """Implement your application's specific workflow"""
    # Add steps specific to your application
    self.click(self.your_button)
    self.type(self.your_field, param)
    # etc.
```

### 4. Update Test Data (30 minutes)

**File**: `tests/test_data.py`

Replace example data with your test accounts and data:

```python
class Users:
    VALID = User("your_test_username", "your_test_password")
```

### 5. Write/Adapt Tests (1-2 hours)

Use existing tests as templates and modify for your application.

---

## 🧪 Running Tests

### Basic Usage

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/login/test_login_functional.py -v

# Run by marker
pytest -m functional         # Functional tests only
pytest -m security          # Security tests only
pytest -m accessibility     # Accessibility tests only
pytest -m performance       # Performance tests only

# Run with coverage
pytest --cov=pages --cov=utils

# Generate HTML report
pytest --html=results/report.html
```

### Advanced Usage

```bash
# Parallel execution (faster)
pytest -n auto

# Rerun failures
pytest --lf                  # Last failed
pytest --ff                  # Failed first

# Generate Allure report
pytest --alluredir=./allure-results
allure serve ./allure-results

# Performance tests with HTML report
pytest -m performance --html=results/performance/report.html
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

---

## 📊 Reports and Outputs

### 1. HTML Reports (`pytest-html`)
- Location: `results/general/`
- Simple, self-contained HTML reports
- Screenshots on failure
- Test duration metrics

### 2. Allure Reports (Professional)
- Interactive, management-friendly reports
- Test history and trends
- Failure categorization
- Detailed logs and attachments

### 3. Code Coverage Reports
- Location: `results/coverage/html/`
- Line and branch coverage
- Missing line indicators
- Coverage percentage by module

### 4. Performance Reports
- Location: `results/performance/`
- Metric summaries (JSON)
- HTML reports with charts
- Threshold validation results

### 5. Accessibility Reports
- Location: `results/accessibility/`
- WCAG violation details (JSON)
- Severity levels (critical, serious, moderate, minor)
- Remediation guidance

---

## 🔒 Security Testing Disclaimer

### What This Framework Does:

✅ **UI-level security validation**:
- Tests input validation (SQL injection payloads)
- Tests output encoding (XSS payloads)
- Observes CSRF token presence (UI layer)
- Tests session behavior through UI
- Validates error messages don't leak information

### What This Framework Does NOT Do:

❌ **Network-level security testing**:
- Does not intercept HTTP requests/responses
- Does not test API endpoints directly
- Does not analyze server responses at protocol level
- Does not perform penetration testing

### For Comprehensive Security Testing, Use:

- **OWASP ZAP**: Automated web application security scanner
- **Burp Suite**: Manual penetration testing proxy
- **Nuclei**: Vulnerability scanner
- **SQLMap**: SQL injection detection tool
- **Dedicated SAST/DAST tools**

**This framework complements but does not replace dedicated security testing tools.**

---

## ♿ Accessibility Testing

### Technology: Axe-core by Deque Systems

**What it tests**:
- WCAG 2.1 Level A/AA/AAA compliance
- 50+ accessibility rules
- Color contrast
- Form labels
- Keyboard navigation
- ARIA attributes
- Semantic HTML

### Usage

```python
from utils.accessibility.axe_helper import AxeHelper

# Run WCAG 2.1 AA scan
axe = AxeHelper(driver)
results = axe.run_wcag_aa()

# Assert no violations
axe.assert_no_violations(results, allow_minor=True)

# Save report
axe.save_report(results, "results/accessibility/page_scan.json")
```

### Example Tests
- Homepage compliance (A11Y-001)
- Modal accessibility (A11Y-002)
- Form accessibility (A11Y-003)
- Color contrast (A11Y-007)
- Keyboard navigation (A11Y-008)

---

## 📈 Performance Testing

### Performance Metrics System

**File**: `utils/performance/metrics.py`

Collects timing metrics with configurable thresholds:

```python
from utils.performance.decorators import track_performance

@track_performance(name="login_action", category="authentication")
def test_login_performance(login_page):
    login_page.login("user", "pass")
    # Automatically tracked and validated against thresholds
```

### Default Thresholds
- Page load: 5.0s
- Login action: 3.0s
- Search: 2.0s
- Add to cart: 1.5s
- Form submission: 3.0s

### Performance Reports
- HTML reports with summary statistics
- JSON metrics for analysis
- Threshold violation tracking
- Historical comparison (manual)

---

## 🔄 CI/CD Integration

### GitHub Actions

**File**: `.github/workflows/tests.yml`

Automated testing on:
- Every push to any branch
- Pull requests to main
- Manual workflow dispatch

**Pipeline stages**:
1. Code quality checks (black, isort, flake8, mypy)
2. Unit tests (utils testing)
3. Functional tests
4. Security tests
5. Coverage reporting
6. Artifact upload

### Pre-commit Hooks

15 automated checks before each commit:

```bash
# Install hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

**Hooks include**:
- Code formatting (black, isort)
- Linting (flake8)
- Type checking (mypy)
- YAML/JSON validation
- File hygiene (trailing whitespace, EOF)
- Security checks (detect-secrets)

---

## 🎓 Learning Resources

### Comprehensive Guides Included:

1. **IMPLEMENTATION-GUIDE.md** (1141 lines)
   - What the framework tests
   - How to implement it in your project
   - Docker execution guide
   - CI/CD integration
   - Output and reports

2. **ACCESSIBILITY-TESTING-GUIDE.md** (332 lines)
   - WCAG 2.1 standards explained
   - Axe-core usage
   - Violation remediation
   - Best practices

3. **TEST-FIXTURES-GUIDE.md** (437 lines)
   - Pytest fixtures explained
   - 18 fixtures documented
   - Usage examples
   - Best practices

4. **PRE-COMMIT-HOOKS.md** (472 lines)
   - 15 hooks explained
   - Configuration guide
   - Troubleshooting
   - Customization

### Test Templates

Located in `templates/`:
- Functional testing templates
- Security testing templates
- Business logic testing templates
- Complete testing philosophy guides

---

## 📊 Framework Statistics

### Codebase
- **Python code**: ~3,500 lines
- **Documentation**: ~13,000+ lines
- **Test files**: 182 functional tests
- **Unit tests**: 85+ utility tests
- **Fixtures**: 18 pytest fixtures
- **Utilities**: Data generators, validators, wait helpers, accessibility, performance

### Test Coverage
- **Modules**: Login, Signup, Catalog, Product, Cart, Purchase
- **Test types**: Functional, Business, Security, Accessibility, Performance
- **Page Objects**: 6 (with base class)
- **Standards referenced**: ISO 25010, OWASP ASVS 5.0, PCI-DSS 4.0.1, WCAG 2.1, NIST 800-63B

---

## 🚧 Honest Limitations

### 1. Not Truly Universal
- Still requires 4-8 hours of adaptation work
- Page objects need modification for different workflows
- Some test logic is application-specific
- External locators help but don't eliminate all code changes

### 2. Security Testing Limitations
- UI-level validation only (not network-level)
- Cannot replace dedicated DAST tools
- Requires manual verification of findings
- Does not test API security directly

### 3. Type Hints Coverage
- Full type hints on `base_page.py`
- Partial coverage on other page objects
- Test files have minimal type hints
- Ongoing improvement (not 100% coverage)

### 4. Learning Curve
- Requires Selenium knowledge
- Pytest framework understanding
- Page Object Model pattern
- Python programming skills
- Not suitable for complete beginners without guidance

### 5. Maintenance
- Locator updates needed when UI changes
- Test data needs periodic refresh
- CI/CD pipeline may need adjustments
- Performance thresholds require tuning

---

## 🤝 Contributing

This is a personal learning project, but contributions welcome:

- **Bug reports**: Open an issue
- **Feature requests**: Open a discussion
- **Pull requests**: Fork and submit PR
- **Documentation improvements**: Always appreciated

---

## 📞 Contact

**Author**: Marc Arévalo
**Email**: marcarevalocano@gmail.com
**GitHub**: [@SrMarcoAurelio](https://github.com/SrMarcoAurelio)

Open to:
- Questions about the framework
- Code review and feedback
- Collaboration opportunities

---

## 📄 License

MIT License - Free to use, modify, and distribute.

If you use this framework:
- Attribution appreciated but not required
- Share improvements with the community (optional)
- Use responsibly and ethically

---

## 🌟 About This Project

### Development Process

This framework was built over **20 days** with significant AI assistance (Claude AI & Gemini) as a learning project. The AI helped with:
- Understanding QA fundamentals
- Learning Python, Selenium, and Pytest
- Code structure and best practices
- Documentation writing
- Debugging and optimization

### Manual Contributions

- All architectural decisions
- Testing strategy and philosophy
- Manual test execution
- Code review and validation
- Standards research
- Project organization

### Why This Transparency Matters

AI-assisted development is increasingly common. What matters is:
- Understanding the code you deploy
- Taking responsibility for the architecture
- Being honest about the process
- Delivering real value regardless of tools used

This framework represents genuine learning and professional-grade architecture, built with modern tooling.

---

## 🎯 Who Is This For?

### Ideal For:

✅ **QA Engineers** learning test automation
✅ **Developers** building testing frameworks
✅ **Teams** needing a professional architecture template
✅ **Students** studying Selenium and Pytest
✅ **Professionals** implementing CI/CD for tests

### Not Ideal For:

❌ Complete beginners without programming experience
❌ Teams needing out-of-the-box ready solution
❌ Projects requiring no adaptation time
❌ Teams wanting fully automated security testing

---

## 🙏 Acknowledgments

- **Selenium WebDriver** - Browser automation
- **Pytest** - Test framework
- **Axe-core by Deque** - Accessibility testing
- **OWASP** - Security standards and guidelines
- **Anthropic & Google** - AI assistance during development

---

**Last Updated**: December 2, 2025
**Version**: 4.0 (Template Edition)
**Status**: Production-ready architecture template

⭐ **If this framework helps you, consider starring the repository!** ⭐
