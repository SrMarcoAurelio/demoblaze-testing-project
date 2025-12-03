# Professional QA Automation Framework

Production-ready test automation architecture built with Python, Selenium, and Pytest.

[![Tests](https://github.com/SrMarcoAurelio/demoblaze-testing-project/actions/workflows/tests.yml/badge.svg)](https://github.com/SrMarcoAurelio/demoblaze-testing-project/actions/workflows/tests.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Selenium](https://img.shields.io/badge/selenium-4.25.0-green.svg)](https://www.selenium.dev/)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**Version**: 4.0 (Template Edition)
**Author**: Marc Arévalo
**License**: MIT

---

## Overview

Professional-grade QA automation framework designed as an architecture template for web application testing. Provides clean structure, comprehensive testing capabilities, and modern development practices.

### What This Framework Provides

- **Clean Architecture** - Page Object Model with proper separation of concerns
- **External Configuration** - JSON-based locator management
- **Comprehensive Testing** - Functional, security, accessibility, and performance tests
- **Type Safety** - Type hints for better IDE support
- **CI/CD Ready** - Docker, GitHub Actions, pre-commit hooks
- **Professional Reporting** - HTML, Allure, and code coverage reports
- **Standards-Based** - References OWASP, ISO 25010, WCAG 2.1, PCI-DSS
- **Well-Documented** - Extensive guides and examples

### What This Framework Is NOT

- Not a zero-configuration solution
- Not production-ready without adaptation
- Not a DAST tool (UI-level testing only)
- Not suitable for complete beginners without guidance

---

## Quick Start

```bash
# 1. Clone and setup
git clone https://github.com/SrMarcoAurelio/demoblaze-testing-project.git
cd demoblaze-testing-project
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Install pre-commit hooks (optional)
pre-commit install

# 4. Run tests
pytest tests/login/test_login_functional.py -v
```

See [Installation Guide](documentation/getting-started/installation.md) for detailed setup instructions.

---

## Documentation

Complete documentation available in `/documentation`:

### Quick Navigation
- [Installation Guide](documentation/getting-started/installation.md)
- [Quick Start](documentation/getting-started/quick-start.md)
- [Your First Test](documentation/getting-started/first-test.md)
- [Implementation Guide](documentation/guides/implementation-guide.md)
- [All Documentation](documentation/README.md)

### Key Guides
- **Getting Started** - Installation, quick start, first test
- **Complete Guides** - Implementation, accessibility, performance, coverage
- **Architecture** - Framework design and technical details
- **Templates** - Structured templates for creating tests
- **Testing Philosophy** - Discover vs Assume methodology

---

## Project Structure

```
demoblaze-testing-project/
├── documentation/          # Complete framework documentation
│   ├── getting-started/   # Installation and quick start
│   ├── guides/           # Implementation guides
│   ├── architecture/     # Framework architecture
│   ├── templates/        # Test templates
│   └── testing-philosophy/ # Testing methodology
│
├── config/               # Configuration
│   ├── config.py        # Application settings
│   └── locators.json    # UI element locators
│
├── pages/               # Page Object Model
│   ├── base_page.py    # Base class
│   └── ...             # Page objects
│
├── tests/              # Test suites
│   ├── login/          # Login tests
│   ├── accessibility/  # WCAG tests
│   ├── performance/    # Performance tests
│   └── test_utils/     # Unit tests
│
├── utils/              # Utilities
│   ├── accessibility/  # Axe-core helper
│   ├── performance/    # Metrics system
│   └── helpers/        # Data generators, validators
│
├── conftest.py         # Pytest fixtures
├── pytest.ini          # Pytest configuration
├── requirements.txt    # Dependencies
└── docker-compose.yml  # Docker setup
```

---

## Testing Capabilities

### Functional Testing
- Login/Signup workflows
- Product browsing and selection
- Shopping cart operations
- Purchase/checkout flows
- Form validation and navigation

### Business Logic Testing
- Standards compliance (ISO 25010)
- Password strength (NIST 800-63B)
- Credit card validation (Luhn algorithm, PCI-DSS)
- Form validation rules

### Security Testing (UI Level)
- SQL injection payloads (input validation)
- XSS payloads (output encoding)
- CSRF token validation (UI observation)
- Session management (UI behavior)

**Note**: UI-level security tests verify input validation and error handling. For comprehensive security testing, use dedicated DAST tools like OWASP ZAP or Burp Suite.

### Accessibility Testing
- WCAG 2.1 Level AA compliance
- Automated scans (axe-core)
- Color contrast verification
- Keyboard navigation
- Screen reader compatibility

### Performance Testing
- Page load times
- Action duration metrics
- Performance baselines
- Threshold validation

### Code Coverage
- Automated coverage reporting
- Configurable threshold (varies by test type)
- HTML coverage reports
- Branch coverage tracking

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
pytest --html=results/report.html
```

### Docker Execution

```bash
# Run all tests
docker-compose up --build

# Run specific module
docker-compose run tests pytest tests/login/ -v

# Run with coverage
docker-compose run tests pytest --cov=pages --cov=utils
```

See [Quick Start Guide](documentation/getting-started/quick-start.md) for more commands.

---

## Adapting This Framework

### Realistic Time Estimate: 4-8 hours

This framework requires adaptation for your specific application:

1. **Update Configuration** (30-60 min) - BASE_URL, timeouts, browser settings
2. **Map UI Elements** (2-4 hours) - Update `config/locators.json` with your selectors
3. **Update Page Objects** (2-3 hours) - Modify workflows to match your application
4. **Update Test Data** (30 min) - Replace test data in `tests/test_data.py`
5. **Adapt Tests** (1-2 hours) - Modify test logic for your application

See [Implementation Guide](documentation/guides/implementation-guide.md) for detailed adaptation instructions.

---

## Key Features

### Page Object Model
Encapsulates page interactions in dedicated classes with type hints for better IDE support.

### External Locators
UI element locators stored in JSON for easier maintenance when UI changes.

### Trinity Structure
Tests organized by type: Functional (does it work?), Business (meets standards?), Security (is it secure?).

### Fixture System
18 pytest fixtures for test data, page objects, and state management.

### Pre-commit Hooks
15 automated checks before each commit: formatting, linting, type checking, security.

### CI/CD Integration
GitHub Actions workflow with automated testing, coverage reporting, and artifact upload.

---

## Requirements

- Python 3.11 or higher
- Modern browser (Chrome, Firefox, or Edge)
- 4GB RAM minimum (8GB recommended)
- Basic knowledge of Python and Selenium
- Familiarity with pytest framework (recommended)

---

## Honest Limitations

### 1. Not Truly Universal
- Requires 4-8 hours of adaptation work
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

## Contributing

This is a personal learning project, but contributions are welcome:

- Bug reports: Open an issue
- Feature requests: Open a discussion
- Pull requests: Fork and submit PR
- Documentation improvements: Always appreciated

---

## Contact

**Author**: Marc Arévalo
**Email**: marcarevalocano@gmail.com
**GitHub**: [@SrMarcoAurelio](https://github.com/SrMarcoAurelio)

Open to:
- Questions about the framework
- Code review and feedback
- Collaboration opportunities

---

## License

MIT License - Free to use, modify, and distribute.

---

## About This Project

This framework was built over 4 months with significant AI assistance (Claude AI & Gemini) as a learning project. The AI helped with understanding QA fundamentals, learning Python/Selenium/Pytest, code structure, and documentation. All architectural decisions, testing strategy, and code validation were done manually.

AI-assisted development is increasingly common. What matters is understanding the code you deploy, taking responsibility for the architecture, and delivering real value regardless of tools used.

---

**Last Updated**: December 3, 2025
**Version**: 4.0 (Template Edition)
**Status**: Production-ready architecture template

For complete documentation, see [documentation/README.md](documentation/README.md)
