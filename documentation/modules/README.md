# Testing Modules Documentation

## Overview

This directory contains comprehensive documentation for all testing modules in the project. Each module provides specialized testing capabilities with professional implementation, maintenance guides, and best practices.

## Table of Contents

- [Core Testing Modules](#core-testing-modules)
- [Utility Modules](#utility-modules)
- [Configuration and Setup](#configuration-and-setup)
- [Module Dependencies](#module-dependencies)

## Core Testing Modules

### 1. [Accessibility Testing](./accessibility-testing.md)
**Purpose:** WCAG 2.1 Level AA compliance testing

**Key Features:**
- Automated accessibility validation using axe-core
- Keyboard navigation testing
- Screen reader compatibility verification
- Color contrast analysis
- ARIA attribute validation

**Test Coverage:** 52 tests across 6 page types

**Standards:** WCAG 2.1, Section 508, EN 301 549, ADA

---

### 2. [API Testing](./api-testing.md)
**Purpose:** REST API endpoint testing and validation

**Key Features:**
- HTTP client with retry logic
- JSON schema validation
- Response time monitoring
- Authentication testing (Basic, Bearer, OAuth)
- Contract testing support

**Test Coverage:** 27+ API endpoint tests

**Standards:** REST API best practices, JSON Schema Draft-07

---

### 3. [Security Testing](./security-testing.md)
**Purpose:** Security vulnerability detection and OWASP Top 10 validation

**Key Features:**
- SQL Injection testing (25 test cases)
- Cross-Site Scripting (XSS) detection (18 test cases)
- Command Injection testing
- CSRF protection validation
- Real HTTP interception with mitmproxy
- Comprehensive payload library (347 lines)
- Automated vulnerability scanning

**Test Coverage:** 102+ security tests covering OWASP Top 10

**Standards:** OWASP Top 10 2021, OWASP ASVS 4.0, CWE Top 25

**WARNING:** Only use on authorized systems. Unauthorized security testing may be illegal.

---

### 4. [Visual Regression Testing](./visual-regression-testing.md)
**Purpose:** Automated visual comparison and UI consistency testing

**Key Features:**
- Full page and element-specific screenshots
- Pixel-perfect image comparison
- Responsive design testing (mobile, tablet, desktop)
- Baseline management and versioning
- Visual diff generation

**Test Coverage:** Visual tests across all critical pages and viewports

**Technologies:** Selenium WebDriver, Pillow, pixelmatch

---

### 5. Test Data Management Module
**Purpose:** Test data generation, management, and cleanup

**Key Features:**
- Fake data generation (users, products, orders)
- Database seeding and cleanup
- Test data versioning
- Data factory patterns
- JSON/CSV data loading

**Location:**
- `tests/test_data/` - Test data tests
- `utils/test_data/` - Data management utilities

---

### 6. Performance Testing Module
**Purpose:** Performance monitoring and Core Web Vitals validation

**Key Features:**
- Core Web Vitals measurement (LCP, FID, CLS)
- Response time tracking
- Resource loading analysis
- Performance regression detection
- Lighthouse integration

**Location:**
- `tests/performance/` - Performance tests
- `utils/performance/` - Performance monitoring utilities

**Standards:** Google Core Web Vitals, Web Performance Working Group (W3C)

---

### 7. Database Testing Module
**Purpose:** Database integrity and data validation testing

**Key Features:**
- Database connection management
- Query execution and validation
- Data integrity checks
- Transaction testing
- Database seeding and cleanup

**Location:**
- `tests/database/` - Database tests
- `utils/database/` - Database utilities

---

## Utility Modules

### 8. Auto-Configurator System
**Purpose:** Intelligent project setup and configuration

**Key Features:**
- Automatic dependency detection
- WebDriver setup (Chrome, Firefox, Edge, Safari)
- Configuration file generation
- Environment validation
- Pre-commit hook setup

**Location:** `utils/auto_config/` and `auto_configure.py`

**Usage:**
```bash
python auto_configure.py
```

---

### 9. Base Page and Helpers
**Purpose:** Core page object model and utility functions

**Components:**
- **BasePage** (`pages/base_page.py`): 598 lines
  - Element interaction methods
  - Wait strategies
  - Navigation utilities
  - Screenshot capture

- **Wait Helpers** (`utils/helpers/wait_helpers.py`): 203 lines
  - Custom wait conditions
  - Element visibility waits
  - Page load waits

- **Performance Monitor** (`utils/helpers/performance_monitor.py`)
  - Real-time performance tracking
  - Metrics collection

**Test Coverage:**
- 35 BasePage integration tests
- 18 wait helpers tests

---

## Configuration and Setup

### Environment Setup

1. **Install dependencies:**
```bash
pip install -r requirements.txt
```

2. **Configure WebDriver:**
```bash
python auto_configure.py
```

3. **Setup pre-commit hooks:**
```bash
pre-commit install
```

4. **Configure environment variables:**
```bash
export BASE_URL="https://your-application-url.com"
export HEADLESS=false
export BROWSER=chrome
```

### Running Tests by Module

**Accessibility:**
```bash
pytest -m accessibility -v
```

**API:**
```bash
pytest -m api -v
```

**Security:**
```bash
pytest -m security -v
```

**Visual:**
```bash
pytest -m visual -v
```

**Performance:**
```bash
pytest -m performance -v
```

**All tests:**
```bash
pytest -v
```

## Module Dependencies

### Dependency Graph

```
┌─────────────────────────────────────────────┐
│         conftest.py (Root Fixtures)         │
│   - browser, api_client, db_connection     │
└─────────────────┬───────────────────────────┘
                  │
        ┌─────────┴─────────┬─────────────────┬──────────────────┐
        │                   │                 │                  │
┌───────▼────────┐ ┌────────▼─────────┐ ┌────▼─────────┐ ┌────▼──────────┐
│  BasePage      │ │  SecurityUtils   │ │  APIClient   │ │  TestData     │
│  (598 lines)   │ │  (1265 lines)    │ │  (300 lines) │ │  (400 lines)  │
└───────┬────────┘ └────────┬─────────┘ └────┬─────────┘ └────┬──────────┘
        │                   │                 │                │
        │          ┌────────┴─────────┐       │                │
        │          │                  │       │                │
┌───────▼──────┐ ┌─▼──────────┐ ┌────▼───────▼────┐ ┌─────────▼─────────┐
│  Page Tests  │ │  Security  │ │   API Tests     │ │  Database Tests   │
│  (Login,     │ │  Tests     │ │                 │ │                   │
│   Signup,    │ │  (102      │ │  (27 tests)     │ │  (15 tests)       │
│   Cart, etc) │ │   tests)   │ │                 │ │                   │
└──────────────┘ └────────────┘ └─────────────────┘ └───────────────────┘
```

### External Dependencies

**Core:**
- `pytest` - Test framework
- `selenium` - Browser automation
- `requests` - HTTP library

**Security:**
- `mitmproxy` - HTTP interception

**Visual:**
- `Pillow` - Image processing
- `pixelmatch` - Image comparison

**API:**
- `jsonschema` - Schema validation
- `responses` - HTTP mocking

**Accessibility:**
- `axe-selenium-python` - WCAG validation

## Test Execution Matrix

| Module | Unit Tests | Integration Tests | E2E Tests | Total |
|--------|-----------|-------------------|-----------|-------|
| Accessibility | 0 | 52 | 0 | 52 |
| API | 12 | 15 | 0 | 27 |
| Security | 37 | 65 | 0 | 102 |
| Visual | 0 | 0 | 35 | 35 |
| Performance | 8 | 12 | 0 | 20 |
| Database | 5 | 10 | 0 | 15 |
| BasePage | 0 | 35 | 0 | 35 |
| Test Utils | 42 | 0 | 0 | 42 |
| Cart | 20 | 35 | 0 | 55 |
| Login | 15 | 25 | 0 | 40 |
| Signup | 12 | 20 | 0 | 32 |
| Catalog | 18 | 30 | 0 | 48 |
| Product | 15 | 25 | 0 | 40 |
| Purchase | 20 | 35 | 0 | 55 |
| **TOTAL** | **204** | **359** | **35** | **598** |

## Integration with CI/CD

All modules are integrated into the CI/CD pipeline defined in `.github/workflows/tests.yml`:

```yaml
jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - run: pytest -m unit -v

  integration-tests:
    runs-on: ubuntu-latest
    steps:
      - run: pytest -m "not unit and not e2e" -v

  accessibility-tests:
    runs-on: ubuntu-latest
    steps:
      - run: pytest -m accessibility -v

  security-tests:
    runs-on: ubuntu-latest
    steps:
      - run: pytest -m security -v
```

## Documentation Standards

All module documentation follows these standards:

1. **Professional tone** - Technical, clear, no emojis
2. **Comprehensive coverage** - Architecture, usage, maintenance
3. **Code examples** - Real, working code snippets
4. **Industry standards** - References to official standards (WCAG, OWASP, etc.)
5. **Troubleshooting** - Common issues and solutions
6. **Best practices** - Production-ready recommendations

## Contributing

When adding new testing modules:

1. Create module in appropriate location (`tests/` or `utils/`)
2. Write comprehensive tests
3. Create professional documentation following existing patterns
4. Update this index
5. Add pytest markers in `pytest.ini`
6. Configure CI/CD integration

## Support

For module-specific questions:
- Review individual module documentation
- Check test examples in module test files
- Consult QA Guidelines in `documentation/qa-guidelines/`

## License

Internal testing modules - follow project license.
