# Project Architecture

**Pytest + Selenium Test Template v6.2.0**
**Author**: Marc Arevalo
**Last Updated**: December 2025

---

## Table of Contents

1. [Overview](#overview)
2. [Design Approach](#design-approach)
3. [Architecture Diagram](#architecture-diagram)
4. [Core Components](#core-components)
5. [Directory Structure](#directory-structure)
6. [Data Flow](#data-flow)
7. [Extension Points](#extension-points)
8. [Dependencies](#dependencies)
9. [Configuration Management](#configuration-management)
10. [Testing Strategy](#testing-strategy)

---

## Overview

This is a **test automation template** built with Python, Selenium, and Pytest. It provides structured patterns and reusable components for web application testing projects.

### Key Characteristics

- **Template-based**: Starting point for pytest + Selenium projects
- **Structured**: Pre-organized directories and example patterns
- **Modular**: Separated utilities for different testing needs
- **Educational**: Well-documented examples and patterns
- **Not production-tested**: Use as reference, not as dependency

---

## Design Approach

### 1. Template, Not Framework

This project provides patterns and structure, not a standalone framework:
- No hardcoded application-specific values
- Configured via environment variables
- Requires adaptation to your application
- Empty `pages/` directory by default (you create your page objects)

### 2. Selenium Wrappers

Convenience methods wrapping Selenium WebDriver:
- `ElementFinder`: Find elements with fallback strategies
- `ElementInteractor`: Interact with elements with retry logic
- `WaitHandler`: Wait utilities (wraps WebDriverWait)

### 3. Layered Architecture

```
┌─────────────────────────────────────────┐
│         User Test Layer                 │  ← Your tests go here
├─────────────────────────────────────────┤
│         Page Object Layer               │  ← Your page objects
├─────────────────────────────────────────┤
│      Framework Core (Universal)         │  ← Discovery, interaction
├─────────────────────────────────────────┤
│         Utilities (Reusable)            │  ← API, DB, security
├─────────────────────────────────────────┤
│     Configuration & Infrastructure      │  ← Config, fixtures, CI/CD
└─────────────────────────────────────────┘
```

### 4. Test-First Development

The framework itself is thoroughly tested:
- `tests/unit/`: Unit tests for framework utilities
- `tests/framework/`: Integration tests for framework features
- `tests/examples/`: Examples demonstrating capabilities

---

## Architecture Diagram

```
universal-test-framework/
│
├── USER SPACE (Your Code)
│   ├── pages/                      # YOUR page objects (empty by default)
│   │   └── README.md              # Instructions for creating page objects
│   └── tests/                     # YOUR application tests go here
│       └── test_*.py
│
├── FRAMEWORK CORE (Universal)
│   └── framework/
│       ├── core/                  # Discovery-based core engine
│       │   ├── discovery_engine.py      # Page structure discovery
│       │   ├── element_finder.py        # Multi-strategy element location
│       │   ├── element_interactor.py    # Safe element interaction
│       │   └── wait_handler.py          # Smart waiting strategies
│       │
│       ├── cli/                   # Command-line tools
│       │   ├── setup_wizard.py         # Interactive configuration
│       │   └── README.md               # CLI documentation
│       │
│       ├── generators/            # Code generation (planned v7.0+)
│       │   └── README.md               # Generator roadmap
│       │
│       └── adapters/              # External system integrations
│           ├── base_adapter.py         # Adapter interface
│           └── adapter_template.py     # Template for custom adapters
│
├── UTILITIES (Reusable)
│   └── utils/
│       ├── api/                   # REST API testing
│       │   ├── api_client.py           # HTTP client wrapper
│       │   ├── response_validator.py   # Response validation
│       │   └── schema_validator.py     # JSON schema validation
│       │
│       ├── database/              # Database testing
│       │   ├── connection_manager.py   # Multi-DB connections
│       │   ├── query_executor.py       # Query execution wrapper
│       │   └── query_validator.py      # Query validation
│       │
│       ├── security/              # Security testing
│       │   ├── payload_library.py      # Attack payloads (XSS, SQLi, etc.)
│       │   ├── vulnerability_scanner.py # Automated scanning
│       │   ├── response_analyzer.py     # Security response analysis
│       │   └── security_report.py       # Security reporting
│       │
│       ├── performance/           # Performance monitoring
│       │   ├── metrics.py              # Performance metrics collection
│       │   ├── decorators.py           # Performance decorators
│       │   └── reporter.py             # Performance reporting
│       │
│       ├── visual/                # Visual regression
│       │   ├── screenshot_manager.py   # Screenshot capture
│       │   └── visual_comparator.py    # Image comparison
│       │
│       ├── accessibility/         # Accessibility testing
│       │   └── axe_helper.py           # Axe-core integration
│       │
│       ├── test_data/             # Test data generation
│       │   ├── generators.py           # Data generators
│       │   └── data_factory.py         # Data factory pattern
│       │
│       ├── auto_config/           # Auto-configuration tools
│       │   ├── page_crawler.py         # Page crawling
│       │   ├── locator_extractor.py    # Locator extraction
│       │   ├── code_generator.py       # Code generation
│       │   └── intelligent_scanner.py  # Intelligent page scanning
│       │
│       ├── helpers/               # Helper utilities
│       │   ├── wait_helpers.py         # Waiting utilities
│       │   ├── validators.py           # Validation utilities
│       │   └── data_generator.py       # Data generation helpers
│       │
│       └── locators_loader.py     # Locator file loader
│
├── CONFIGURATION
│   ├── config/                    # Configuration examples
│   │   └── examples/              # Browser configs, environment examples
│   ├── config.py                  # Main configuration loader
│   ├── .env                       # Environment variables (user-created)
│   └── .env.template              # Environment template
│
├── TESTING INFRASTRUCTURE
│   ├── tests/
│   │   ├── unit/                  # Framework unit tests
│   │   ├── framework/             # Framework feature tests
│   │   └── examples/              # Usage examples
│   │       ├── api/               # API testing examples
│   │       └── database/          # Database testing examples
│   │
│   ├── conftest.py                # Pytest fixtures and configuration
│   ├── pytest.ini                 # Pytest configuration
│   └── static_test_data.py        # Shared test data
│
├── TEMPLATES
│   ├── templates/
│   │   ├── page_objects/          # Page object templates
│   │   ├── tests/                 # Test templates
│   │   └── locators/              # Locator file templates
│
├── ONBOARDING
│   ├── quick_start.py             # Interactive setup script
│   └── auto_configure.py          # Auto-configuration tool
│
├── CI/CD
│   ├── .github/workflows/         # GitHub Actions
│   ├── .pre-commit-config.yaml    # Pre-commit hooks
│   └── docker-compose.yml         # Docker Selenium Grid
│
└── 📖 DOCUMENTATION
    ├── documentation/
    │   ├── guides/                # User guides
    │   ├── api-reference/         # API documentation
    │   └── qa-guidelines/         # QA best practices
    └── README.md                  # Main documentation
```

---

## Core Components

### 1. Framework Core (`framework/core/`)

The heart of the universal framework - provides discovery-based automation.

#### `discovery_engine.py`
- **Purpose**: Discovers page structure dynamically
- **Key Features**:
  - Detects forms, tables, navigation menus
  - Identifies interactive elements
  - Builds page structure map
- **Usage**: `engine = DiscoveryEngine(driver); structure = engine.discover_page()`

#### `element_finder.py`
- **Purpose**: Locates elements using multiple strategies
- **Key Features**:
  - ID → Name → CSS → XPath fallback chain
  - Shadow DOM support
  - Iframe handling
- **Usage**: `finder = ElementFinder(driver); element = finder.find_element(locator)`

#### `element_interactor.py`
- **Purpose**: Safe, resilient element interaction
- **Key Features**:
  - Automatic retry on stale element
  - Scrolling into view
  - Wait for clickability
- **Usage**: `interactor.click(element); interactor.type(element, "text")`

#### `wait_handler.py`
- **Purpose**: Smart waiting strategies
- **Key Features**:
  - Configurable timeouts
  - Custom wait conditions
  - Polling strategies
- **Usage**: `wait = WaitHandler(driver); wait.until(condition)`

### 2. Framework CLI (`framework/cli/`)

Command-line tools for framework management.

#### `setup_wizard.py`
- **Purpose**: Interactive framework configuration
- **Features**:
  - Basic settings (URL, browser, timeouts)
  - Advanced settings (Grid, performance, parallel)
  - Generates `.env` file with validation
- **Usage**: `python -m framework.cli.setup_wizard`

### 3. Utilities (`utils/`)

Reusable utilities for various testing needs.

#### API Testing (`utils/api/`)
- `APIClient`: HTTP client with retry logic and authentication
- `ResponseValidator`: Validates response status, JSON, headers
- `SchemaValidator`: JSON schema validation

#### Database Testing (`utils/database/`)
- `ConnectionManager`: Multi-database connection management (MySQL, PostgreSQL, SQLite)
- `QueryExecutor`: Safe query execution with parameterization
- `QueryValidator`: SQL injection detection

#### Security Testing (`utils/security/`)
- `PayloadLibrary`: 500+ attack payloads (XSS, SQLi, CSRF, XXE, etc.)
- `VulnerabilityScanner`: Automated security scanning
- `ResponseAnalyzer`: Detects security vulnerabilities in responses
- `SecurityReport`: Generates security reports

#### Performance Monitoring (`utils/performance/`)
- `Metrics`: Collects performance metrics (response time, page load)
- `Decorators`: `@measure_performance` decorator for tests
- `Reporter`: Generates performance reports

---

## Directory Structure

### User Space
- **`pages/`**: Where YOU create page objects for YOUR application
- **`tests/` (root)**: Where YOU write tests for YOUR application

### Framework Space (Don't Modify)
- **`framework/`**: Universal framework core - discovery, interaction, CLI
- **`utils/`**: Reusable utilities - API, DB, security, performance
- **`tests/unit/`**: Framework unit tests
- **`tests/framework/`**: Framework integration tests
- **`tests/examples/`**: Example tests demonstrating features

### Configuration Space
- **`config/`**: Configuration examples and templates
- **`config.py`**: Configuration loader (reads from environment)
- **`.env`**: Your environment variables (created by setup wizard)

### Infrastructure Space
- **`conftest.py`**: Pytest fixtures (browser, page objects, test data)
- **`pytest.ini`**: Pytest configuration (markers, coverage, parallelization)
- **`templates/`**: Templates for page objects, tests, locators

---

## Data Flow

### Test Execution Flow

```
┌──────────────────────────────────────────────────────────────┐
│ 1. Test Start (pytest)                                       │
└──────────────┬───────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────┐
│ 2. Configuration Load (config.py reads .env)                 │
└──────────────┬───────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────┐
│ 3. Browser Initialization (conftest.py fixture)              │
│    - Reads BROWSER, HEADLESS from config                     │
│    - Creates WebDriver instance                              │
│    - Navigates to BASE_URL                                   │
└──────────────┬───────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────┐
│ 4. Page Object Initialization (if used)                      │
│    - User's page object receives browser                     │
│    - Optionally uses DiscoveryEngine to find elements        │
└──────────────┬───────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────┐
│ 5. Test Execution                                            │
│    - Test interacts with page objects                        │
│    - Page objects use framework core for element operations  │
│    - ElementFinder locates elements                          │
│    - ElementInteractor performs actions                      │
│    - WaitHandler ensures element readiness                   │
└──────────────┬───────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────┐
│ 6. Assertions                                                │
│    - Test validates expected behavior                        │
└──────────────┬───────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────┐
│ 7. Cleanup (conftest.py teardown)                           │
│    - Screenshots on failure (if configured)                  │
│    - Browser closed                                          │
│    - Reports generated (HTML, Allure, coverage)              │
└──────────────────────────────────────────────────────────────┘
```

### Configuration Flow

```
Environment Variables (.env)
            ↓
    config.py (ConfigLoader)
            ↓
    conftest.py (fixtures)
            ↓
    Tests (via fixtures)
```

---

## Extension Points

The framework is designed to be extended without modifying core code.

### 1. Custom Page Objects

Create in `pages/` directory:

```python
# pages/my_login_page.py
from framework.core.element_finder import ElementFinder
from framework.core.element_interactor import ElementInteractor

class MyLoginPage:
    def __init__(self, driver):
        self.driver = driver
        self.finder = ElementFinder(driver)
        self.interactor = ElementInteractor(driver)

    def login(self, username, password):
        username_field = self.finder.find_element(("id", "username"))
        password_field = self.finder.find_element(("id", "password"))

        self.interactor.type(username_field, username)
        self.interactor.type(password_field, password)
        self.interactor.click(("id", "login-button"))
```

### 2. Custom Fixtures

Add to `conftest.py`:

```python
@pytest.fixture
def my_custom_fixture(browser):
    """Your custom setup."""
    # Setup code
    yield data
    # Teardown code
```

### 3. Custom Utilities

Add to `utils/` directory:

```python
# utils/my_custom/my_utility.py
class MyUtility:
    """Custom utility for your needs."""
    pass
```

### 4. Custom Adapters

Create in `framework/adapters/`:

```python
# framework/adapters/my_adapter.py
from framework.adapters.base_adapter import BaseAdapter

class MyAdapter(BaseAdapter):
    """Adapter for external system integration."""

    def connect(self):
        """Connect to external system."""
        pass

    def disconnect(self):
        """Disconnect from external system."""
        pass
```

### 5. Custom Pytest Markers

Add to `pytest.ini`:

```ini
markers =
    my_custom_marker: Description of my custom marker
```

Use in tests:

```python
@pytest.mark.my_custom_marker
def test_something():
    pass
```

---

## Dependencies

### Core Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| **Python** | 3.11+ | Runtime |
| **Selenium** | 4.25.0+ | Browser automation |
| **Pytest** | 8.3.4+ | Test framework |
| **pytest-xdist** | 3.6.1+ | Parallel execution |
| **pytest-html** | 4.1.1+ | HTML reporting |
| **pytest-rerunfailures** | 14.0+ | Retry failed tests |
| **pytest-cov** | 6.0.0+ | Code coverage |
| **python-dotenv** | 1.0.1+ | Environment variables |
| **requests** | 2.32.3+ | HTTP client |
| **Pillow** | 11.0.0+ | Image processing |
| **allure-pytest** | 2.13.5+ | Allure reporting |

### Optional Dependencies

| Library | Purpose |
|---------|---------|
| **pymysql** | MySQL database testing |
| **psycopg2-binary** | PostgreSQL database testing |
| **jsonschema** | JSON schema validation |
| **axe-selenium-python** | Accessibility testing |

### Development Dependencies

| Library | Purpose |
|---------|---------|
| **black** | Code formatting |
| **flake8** | Linting |
| **mypy** | Type checking |
| **pre-commit** | Git hooks |

---

## Configuration Management

### Environment-Based Configuration

All configuration comes from `.env` file:

```bash
# Application
BASE_URL=https://www.example.com

# Browser
BROWSER=chrome
HEADLESS=false

# Timeouts
IMPLICIT_WAIT=10
EXPLICIT_WAIT=30
PAGE_LOAD_TIMEOUT=60

# Selenium Grid (optional)
USE_SELENIUM_GRID=false
SELENIUM_GRID_URL=http://localhost:4444/wd/hub
```

### Configuration Priority

1. **Environment variables** (highest priority)
2. **`.env` file**
3. **Default values in `config.py`** (lowest priority)

### Creating Configuration

**Option 1**: Interactive setup wizard
```bash
python -m framework.cli.setup_wizard
```

**Option 2**: Copy template
```bash
cp .env.template .env
# Edit .env with your settings
```

**Option 3**: Quick start script
```bash
python quick_start.py
```

---

## Testing Strategy

### Framework Self-Testing

The framework tests itself at three levels:

1. **Unit Tests** (`tests/unit/`)
   - Test individual utilities in isolation
   - No browser required
   - Fast execution (~2 seconds)
   - Marker: `@pytest.mark.unit`

2. **Integration Tests** (`tests/framework/`)
   - Test framework features end-to-end
   - May require browser
   - Test security, performance, auto-config
   - Markers: `@pytest.mark.security`, `@pytest.mark.performance`

3. **Example Tests** (`tests/examples/`)
   - Demonstrate framework usage
   - Not actual tests of the framework
   - Show API testing, database testing patterns
   - Markers: `@pytest.mark.api`, `@pytest.mark.database`

### User Testing

Users write tests in:
- **`tests/` (root)**: Application-specific tests
- **`pages/`**: Application-specific page objects

### Test Execution

```bash
# Run all tests
pytest

# Run only unit tests (fast)
pytest -m unit

# Run functional tests
pytest -m functional

# Run security tests
pytest -m security

# Run with coverage
pytest --cov=framework --cov=utils

# Run in parallel
pytest -n auto

# Run without retries (local dev)
pytest -n 0 --reruns=0
```

---

## Best Practices

### 1. Keep Framework Code Universal

❌ **Don't** hardcode application-specific values in framework code:
```python
# BAD: framework/core/discovery_engine.py
LOGIN_URL = "https://myapp.com/login"  # ❌ Application-specific
```

✅ **Do** use configuration and parameters:
```python
# GOOD: Use config
from config import Config
url = Config.BASE_URL + "/login"
```

### 2. Use Discovery Over Hardcoding

❌ **Don't** hardcode element locators in framework:
```python
# BAD
LOGIN_BUTTON = ("id", "login-btn-123")  # ❌ Application-specific
```

✅ **Do** discover elements or use user-provided locators:
```python
# GOOD
def find_login_button(self):
    """Discover login button using multiple strategies."""
    return self.finder.find_element_by_patterns(["login", "submit", "sign in"])
```

### 3. Separate Concerns

- **Framework code** (`framework/`, `utils/`): Universal, reusable
- **User code** (`pages/`, `tests/`): Application-specific
- **Configuration** (`config/`, `.env`): Environment-specific

### 4. Document Extension Points

When adding new framework features, document how users can extend them in:
- `documentation/guides/extending-framework.md`
- Code comments
- README files in relevant directories

### 5. Test Your Changes

Before committing framework changes:
```bash
# Run framework tests
pytest tests/unit/ tests/framework/ -v

# Check coverage
pytest --cov=framework --cov=utils --cov-report=html

# Run linting
flake8 framework/ utils/

# Run type checking
mypy framework/ --ignore-missing-imports
```

---

## Version History

| Version | Date | Key Changes |
|---------|------|-------------|
| **6.2.0** | Dec 2025 | Structure cleanup, CLI tools, unified version, full documentation |
| **6.1.0** | Dec 2025 | Post-universal transformation improvements, optimization |
| **6.0.0** | Dec 2025 | Complete transformation to universal framework |
| **5.0** | Nov 2025 | DemoBlaze-specific test suite |

See [CHANGELOG.md](CHANGELOG.md) for detailed version history.

---

## Contributing

When contributing to the framework:

1. **Maintain universality**: No application-specific code in framework/utils
2. **Add tests**: All new features must have unit tests
3. **Update documentation**: Update this file and relevant guides
4. **Follow style**: Use black, flake8, mypy
5. **Test thoroughly**: Run full test suite before committing

---

## Support

- **Documentation**: See [documentation/README.md](documentation/README.md)
- **Issues**: Report bugs and request features on GitHub
- **Guides**: See [documentation/guides/](documentation/guides/)
- **Examples**: See [tests/examples/](tests/examples/)

---

**Project Architecture Documentation v6.2.0**
**Pytest + Selenium Test Template**
