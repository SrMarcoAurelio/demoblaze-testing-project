# API Reference

Complete technical reference for all framework components.

## Overview

This section provides detailed API documentation for every class, method, and function in the framework. Each entry includes:

- Complete method signatures with type hints
- Detailed parameter descriptions
- Return value documentation
- Exceptions that can be raised
- Practical usage examples
- Internal implementation notes

## API Documentation

### Core Components

#### [BasePage API](base-page-api.md)
Complete reference for the BasePage class - the foundation of all page objects.

**Contents:**
- Element finding methods (find_element, find_elements)
- Wait methods (wait_for_element_visible, wait_for_element_clickable, wait_for_element_invisible)
- Interaction methods (click, type, get_text, get_attribute)
- Alert handling methods (wait_for_alert, accept_alert, dismiss_alert)
- Navigation methods (navigate_to, refresh_page, go_back)
- JavaScript execution (execute_script, scroll_to_element)
- Utility methods (take_screenshot, get_page_source)

**Total Methods:** 33

#### [Fixtures API](fixtures-api.md)
Complete reference for all 18 pytest fixtures available in the framework.

**Contents:**
- Configuration fixtures (base_url, timeout_config, test_config)
- Browser fixtures (browser, slow_down)
- Data fixtures (valid_user, invalid_user_username, invalid_user_password, new_user, purchase_data)
- Page object fixtures (login_page, signup_page, catalog_page, product_page, cart_page, purchase_page)
- Product fixtures (product_phone, product_laptop, product_monitor, random_product)
- State fixtures (logged_in_user, cart_with_product, prepared_checkout)
- Performance fixtures (performance_collector, performance_timer)

**Total Fixtures:** 18

### Utilities

#### [Locators API](locators-api.md)
External locators management system for UI element selectors.

**Contents:**
- LocatorsLoader class
- get_loader() singleton function
- load_locator() convenience function
- JSON configuration format

#### [Data Generators API](data-generators-api.md)
Test data generation utilities.

**Contents:**
- generate_unique_username()
- generate_random_password()
- generate_random_email()
- generate_credit_card_number()
- generate_random_string()

#### [Validators API](validators-api.md)
Data validation utilities for business logic testing.

**Contents:**
- validate_email()
- validate_url()
- validate_credit_card() (Luhn algorithm)
- validate_phone_number()
- validate_password_strength()
- validate_date_format()
- validate_postal_code()
- validate_username()

#### [Performance Metrics API](performance-metrics-api.md)
Performance testing and metrics collection system.

**Contents:**
- PerformanceMetricsCollector class
- PerformanceMetric dataclass
- PerformanceThreshold dataclass
- get_collector() singleton function
- Timer management methods
- Statistics and reporting methods

#### [Accessibility API](accessibility-api.md)
WCAG 2.1 accessibility testing with axe-core.

**Contents:**
- AxeHelper class
- WCAG compliance levels (A, AA, AAA)
- Violation detection and reporting
- Accessibility report generation

## Quick Navigation

### By Use Case

**Creating Tests:**
- [Fixtures API](fixtures-api.md) - Get test data and page objects
- [BasePage API](base-page-api.md) - Interact with web elements

**Managing Locators:**
- [Locators API](locators-api.md) - Load and manage UI selectors

**Generating Test Data:**
- [Data Generators API](data-generators-api.md) - Create test data
- [Validators API](validators-api.md) - Validate business logic

**Performance Testing:**
- [Performance Metrics API](performance-metrics-api.md) - Collect and analyze metrics

**Accessibility Testing:**
- [Accessibility API](accessibility-api.md) - WCAG compliance testing

### By Component Type

**Classes:**
- BasePage (base_page.py)
- LocatorsLoader (locators_loader.py)
- PerformanceMetricsCollector (performance/metrics.py)
- AxeHelper (accessibility/axe_helper.py)

**Functions:**
- Data generators (7 functions)
- Validators (9 functions)
- Locator helpers (2 functions)

**Fixtures:**
- 18 pytest fixtures for dependency injection

## Usage Patterns

### Common Workflows

**1. Create a new test:**
```python
def test_example(login_page, valid_user):
    # Use fixture-provided page object and data
    login_page.login(**valid_user)
    assert login_page.is_user_logged_in()
```

**2. Generate test data:**
```python
from utils.helpers.data_generator import generate_unique_username

username = generate_unique_username()
```

**3. Validate business logic:**
```python
from utils.helpers.validators import validate_credit_card

is_valid = validate_credit_card("4532015112830366")
```

**4. Measure performance:**
```python
def test_performance(performance_collector):
    performance_collector.start_timer("operation")
    # Perform operation
    duration = performance_collector.stop_timer("operation")
    assert performance_collector.check_threshold("operation", duration)
```

**5. Test accessibility:**
```python
from utils.accessibility.axe_helper import AxeHelper

axe = AxeHelper(driver)
results = axe.run_wcag_aa()
axe.assert_no_violations(results)
```

## Related Documentation

- [Code Walkthrough Guide](../guides/code-walkthrough.md) - Understand code execution flow
- [Extending Framework Guide](../guides/extending-framework.md) - Customize and extend
- [Troubleshooting Guide](../guides/troubleshooting.md) - Common issues and solutions

## API Versioning

**Current Version:** 4.0

Breaking changes are documented in each API section. The framework follows semantic versioning principles.
