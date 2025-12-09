# Accessibility Utilities

## Overview

WCAG 2.1 validation utilities using axe-core integration.

## Files

- `wcag_validator.py` - WCAG compliance validation
- `accessibility_checker.py` - Core accessibility checking

## Key Classes

### WCAGValidator

Validates pages against WCAG 2.1 Level AA standards.

**Methods:**
- `validate_page(driver, page_name)` - Full page validation
- `check_keyboard_navigation(driver, elements)` - Keyboard accessibility
- `verify_color_contrast(driver, element)` - Contrast ratio checking

## Usage

```python
from utils.accessibility.wcag_validator import WCAGValidator

validator = WCAGValidator()
result = validator.validate_page(driver, "login")
assert len(result['violations']) == 0
```

## Documentation

See [Accessibility Testing Module](../../documentation/modules/accessibility-testing.md)
