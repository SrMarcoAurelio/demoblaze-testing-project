# Accessibility Tests

## Overview

WCAG 2.1 Level AA compliance testing using axe-core. Validates accessibility across all pages.

## Test Coverage (52 tests)

- Login accessibility (8 tests)
- Signup accessibility (6 tests)
- Cart accessibility (8 tests)
- Catalog accessibility (12 tests)
- Product accessibility (8 tests)
- Purchase accessibility (10 tests)

## Standards

- WCAG 2.1 Level AA
- Section 508
- EN 301 549
- ADA Title III

## Running Tests

```bash
pytest -m accessibility -v
pytest tests/accessibility/ -v
```

## Utilities

Uses `utils/accessibility/wcag_validator.py`

## Documentation

See [Accessibility Testing Module](../../documentation/modules/accessibility-testing.md)
