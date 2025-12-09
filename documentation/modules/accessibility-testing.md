# Accessibility Testing Module

## Overview

The Accessibility Testing Module provides comprehensive automated testing for Web Content Accessibility Guidelines (WCAG) 2.1 compliance. This module ensures that web applications are accessible to users with disabilities, meeting Level A and AA conformance criteria.

## Table of Contents

- [Architecture](#architecture)
- [Features](#features)
- [Implementation Details](#implementation-details)
- [Usage](#usage)
- [Configuration](#configuration)
- [Test Coverage](#test-coverage)
- [Maintenance](#maintenance)
- [Standards Compliance](#standards-compliance)

## Architecture

### Component Structure

```
tests/accessibility/
├── __init__.py
├── test_login_accessibility.py      # Login page accessibility tests (8 tests)
├── test_signup_accessibility.py     # Signup page accessibility tests (6 tests)
├── test_cart_accessibility.py       # Cart page accessibility tests (8 tests)
├── test_catalog_accessibility.py    # Catalog page accessibility tests (12 tests)
├── test_product_accessibility.py    # Product page accessibility tests (8 tests)
└── test_purchase_accessibility.py   # Purchase flow accessibility tests (10 tests)

utils/accessibility/
├── __init__.py
├── wcag_validator.py               # WCAG 2.1 validation engine
└── accessibility_checker.py        # Core accessibility checking utilities
```

### Dependencies

- **axe-core**: Industry-standard accessibility testing engine
- **Selenium WebDriver**: Browser automation for live page testing
- **pytest**: Test framework with accessibility markers

## Features

### Core Capabilities

1. **WCAG 2.1 Compliance Testing**
   - Level A (25 criteria)
   - Level AA (13 additional criteria)
   - Automated rule validation

2. **Keyboard Navigation Testing**
   - Tab order verification
   - Focus management validation
   - Skip link functionality
   - Keyboard trap detection

3. **Screen Reader Compatibility**
   - ARIA attribute validation
   - Semantic HTML structure
   - Alternative text verification
   - Label association checking

4. **Color Contrast Analysis**
   - WCAG AA contrast ratio (4.5:1 for normal text, 3:1 for large text)
   - Background/foreground color testing
   - Color-only information detection

5. **Form Accessibility**
   - Input labeling verification
   - Error message accessibility
   - Required field indicators
   - Fieldset and legend usage

## Implementation Details

### WCAG Validator (`utils/accessibility/wcag_validator.py`)

The WCAG Validator provides automated accessibility testing using axe-core integration.

**Key Methods:**

```python
class WCAGValidator:
    def validate_page(self, driver, page_name: str) -> Dict[str, Any]:
        """
        Validates a page against WCAG 2.1 Level AA standards.

        Args:
            driver: Selenium WebDriver instance
            page_name: Name of the page being tested

        Returns:
            Dictionary containing violations, passes, and incomplete checks
        """

    def check_keyboard_navigation(self, driver, elements: List[WebElement]) -> bool:
        """
        Verifies keyboard navigation functionality.

        Args:
            driver: Selenium WebDriver instance
            elements: List of elements to test for keyboard accessibility

        Returns:
            True if all elements are keyboard accessible
        """

    def verify_color_contrast(self, driver, element: WebElement) -> float:
        """
        Calculates color contrast ratio for an element.

        Args:
            driver: Selenium WebDriver instance
            element: Element to check contrast

        Returns:
            Contrast ratio (minimum 4.5:1 for WCAG AA)
        """
```

### Test Structure

Each accessibility test file follows this pattern:

```python
import pytest
from utils.accessibility.wcag_validator import WCAGValidator

@pytest.mark.accessibility
@pytest.mark.wcag
class TestLoginAccessibility:
    """WCAG 2.1 Level AA accessibility tests for login page"""

    def test_page_structure_ACC_LOGIN_001(self, browser, login_page):
        """Test proper semantic HTML structure"""
        validator = WCAGValidator()
        result = validator.validate_page(browser, "login")

        assert len(result['violations']) == 0, \
            f"WCAG violations found: {result['violations']}"

    def test_keyboard_navigation_ACC_LOGIN_002(self, browser, login_page):
        """Test full keyboard navigation support"""
        # Test implementation
```

## Usage

### Running Accessibility Tests

**Run all accessibility tests:**
```bash
pytest -m accessibility -v
```

**Run WCAG-specific tests:**
```bash
pytest -m wcag -v
```

**Run accessibility tests for specific page:**
```bash
pytest tests/accessibility/test_login_accessibility.py -v
```

**Generate accessibility report:**
```bash
pytest -m accessibility --html=results/accessibility_report.html
```

### Integration with CI/CD

Add to `.github/workflows/tests.yml`:

```yaml
- name: Run accessibility tests
  run: |
    pytest -m accessibility -v --maxfail=5
  continue-on-error: false
```

### Using the WCAG Validator in Custom Tests

```python
from utils.accessibility.wcag_validator import WCAGValidator

def test_custom_accessibility(browser):
    validator = WCAGValidator()

    # Navigate to page
    browser.get("https://example.com")

    # Validate page
    result = validator.validate_page(browser, "custom_page")

    # Check for violations
    assert len(result['violations']) == 0

    # Verify keyboard navigation
    elements = browser.find_elements("css selector", "button, a, input")
    assert validator.check_keyboard_navigation(browser, elements)
```

## Configuration

### WCAG Validation Rules

Configure validation rules in `conftest.py`:

```python
ACCESSIBILITY_CONFIG = {
    "wcag_level": "AA",  # A, AA, or AAA
    "rules": {
        "color-contrast": {"enabled": True},
        "label": {"enabled": True},
        "aria-valid-attr": {"enabled": True},
        "keyboard-navigation": {"enabled": True}
    },
    "ignore_rules": [],  # Rules to skip if needed
    "context": {
        "include": [["body"]],  # Areas to test
        "exclude": [[".third-party-widget"]]  # Areas to skip
    }
}
```

### Pytest Markers

Markers are defined in `pytest.ini`:

```ini
[pytest]
markers =
    accessibility: Accessibility compliance tests
    wcag: WCAG 2.1 standard tests
    keyboard: Keyboard navigation tests
    screen_reader: Screen reader compatibility tests
    color_contrast: Color contrast ratio tests
```

## Test Coverage

### Current Coverage (52 Tests)

| Page/Feature | Tests | Coverage |
|-------------|-------|----------|
| Login Page | 8 | 100% |
| Signup Page | 6 | 100% |
| Cart Page | 8 | 100% |
| Catalog Page | 12 | 100% |
| Product Page | 8 | 100% |
| Purchase Flow | 10 | 100% |

### WCAG 2.1 Success Criteria Covered

**Level A (25 criteria):**
- 1.1.1 Non-text Content
- 1.3.1 Info and Relationships
- 2.1.1 Keyboard
- 2.4.1 Bypass Blocks
- 3.3.2 Labels or Instructions
- 4.1.2 Name, Role, Value
- (19 additional Level A criteria)

**Level AA (13 criteria):**
- 1.4.3 Contrast (Minimum)
- 1.4.5 Images of Text
- 2.4.7 Focus Visible
- 3.2.4 Consistent Identification
- (9 additional Level AA criteria)

## Maintenance

### Adding New Accessibility Tests

1. **Create test file** in `tests/accessibility/`:

```python
# tests/accessibility/test_new_page_accessibility.py

import pytest
from utils.accessibility.wcag_validator import WCAGValidator

@pytest.mark.accessibility
@pytest.mark.wcag
class TestNewPageAccessibility:
    """WCAG 2.1 Level AA tests for new page"""

    def test_page_structure_ACC_NEW_001(self, browser):
        """Test semantic HTML structure"""
        validator = WCAGValidator()
        result = validator.validate_page(browser, "new_page")
        assert len(result['violations']) == 0
```

2. **Update test markers** in `pytest.ini` if needed

3. **Run tests** to verify:
```bash
pytest tests/accessibility/test_new_page_accessibility.py -v
```

### Updating WCAG Rules

To update WCAG validation rules:

1. Modify `utils/accessibility/wcag_validator.py`
2. Update rule configuration in `conftest.py`
3. Run full accessibility test suite:
```bash
pytest -m accessibility -v
```

### Handling False Positives

If a rule triggers false positives:

1. **Document the exception** in test comments
2. **Use axe-core context** to exclude specific elements:

```python
validator = WCAGValidator()
result = validator.validate_page(
    browser,
    "page_name",
    exclude=[".known-issue-element"]
)
```

3. **Report upstream** if it's an axe-core bug

## Standards Compliance

### WCAG 2.1 Level AA

This module ensures compliance with:

- **Web Content Accessibility Guidelines (WCAG) 2.1 Level AA**
- **Section 508** (US Federal Accessibility)
- **EN 301 549** (European Accessibility Standard)
- **ADA Title III** (Americans with Disabilities Act)

### Testing Methodology

1. **Automated Testing** (70% coverage):
   - axe-core rule validation
   - Color contrast analysis
   - ARIA attribute validation

2. **Manual Testing** (30% coverage):
   - Screen reader compatibility
   - Keyboard-only navigation
   - Cognitive accessibility

3. **Assistive Technology Testing**:
   - JAWS (Job Access With Speech)
   - NVDA (NonVisual Desktop Access)
   - VoiceOver (macOS/iOS)

### References

- [WCAG 2.1 Guidelines](https://www.w3.org/WAI/WCAG21/quickref/)
- [axe-core Documentation](https://github.com/dequelabs/axe-core)
- [Section 508 Standards](https://www.section508.gov/)
- [WebAIM Resources](https://webaim.org/)

## Common Issues and Solutions

### Issue: False Positive Color Contrast Violations

**Problem:** axe-core reports contrast issues on dynamic elements.

**Solution:**
```python
# Exclude dynamic elements from contrast checking
result = validator.validate_page(
    browser,
    "page",
    exclude=[".dynamic-loading"]
)
```

### Issue: Keyboard Navigation Tests Failing

**Problem:** Focus not visible on custom controls.

**Solution:**
```css
/* Add focus styles */
.custom-button:focus {
    outline: 2px solid #0000FF;
    outline-offset: 2px;
}
```

### Issue: Missing ARIA Labels

**Problem:** Form inputs lack proper labeling.

**Solution:**
```html
<!-- Use explicit labels -->
<label for="username">Username:</label>
<input id="username" name="username" type="text" aria-required="true">

<!-- Or use aria-label -->
<input type="text" aria-label="Search products">
```

## Performance Considerations

- **Test execution time**: ~3-5 seconds per page
- **Memory usage**: Minimal (axe-core runs in browser context)
- **Parallel execution**: Fully supported with pytest-xdist

**Optimize test performance:**
```bash
pytest -m accessibility -n auto  # Parallel execution
```

## Future Enhancements

1. **WCAG 2.2 Support** (when released)
2. **Automated screen reader testing**
3. **Mobile accessibility testing**
4. **PDF accessibility validation**
5. **Cognitive accessibility checks**

## Support

For issues or questions:
- Review test failures in `results/accessibility/`
- Check WCAG guidelines: https://www.w3.org/WAI/WCAG21/quickref/
- Consult accessibility team lead

## License

Internal testing module - follows project license.
