# Accessibility API Reference

WCAG 2.1 accessibility testing with axe-core.

**File:** `utils/accessibility/axe_helper.py`
**Version:** 1.0
**Author:** Marc Arévalo

## Overview

The AxeHelper class provides a Python interface to axe-core, the accessibility testing engine. It enables automated WCAG 2.1 compliance testing directly within Selenium tests.

**Key Features:**
- WCAG 2.1 Level A, AA, AAA testing
- Automated violation detection
- Detailed violation reports
- Critical/serious violation filtering
- JSON report generation

---

## AxeHelper Class

### Constructor

```python
def __init__(self, driver) -> None:
```

**Parameters:**
- `driver` (WebDriver): Selenium WebDriver instance

**Internal State:**
- `self.driver`: WebDriver reference
- `self.axe`: Axe instance (axe-selenium-python)

**Example:**
```python
from utils.accessibility.axe_helper import AxeHelper

axe = AxeHelper(driver)
```

---

## WCAG Level Constants

Class-level constants for WCAG compliance levels:

```python
# WCAG 2.1 Level A
LEVEL_A = ["wcag2a", "wcag21a"]

# WCAG 2.1 Level AA
LEVEL_AA = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]

# WCAG 2.1 Level AAA
LEVEL_AAA = [
    "wcag2a", "wcag2aa", "wcag2aaa",
    "wcag21a", "wcag21aa", "wcag21aaa"
]

# Additional rule sets
BEST_PRACTICE = ["best-practice"]
EXPERIMENTAL = ["experimental"]
```

**Usage:**
```python
# Run scan with specific level
results = axe.axe.run(
    options={"runOnly": {"type": "tag", "values": axe.LEVEL_AA}}
)
```

---

## Core Scanning Methods

### inject_axe()

Inject axe-core script into current page.

**Signature:**
```python
def inject_axe(self) -> None:
```

**Returns:**
- None

**Note:**
- Called automatically by run_* methods
- Can be called manually for debugging

**Example:**
```python
axe.inject_axe()  # Explicit injection (usually not needed)
```

**Location:** axe_helper.py:48-51

---

### run_wcag_aa()

Run WCAG 2.1 Level AA accessibility scan.

**Signature:**
```python
def run_wcag_aa(self) -> Dict[str, Any]:
```

**Returns:**
- `Dict[str, Any]`: Axe results dictionary

**Result Structure:**
```python
{
    'url': 'https://example.com',
    'timestamp': '2025-12-03T14:30:15.123456',
    'violations': [...],      # List of violations
    'passes': [...],          # List of passed checks
    'incomplete': [...],      # Checks requiring manual review
    'inapplicable': [...]     # Not applicable checks
}
```

**Example:**
```python
from utils.accessibility.axe_helper import AxeHelper

# Navigate to page
browser.get("https://example.com")

# Run scan
axe = AxeHelper(browser)
results = axe.run_wcag_aa()

# Check violations
print(f"Violations found: {len(results['violations'])}")
```

**Location:** axe_helper.py:53-67

---

### run_wcag_a()

Run WCAG 2.1 Level A accessibility scan.

**Signature:**
```python
def run_wcag_a(self) -> Dict[str, Any]:
```

**Returns:**
- `Dict[str, Any]`: Axe results dictionary

**Example:**
```python
# Run Level A scan (minimum compliance)
results = axe.run_wcag_a()
```

**Location:** axe_helper.py:69-75

---

### run_full()

Run full accessibility scan (all available rules).

**Signature:**
```python
def run_full(self) -> Dict[str, Any]:
```

**Returns:**
- `Dict[str, Any]`: Axe results dictionary

**Example:**
```python
# Run comprehensive scan
results = axe.run_full()
```

**Location:** axe_helper.py:77-82

---

## Violation Analysis Methods

### get_violations(results=None)

Get violations from results.

**Signature:**
```python
def get_violations(
    self, results: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
```

**Parameters:**
- `results` (Optional[Dict]): Axe results. If None, runs new WCAG AA scan

**Returns:**
- `List[Dict[str, Any]]`: List of violation objects

**Violation Object Structure:**
```python
{
    'id': 'color-contrast',
    'impact': 'serious',  # 'critical', 'serious', 'moderate', 'minor'
    'description': 'Elements must have sufficient color contrast',
    'help': 'Elements must have sufficient color contrast',
    'helpUrl': 'https://dequeuniversity.com/rules/axe/4.x/color-contrast',
    'tags': ['wcag2aa', 'wcag143'],
    'nodes': [
        {
            'html': '<button>Click</button>',
            'target': ['#submit-button'],
            'failureSummary': 'Fix the following: ...',
            ...
        }
    ]
}
```

**Example:**
```python
results = axe.run_wcag_aa()
violations = axe.get_violations(results)

for violation in violations:
    print(f"Rule: {violation['id']}")
    print(f"Impact: {violation['impact']}")
    print(f"Affected elements: {len(violation['nodes'])}")
```

**Location:** axe_helper.py:84-98

---

### get_violation_count(results=None)

Get total number of violations.

**Signature:**
```python
def get_violation_count(
    self, results: Optional[Dict[str, Any]] = None
) -> int:
```

**Parameters:**
- `results` (Optional[Dict]): Axe results. If None, runs new scan

**Returns:**
- `int`: Number of violations

**Example:**
```python
count = axe.get_violation_count()
print(f"Found {count} violations")
```

**Location:** axe_helper.py:99-105

---

### get_critical_violations(results=None)

Get critical and serious violations only.

**Signature:**
```python
def get_critical_violations(
    self, results: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
```

**Parameters:**
- `results` (Optional[Dict]): Axe results. If None, runs new scan

**Returns:**
- `List[Dict[str, Any]]`: List of critical/serious violations

**Example:**
```python
# Focus on high-priority issues
critical = axe.get_critical_violations()

if critical:
    print(f"⚠ {len(critical)} critical/serious violations found:")
    for v in critical:
        print(f"  - {v['id']} ({v['impact']})")
```

**Location:** axe_helper.py:106-114

---

## Assertion Methods

### assert_no_violations(results=None, allow_minor=False)

Assert no accessibility violations.

**Signature:**
```python
def assert_no_violations(
    self,
    results: Optional[Dict[str, Any]] = None,
    allow_minor: bool = False,
) -> None:
```

**Parameters:**
- `results` (Optional[Dict]): Axe results. If None, runs new scan
- `allow_minor` (bool): If True, only fails on critical/serious violations

**Raises:**
- `AssertionError`: If violations found (with detailed message)

**Example:**
```python
# Strict - fail on any violation
axe.assert_no_violations()

# Lenient - allow minor violations
axe.assert_no_violations(allow_minor=True)

# With explicit results
results = axe.run_wcag_aa()
axe.assert_no_violations(results)
```

**Error Message Format:**
```
AssertionError: Accessibility violations found:
  [SERIOUS] color-contrast
    Description: Elements must have sufficient color contrast
    Affected elements: 3
    Help: https://dequeuniversity.com/rules/axe/4.x/color-contrast

  [CRITICAL] label
    Description: Form elements must have labels
    Affected elements: 1
    Help: https://dequeuniversity.com/rules/axe/4.x/label
```

**Location:** axe_helper.py:115-143

---

## Report Methods

### format_violations_summary(violations)

Format violations into readable summary.

**Signature:**
```python
def format_violations_summary(
    self, violations: List[Dict[str, Any]]
) -> str:
```

**Parameters:**
- `violations` (List[Dict]): List of violations

**Returns:**
- `str`: Formatted summary text

**Example:**
```python
violations = axe.get_violations()
summary = axe.format_violations_summary(violations)
print(summary)

# Output:
#   [SERIOUS] color-contrast
#     Description: Elements must have sufficient color contrast
#     Affected elements: 3
#     Help: https://dequeuniversity.com/rules/axe/4.x/color-contrast
#
#   [MODERATE] link-name
#     Description: Links must have discernible text
#     Affected elements: 2
#     Help: https://dequeuniversity.com/rules/axe/4.x/link-name
```

**Location:** axe_helper.py:144-163

---

### save_report(results, filepath, include_passes=False)

Save accessibility report to JSON file.

**Signature:**
```python
def save_report(
    self,
    results: Dict[str, Any],
    filepath: str,
    include_passes: bool = False,
) -> None:
```

**Parameters:**
- `results` (Dict): Axe results
- `filepath` (str): Output file path (creates parent directories)
- `include_passes` (bool): Include passed checks. Default: False

**Report Contents:**
- URL tested
- Timestamp
- Violations (always included)
- Incomplete checks (always included)
- Passes (only if include_passes=True)

**Example:**
```python
results = axe.run_wcag_aa()

# Save violations only
axe.save_report(results, "reports/accessibility/violations.json")

# Save full report including passes
axe.save_report(
    results,
    "reports/accessibility/full_report.json",
    include_passes=True
)
```

**Location:** axe_helper.py:164-195

---

### get_summary(results)

Get summary statistics from results.

**Signature:**
```python
def get_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
```

**Parameters:**
- `results` (Dict): Axe results

**Returns:**
- `Dict[str, Any]`: Summary statistics

**Return Dictionary:**
```python
{
    'total_violations': 5,
    'critical': 1,
    'serious': 2,
    'moderate': 1,
    'minor': 1,
    'incomplete': 3,
    'passes': 45
}
```

**Example:**
```python
results = axe.run_wcag_aa()
summary = axe.get_summary(results)

print(f"Accessibility Summary:")
print(f"  Total Violations: {summary['total_violations']}")
print(f"  Critical: {summary['critical']}")
print(f"  Serious: {summary['serious']}")
print(f"  Moderate: {summary['moderate']}")
print(f"  Minor: {summary['minor']}")
print(f"  Passes: {summary['passes']}")
```

**Location:** axe_helper.py:196-224

---

## Usage Examples

### Example 1: Basic Accessibility Test

```python
from utils.accessibility.axe_helper import AxeHelper

def test_homepage_accessibility(browser, base_url):
    # Navigate to page
    browser.get(base_url)

    # Run accessibility scan
    axe = AxeHelper(browser)
    axe.assert_no_violations()  # Fails if violations found
```

### Example 2: Detailed Violation Analysis

```python
def test_login_page_accessibility(browser, base_url):
    browser.get(base_url + "/login")

    axe = AxeHelper(browser)
    results = axe.run_wcag_aa()

    # Get violations
    violations = axe.get_violations(results)

    if violations:
        # Print detailed information
        for violation in violations:
            print(f"\nRule: {violation['id']}")
            print(f"Impact: {violation['impact']}")
            print(f"Description: {violation['description']}")
            print(f"Help URL: {violation['helpUrl']}")

            # Affected elements
            print(f"Affected elements:")
            for node in violation['nodes']:
                print(f"  - {node['html']}")
                print(f"    Selector: {node['target']}")

        # Save detailed report
        axe.save_report(results, "reports/accessibility/login_violations.json")

        pytest.fail(f"Found {len(violations)} accessibility violations")
```

### Example 3: Allow Minor Violations

```python
def test_accessibility_critical_only(browser, base_url):
    """Fail only on critical/serious violations."""
    browser.get(base_url)

    axe = AxeHelper(browser)

    # Allow minor/moderate violations
    axe.assert_no_violations(allow_minor=True)
```

### Example 4: Multi-Page Accessibility Suite

```python
import pytest

@pytest.mark.accessibility
@pytest.mark.parametrize("page", [
    "/",
    "/login",
    "/catalog",
    "/product/1",
    "/cart",
])
def test_page_accessibility(browser, base_url, page):
    """Test accessibility across all pages."""
    url = base_url + page
    browser.get(url)

    axe = AxeHelper(browser)
    results = axe.run_wcag_aa()

    # Get summary
    summary = axe.get_summary(results)

    # Log results
    print(f"\nAccessibility Results for {page}:")
    print(f"  Violations: {summary['total_violations']}")
    print(f"  Critical: {summary['critical']}")
    print(f"  Serious: {summary['serious']}")

    # Save report
    safe_page_name = page.replace("/", "_") or "home"
    axe.save_report(results, f"reports/accessibility/{safe_page_name}.json")

    # Assert
    assert summary['critical'] == 0, f"Critical violations on {page}"
    assert summary['serious'] == 0, f"Serious violations on {page}"
```

### Example 5: Test Specific Elements

```python
def test_form_accessibility(browser, base_url):
    """Test accessibility of a specific form."""
    browser.get(base_url + "/contact")

    # Inject axe
    axe = AxeHelper(browser)
    axe.inject_axe()

    # Scan specific element
    results = axe.axe.run(context="#contact-form")

    violations = axe.get_violations(results)
    if violations:
        summary = axe.format_violations_summary(violations)
        pytest.fail(f"Form accessibility issues:\n{summary}")
```

---

## Violation Impact Levels

Axe-core assigns impact levels to violations:

| Level | Description | Example Rules |
|-------|-------------|---------------|
| **Critical** | Severe impact on users | Missing alt text, no labels |
| **Serious** | Significant accessibility barrier | Poor color contrast, missing ARIA |
| **Moderate** | Noticeable but not blocking | Link text issues, duplicate IDs |
| **Minor** | Minor inconvenience | Missing language attribute |

**Priority Guidelines:**
- Fix Critical first
- Fix Serious before release
- Address Moderate in near term
- Minor can be deferred but should be tracked

---

## Common WCAG Rules Tested

### Color Contrast (color-contrast)
- **Level:** AA
- **Impact:** Serious
- **Requirement:** 4.5:1 for normal text, 3:1 for large text

### Form Labels (label)
- **Level:** A
- **Impact:** Critical
- **Requirement:** All form inputs must have labels

### Image Alt Text (image-alt)
- **Level:** A
- **Impact:** Critical
- **Requirement:** All images must have alt attributes

### Link Text (link-name)
- **Level:** A
- **Impact:** Serious
- **Requirement:** Links must have discernible text

### Heading Order (heading-order)
- **Level:** AA
- **Impact:** Moderate
- **Requirement:** Heading levels should not be skipped

### ARIA Attributes (aria-valid-attr)
- **Level:** A
- **Impact:** Critical
- **Requirement:** ARIA attributes must be valid

---

## Best Practices

1. **Run scans on every major page:**
```python
@pytest.mark.accessibility
class TestAccessibility:
    pages = ["/", "/login", "/catalog", "/cart", "/checkout"]

    @pytest.mark.parametrize("page", pages)
    def test_page(self, browser, base_url, page):
        browser.get(base_url + page)
        axe = AxeHelper(browser)
        axe.assert_no_violations()
```

2. **Use appropriate compliance level:**
```python
# Most common - Level AA
results = axe.run_wcag_aa()

# Minimum compliance - Level A
results = axe.run_wcag_a()

# Gold standard - Level AAA (very strict)
results = axe.run_full()
```

3. **Save reports for review:**
```python
results = axe.run_wcag_aa()
axe.save_report(results, f"reports/a11y/{test_name}.json")
```

4. **Focus on critical issues first:**
```python
critical = axe.get_critical_violations()
if critical:
    pytest.fail(f"Fix {len(critical)} critical violations first")
```

5. **Test after UI changes:**
```python
def test_new_feature_accessibility(browser):
    # Navigate to new feature
    browser.get("/new-feature")

    # Verify accessibility
    axe = AxeHelper(browser)
    axe.assert_no_violations()
```

---

## Limitations

**What axe-core CAN test:**
- Color contrast
- Form labels
- ARIA attributes
- Semantic HTML
- Keyboard navigation (partially)
- Alt text presence

**What axe-core CANNOT test:**
- Screen reader compatibility (requires manual testing)
- Logical tab order (automated check is limited)
- Context-appropriate alt text (requires human judgment)
- Usability for specific disabilities

**Manual Testing Still Required:**
- Screen reader testing (JAWS, NVDA, VoiceOver)
- Keyboard-only navigation
- Zoom/magnification
- Alt text quality (automated only checks presence)

---

## Related Documentation

- [Accessibility Testing Guide](../guides/accessibility-testing.md) - Complete testing guide
- [WCAG 2.1 Guidelines](https://www.w3.org/WAI/WCAG21/quickref/) - Official WCAG reference
- [axe-core Documentation](https://github.com/dequelabs/axe-core) - Axe-core project
