# Accessibility Testing Guide - Phase 9

## 🎯 Overview

Accessibility (a11y) testing ensures the application is usable by people with disabilities, complying with WCAG 2.1 standards.

## ♿ What is WCAG 2.1?

**Web Content Accessibility Guidelines 2.1** - International standard for web accessibility.

### Compliance Levels:
- **Level A**: Minimum (basic accessibility)
- **Level AA**: Mid-range (**our target**)
- **Level AAA**: Highest (enhanced accessibility)

### Four Principles (POUR):
1. **Perceivable**: Information must be presentable to users
2. **Operable**: Interface must be operable by all users
3. **Understandable**: Information and operation must be understandable
4. **Robust**: Content must work with assistive technologies

## 🛠️ Technology Stack

**Axe-core** by Deque Systems - Industry-standard accessibility testing engine
- **Coverage**: 50+ WCAG rules
- **Accuracy**: Best-in-class (low false positives)
- **Integration**: Selenium WebDriver

## 📦 Components

### AxeHelper (`utils/accessibility/axe_helper.py`)

Main accessibility testing wrapper:

```python
from utils.accessibility.axe_helper import AxeHelper

axe = AxeHelper(browser)

# Run WCAG 2.1 AA scan
results = axe.run_wcag_aa()

# Get violations
violations = axe.get_violations(results)

# Assert no violations
axe.assert_no_violations(results, allow_minor=True)
```

**Key Methods:**
- `run_wcag_aa()` - WCAG 2.1 Level AA scan
- `run_wcag_a()` - WCAG 2.1 Level A scan
- `run_full()` - Complete accessibility audit
- `get_violations()` - Extract violations
- `get_critical_violations()` - Critical/serious only
- `assert_no_violations()` - Assertion helper
- `save_report()` - Save JSON report

## ✅ Test Suite

8 accessibility tests covering:

| Test | Description | Standard |
|------|-------------|----------|
| **A11Y-001** | Homepage compliance | WCAG AA |
| **A11Y-002** | Login modal | WCAG AA |
| **A11Y-003** | Catalog page | WCAG AA |
| **A11Y-004** | Product page | WCAG AA |
| **A11Y-005** | Cart page | WCAG AA |
| **A11Y-006** | Full scan | All rules |
| **A11Y-007** | Color contrast | WCAG AA |
| **A11Y-008** | Keyboard navigation | WCAG AA |

## 🚀 Usage

### Run Accessibility Tests

```bash
# All accessibility tests
pytest -m accessibility -v

# Specific test
pytest tests/accessibility/test_accessibility_wcag.py::test_homepage_wcag_aa_compliance

# With HTML report
pytest -m accessibility --html=results/a11y_report.html
```

### In Test Code

```python
@pytest.mark.accessibility
def test_page_accessibility(browser, base_url):
    browser.get(base_url)
    axe = AxeHelper(browser)

    # Run scan
    results = axe.run_wcag_aa()

    # Get summary
    summary = axe.get_summary(results)
    # {'total_violations': 5, 'critical': 1, 'serious': 2, ...}

    # Save report
    axe.save_report(results, "results/accessibility/page_report.json")

    # Assert
    axe.assert_no_violations(results, allow_minor=True)
```

## 📊 Understanding Results

### Violation Structure

```json
{
  "id": "color-contrast",
  "impact": "serious",
  "description": "Ensures text has sufficient color contrast",
  "help": "Elements must have sufficient color contrast",
  "helpUrl": "https://dequeuniversity.com/rules/axe/4.6/color-contrast",
  "nodes": [
    {
      "html": "<a href=\"#\">Click here</a>",
      "target": ["#header > a"],
      "failureSummary": "Fix any of the following:\n  Element has insufficient color contrast"
    }
  ]
}
```

### Impact Levels

- **Critical**: Must fix immediately
- **Serious**: Should fix soon
- **Moderate**: Fix when possible
- **Minor**: Low priority

### Common Violations

1. **Missing alt text**: `<img>` without alt attribute
2. **Color contrast**: Insufficient contrast ratio
3. **Form labels**: Input fields without labels
4. **Heading order**: Skipped heading levels (h1 → h3)
5. **Link text**: Links with "click here" text
6. **Keyboard access**: Elements not keyboard accessible

## 📁 Reports

Location: `results/accessibility/`

```
results/accessibility/
├── homepage_wcag_aa.json
├── login_modal_wcag_aa.json
├── catalog_wcag_aa.json
├── product_wcag_aa.json
├── cart_wcag_aa.json
└── full_scan.json
```

### Report Content

```json
{
  "url": "https://www.demoblaze.com",
  "timestamp": "2023-12-15T14:30:00.000Z",
  "violations": [...],
  "incomplete": [...],
  "passes": [...]
}
```

## 🔧 Configuration

### Allow Minor Issues

```python
# Fail on critical/serious only
axe.assert_no_violations(results, allow_minor=True)

# Fail on all violations
axe.assert_no_violations(results, allow_minor=False)
```

### Custom Rules

```python
# Run specific tags
results = axe.run(options={
    "runOnly": {
        "type": "tag",
        "values": ["wcag2aa", "best-practice"]
    }
})

# Disable specific rules
results = axe.run(options={
    "rules": {
        "color-contrast": {"enabled": False}
    }
})
```

## 💡 Fixing Violations

### 1. Missing Alt Text

```html
<!-- Bad -->
<img src="product.jpg">

<!-- Good -->
<img src="product.jpg" alt="Blue running shoes">
```

### 2. Form Labels

```html
<!-- Bad -->
<input type="text" name="username">

<!-- Good -->
<label for="username">Username:</label>
<input type="text" id="username" name="username">
```

### 3. Color Contrast

```css
/* Bad - Insufficient contrast */
.text { color: #777; background: #fff; } /* 4.47:1 */

/* Good - Sufficient contrast */
.text { color: #595959; background: #fff; } /* 4.54:1 ✓ */
```

### 4. Keyboard Navigation

```html
<!-- Bad - div not keyboard accessible -->
<div onclick="submit()">Submit</div>

<!-- Good - button is keyboard accessible -->
<button onclick="submit()">Submit</button>
```

### 5. Heading Hierarchy

```html
<!-- Bad - Skips h2 -->
<h1>Title</h1>
<h3>Subtitle</h3>

<!-- Good - Proper hierarchy -->
<h1>Title</h1>
<h2>Subtitle</h2>
```

## 🎯 Best Practices

### ✅ DO:

- Test early and often
- Fix critical/serious violations first
- Test with real screen readers (manual testing)
- Include accessibility in CI/CD
- Test keyboard navigation manually
- Provide text alternatives for images
- Ensure proper semantic HTML

### ❌ DON'T:

- Rely solely on automated testing (covers ~30-50% of issues)
- Ignore minor violations completely
- Use generic "image" or "link" alt text
- Skip manual keyboard testing
- Remove focus indicators for aesthetics

## 📚 Resources

- **WCAG 2.1 Guidelines**: https://www.w3.org/WAI/WCAG21/quickref/
- **Axe-core Rules**: https://github.com/dequelabs/axe-core/blob/develop/doc/rule-descriptions.md
- **Deque University**: https://dequeuniversity.com/
- **WebAIM**: https://webaim.org/
- **a11y Project**: https://www.a11yproject.com/

## 🔗 Integration

### CI/CD Integration

```bash
# Run in CI pipeline
pytest -m accessibility --junit-xml=results/a11y_junit.xml

# Fail build on violations
pytest -m accessibility || exit 1
```

### Continuous Monitoring

```python
# Schedule regular scans
@pytest.mark.accessibility
@pytest.mark.schedule("daily")
def test_production_accessibility():
    # Test production site
    pass
```

## 🎓 Quick Reference

```bash
# Run all a11y tests
pytest -m accessibility

# Specific page
pytest tests/accessibility/test_accessibility_wcag.py::test_homepage_wcag_aa_compliance

# Skip a11y tests
pytest -m "not accessibility"

# Generate report
pytest -m accessibility --html=a11y_report.html
```

---

**Phase 9 Complete** - WCAG 2.1 Accessibility Testing
**Target**: WCAG 2.1 Level AA Compliance
**Framework Universality**: 10/10 (Industry standard - axe-core)
