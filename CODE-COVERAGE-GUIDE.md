# Code Coverage Guide - Phase 8

## 🎯 Overview

Code coverage measures which parts of your code are executed during tests. This helps identify untested code and improve test quality.

## 📊 Coverage Metrics

**Line Coverage**: Percentage of code lines executed
**Branch Coverage**: Percentage of if/else branches taken
**Function Coverage**: Percentage of functions called

**Our Target**: ≥70% coverage for production code

## ⚙️ Configuration

### Coverage Sources
Measuring coverage for:
- ✅ `pages/` - Page Object Models
- ✅ `utils/` - Utility functions

Excluded from coverage:
- ❌ `tests/` - Test files
- ❌ `conftest.py` - Pytest configuration
- ❌ `config.py` - Application config

### Threshold
**Minimum**: 70% coverage
**Enforcement**: Tests fail if below threshold

## 🚀 Usage

### Automatic (Default)
Coverage runs automatically with every pytest execution:
```bash
pytest
# Coverage reports generated automatically
```

### Manual Coverage Run
```bash
# Run tests with coverage
pytest --cov=pages --cov=utils

# HTML report only
pytest --cov=pages --cov=utils --cov-report=html

# Terminal report only
pytest --cov=pages --cov=utils --cov-report=term

# Skip coverage
pytest --no-cov
```

### Specific Tests
```bash
# Coverage for specific module
pytest tests/login/ --cov=pages.login_page

# Coverage for specific test
pytest tests/login/test_login_functional.py --cov=pages
```

## 📁 Reports Location

All coverage reports are in: `results/coverage/`

```
results/coverage/
├── html/              # HTML report (open index.html)
│   ├── index.html    # Main dashboard
│   ├── pages/        # Coverage per file
│   └── utils/
├── coverage.xml      # XML for CI/CD
├── coverage.json     # JSON for tools
└── .coverage         # Raw data
```

## 📊 Reading Reports

### Terminal Report
```
----------- coverage: platform linux, python 3.11.14 -----------
Name                               Stmts   Miss Branch BrPart  Cover   Missing
-------------------------------------------------------------------------------
pages/__init__.py                      0      0      0      0   100%
pages/base_page.py                    45      2     12      1    94%   23, 67
pages/login_page.py                   67      5     18      2    89%   45-49, 102
pages/cart_page.py                    52      0     14      0   100%
-------------------------------------------------------------------------------
TOTAL                                164      7     44      3    93%

Required coverage: 70.0%
✅ Coverage threshold met!
```

**Columns:**
- **Stmts**: Total statements
- **Miss**: Missed statements
- **Branch**: Total branches
- **BrPart**: Partial branches
- **Cover**: Coverage %
- **Missing**: Line numbers not covered

### HTML Report
1. Open `results/coverage/html/index.html`
2. Click on any file to see line-by-line coverage
3. **Green**: Executed lines
4. **Red**: Not executed
5. **Yellow**: Partial branch coverage

## 🎯 Coverage Goals

| Component | Current | Target | Status |
|-----------|---------|--------|--------|
| pages/ | TBD | ≥80% | 🎯 |
| utils/ | TBD | ≥75% | 🎯 |
| Overall | ≥70% | ≥75% | ✅ |

## 💡 Improving Coverage

### 1. Find Uncovered Code
```bash
# Run with missing lines
pytest --cov=pages --cov-report=term-missing

# Look for red lines in HTML report
open results/coverage/html/index.html
```

### 2. Write Tests for Missing Lines
```python
# Example: base_page.py line 67 not covered
def test_error_handling(browser):
    page = BasePage(browser)
    # Test the error handling path
    with pytest.raises(TimeoutException):
        page.wait_for_element("invalid_locator", timeout=1)
```

### 3. Check Branch Coverage
```python
# Both branches need testing
if user.is_logged_in():  # Branch 1: True
    show_dashboard()
else:                    # Branch 2: False
    show_login()

# Need 2 tests:
def test_logged_in_user():    # Covers Branch 1
    ...

def test_guest_user():        # Covers Branch 2
    ...
```

## 🚨 Common Issues

### Issue: Coverage Too Low
**Solution**:
```bash
# Identify missing coverage
pytest --cov=pages --cov-report=term-missing

# Add tests for uncovered lines
# Aim for critical paths first
```

### Issue: False Positives
**Solution**: Add `# pragma: no cover` to exclude lines
```python
def debug_helper():  # pragma: no cover
    # Development-only code
    print(debug_info)
```

### Issue: Slow Test Runs
**Solution**: Skip coverage for quick runs
```bash
pytest --no-cov  # Skip coverage measurement
```

## ⚙️ Configuration Files

### `.coveragerc`
Main configuration file with:
- Source directories
- Omit patterns
- Report settings
- Thresholds

### `pytest.ini`
Coverage options in pytest:
```ini
--cov=pages                                # Measure pages/
--cov=utils                                # Measure utils/
--cov-report=html:results/coverage/html    # HTML report
--cov-report=term-missing                  # Terminal report
--cov-branch                               # Branch coverage
--cov-fail-under=70                        # Minimum 70%
```

## 📈 CI/CD Integration

### Use XML Report
```bash
# Generate XML for CI tools (Jenkins, GitLab CI, etc.)
pytest --cov=pages --cov=utils --cov-report=xml

# XML file: results/coverage/coverage.xml
```

### Fail Build on Low Coverage
Already configured! Tests fail if coverage < 70%
```bash
pytest  # Automatically fails if coverage < 70%
```

### Coverage Badge
Use XML report with tools like:
- Codecov
- Coveralls
- Shields.io

## 🎓 Best Practices

### ✅ DO:
- Aim for 80%+ coverage on critical code
- Test both happy and error paths
- Use branch coverage for if/else
- Review coverage reports regularly
- Fix coverage before merging

### ❌ DON'T:
- Don't aim for 100% (diminishing returns)
- Don't test trivial code (getters/setters)
- Don't sacrifice test quality for coverage %
- Don't ignore branch coverage

## 📚 Quick Reference

```bash
# Run with coverage (default)
pytest

# Skip coverage
pytest --no-cov

# Only HTML report
pytest --cov-report=html --cov-report=

# Only terminal report
pytest --cov-report=term

# Detailed terminal report
pytest --cov-report=term-missing

# Specific module
pytest --cov=pages.login_page tests/login/

# Lower threshold for one run
pytest --cov-fail-under=60
```

## 🔗 Resources

- **Coverage.py Docs**: https://coverage.readthedocs.io/
- **pytest-cov Docs**: https://pytest-cov.readthedocs.io/
- **HTML Reports**: `results/coverage/html/index.html`
- **Configuration**: `.coveragerc`

---

**Phase 8 Complete** - Code Coverage Reporting
**Target Coverage**: ≥70%
**Framework Universality**: 10/10 (Industry standard)
