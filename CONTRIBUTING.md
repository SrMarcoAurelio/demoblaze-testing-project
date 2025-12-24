# Contributing to Universal Test Automation Framework

Thank you for your interest in contributing! This document provides guidelines and conventions for contributing to this project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Test Naming Conventions](#test-naming-conventions)
- [Commit Message Guidelines](#commit-message-guidelines)
- [Pull Request Process](#pull-request-process)

---

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Follow project conventions

---

## Getting Started

### Prerequisites

```bash
# Python 3.11+ required
python --version

# Install dependencies
pip install -r requirements.txt

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test category
pytest -m smoke
pytest -m security
pytest -m functional

# Run with coverage
pytest --cov=framework --cov=utils
```

---

## Development Setup

### 1. Fork and Clone

```bash
git clone https://github.com/YOUR_USERNAME/test-automation-framework.git
cd test-automation-framework
```

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
pre-commit install
```

### 4. Create Feature Branch

```bash
git checkout -b feature/your-feature-name
```

---

## Coding Standards

### Python Style

- **Formatter**: Black (line length: 88)
- **Linter**: Flake8
- **Type Checker**: MyPy
- **Import Sorter**: isort

All enforced via pre-commit hooks.

### Code Quality

```python
# ✅ GOOD: Type hints, docstrings, clear naming
def validate_email(email: str) -> bool:
    """
    Validate email address format.

    Args:
        email: Email address to validate

    Returns:
        True if valid, False otherwise
    """
    if not isinstance(email, str):
        return False
    # ... validation logic

# ❌ BAD: No types, no docs, unclear
def check(e):
    if not e:
        return False
    # ...
```

### Documentation Requirements

**All public functions/classes MUST have**:
- Docstring with description
- Args section with types
- Returns section
- Example usage (when helpful)

```python
def example_function(param1: str, param2: int = 10) -> bool:
    """
    Brief description of what function does.

    Longer description if needed. Explain the purpose,
    use cases, and any important details.

    Args:
        param1: Description of param1
        param2: Description of param2 (default: 10)

    Returns:
        True if successful, False otherwise

    Raises:
        ValueError: When param1 is empty

    Example:
        >>> result = example_function("test", 20)
        >>> print(result)
        True
    """
    # Implementation
```

---

## Test Naming Conventions

### Test File Names

```
test_<feature>_<type>.py
```

Examples:
- `test_login_functional.py`
- `test_login_security.py`
- `test_login_business.py`

### Test Function Names

```
test_<feature>_<scenario>_<id>
```

Examples:
```python
def test_login_valid_credentials_AUTH_001(driver):
    """TC-AUTH-001: Test login with valid credentials."""
    pass

def test_sql_injection_username_field_INJ_001(driver):
    """TC-INJ-001: Test SQL injection in username field."""
    pass
```

### Test ID Prefixes

| Category | Prefix | Example |
|----------|--------|---------|
| Functional | FN | FN_001 |
| Business Rules | BR | BR_001 |
| Security | SEC | SEC_001 |
| SQL Injection | INJ | INJ_001 |
| XSS | XSS | XSS_001 |
| Authentication | AUTH | AUTH_001 |
| Performance | PERF | PERF_001 |
| API | API | API_001 |
| Database | DB | DB_001 |

### Test Markers

Always mark tests appropriately:

```python
@pytest.mark.smoke  # Critical path
@pytest.mark.functional  # Feature tests
@pytest.mark.security  # Security tests
@pytest.mark.high  # High priority
def test_critical_feature_FN_001(driver):
    """Test critical feature functionality."""
    pass
```

---

## Commit Message Guidelines

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `refactor`: Code refactoring
- `test`: Adding/updating tests
- `chore`: Maintenance tasks
- `perf`: Performance improvements
- `style`: Code style changes (formatting)

### Examples

```
feat(login): Add remember me functionality

Implemented remember me checkbox that stores credentials
securely using browser localStorage with encryption.

Closes #123
```

```
fix(security): Prevent SQL injection in search

Added parameterized queries to prevent SQL injection
vulnerabilities in product search functionality.

BREAKING CHANGE: Search API now requires sanitized inputs
```

```
test(api): Add comprehensive API validation tests

Added 14 new tests covering:
- CRUD operations
- Authentication flows
- Error handling
- Schema validation

Related to #456
```

### Commit Message Rules

1. Use imperative mood ("Add feature" not "Added feature")
2. First line <= 72 characters
3. Blank line between subject and body
4. Body explains WHAT and WHY, not HOW
5. Reference issues/PRs in footer

---

## Pull Request Process

### 1. Before Creating PR

```bash
# Ensure tests pass
pytest

# Check code quality
flake8 .
mypy .

# Verify pre-commit hooks
pre-commit run --all-files

# Update documentation if needed
```

### 2. PR Title Format

```
[Type] Brief description

Examples:
[Feature] Add visual regression testing module
[Fix] Resolve namespace conflict in test_data
[Refactor] Extract modal operations to BasePage
```

### 3. PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] All tests pass locally
- [ ] Added new tests for changes
- [ ] Manual testing completed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No console warnings/errors
- [ ] Pre-commit hooks pass

## Screenshots (if applicable)

## Related Issues
Closes #123
Related to #456
```

### 4. Review Process

- At least 1 approval required
- All CI checks must pass
- No merge conflicts
- Documentation updated

---

## File Organization

### Page Objects

```
pages/
├── __init__.py          # Export all page objects
├── base_page.py         # Base class for all pages
├── login_page.py        # Login-specific actions
└── ...
```

**Rules**:
- One class per file
- Inherit from `BasePage`
- Use descriptive method names
- Group related methods

### Tests

```
tests/
├── <feature>/
│   ├── __init__.py
│   ├── test_<feature>_functional.py
│   ├── test_<feature>_security.py
│   └── test_<feature>_business.py
```

**Rules**:
- Organize by feature
- Separate by test type
- Use fixtures from conftest.py
- Keep tests independent

### Utils

```
utils/
├── <module>/
│   ├── __init__.py      # Export with __all__
│   ├── <module>.py      # Implementation
│   └── ...
```

---

## Environment Variables

### Required

```bash
# Test environment
TEST_USERNAME=your_test_user
TEST_PASSWORD=your_test_password

# Required
BASE_URL=https://your-application-url.com

# Optional
BROWSER=chrome
HEADLESS=true
```

### Configuration

Create `.env` file (not committed):

```bash
TEST_USERNAME=testuser
TEST_PASSWORD=securepassword
HEADLESS=false
```

---

## Common Issues

### Pre-commit Hook Failures

```bash
# Black formatting
black .

# Import sorting
isort .

# Type checking
mypy utils/
```

### Test Collection Errors

```bash
# Check for missing markers
pytest --strict-markers

# Verify imports
python -c "import pages; import utils"
```

### Dependency Issues

```bash
# Reinstall dependencies
pip install --force-reinstall -r requirements.txt

# Check installed versions
pip list | grep -E "selenium|pytest|faker"
```

---

## Resources

- [Project Documentation](documentation/)
- [Pytest Documentation](https://docs.pytest.org)
- [Selenium Documentation](https://selenium-python.readthedocs.io)
- [Black Code Style](https://black.readthedocs.io)

---

## Questions?

- Open an issue for bugs/feature requests
- Check existing issues before creating new ones
- Provide minimal reproducible examples

---

**Thank you for contributing! 🎉**
