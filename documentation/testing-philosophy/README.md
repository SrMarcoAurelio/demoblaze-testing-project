# Testing Philosophy

Framework testing methodology and principles.

## Core Philosophy

### [Discover vs Assume](discover-vs-assume.md)
The fundamental testing approach used throughout the framework.

**Traditional Approach (Assume):**
Tests assume expected behavior and fail when assumptions are wrong.

**Framework Approach (Discover):**
Tests discover actual behavior and report objectively whether it meets standards.

**Key Difference:**
- Assumption-based tests: "This SHOULD work this way"
- Discovery-based tests: "This WORKS this way - does it meet standards?"

## Testing Principles

### 1. Standards-Based Testing
All business logic tests reference specific standards:
- ISO 25010 - Software Quality Model
- OWASP ASVS 5.0 - Application Security
- PCI-DSS 4.0.1 - Payment Card Security
- WCAG 2.1 - Web Accessibility
- NIST 800-63B - Digital Identity

### 2. Objective Discovery
Tests objectively discover behavior rather than assuming outcomes:
```python
# Not: assert validation_exists()
# But: if validation_exists(): pass, else: report_violation()
```

### 3. Trinity Structure
Separate concerns into three test categories:
- Functional: Does it work?
- Business: Does it meet standards?
- Security: Is it secure?

### 4. Test Independence
Each test runs independently:
- No shared state between tests
- Fixtures provide clean state
- Tests can run in any order
- Parallel execution supported

### 5. Clear Documentation
Every test includes:
- Descriptive docstring
- Standards references
- Expected behavior
- Actual behavior discovered

## Testing Methodology

### Test Lifecycle
1. **Arrange** - Set up test data and state
2. **Act** - Perform the action being tested
3. **Assert** - Verify expected outcome
4. **Cleanup** - Automatic via fixtures

### Test Organization
Tests organized by:
- Module (login, catalog, product, etc.)
- Type (functional, business, security)
- Priority (critical, high, medium, low)

### Test Execution
Framework supports:
- Sequential execution
- Parallel execution (-n auto)
- Selective execution (by marker)
- Retry mechanism for flaky tests

## Quality Principles

### Code Quality
- Type hints for clarity
- Black formatting for consistency
- Flake8 linting for standards
- Mypy type checking

### Test Quality
- Clear test names
- Comprehensive docstrings
- Single assertion focus
- Appropriate markers

### Maintainability
- Page Object Model pattern
- External configuration
- Reusable fixtures
- DRY (Don't Repeat Yourself)

## Related Documentation

- [Implementation Guide](../guides/implementation-guide.md)
- [Test Templates](../templates/)
- [Getting Started](../getting-started/first-test.md)
