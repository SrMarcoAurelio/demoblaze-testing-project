# Test Templates

Structured templates for creating different types of tests.

## Available Templates

### [Functional Test Template](functional-test-template.md)
Template for writing functional tests that verify core features and user workflows.

**Use this template for:**
- Happy path scenarios
- Feature validation
- User workflow testing
- Edge case handling
- Error handling

**Template includes:**
- Test structure guidelines
- Naming conventions
- Documentation standards
- Common patterns
- Example implementations

### [Security Test Template](security-test-template.md)
Template for writing security tests that check for vulnerabilities and security issues.

**Use this template for:**
- SQL injection testing
- XSS (Cross-Site Scripting) testing
- CSRF token validation
- Session management testing
- Authentication bypass attempts
- Input validation

**Template includes:**
- OWASP testing guidelines
- Common attack vectors
- Security test patterns
- Standards references (OWASP ASVS)
- Exploitation examples

## Using Templates

1. Choose the appropriate template for your test type
2. Copy the template structure
3. Adapt to your specific use case
4. Follow the naming conventions
5. Include proper documentation

## Template Structure

Each template follows this structure:

```python
# Test file header with description
import statements
fixtures and constants

@pytest.mark.category
def test_descriptive_name(fixtures):
    """
    Docstring explaining:
    - What is being tested
    - Why it's important
    - Standards referenced
    - Expected behavior
    """
    # Arrange
    setup_test_data()

    # Act
    perform_action()

    # Assert
    verify_outcome()
```

## Best Practices

**Test Naming:**
- Use descriptive names: `test_login_fails_with_invalid_password`
- Follow convention: `test_<what>_<condition>`
- Be specific about what is tested

**Documentation:**
- Always include docstrings
- Reference standards when applicable
- Explain complex logic
- Document expected behavior

**Organization:**
- Group related tests
- Use markers appropriately
- Keep tests focused and atomic
- Avoid test interdependencies

## Related Documentation

- [Getting Started Guide](../getting-started/first-test.md)
- [Test Fixtures Guide](../guides/test-fixtures.md)
- [Implementation Guide](../guides/implementation-guide.md)
