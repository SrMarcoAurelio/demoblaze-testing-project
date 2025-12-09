# Test Templates

## Overview

Structured templates for creating new tests following framework standards.

## Directory Structure

```
templates/
├── Functionality/
│   ├── Guide/
│   │   └── Template guide and examples
│   └── test_template.py - Functional test template
└── Security/
    ├── Guide/
    │   └── Security test guide
    └── test_security_template.py - Security test template
```

## Templates

### Functional Test Template

Location: `templates/Functionality/test_template.py`

Template for creating functional tests with:
- Proper test structure
- Fixture usage
- Assertion patterns
- Documentation standards

### Security Test Template

Location: `templates/Security/test_security_template.py`

Template for security tests with:
- OWASP validation patterns
- Payload usage examples
- Vulnerability detection
- Security reporting

## Usage

1. Copy appropriate template
2. Rename file and test class
3. Update test methods
4. Add to appropriate test directory
5. Run tests to verify

## Example

```bash
# Copy template
cp templates/Functionality/test_template.py tests/new_feature/test_new_feature.py

# Edit and customize
# Run tests
pytest tests/new_feature/ -v
```

## Guidelines

See template guides in respective Guide/ directories for detailed instructions.
