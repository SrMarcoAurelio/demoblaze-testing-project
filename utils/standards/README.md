# Standards Utilities

## Overview

Utilities for validating compliance with industry standards (ISO, NIST, PCI-DSS, WCAG).

## Features

- Password strength validation (NIST 800-63B)
- Credit card validation (Luhn algorithm, PCI-DSS)
- Software quality validation (ISO 25010)
- Accessibility standards validation (WCAG 2.1)

## Usage

```python
from utils.standards import PasswordValidator, CreditCardValidator

# Password validation
password_validator = PasswordValidator()
is_valid = password_validator.validate("MyP@ssw0rd123")

# Credit card validation
cc_validator = CreditCardValidator()
is_valid = cc_validator.validate_luhn("4111111111111111")
```

## Standards

- NIST 800-63B (Password guidelines)
- PCI-DSS (Payment Card Industry Data Security Standard)
- ISO 25010 (Software Quality Model)
- WCAG 2.1 (Web Content Accessibility Guidelines)
