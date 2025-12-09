# Database Tests

## Overview

Database integrity and data validation testing. Verifies data consistency and query correctness.

## Test Coverage (15 tests)

- Database connection tests
- Query execution validation
- Data integrity checks
- Transaction testing

## Utilities

Uses `utils/database/` for database connections and operations.

## Running Tests

```bash
pytest -m database -v
pytest tests/database/ -v
```
