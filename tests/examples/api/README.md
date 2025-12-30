# API Tests

## Overview

REST API endpoint testing with schema validation, response time monitoring, and authentication testing.

## Test Coverage (27+ tests)

- API endpoint tests
- Authentication flow tests
- Contract testing
- Schema validation tests

## Utilities

Uses `utils/api/`:
- `api_client.py` - HTTP client with retry logic
- `response_validator.py` - Response validation
- `schema_validator.py` - JSON schema validation

## Running Tests

```bash
pytest -m api -v
pytest tests/api/ -v
```

## Documentation

See [API Testing Module](../../documentation/modules/api-testing.md)
