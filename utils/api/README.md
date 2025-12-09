# API Utilities

## Overview

REST API testing utilities with HTTP client, response validation, and schema checking.

## Files (300+ lines)

- `api_client.py` (8545 bytes) - HTTP client with retry logic
- `response_validator.py` (10205 bytes) - Response validation engine
- `schema_validator.py` (2568 bytes) - JSON schema validation

## Key Classes

### APIClient

HTTP client with automatic retries and timeout handling.

**Methods:**
- `get(endpoint, params, headers)` - GET request
- `post(endpoint, data, json, headers)` - POST request
- `put(endpoint, data, json, headers)` - PUT request
- `delete(endpoint, headers)` - DELETE request

### ResponseValidator

Validates HTTP responses comprehensively.

**Methods:**
- `validate_status_code(response, expected)` - Status code check
- `validate_response_time(response, max_time)` - Performance check
- `validate_headers(response, expected_headers)` - Header validation
- `validate_json_body(response, schema)` - Body schema validation

### SchemaValidator

JSON Schema Draft-07 validation.

**Methods:**
- `validate(data, schema)` - Validate data against schema
- `generate_schema(sample_data)` - Generate schema from sample

## Usage

```python
from utils.api.api_client import APIClient
from utils.api.response_validator import ResponseValidator

client = APIClient(base_url="https://api.example.com")
response = client.get("/products")

validator = ResponseValidator()
validator.validate_status_code(response, 200)
validator.validate_response_time(response, max_time=2.0)
```

## Documentation

See [API Testing Module](../../documentation/modules/api-testing.md)
