"""
API Testing Examples
Demonstrates API testing with APIClient and validators.

Author: Marc Arévalo
Version: 1.0

These tests demonstrate:
- GET/POST/PUT/DELETE requests
- Response validation
- JSON schema validation
- Authentication
- Error handling
"""

import pytest

from utils.api.api_client import APIClient
from utils.api.response_validator import ResponseValidator
from utils.api.schema_validator import SchemaValidator


@pytest.fixture
def api_client():
    """Create API client for testing."""
    # Example using JSONPlaceholder API
    client = APIClient(
        base_url="https://jsonplaceholder.typicode.com",
        timeout=10,
        default_headers={"Content-Type": "application/json"},
    )
    yield client
    client.close()


@pytest.mark.api
@pytest.mark.smoke
def test_get_request(api_client):
    """
    TC-API-001: Test GET request with response validation.

    Validates:
    - Status code 200
    - Response is valid JSON
    - Response time < 2000ms
    - Content-Type is JSON
    - Response fields exist
    """
    # Send GET request
    response = api_client.get("/posts/1")

    # Validate status code
    ResponseValidator.validate_status_code(response, 200)

    # Validate JSON response
    data = ResponseValidator.validate_json_response(response)

    # Validate response time
    ResponseValidator.validate_response_time(response, max_time_ms=2000)

    # Validate Content-Type
    ResponseValidator.validate_content_type(response, "application/json")

    # Validate JSON fields
    ResponseValidator.validate_json_field(data, "id", expected_value=1)
    ResponseValidator.validate_json_field(data, "userId")
    ResponseValidator.validate_json_field(data, "title")
    ResponseValidator.validate_json_field(data, "body")

    # Validate field types
    ResponseValidator.validate_json_field_type(data, "id", int)
    ResponseValidator.validate_json_field_type(data, "title", str)


@pytest.mark.api
def test_get_list(api_client):
    """
    TC-API-002: Test GET request for list of items.

    Validates array responses and pagination.
    """
    response = api_client.get("/posts")

    ResponseValidator.validate_status_code(response, 200)
    data = ResponseValidator.validate_json_response(response)

    # Validate it's an array
    assert isinstance(data, list), "Response should be an array"

    # Validate array is not empty
    assert len(data) > 0, "Response array should not be empty"

    # Validate first item structure
    first_item = data[0]
    ResponseValidator.validate_json_field(first_item, "id")
    ResponseValidator.validate_json_field(first_item, "userId")
    ResponseValidator.validate_json_field(first_item, "title")
    ResponseValidator.validate_json_field(first_item, "body")


@pytest.mark.api
def test_post_request(api_client):
    """
    TC-API-003: Test POST request to create resource.

    Validates:
    - Status code 201 Created
    - Response contains created resource
    - Response includes new ID
    """
    # Create payload
    payload = {"title": "Test Post", "body": "Test content", "userId": 1}

    # Send POST request
    response = api_client.post("/posts", json=payload)

    # Validate status code
    ResponseValidator.validate_status_code(response, 201)

    # Validate response
    data = ResponseValidator.validate_json_response(response)

    # Validate created resource
    ResponseValidator.validate_json_field(data, "id")
    ResponseValidator.validate_json_field(
        data, "title", expected_value="Test Post"
    )
    ResponseValidator.validate_json_field(
        data, "body", expected_value="Test content"
    )
    ResponseValidator.validate_json_field(data, "userId", expected_value=1)


@pytest.mark.api
def test_put_request(api_client):
    """
    TC-API-004: Test PUT request to update resource.

    Validates full resource update.
    """
    payload = {
        "id": 1,
        "title": "Updated Title",
        "body": "Updated content",
        "userId": 1,
    }

    response = api_client.put("/posts/1", json=payload)

    ResponseValidator.validate_status_code(response, 200)
    data = ResponseValidator.validate_json_response(response)

    ResponseValidator.validate_json_field(
        data, "title", expected_value="Updated Title"
    )
    ResponseValidator.validate_json_field(
        data, "body", expected_value="Updated content"
    )


@pytest.mark.api
def test_patch_request(api_client):
    """
    TC-API-005: Test PATCH request for partial update.

    Validates partial resource update.
    """
    payload = {"title": "Patched Title"}

    response = api_client.patch("/posts/1", json=payload)

    ResponseValidator.validate_status_code(response, 200)
    data = ResponseValidator.validate_json_response(response)

    ResponseValidator.validate_json_field(
        data, "title", expected_value="Patched Title"
    )


@pytest.mark.api
def test_delete_request(api_client):
    """
    TC-API-006: Test DELETE request.

    Validates resource deletion.
    """
    response = api_client.delete("/posts/1")

    # DELETE typically returns 200 or 204
    ResponseValidator.validate_status_code(response, [200, 204])


@pytest.mark.api
def test_query_parameters(api_client):
    """
    TC-API-007: Test GET with query parameters.

    Validates filtering and searching.
    """
    # Get posts for specific user
    params = {"userId": 1}
    response = api_client.get("/posts", params=params)

    ResponseValidator.validate_status_code(response, 200)
    data = ResponseValidator.validate_json_response(response)

    # Validate all posts belong to userId 1
    assert all(
        post["userId"] == 1 for post in data
    ), "All posts should have userId=1"


@pytest.mark.api
def test_404_not_found(api_client):
    """
    TC-API-008: Test 404 Not Found error.

    Validates error handling.
    """
    response = api_client.get("/posts/99999")

    ResponseValidator.validate_status_code(response, 404)


@pytest.mark.api
def test_json_schema_validation(api_client):
    """
    TC-API-009: Test JSON schema validation.

    Validates response against JSON Schema.
    """
    response = api_client.get("/posts/1")

    ResponseValidator.validate_status_code(response, 200)
    data = ResponseValidator.validate_json_response(response)

    # Define schema
    schema = SchemaValidator.create_simple_schema(
        required_fields=["id", "userId", "title", "body"],
        field_types={
            "id": "integer",
            "userId": "integer",
            "title": "string",
            "body": "string",
        },
    )

    # Validate against schema
    SchemaValidator.validate_schema(data, schema)


@pytest.mark.api
def test_array_schema_validation(api_client):
    """
    TC-API-010: Test array schema validation.

    Validates array response structure.
    """
    response = api_client.get("/posts")

    ResponseValidator.validate_status_code(response, 200)
    data = ResponseValidator.validate_json_response(response)

    # Define item schema
    item_schema = SchemaValidator.create_simple_schema(
        required_fields=["id", "userId", "title", "body"],
        field_types={
            "id": "integer",
            "userId": "integer",
            "title": "string",
            "body": "string",
        },
    )

    # Create array schema
    array_schema = SchemaValidator.create_array_schema(item_schema)

    # Validate against schema
    SchemaValidator.validate_schema(data, array_schema)


@pytest.mark.api
def test_authentication_with_bearer_token(api_client):
    """
    TC-API-011: Test authentication with Bearer token.

    Demonstrates token authentication.
    """
    # Set Bearer token
    api_client.set_auth_token("fake_token_12345")

    # Verify Authorization header is set
    assert "Authorization" in api_client.session.headers
    assert (
        api_client.session.headers["Authorization"]
        == "Bearer fake_token_12345"
    )

    # Clear auth
    api_client.clear_auth()
    assert "Authorization" not in api_client.session.headers


@pytest.mark.api
def test_custom_headers(api_client):
    """
    TC-API-012: Test custom headers.

    Validates custom header functionality.
    """
    # Set custom header
    api_client.set_header("X-Custom-Header", "custom_value")

    response = api_client.get("/posts/1")

    # Verify request was sent (even though this API doesn't use custom headers)
    ResponseValidator.validate_status_code(response, 200)

    # Remove header
    api_client.remove_header("X-Custom-Header")


@pytest.mark.api
@pytest.mark.performance
def test_response_time_validation(api_client):
    """
    TC-API-013: Test response time validation.

    Validates API performance.
    """
    response = api_client.get("/posts")

    ResponseValidator.validate_status_code(response, 200)

    # API should respond in less than 2 seconds
    ResponseValidator.validate_response_time(response, max_time_ms=2000)


@pytest.mark.api
def test_nested_json_fields(api_client):
    """
    TC-API-014: Test nested JSON field validation.

    Validates nested object access.
    """
    # This is a placeholder - adjust based on your actual API
    # Example: response with nested structure
    # {"user": {"profile": {"name": "John"}}}

    # For demo purposes with JSONPlaceholder
    response = api_client.get("/posts/1")
    data = ResponseValidator.validate_json_response(response)

    # Validate simple fields
    ResponseValidator.validate_json_field(data, "id")
    ResponseValidator.validate_json_field(data, "userId")
