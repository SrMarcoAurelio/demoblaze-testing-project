"""
Response Validator
Validates HTTP responses for API testing.

Author: Marc Arévalo
Version: 1.0
"""

import json
import logging
from typing import Any, Dict, List, Optional, Union

import requests

logger = logging.getLogger(__name__)


class ResponseValidator:
    """
    Validates HTTP responses for API testing.

    Provides comprehensive validation of:
    - Status codes
    - Headers
    - Response body (JSON, text)
    - Response time
    - Content type
    """

    @staticmethod
    def validate_status_code(
        response: requests.Response,
        expected_status: Union[int, List[int]],
    ) -> bool:
        """
        Validate response status code.

        Args:
            response: HTTP response
            expected_status: Expected status code(s)

        Returns:
            True if valid

        Raises:
            AssertionError: If status code doesn't match
        """
        if isinstance(expected_status, int):
            expected_status = [expected_status]

        actual = response.status_code

        assert (
            actual in expected_status
        ), f"Expected status {expected_status}, got {actual}"

        logger.debug(f"✓ Status code {actual} matches expected")
        return True

    @staticmethod
    def validate_json_response(response: requests.Response) -> Dict[str, Any]:
        """
        Validate response contains valid JSON.

        Args:
            response: HTTP response

        Returns:
            Parsed JSON data

        Raises:
            AssertionError: If response is not valid JSON
        """
        try:
            data = response.json()
            logger.debug("✓ Response is valid JSON")
            return data
        except json.JSONDecodeError as e:
            raise AssertionError(f"Response is not valid JSON: {e}")

    @staticmethod
    def validate_response_time(
        response: requests.Response,
        max_time_ms: float,
    ) -> bool:
        """
        Validate response time.

        Args:
            response: HTTP response
            max_time_ms: Maximum acceptable time in milliseconds

        Returns:
            True if valid

        Raises:
            AssertionError: If response time exceeds limit
        """
        actual_ms = response.elapsed.total_seconds() * 1000

        assert (
            actual_ms <= max_time_ms
        ), f"Response time {actual_ms:.2f}ms exceeds limit {max_time_ms}ms"

        logger.debug(f"✓ Response time {actual_ms:.2f}ms within limit")
        return True

    @staticmethod
    def validate_header_exists(
        response: requests.Response,
        header_name: str,
    ) -> bool:
        """
        Validate header exists.

        Args:
            response: HTTP response
            header_name: Header name

        Returns:
            True if valid

        Raises:
            AssertionError: If header doesn't exist
        """
        assert (
            header_name in response.headers
        ), f"Header '{header_name}' not found in response"

        logger.debug(f"✓ Header '{header_name}' exists")
        return True

    @staticmethod
    def validate_header_value(
        response: requests.Response,
        header_name: str,
        expected_value: str,
    ) -> bool:
        """
        Validate header value.

        Args:
            response: HTTP response
            header_name: Header name
            expected_value: Expected header value

        Returns:
            True if valid

        Raises:
            AssertionError: If header value doesn't match
        """
        actual = response.headers.get(header_name)

        assert actual is not None, f"Header '{header_name}' not found"
        assert (
            actual == expected_value
        ), f"Header '{header_name}': expected '{expected_value}', got '{actual}'"

        logger.debug(f"✓ Header '{header_name}' matches expected value")
        return True

    @staticmethod
    def validate_content_type(
        response: requests.Response,
        expected_type: str,
    ) -> bool:
        """
        Validate Content-Type header.

        Args:
            response: HTTP response
            expected_type: Expected content type

        Returns:
            True if valid

        Raises:
            AssertionError: If content type doesn't match
        """
        actual = response.headers.get("Content-Type", "")

        assert (
            expected_type in actual
        ), f"Expected Content-Type '{expected_type}', got '{actual}'"

        logger.debug(f"✓ Content-Type matches: {expected_type}")
        return True

    @staticmethod
    def validate_json_field(
        data: Dict[str, Any],
        field_path: str,
        expected_value: Optional[Any] = None,
    ) -> bool:
        """
        Validate JSON field exists and optionally check value.

        Args:
            data: JSON data
            field_path: Field path (dot notation, e.g., "user.name")
            expected_value: Expected value (optional)

        Returns:
            True if valid

        Raises:
            AssertionError: If validation fails
        """
        # Navigate through nested fields
        keys = field_path.split(".")
        current = data

        for key in keys:
            assert (
                isinstance(current, dict) and key in current
            ), f"Field '{field_path}' not found in JSON"
            current = current[key]

        if expected_value is not None:
            assert (
                current == expected_value
            ), f"Field '{field_path}': expected '{expected_value}', got '{current}'"
            logger.debug(
                f"✓ Field '{field_path}' = '{current}' matches expected"
            )
        else:
            logger.debug(f"✓ Field '{field_path}' exists")

        return True

    @staticmethod
    def validate_json_field_type(
        data: Dict[str, Any],
        field_path: str,
        expected_type: type,
    ) -> bool:
        """
        Validate JSON field type.

        Args:
            data: JSON data
            field_path: Field path
            expected_type: Expected type (str, int, list, dict, etc.)

        Returns:
            True if valid

        Raises:
            AssertionError: If type doesn't match
        """
        keys = field_path.split(".")
        current = data

        for key in keys:
            assert (
                isinstance(current, dict) and key in current
            ), f"Field '{field_path}' not found"
            current = current[key]

        actual_type = type(current)
        assert isinstance(
            current, expected_type
        ), f"Field '{field_path}': expected {expected_type.__name__}, got {actual_type.__name__}"

        logger.debug(
            f"✓ Field '{field_path}' type is {expected_type.__name__}"
        )
        return True

    @staticmethod
    def validate_json_array_length(
        data: Dict[str, Any],
        field_path: str,
        expected_length: Optional[int] = None,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
    ) -> bool:
        """
        Validate JSON array length.

        Args:
            data: JSON data
            field_path: Field path to array
            expected_length: Expected exact length (optional)
            min_length: Minimum length (optional)
            max_length: Maximum length (optional)

        Returns:
            True if valid

        Raises:
            AssertionError: If validation fails
        """
        keys = field_path.split(".")
        current = data

        for key in keys:
            assert (
                isinstance(current, dict) and key in current
            ), f"Field '{field_path}' not found"
            current = current[key]

        assert isinstance(
            current, list
        ), f"Field '{field_path}' is not an array"

        actual_length = len(current)

        if expected_length is not None:
            assert (
                actual_length == expected_length
            ), f"Array '{field_path}': expected length {expected_length}, got {actual_length}"
            logger.debug(f"✓ Array '{field_path}' length = {actual_length}")

        if min_length is not None:
            assert (
                actual_length >= min_length
            ), f"Array '{field_path}': length {actual_length} < minimum {min_length}"
            logger.debug(f"✓ Array '{field_path}' length >= {min_length}")

        if max_length is not None:
            assert (
                actual_length <= max_length
            ), f"Array '{field_path}': length {actual_length} > maximum {max_length}"
            logger.debug(f"✓ Array '{field_path}' length <= {max_length}")

        return True

    @staticmethod
    def validate_error_response(
        response: requests.Response,
        expected_error_message: Optional[str] = None,
    ) -> bool:
        """
        Validate error response.

        Args:
            response: HTTP response
            expected_error_message: Expected error message (optional)

        Returns:
            True if valid

        Raises:
            AssertionError: If validation fails
        """
        assert (
            response.status_code >= 400
        ), f"Expected error status (>=400), got {response.status_code}"

        logger.debug(f"✓ Response is error: {response.status_code}")

        if expected_error_message:
            data = response.json()
            # Common error message fields
            error_fields = ["error", "message", "detail", "msg"]

            found_message = None
            for field in error_fields:
                if field in data:
                    found_message = data[field]
                    break

            assert (
                found_message is not None
            ), "No error message found in response"
            assert expected_error_message in str(
                found_message
            ), f"Expected error message '{expected_error_message}' not found in '{found_message}'"

            logger.debug(f"✓ Error message matches: {expected_error_message}")

        return True
