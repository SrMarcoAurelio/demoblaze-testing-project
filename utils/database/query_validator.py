"""
Query Validator
Validates database query results for testing.

Author: Marc Arévalo
Version: 1.0
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class QueryValidator:
    """
    Validates database query results.

    Provides assertion-style validations for test scenarios.
    """

    @staticmethod
    def validate_row_exists(
        results: List[Dict[str, Any]],
        expected_values: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Validate at least one row exists.

        Args:
            results: Query results
            expected_values: Expected values to match (optional)

        Returns:
            True if valid

        Raises:
            AssertionError: If validation fails
        """
        assert len(results) > 0, "Expected at least one row, got 0"

        if expected_values:
            found = any(
                all(row.get(k) == v for k, v in expected_values.items())
                for row in results
            )
            assert found, f"No row found matching {expected_values}"

        logger.debug(f"✓ Row exists (found {len(results)} rows)")
        return True

    @staticmethod
    def validate_row_not_exists(results: List[Dict[str, Any]]) -> bool:
        """
        Validate no rows exist.

        Args:
            results: Query results

        Returns:
            True if valid

        Raises:
            AssertionError: If validation fails
        """
        assert len(results) == 0, f"Expected 0 rows, got {len(results)}"

        logger.debug("✓ Row does not exist")
        return True

    @staticmethod
    def validate_row_count(
        results: List[Dict[str, Any]], expected_count: int
    ) -> bool:
        """
        Validate exact row count.

        Args:
            results: Query results
            expected_count: Expected number of rows

        Returns:
            True if valid

        Raises:
            AssertionError: If validation fails
        """
        actual_count = len(results)
        assert (
            actual_count == expected_count
        ), f"Expected {expected_count} rows, got {actual_count}"

        logger.debug(f"✓ Row count = {actual_count}")
        return True

    @staticmethod
    def validate_field_value(
        row: Dict[str, Any], field: str, expected_value: Any
    ) -> bool:
        """
        Validate field value in row.

        Args:
            row: Database row
            field: Field name
            expected_value: Expected value

        Returns:
            True if valid

        Raises:
            AssertionError: If validation fails
        """
        assert field in row, f"Field '{field}' not found in row"

        actual_value = row[field]
        assert (
            actual_value == expected_value
        ), f"Field '{field}': expected '{expected_value}', got '{actual_value}'"

        logger.debug(f"✓ Field '{field}' = '{expected_value}'")
        return True

    @staticmethod
    def validate_field_not_null(row: Dict[str, Any], field: str) -> bool:
        """
        Validate field is not NULL.

        Args:
            row: Database row
            field: Field name

        Returns:
            True if valid

        Raises:
            AssertionError: If validation fails
        """
        assert field in row, f"Field '{field}' not found in row"
        assert row[field] is not None, f"Field '{field}' is NULL"

        logger.debug(f"✓ Field '{field}' is not NULL")
        return True

    @staticmethod
    def validate_field_is_null(row: Dict[str, Any], field: str) -> bool:
        """
        Validate field is NULL.

        Args:
            row: Database row
            field: Field name

        Returns:
            True if valid

        Raises:
            AssertionError: If validation fails
        """
        assert field in row, f"Field '{field}' not found in row"
        assert row[field] is None, f"Field '{field}' is not NULL: {row[field]}"

        logger.debug(f"✓ Field '{field}' is NULL")
        return True

    @staticmethod
    def validate_field_type(
        row: Dict[str, Any], field: str, expected_type: type
    ) -> bool:
        """
        Validate field type.

        Args:
            row: Database row
            field: Field name
            expected_type: Expected type

        Returns:
            True if valid

        Raises:
            AssertionError: If validation fails
        """
        assert field in row, f"Field '{field}' not found in row"

        actual_value = row[field]
        actual_type = type(actual_value)

        assert isinstance(
            actual_value, expected_type
        ), f"Field '{field}': expected {expected_type.__name__}, got {actual_type.__name__}"

        logger.debug(f"✓ Field '{field}' type is {expected_type.__name__}")
        return True

    @staticmethod
    def validate_all_rows_match(
        results: List[Dict[str, Any]], field: str, expected_value: Any
    ) -> bool:
        """
        Validate all rows have same field value.

        Args:
            results: Query results
            field: Field name
            expected_value: Expected value

        Returns:
            True if valid

        Raises:
            AssertionError: If validation fails
        """
        for i, row in enumerate(results):
            assert field in row, f"Field '{field}' not found in row {i}"
            actual = row[field]
            assert (
                actual == expected_value
            ), f"Row {i}: field '{field}' expected '{expected_value}', got '{actual}'"

        logger.debug(
            f"✓ All {len(results)} rows have '{field}' = '{expected_value}'"
        )
        return True
