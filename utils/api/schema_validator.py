"""
Schema Validator
Validates JSON responses against JSON Schema.

Author: Marc Arévalo
Version: 1.0
"""

import logging
from typing import Any, Dict

from jsonschema import ValidationError, validate

logger = logging.getLogger(__name__)


class SchemaValidator:
    """
    Validates JSON responses against JSON Schema.

    Uses jsonschema library for comprehensive JSON validation.
    """

    @staticmethod
    def validate_schema(data: Dict[str, Any], schema: Dict[str, Any]) -> bool:
        """
        Validate JSON data against schema.

        Args:
            data: JSON data to validate
            schema: JSON Schema

        Returns:
            True if valid

        Raises:
            AssertionError: If validation fails
        """
        try:
            validate(instance=data, schema=schema)
            logger.debug("✓ JSON schema validation passed")
            return True
        except ValidationError as e:
            raise AssertionError(f"JSON schema validation failed: {e.message}")

    @staticmethod
    def create_simple_schema(
        required_fields: list,
        field_types: Dict[str, str],
        additional_properties: bool = True,
    ) -> Dict[str, Any]:
        """
        Create simple JSON schema.

        Args:
            required_fields: List of required field names
            field_types: Dict mapping field names to types
            additional_properties: Allow additional properties

        Returns:
            JSON Schema dict

        Example:
            schema = SchemaValidator.create_simple_schema(
                required_fields=["id", "name"],
                field_types={"id": "integer", "name": "string"}
            )
        """
        properties = {}

        for field, field_type in field_types.items():
            properties[field] = {"type": field_type}

        schema = {
            "type": "object",
            "properties": properties,
            "required": required_fields,
            "additionalProperties": additional_properties,
        }

        return schema

    @staticmethod
    def create_array_schema(item_schema: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create schema for array response.

        Args:
            item_schema: Schema for array items

        Returns:
            JSON Schema dict

        Example:
            item_schema = {"type": "object", "properties": {"id": {"type": "integer"}}}
            schema = SchemaValidator.create_array_schema(item_schema)
        """
        return {"type": "array", "items": item_schema}
