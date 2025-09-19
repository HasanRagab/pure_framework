"""
Request/Response validation system for Pure Framework.

Provides Pydantic-style validation decorators with detailed error messages.
"""

from typing import Dict, Any, Optional, Type, Union, List, Callable, get_type_hints
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
import json
import inspect
from datetime import datetime
from enum import Enum

from .framework_types import IRequest, IResponse, ValidationError


class ValidationErrorType(Enum):
    """Types of validation errors."""

    MISSING_FIELD = "missing_field"
    INVALID_TYPE = "invalid_type"
    INVALID_VALUE = "invalid_value"
    INVALID_FORMAT = "invalid_format"
    OUT_OF_RANGE = "out_of_range"
    CUSTOM_ERROR = "custom_error"


@dataclass
class ValidationErrorDetail:
    """Detailed information about a validation error."""

    field: str
    error_type: ValidationErrorType
    message: str
    value: Any = None
    expected_type: Optional[str] = None


@dataclass
class ValidationResult:
    """Result of validation operation."""

    is_valid: bool
    data: Optional[Dict[str, Any]] = None
    errors: List[ValidationErrorDetail] = field(default_factory=list)

    def add_error(
        self,
        field: str,
        error_type: ValidationErrorType,
        message: str,
        value: Any = None,
        expected_type: Optional[str] = None,
    ) -> None:
        """Add a validation error."""
        self.errors.append(
            ValidationErrorDetail(
                field=field,
                error_type=error_type,
                message=message,
                value=value,
                expected_type=expected_type,
            )
        )
        self.is_valid = False


class Validator(ABC):
    """Base class for field validators."""

    @abstractmethod
    def validate(self, value: Any, field_name: str) -> ValidationResult:
        """Validate a value."""
        pass


class TypeValidator(Validator):
    """Validator for basic type checking."""

    def __init__(self, expected_type: Type, required: bool = True):
        self.expected_type = expected_type
        self.required = required

    def validate(self, value: Any, field_name: str) -> ValidationResult:
        """Validate type."""
        result = ValidationResult(is_valid=True)

        if value is None:
            if self.required:
                result.add_error(
                    field_name,
                    ValidationErrorType.MISSING_FIELD,
                    f"Field '{field_name}' is required",
                )
            return result

        if not isinstance(value, self.expected_type):
            # Try type conversion for basic types
            if self.expected_type in (int, float, bool, str):
                try:
                    converted_value = self.expected_type(value)
                    result.data = {field_name: converted_value}
                    return result
                except (ValueError, TypeError):
                    pass

            result.add_error(
                field_name,
                ValidationErrorType.INVALID_TYPE,
                f"Expected {self.expected_type.__name__}, got {type(value).__name__}",
                value=value,
                expected_type=self.expected_type.__name__,
            )

        return result


class StringValidator(Validator):
    """Validator for string fields."""

    def __init__(
        self,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
        pattern: Optional[str] = None,
        required: bool = True,
    ):
        self.min_length = min_length
        self.max_length = max_length
        self.pattern = pattern
        self.required = required

    def validate(self, value: Any, field_name: str) -> ValidationResult:
        """Validate string."""
        result = ValidationResult(is_valid=True)

        if value is None:
            if self.required:
                result.add_error(
                    field_name,
                    ValidationErrorType.MISSING_FIELD,
                    f"Field '{field_name}' is required",
                )
            return result

        # Convert to string if possible
        if not isinstance(value, str):
            try:
                value = str(value)
            except (ValueError, TypeError):
                result.add_error(
                    field_name,
                    ValidationErrorType.INVALID_TYPE,
                    f"Cannot convert {type(value).__name__} to string",
                    value=value,
                    expected_type="string",
                )
                return result

        # Length validation
        if self.min_length is not None and len(value) < self.min_length:
            result.add_error(
                field_name,
                ValidationErrorType.OUT_OF_RANGE,
                f"String must be at least {self.min_length} characters long",
                value=value,
            )

        if self.max_length is not None and len(value) > self.max_length:
            result.add_error(
                field_name,
                ValidationErrorType.OUT_OF_RANGE,
                f"String must be at most {self.max_length} characters long",
                value=value,
            )

        # Pattern validation
        if self.pattern is not None:
            import re

            if not re.match(self.pattern, value):
                result.add_error(
                    field_name,
                    ValidationErrorType.INVALID_FORMAT,
                    f"String does not match required pattern: {self.pattern}",
                    value=value,
                )

        if result.is_valid:
            result.data = {field_name: value}

        return result


class NumberValidator(Validator):
    """Validator for numeric fields."""

    def __init__(
        self,
        num_type: Type[Union[int, float]] = int,
        min_value: Optional[Union[int, float]] = None,
        max_value: Optional[Union[int, float]] = None,
        required: bool = True,
    ):
        self.num_type = num_type
        self.min_value = min_value
        self.max_value = max_value
        self.required = required

    def validate(self, value: Any, field_name: str) -> ValidationResult:
        """Validate number."""
        result = ValidationResult(is_valid=True)

        if value is None:
            if self.required:
                result.add_error(
                    field_name,
                    ValidationErrorType.MISSING_FIELD,
                    f"Field '{field_name}' is required",
                )
            return result

        # Convert to number if possible
        if not isinstance(value, (int, float)):
            try:
                value = self.num_type(value)
            except (ValueError, TypeError):
                result.add_error(
                    field_name,
                    ValidationErrorType.INVALID_TYPE,
                    f"Cannot convert {type(value).__name__} to {self.num_type.__name__}",
                    value=value,
                    expected_type=self.num_type.__name__,
                )
                return result

        # Range validation
        if self.min_value is not None and value < self.min_value:
            result.add_error(
                field_name,
                ValidationErrorType.OUT_OF_RANGE,
                f"Value must be at least {self.min_value}",
                value=value,
            )

        if self.max_value is not None and value > self.max_value:
            result.add_error(
                field_name,
                ValidationErrorType.OUT_OF_RANGE,
                f"Value must be at most {self.max_value}",
                value=value,
            )

        if result.is_valid:
            result.data = {field_name: value}

        return result


class EmailValidator(Validator):
    """Validator for email addresses."""

    def __init__(self, required: bool = True):
        self.required = required

    def validate(self, value: Any, field_name: str) -> ValidationResult:
        """Validate email."""
        result = ValidationResult(is_valid=True)

        if value is None:
            if self.required:
                result.add_error(
                    field_name,
                    ValidationErrorType.MISSING_FIELD,
                    f"Field '{field_name}' is required",
                )
            return result

        if not isinstance(value, str):
            result.add_error(
                field_name,
                ValidationErrorType.INVALID_TYPE,
                "Email must be a string",
                value=value,
                expected_type="string",
            )
            return result

        # Simple email validation
        import re

        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_pattern, value):
            result.add_error(
                field_name,
                ValidationErrorType.INVALID_FORMAT,
                "Invalid email format",
                value=value,
            )
        else:
            result.data = {field_name: value}

        return result


class ListValidator(Validator):
    """Validator for list fields."""

    def __init__(
        self,
        item_validator: Optional[Validator] = None,
        min_items: Optional[int] = None,
        max_items: Optional[int] = None,
        required: bool = True,
    ):
        self.item_validator = item_validator
        self.min_items = min_items
        self.max_items = max_items
        self.required = required

    def validate(self, value: Any, field_name: str) -> ValidationResult:
        """Validate list."""
        result = ValidationResult(is_valid=True)

        if value is None:
            if self.required:
                result.add_error(
                    field_name,
                    ValidationErrorType.MISSING_FIELD,
                    f"Field '{field_name}' is required",
                )
            return result

        if not isinstance(value, list):
            result.add_error(
                field_name,
                ValidationErrorType.INVALID_TYPE,
                f"Expected list, got {type(value).__name__}",
                value=value,
                expected_type="list",
            )
            return result

        # Length validation
        if self.min_items is not None and len(value) < self.min_items:
            result.add_error(
                field_name,
                ValidationErrorType.OUT_OF_RANGE,
                f"List must contain at least {self.min_items} items",
                value=value,
            )

        if self.max_items is not None and len(value) > self.max_items:
            result.add_error(
                field_name,
                ValidationErrorType.OUT_OF_RANGE,
                f"List must contain at most {self.max_items} items",
                value=value,
            )

        # Validate items
        validated_items = []
        if self.item_validator and result.is_valid:
            for i, item in enumerate(value):
                item_result = self.item_validator.validate(item, f"{field_name}[{i}]")
                if not item_result.is_valid:
                    result.errors.extend(item_result.errors)
                    result.is_valid = False
                else:
                    validated_items.append(
                        item_result.data.get(f"{field_name}[{i}]", item)
                        if item_result.data
                        else item
                    )

        if result.is_valid:
            result.data = {field_name: validated_items if self.item_validator else value}

        return result


class Schema:
    """Schema for request/response validation."""

    def __init__(self, fields: Dict[str, Validator]):
        self.fields = fields

    def validate(self, data: Dict[str, Any]) -> ValidationResult:
        """Validate data against schema."""
        result = ValidationResult(is_valid=True, data={})

        for field_name, validator in self.fields.items():
            field_value = data.get(field_name)
            field_result = validator.validate(field_value, field_name)

            if not field_result.is_valid:
                result.errors.extend(field_result.errors)
                result.is_valid = False
            elif field_result.data:
                if result.data is None:
                    result.data = {}
                result.data.update(field_result.data)

        return result


def validate_json(schema: Schema) -> Callable:
    """
    Decorator for validating JSON request body.

    Args:
        schema: Validation schema

    Returns:
        Decorator function
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Find request object
            request = None
            response = None

            # Check arguments for request/response
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()

            for param_name, param_value in bound_args.arguments.items():
                if hasattr(param_value, "json") and hasattr(param_value, "method"):  # IRequest
                    request = param_value
                elif hasattr(param_value, "status_code") and hasattr(
                    param_value, "json"
                ):  # IResponse
                    response = param_value

            if not request or not response:
                raise ValidationError(
                    "validate_json decorator requires request and response parameters"
                )

            # Validate JSON body
            try:
                json_data = request.json
                if json_data is None:
                    response.status_code = 400
                    response.json(
                        {
                            "error": "Validation Error",
                            "message": "Request body must be valid JSON",
                            "status_code": 400,
                        }
                    )
                    return

                validation_result = schema.validate(json_data)

                if not validation_result.is_valid:
                    response.status_code = 400
                    response.json(
                        {
                            "error": "Validation Error",
                            "message": "Request validation failed",
                            "details": [
                                {
                                    "field": error.field,
                                    "type": error.error_type.value,
                                    "message": error.message,
                                    "value": error.value,
                                    "expected_type": error.expected_type,
                                }
                                for error in validation_result.errors
                            ],
                            "status_code": 400,
                        }
                    )
                    return

                # Add validated data to kwargs
                kwargs["validated_data"] = validation_result.data

            except json.JSONDecodeError:
                response.status_code = 400
                response.json(
                    {
                        "error": "Validation Error",
                        "message": "Invalid JSON in request body",
                        "status_code": 400,
                    }
                )
                return
            except Exception as e:
                response.status_code = 500
                response.json(
                    {
                        "error": "Internal Server Error",
                        "message": f"Validation error: {str(e)}",
                        "status_code": 500,
                    }
                )
                return

            return func(*args, **kwargs)

        return wrapper

    return decorator


def validate_query(schema: Schema) -> Callable:
    """
    Decorator for validating query parameters.

    Args:
        schema: Validation schema

    Returns:
        Decorator function
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Find request object
            request = None
            response = None

            # Check arguments for request/response
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()

            for param_name, param_value in bound_args.arguments.items():
                if hasattr(param_value, "query") and hasattr(param_value, "method"):  # IRequest
                    request = param_value
                elif hasattr(param_value, "status_code") and hasattr(
                    param_value, "json"
                ):  # IResponse
                    response = param_value

            if not request or not response:
                raise ValidationError(
                    "validate_query decorator requires request and response parameters"
                )

            # Validate query parameters
            try:
                query_data = dict(request.query)

                # Convert list values to single values for simple validation
                for key, value in query_data.items():
                    if isinstance(value, list) and len(value) == 1:
                        query_data[key] = value[0]

                validation_result = schema.validate(query_data)

                if not validation_result.is_valid:
                    response.status_code = 400
                    response.json(
                        {
                            "error": "Validation Error",
                            "message": "Query parameter validation failed",
                            "details": [
                                {
                                    "field": error.field,
                                    "type": error.error_type.value,
                                    "message": error.message,
                                    "value": error.value,
                                    "expected_type": error.expected_type,
                                }
                                for error in validation_result.errors
                            ],
                            "status_code": 400,
                        }
                    )
                    return

                # Add validated data to kwargs
                kwargs["validated_query"] = validation_result.data

            except Exception as e:
                response.status_code = 500
                response.json(
                    {
                        "error": "Internal Server Error",
                        "message": f"Query validation error: {str(e)}",
                        "status_code": 500,
                    }
                )
                return

            return func(*args, **kwargs)

        return wrapper

    return decorator


# Convenience functions for creating common validators
def string(
    min_length: Optional[int] = None,
    max_length: Optional[int] = None,
    pattern: Optional[str] = None,
    required: bool = True,
) -> StringValidator:
    """Create a string validator."""
    return StringValidator(min_length, max_length, pattern, required)


def integer(
    min_value: Optional[int] = None, max_value: Optional[int] = None, required: bool = True
) -> NumberValidator:
    """Create an integer validator."""
    return NumberValidator(int, min_value, max_value, required)


def number(
    min_value: Optional[float] = None, max_value: Optional[float] = None, required: bool = True
) -> NumberValidator:
    """Create a float validator."""
    return NumberValidator(float, min_value, max_value, required)


def email(required: bool = True) -> EmailValidator:
    """Create an email validator."""
    return EmailValidator(required)


def list_of(
    item_validator: Validator,
    min_items: Optional[int] = None,
    max_items: Optional[int] = None,
    required: bool = True,
) -> ListValidator:
    """Create a list validator."""
    return ListValidator(item_validator, min_items, max_items, required)


# Import functools for decorator functionality
import functools
