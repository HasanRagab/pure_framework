"""
Enhanced error handling system for Pure Framework.

Provides structured error types, handlers, and response formatting.
"""

from typing import Dict, Any, Optional, Type, Callable, List
from abc import ABC, abstractmethod
from enum import Enum
import traceback
import logging
from datetime import datetime

from .framework_types import IRequest, IResponse, FrameworkError


class ErrorCategory(Enum):
    """Categories of errors for better organization."""

    VALIDATION = "validation"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    NOT_FOUND = "not_found"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    RATE_LIMIT = "rate_limit"
    SERVER_ERROR = "server_error"
    DEPENDENCY_INJECTION = "dependency_injection"
    MIDDLEWARE = "middleware"
    BUSINESS_LOGIC = "business_logic"
    EXTERNAL_SERVICE = "external_service"


class HTTPException(FrameworkError):
    """Base class for HTTP exceptions with proper status codes."""

    def __init__(
        self,
        status_code: int,
        message: str,
        category: ErrorCategory = ErrorCategory.SERVER_ERROR,
        details: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.category = category
        self.details = details or {}
        self.headers = headers or {}
        self.timestamp = datetime.utcnow().isoformat()


class BadRequestError(HTTPException):
    """400 Bad Request error."""

    def __init__(
        self,
        message: str = "Bad Request",
        details: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        super().__init__(400, message, ErrorCategory.VALIDATION, details, headers)


class UnauthorizedError(HTTPException):
    """401 Unauthorized error."""

    def __init__(
        self,
        message: str = "Unauthorized",
        details: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        super().__init__(401, message, ErrorCategory.AUTHENTICATION, details, headers)


class ForbiddenError(HTTPException):
    """403 Forbidden error."""

    def __init__(
        self,
        message: str = "Forbidden",
        details: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        super().__init__(403, message, ErrorCategory.AUTHORIZATION, details, headers)


class NotFoundError(HTTPException):
    """404 Not Found error."""

    def __init__(
        self,
        message: str = "Not Found",
        resource: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        if resource:
            message = f"{resource} not found"
        super().__init__(404, message, ErrorCategory.NOT_FOUND, details, headers)


class MethodNotAllowedError(HTTPException):
    """405 Method Not Allowed error."""

    def __init__(
        self,
        message: str = "Method Not Allowed",
        allowed_methods: Optional[List[str]] = None,
        details: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        super().__init__(405, message, ErrorCategory.METHOD_NOT_ALLOWED, details, headers)
        if allowed_methods:
            if headers is None:
                self.headers = {}
            self.headers["Allow"] = ", ".join(allowed_methods)


class ConflictError(HTTPException):
    """409 Conflict error."""

    def __init__(
        self,
        message: str = "Conflict",
        details: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        super().__init__(409, message, ErrorCategory.BUSINESS_LOGIC, details, headers)


class ValidationError(HTTPException):
    """422 Unprocessable Entity error for validation failures."""

    def __init__(
        self,
        message: str = "Validation Error",
        validation_errors: Optional[List[Dict[str, Any]]] = None,
        details: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        if validation_errors:
            if details is None:
                details = {}
            details["validation_errors"] = validation_errors
        super().__init__(422, message, ErrorCategory.VALIDATION, details, headers)


class RateLimitError(HTTPException):
    """429 Too Many Requests error."""

    def __init__(
        self,
        message: str = "Rate Limit Exceeded",
        retry_after: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        super().__init__(429, message, ErrorCategory.RATE_LIMIT, details, headers)
        if retry_after:
            if headers is None:
                self.headers = {}
            self.headers["Retry-After"] = str(retry_after)


class InternalServerError(HTTPException):
    """500 Internal Server Error."""

    def __init__(
        self,
        message: str = "Internal Server Error",
        details: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        super().__init__(500, message, ErrorCategory.SERVER_ERROR, details, headers)


class ServiceUnavailableError(HTTPException):
    """503 Service Unavailable error."""

    def __init__(
        self,
        message: str = "Service Unavailable",
        retry_after: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        super().__init__(503, message, ErrorCategory.EXTERNAL_SERVICE, details, headers)
        if retry_after:
            if headers is None:
                self.headers = {}
            self.headers["Retry-After"] = str(retry_after)


class ErrorHandler(ABC):
    """Base class for error handlers."""

    @abstractmethod
    def can_handle(self, error: Exception) -> bool:
        """Check if this handler can handle the error."""
        pass

    @abstractmethod
    def handle(self, error: Exception, request: IRequest, response: IResponse) -> bool:
        """Handle the error and return True if handled."""
        pass


class HTTPExceptionHandler(ErrorHandler):
    """Handler for HTTP exceptions."""

    def __init__(self, include_details: bool = True, include_traceback: bool = False):
        self.include_details = include_details
        self.include_traceback = include_traceback

    def can_handle(self, error: Exception) -> bool:
        """Check if error is an HTTP exception."""
        return isinstance(error, HTTPException)

    def handle(self, error: Exception, request: IRequest, response: IResponse) -> bool:
        """Handle HTTP exception."""
        if not isinstance(error, HTTPException):
            return False

        response.status_code = error.status_code

        # Set any custom headers
        for header_name, header_value in error.headers.items():
            response.set_header(header_name, header_value)

        # Build error response
        error_response = {
            "error": error.__class__.__name__.replace("Error", ""),
            "message": error.message,
            "status_code": error.status_code,
            "category": error.category.value,
            "timestamp": error.timestamp,
        }

        if self.include_details and error.details:
            error_response["details"] = error.details

        if self.include_traceback:
            error_response["traceback"] = traceback.format_exc()

        response.json(error_response)
        return True


class ValidationErrorHandler(ErrorHandler):
    """Handler for validation errors from the validation module."""

    def can_handle(self, error: Exception) -> bool:
        """Check if error is a validation error."""
        return isinstance(error, ValidationError)

    def handle(self, error: Exception, request: IRequest, response: IResponse) -> bool:
        """Handle validation error."""
        if not isinstance(error, ValidationError):
            return False

        response.status_code = 422
        response.json(
            {
                "error": "Validation Error",
                "message": "Request validation failed",
                "status_code": 422,
                "category": "validation",
                "timestamp": datetime.utcnow().isoformat(),
                "details": error.details if hasattr(error, "details") else {},
            }
        )
        return True


class GenericErrorHandler(ErrorHandler):
    """Generic handler for unhandled exceptions."""

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.logger = logging.getLogger(__name__)

    def can_handle(self, error: Exception) -> bool:
        """Can handle any exception."""
        return True

    def handle(self, error: Exception, request: IRequest, response: IResponse) -> bool:
        """Handle generic exception."""
        self.logger.error(f"Unhandled exception: {error}", exc_info=True)

        response.status_code = 500

        if self.debug:
            response.json(
                {
                    "error": "Internal Server Error",
                    "message": str(error),
                    "type": error.__class__.__name__,
                    "status_code": 500,
                    "category": "server_error",
                    "timestamp": datetime.utcnow().isoformat(),
                    "traceback": traceback.format_exc(),
                    "request_info": {
                        "method": request.method.value,
                        "path": request.path,
                        "headers": dict(request.headers),
                    },
                }
            )
        else:
            response.json(
                {
                    "error": "Internal Server Error",
                    "message": "An unexpected error occurred",
                    "status_code": 500,
                    "category": "server_error",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )
        return True


class ErrorHandlerRegistry:
    """Registry for error handlers."""

    def __init__(self):
        self.handlers: List[ErrorHandler] = []
        self.logger = logging.getLogger(__name__)

    def register(self, handler: ErrorHandler) -> "ErrorHandlerRegistry":
        """Register an error handler."""
        self.handlers.append(handler)
        return self

    def handle_error(self, error: Exception, request: IRequest, response: IResponse) -> bool:
        """Handle an error using registered handlers."""
        for handler in self.handlers:
            try:
                if handler.can_handle(error):
                    if handler.handle(error, request, response):
                        return True
            except Exception as handler_error:
                self.logger.error(
                    f"Error in error handler {handler.__class__.__name__}: {handler_error}",
                    exc_info=True,
                )

        return False

    @staticmethod
    def get_default_registry(debug: bool = False) -> "ErrorHandlerRegistry":
        """Get a registry with default error handlers."""
        registry = ErrorHandlerRegistry()

        # Register handlers in order of specificity
        registry.register(HTTPExceptionHandler(include_traceback=debug))
        registry.register(ValidationErrorHandler())
        registry.register(GenericErrorHandler(debug=debug))

        return registry


# Convenience functions for raising common errors
def bad_request(message: str = "Bad Request", **kwargs) -> BadRequestError:
    """Create a BadRequestError."""
    return BadRequestError(message, **kwargs)


def unauthorized(message: str = "Unauthorized", **kwargs) -> UnauthorizedError:
    """Create an UnauthorizedError."""
    return UnauthorizedError(message, **kwargs)


def forbidden(message: str = "Forbidden", **kwargs) -> ForbiddenError:
    """Create a ForbiddenError."""
    return ForbiddenError(message, **kwargs)


def not_found(
    message: str = "Not Found", resource: Optional[str] = None, **kwargs
) -> NotFoundError:
    """Create a NotFoundError."""
    return NotFoundError(message, resource, **kwargs)


def conflict(message: str = "Conflict", **kwargs) -> ConflictError:
    """Create a ConflictError."""
    return ConflictError(message, **kwargs)


def validation_error(message: str = "Validation Error", **kwargs) -> ValidationError:
    """Create a ValidationError."""
    return ValidationError(message, **kwargs)


def rate_limit(message: str = "Rate Limit Exceeded", **kwargs) -> RateLimitError:
    """Create a RateLimitError."""
    return RateLimitError(message, **kwargs)


def internal_server_error(message: str = "Internal Server Error", **kwargs) -> InternalServerError:
    """Create an InternalServerError."""
    return InternalServerError(message, **kwargs)


def service_unavailable(message: str = "Service Unavailable", **kwargs) -> ServiceUnavailableError:
    """Create a ServiceUnavailableError."""
    return ServiceUnavailableError(message, **kwargs)


# Decorator for automatic error handling
def handle_errors(error_registry: Optional[ErrorHandlerRegistry] = None):
    """
    Decorator that automatically handles errors in route handlers.

    Args:
        error_registry: Custom error handler registry
    """

    def decorator(func: Callable) -> Callable:
        import functools

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Find request and response objects
            request = None
            response = None

            for arg in args:
                if hasattr(arg, "method") and hasattr(arg, "path"):  # IRequest
                    request = arg
                elif hasattr(arg, "status_code") and hasattr(arg, "json"):  # IResponse
                    response = arg

            if not request or not response:
                # Check kwargs
                for key, value in kwargs.items():
                    if hasattr(value, "method") and hasattr(value, "path"):  # IRequest
                        request = value
                    elif hasattr(value, "status_code") and hasattr(value, "json"):  # IResponse
                        response = value

            if not request or not response:
                # Can't handle errors without request/response
                return func(*args, **kwargs)

            try:
                return func(*args, **kwargs)
            except Exception as e:
                registry = error_registry or ErrorHandlerRegistry.get_default_registry()
                if not registry.handle_error(e, request, response):
                    # If no handler processed the error, re-raise it
                    raise

        return wrapper

    return decorator
